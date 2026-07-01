//! [`DhtTransport`] — the one operation the DHT needs from the network: "send this
//! [`DhtRequest`] to that peer and give me the [`DhtResponse`]."
//!
//! The DHT's lookup + provider machinery is written entirely against this trait, so it is exercised
//! over an **in-memory harness** (`MemoryTransport`, test-only) with many virtual nodes in one
//! process and **no real network**. In production the trait is implemented over dig-nat: the impl
//! opens a [`dig_nat::connect`] mTLS connection (or reuses a pooled one), opens a logical stream,
//! writes the framed request, and reads the framed response — the DHT RPC "rides" the same
//! authenticated, multiplexed peer transport the content fetch uses.
//!
//! ## Why a trait (not a concrete dig-nat call)
//!
//! - **Testability.** A DHT is inherently a *network* of many nodes; the only way to test iterative
//!   lookup convergence, provider replication, and TTL/republish deterministically is to simulate a
//!   swarm in-process. The trait lets the tests inject a router that connects N virtual nodes with
//!   zero sockets.
//! - **Transport independence.** dig-node owns the connection pool + the NAT-traversal context
//!   (gateway, reflexive addr, live relay) that `dig_nat::connect` needs. The DHT should not
//!   re-implement that; it takes "a way to talk to a peer" as a dependency. The production impl is a
//!   thin adapter dig-node wires up (see the implementers' note in the crate docs).

use async_trait::async_trait;

use crate::error::DhtError;
use crate::routing::Contact;
use crate::wire::{DhtRequest, DhtResponse};

/// Send one DHT RPC to one peer and return its response.
///
/// Implementations connect to `peer` (by `peer_id` + candidate addresses) over an authenticated
/// transport, perform the framed request/response exchange, and return the decoded response. A
/// failure to reach or parse the peer is a [`DhtError`]; the lookup treats it as "that peer is
/// unreachable" and continues with others — a transport error is never fatal to a lookup.
#[async_trait]
pub trait DhtTransport: Send + Sync {
    /// Perform `request` from this node (`from`) against `peer`, returning the peer's
    /// [`DhtResponse`].
    ///
    /// - `from` is THIS node's own [`Contact`] (its `peer_id` + candidate addresses). On a real
    ///   dig-nat connection the remote learns this identity from the mTLS certificate, not the wire
    ///   body; a conforming transport therefore supplies it to the responder as the *authenticated*
    ///   caller (so the responder can populate its routing table — see
    ///   [`DhtService::handle_request_from`](crate::DhtService::handle_request_from)).
    /// - `peer` carries the target's `peer_id` (for mTLS verification) and candidate addresses (to
    ///   dial).
    ///
    /// The implementation is responsible for the per-RPC timeout. A failure to reach or parse the
    /// peer is a [`DhtError`]; the lookup treats it as "that peer is unreachable" and continues.
    async fn rpc(
        &self,
        from: &Contact,
        peer: &Contact,
        request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError>;
}

#[cfg(test)]
pub(crate) mod memory {
    //! An in-memory transport swarm for tests: a shared router maps each virtual node's `peer_id` to
    //! its request handler, so `rpc(peer, req)` is dispatched to that node's handler with no sockets.

    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;

    /// A per-node request handler (the serving half of a DHT node): given an inbound request, produce
    /// the response. Boxed so the router can hold heterogeneous node behaviours.
    pub type Handler = Arc<dyn Fn(DhtRequest) -> DhtResponse + Send + Sync>;

    /// The shared swarm: `peer_id` (64-hex) → that node's handler. Cloneable (`Arc` inside) so every
    /// node's [`MemoryTransport`] shares one routing table of handlers.
    #[derive(Clone, Default)]
    pub struct Swarm {
        nodes: Arc<Mutex<HashMap<String, Handler>>>,
        /// Peer ids that are "offline" — `rpc` to them fails (simulates an unreachable/dead peer).
        offline: Arc<Mutex<HashMap<String, ()>>>,
    }

    impl Swarm {
        /// A new empty swarm.
        pub fn new() -> Self {
            Swarm::default()
        }

        /// Register `handler` as the responder for `peer_id`.
        pub async fn register(&self, peer_id: String, handler: Handler) {
            self.nodes.lock().await.insert(peer_id, handler);
        }

        /// Mark a peer offline so `rpc` to it fails (simulates a dead/unreachable peer for
        /// liveness-eviction + retry tests).
        pub async fn set_offline(&self, peer_id: &str) {
            self.offline.lock().await.insert(peer_id.to_string(), ());
        }

        /// A transport handle bound to this swarm (every node shares the same swarm).
        pub fn transport(&self) -> MemoryTransport {
            MemoryTransport {
                swarm: self.clone(),
            }
        }
    }

    /// A [`DhtTransport`] that dispatches to the [`Swarm`]'s registered handlers instead of the
    /// network.
    pub struct MemoryTransport {
        swarm: Swarm,
    }

    #[async_trait]
    impl DhtTransport for MemoryTransport {
        async fn rpc(
            &self,
            _from: &Contact,
            peer: &Contact,
            request: &DhtRequest,
        ) -> Result<DhtResponse, DhtError> {
            if self.swarm.offline.lock().await.contains_key(&peer.peer_id) {
                return Err(DhtError::transport(format!("{} is offline", peer.peer_id)));
            }
            let handler = {
                let nodes = self.swarm.nodes.lock().await;
                nodes.get(&peer.peer_id).cloned()
            };
            match handler {
                // Round-trip the request through the wire encode/decode so tests also exercise the
                // framing, exactly as a real transport would.
                Some(h) => {
                    let encoded = request.encode();
                    let mut cur = std::io::Cursor::new(encoded);
                    let decoded = DhtRequest::decode(&mut cur)
                        .await
                        .map_err(DhtError::transport)?;
                    let resp = h(decoded);
                    let mut rcur = std::io::Cursor::new(resp.encode());
                    DhtResponse::decode(&mut rcur)
                        .await
                        .map_err(DhtError::transport)
                }
                None => Err(DhtError::transport(format!("no route to {}", peer.peer_id))),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use dig_nat::PeerId;

        fn contact(b: u8) -> Contact {
            Contact::new(&PeerId::from_bytes([b; 32]), vec![])
        }

        #[tokio::test]
        async fn dispatches_to_registered_handler() {
            let swarm = Swarm::new();
            let c = contact(1);
            swarm
                .register(
                    c.peer_id.clone(),
                    Arc::new(|req| match req {
                        DhtRequest::Ping { nonce } => DhtResponse::Pong { nonce },
                        _ => DhtResponse::Error {
                            code: 1,
                            message: "unexpected".into(),
                        },
                    }),
                )
                .await;
            let t = swarm.transport();
            let resp = t
                .rpc(&contact(0), &c, &DhtRequest::Ping { nonce: 42 })
                .await
                .unwrap();
            assert_eq!(resp, DhtResponse::Pong { nonce: 42 });
        }

        #[tokio::test]
        async fn unrouted_peer_errors() {
            let swarm = Swarm::new();
            let t = swarm.transport();
            let err = t
                .rpc(&contact(0), &contact(9), &DhtRequest::Ping { nonce: 1 })
                .await;
            assert!(matches!(err, Err(DhtError::Transport(_))));
        }

        #[tokio::test]
        async fn offline_peer_errors() {
            let swarm = Swarm::new();
            let c = contact(2);
            swarm
                .register(c.peer_id.clone(), Arc::new(|_| DhtResponse::AddProviderOk))
                .await;
            swarm.set_offline(&c.peer_id).await;
            assert!(t_err(&swarm, &c).await);
        }

        async fn t_err(swarm: &Swarm, c: &Contact) -> bool {
            swarm
                .transport()
                .rpc(&contact(0), c, &DhtRequest::Ping { nonce: 0 })
                .await
                .is_err()
        }
    }
}
