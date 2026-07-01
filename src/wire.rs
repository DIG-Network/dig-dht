//! The DHT RPC wire — the four request/response messages, `type`-tagged JSON, framed as a `u32`
//! big-endian length prefix + JSON body (the same uniform framing dig-nat uses for its control
//! messages).
//!
//! ## The four methods (RLY-style, aligned to the L7 peer-network wire)
//!
//! | Method | Request | Response | Purpose |
//! |---|---|---|---|
//! | `find_node` | `{ type:"find_node", target:<64hex key> }` | `{ type:"nodes", nodes:[Contact] }` | the `k` peers this node knows closest to `target` |
//! | `find_providers` | `{ type:"find_providers", content_key:<64hex> }` | `{ type:"providers", providers:[ProviderRecord], closer:[Contact] }` | providers held locally + `k` closer peers if none |
//! | `add_provider` | `{ type:"add_provider", record:ProviderRecord }` | `{ type:"add_provider_ok" }` | store the record (announce to the `k` closest) |
//! | `ping` | `{ type:"ping", nonce:uint }` | `{ type:"pong", nonce:uint }` | liveness (echoes the nonce) |
//!
//! A [`Contact`] on the wire is `{ peer_id:<64hex>, addresses:[{host,port,
//! kind}] }` — the same address shape as the L7 `dig.getPeers` peers and a [`ProviderRecord`]'s
//! addresses, so a returned contact drops straight into a `PeerTarget` for [`dig_nat::connect`].
//!
//! Framing (`encode` / `decode`): a `u32` big-endian body length, then the JSON body, bounded by
//! [`MAX_FRAMED_BODY`] to guard against a malicious length prefix. This is byte-identical to the
//! dig-nat control framing so a node speaks one framing across the peer network.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::record::ProviderRecord;
use crate::routing::Contact;

/// A DHT RPC **request** — one of the four methods, discriminated by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DhtRequest {
    /// Ask for the `k` peers the responder knows closest to `target` (an XOR-metric target key).
    FindNode {
        /// The 64-hex target [`Key`](crate::Key) to find close peers to.
        target: String,
    },
    /// Ask for providers of `content_key`; if the responder holds none, it returns the `k` peers it
    /// knows closest to the key so the lookup can walk closer.
    FindProviders {
        /// The 64-hex content [`Key`](crate::Key) to find providers for.
        content_key: String,
    },
    /// Announce that the record's `provider_peer_id` holds the record's content. The responder
    /// stores the record (it is, by construction of the announce, one of the `k` closest to the key).
    AddProvider {
        /// The provider record to store.
        record: ProviderRecord,
    },
    /// Liveness check — the responder echoes `nonce` in its `pong`.
    Ping {
        /// An opaque nonce the responder echoes back, so a caller can match pong to ping.
        nonce: u64,
    },
}

/// A DHT RPC **response**, discriminated by `type`. Each variant is the reply to the correspondingly
/// named [`DhtRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DhtResponse {
    /// Reply to [`DhtRequest::FindNode`]: the `k` closest contacts the responder knows.
    Nodes {
        /// Up to `k` contacts, closest-first to the requested target.
        nodes: Vec<Contact>,
    },
    /// Reply to [`DhtRequest::FindProviders`]: any providers the responder holds for the key, plus
    /// (always) the `closer` contacts so a lookup can continue toward the key even when providers
    /// are already found (more may live nearer the key).
    Providers {
        /// Provider records the responder holds for the content key (may be empty).
        providers: Vec<ProviderRecord>,
        /// The `k` closest contacts the responder knows — used to walk the lookup closer.
        closer: Vec<Contact>,
    },
    /// Reply to [`DhtRequest::AddProvider`]: the record was accepted + stored.
    AddProviderOk,
    /// Reply to [`DhtRequest::Ping`]: the echoed nonce (proves liveness + round-trip).
    Pong {
        /// The nonce from the ping.
        nonce: u64,
    },
    /// A responder-side error (bad request, over capacity). Advisory — a lookup treats it like an
    /// unreachable peer and moves on.
    Error {
        /// A stable error code.
        code: u32,
        /// A human-readable message.
        message: String,
    },
}

/// Maximum length-prefixed body — guards against a malicious length prefix forcing a huge
/// allocation. Provider lists at `k = 20` with a handful of addresses each are well under this.
pub const MAX_FRAMED_BODY: usize = 256 * 1024;

impl DhtRequest {
    /// Serialize as a `u32` big-endian length prefix + JSON body.
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode a request from `r` (the serving side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

impl DhtResponse {
    /// Serialize as a `u32` big-endian length prefix + JSON body.
    pub fn encode(&self) -> Vec<u8> {
        encode_framed(self)
    }
    /// Read + decode a response from `r` (the requesting side).
    pub async fn decode<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        decode_framed(r).await
    }
}

/// Serialize `value` as a `u32` big-endian length prefix + JSON body — the uniform DHT-RPC framing.
fn encode_framed<T: Serialize>(value: &T) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("dht message serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Read + decode a length-prefixed JSON DHT message from `r`, bounded by [`MAX_FRAMED_BODY`].
async fn decode_framed<T: for<'de> Deserialize<'de>, R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAMED_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dht message too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AddressKind, CandidateAddr};
    use std::io::Cursor;

    #[tokio::test]
    async fn find_node_round_trips_framed() {
        let req = DhtRequest::FindNode {
            target: "ab".repeat(32),
        };
        let bytes = req.encode();
        let mut cur = Cursor::new(bytes);
        let back = DhtRequest::decode(&mut cur).await.unwrap();
        assert_eq!(req, back);
    }

    #[tokio::test]
    async fn providers_response_round_trips() {
        let resp = DhtResponse::Providers {
            providers: vec![ProviderRecord {
                content_key: "cd".repeat(32),
                provider_peer_id: "ef".repeat(32),
                addresses: vec![CandidateAddr::direct("203.0.113.7", 9444)],
                expires_at: 1_719_763_200,
            }],
            closer: vec![Contact {
                peer_id: "12".repeat(32),
                addresses: vec![CandidateAddr {
                    host: "h".into(),
                    port: 1,
                    kind: AddressKind::Mapped,
                }],
            }],
        };
        let mut cur = Cursor::new(resp.encode());
        let back = DhtResponse::decode(&mut cur).await.unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn request_type_tags_are_snake_case() {
        let s = serde_json::to_string(&DhtRequest::Ping { nonce: 7 }).unwrap();
        assert!(s.contains("\"type\":\"ping\""));
        assert!(s.contains("\"nonce\":7"));
        let fp = serde_json::to_string(&DhtRequest::FindProviders {
            content_key: "00".repeat(32),
        })
        .unwrap();
        assert!(fp.contains("\"type\":\"find_providers\""));
    }

    #[test]
    fn response_type_tags_are_snake_case() {
        assert!(serde_json::to_string(&DhtResponse::AddProviderOk)
            .unwrap()
            .contains("\"type\":\"add_provider_ok\""));
        assert!(serde_json::to_string(&DhtResponse::Pong { nonce: 9 })
            .unwrap()
            .contains("\"type\":\"pong\""));
    }

    #[tokio::test]
    async fn oversize_length_prefix_is_rejected() {
        // A frame claiming a body larger than MAX_FRAMED_BODY must error, not allocate.
        let mut buf = ((MAX_FRAMED_BODY + 1) as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        let mut cur = Cursor::new(buf);
        let err = DhtRequest::decode(&mut cur).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_errors() {
        // A length prefix promising 100 bytes but only 2 present → error (not a hang / partial).
        let mut buf = 100u32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"{}");
        let mut cur = Cursor::new(buf);
        assert!(DhtRequest::decode(&mut cur).await.is_err());
    }
}
