//! [`DhtError`] — the crate's error type.

use thiserror::Error;

/// An error from a DHT operation.
#[derive(Debug, Error)]
pub enum DhtError {
    /// A transport-level failure talking to a peer (connect failed, stream error, timeout). Carries
    /// the underlying reason as text — the DHT treats a transport failure to one peer as that peer
    /// being unreachable and continues the lookup with others.
    #[error("transport error: {0}")]
    Transport(String),

    /// A peer's response could not be parsed / did not match the expected shape for the request.
    #[error("malformed response: {0}")]
    MalformedResponse(String),

    /// A hex `peer_id` / content key / root supplied to the API was not valid 64-char hex.
    #[error("invalid hex identifier: {0}")]
    InvalidHex(String),

    /// The lookup could not proceed because the routing table + bootstrap set were empty — there is
    /// no one to ask. Bootstrap the node with at least one reachable peer first.
    #[error("no peers to query (routing table + bootstrap set are empty)")]
    NoPeers,

    /// The RPC timed out waiting for a peer response.
    #[error("rpc timed out")]
    Timeout,
}

impl DhtError {
    /// Convenience: build a [`DhtError::Transport`] from anything displayable.
    pub fn transport(e: impl std::fmt::Display) -> Self {
        DhtError::Transport(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_helper_formats() {
        let e = DhtError::transport("connection refused");
        assert!(e.to_string().contains("connection refused"));
        assert!(matches!(e, DhtError::Transport(_)));
    }

    #[test]
    fn error_messages_are_descriptive() {
        assert!(DhtError::NoPeers.to_string().contains("no peers"));
        assert!(DhtError::Timeout.to_string().contains("timed out"));
        assert!(DhtError::MalformedResponse("x".into())
            .to_string()
            .contains("malformed"));
    }
}
