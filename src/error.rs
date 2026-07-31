//! [`DhtError`] — the crate's error type.
//!
//! Every variant that carries text carries a [`SafeText`], never a `String` (#1675). A `String`
//! parameter accepts anything, so it invites a caller to embed whatever a peer sent; the safety of
//! the crate then rests on every present and future caller remembering a convention that is written
//! down nowhere in the type. `SafeText` cannot be built from a runtime `String` without saying the
//! text is untrusted, so raw peer text is unrepresentable in a `DhtError` rather than merely
//! discouraged.
//!
//! The constructors below make the provenance of every message explicit at the call site:
//! [`DhtError::transport`] for text this crate wrote, [`DhtError::transport_from_untrusted`] for
//! text that came from, or was derived from, a remote party.

use thiserror::Error;

use dig_nat::SafeText;

/// An error from a DHT operation.
#[derive(Debug, Error)]
pub enum DhtError {
    /// A transport-level failure talking to a peer (connect failed, stream error, timeout). Carries
    /// the underlying reason as text — the DHT treats a transport failure to one peer as that peer
    /// being unreachable and continues the lookup with others.
    #[error("transport error: {0}")]
    Transport(SafeText),

    /// A peer's response could not be parsed / did not match the expected shape for the request.
    ///
    /// The reason describes the failure WITHOUT quoting the response, because the response is
    /// exactly the thing the peer chose — see [`SafeText::describing_json_error`].
    #[error("malformed response: {0}")]
    MalformedResponse(SafeText),

    /// A hex `peer_id` / content key / root supplied to the API was not valid 64-char hex.
    #[error("invalid hex identifier: {0}")]
    InvalidHex(SafeText),

    /// The lookup could not proceed because the routing table + bootstrap set were empty — there is
    /// no one to ask. Bootstrap the node with at least one reachable peer first.
    #[error("no peers to query (routing table + bootstrap set are empty)")]
    NoPeers,

    /// The RPC timed out waiting for a peer response.
    #[error("rpc timed out")]
    Timeout,
}

impl DhtError {
    /// Build a [`DhtError::Transport`] from text THIS CRATE wrote.
    ///
    /// Accepts a `&'static str` (a source literal) or an already-vetted [`SafeText`]. It deliberately
    /// does NOT accept a `String` or an arbitrary `Display`: those are how a peer's own bytes used to
    /// get in. For a message derived from a remote party, say so with
    /// [`Self::transport_from_untrusted`].
    ///
    /// ```
    /// use dig_dht::DhtError;
    ///
    /// let err = DhtError::transport("connection refused");
    /// assert_eq!(err.to_string(), "transport error: connection refused");
    /// ```
    ///
    /// A raw `String` — the shape that let peer text in — no longer compiles:
    ///
    /// ```compile_fail
    /// use dig_dht::DhtError;
    ///
    /// let from_the_wire: String = std::env::var("PEER_SAID").unwrap_or_default();
    /// let err = DhtError::transport(from_the_wire);
    /// ```
    pub fn transport(text: impl Into<SafeText>) -> Self {
        DhtError::Transport(text.into())
    }

    /// Build a [`DhtError::Transport`] from text of REMOTE origin, neutralizing it on the way in.
    ///
    /// Use this for an `io::Error`, a TLS error, or any message whose content a peer could have
    /// influenced. The name is the documentation: a reader of the call site can see that untrusted
    /// text is entering an error, which is precisely what a bare `String` parameter concealed.
    pub fn transport_from_untrusted(reason: impl std::fmt::Display) -> Self {
        DhtError::Transport(SafeText::from_untrusted(reason.to_string()))
    }

    /// Build a [`DhtError::MalformedResponse`] describing a `serde_json` decode failure on a peer's
    /// reply, without quoting the reply.
    pub fn malformed_response(error: &serde_json::Error) -> Self {
        DhtError::MalformedResponse(SafeText::describing_json_error(error))
    }

    /// Build a [`DhtError::InvalidHex`] naming WHICH argument was not canonical 64-hex.
    ///
    /// The offending value is NOT echoed. A non-canonical identifier is by definition not one of our
    /// own, so quoting it back would put a stranger's bytes in the message; the caller already knows
    /// what it passed, so naming the argument is the diagnosis that actually helps.
    pub fn invalid_hex(which: &'static str) -> Self {
        DhtError::InvalidHex(SafeText::from_static(which))
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

    /// The untrusted door sanitizes; the trusted door has nothing to sanitize.
    #[test]
    fn untrusted_transport_text_cannot_forge_a_log_line() {
        let e = DhtError::transport_from_untrusted("refused\n2026-07-31 ERROR forged");

        let rendered = e.to_string();
        assert!(!rendered.contains('\n'), "got: {rendered:?}");
        assert!(
            rendered.contains("refused") && rendered.contains("forged"),
            "escaped, not deleted: {rendered}"
        );
    }

    #[test]
    fn a_malformed_response_does_not_quote_the_response() {
        let json_err =
            serde_json::from_str::<u64>(r#""what-the-peer-sent""#).expect_err("not a u64");

        let rendered = DhtError::malformed_response(&json_err).to_string();

        assert!(!rendered.contains("what-the-peer-sent"));
        assert!(rendered.contains("malformed response"));
        assert!(rendered.contains("line 1"), "still locatable: {rendered}");
    }

    #[test]
    fn invalid_hex_names_the_argument_rather_than_echoing_it() {
        let rendered = DhtError::invalid_hex("peer_id").to_string();

        assert!(rendered.contains("peer_id"));
        assert!(rendered.contains("invalid hex"));
    }

    #[test]
    fn error_messages_are_descriptive() {
        assert!(DhtError::NoPeers.to_string().contains("no peers"));
        assert!(DhtError::Timeout.to_string().contains("timed out"));
        assert!(DhtError::MalformedResponse(SafeText::from_static("x"))
            .to_string()
            .contains("malformed"));
    }
}
