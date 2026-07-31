//! A peer's own bytes must never reach the text of a `DhtError` (#1674, #1675).
//!
//! `DhtRequest`/`DhtResponse` are internally tagged (`#[serde(tag = "type")]`), and an unrecognised
//! tag makes `serde_json` answer ``unknown variant `…`, expected one of …`` — with the tag rendered
//! through plain `Display`, NOT quoted. Nothing escapes it. So a stranger who sends one DHT frame
//! chooses text, control characters included, that lands in the receiver's own log.
//!
//! Every test drives the REAL public decoder over a REAL byte stream, and asserts the precondition
//! (that serde does echo) before asserting the fix, so none of them can pass against a message that
//! never contained the peer's bytes in the first place.

use dig_dht::{DhtError, DhtRequest};

/// The stranger's tag: a forged log line, complete with a real newline and a plausible timestamp.
///
/// The newline is the point. A marker of inert ASCII would prove only the disclosure half; here the
/// unescaped echo means a single unauthenticated frame can write a whole line of the operator's log.
const FORGED_TAG: &str = "ping\n2026-07-31T00:00:00Z INFO peer vouched-for by operator";

/// The forged line as it exists after serde decodes the JSON `\n` escape into a real newline.
const FORGED_DECODED: &str = "2026-07-31T00:00:00Z INFO peer vouched-for by operator";

/// The JSON body of a DHT frame whose `type` tag is `tag`.
///
/// Built with `serde_json` rather than string interpolation ON PURPOSE. `tag` contains a real
/// newline, and hand-writing the body put that byte into the JSON raw, which serde rejected as a
/// SYNTAX error — a frame that never reached the unknown-variant path at all, so the first version of
/// this test proved nothing while looking convincing. Letting the encoder escape it means the wire
/// bytes are valid JSON and serde decodes the tag back to a real newline, which is the actual attack.
fn body_with_tag(tag: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "type": tag, "nonce": 1 }))
        .expect("the test body serializes")
}

/// One length-prefixed DHT frame whose `type` tag is `tag`.
fn frame_with_tag(tag: &str) -> Vec<u8> {
    let body = body_with_tag(tag);
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(&body);
    wire
}

/// PRECONDITION — serde echoes an unknown tag, unescaped.
///
/// If this ever stops holding, the tests below stop proving anything and must be revisited rather
/// than trusted.
#[test]
fn serde_json_echoes_an_unknown_type_tag_without_escaping_it() {
    let raw = serde_json::from_slice::<DhtRequest>(&body_with_tag(FORGED_TAG))
        .expect_err("no such variant")
        .to_string();

    assert!(
        raw.contains(FORGED_DECODED),
        "premise gone: serde no longer echoes the tag. Got: {raw}"
    );
    assert!(
        raw.contains('\n'),
        "premise gone: serde now escapes the tag, so this is no longer an injection channel. \
         Got: {raw:?}"
    );
}

/// THE PROPERTY — the real decoder's error carries neither the forged line nor a line break.
#[tokio::test]
async fn a_forged_log_line_cannot_be_smuggled_through_a_dht_frame() {
    let mut cursor = std::io::Cursor::new(frame_with_tag(FORGED_TAG));

    let err = DhtRequest::decode(&mut cursor)
        .await
        .expect_err("an unknown tag must not decode");

    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains('\n') && !rendered.contains('\r'),
            "a peer forged a line break through a DHT frame: {rendered:?}"
        );
        assert!(
            !rendered.contains(FORGED_DECODED),
            "the error echoed the peer's forged line: {rendered:?}"
        );
    }
}

/// THE CONTROL — the fix must not be "say less".
#[tokio::test]
async fn a_rejected_dht_frame_still_diagnoses_the_failure() {
    let mut cursor = std::io::Cursor::new(frame_with_tag("no_such_method"));

    let err = DhtRequest::decode(&mut cursor)
        .await
        .expect_err("an unknown tag must not decode");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(
        msg.contains("line 1") && msg.contains("column"),
        "a developer must still be able to locate the failure: {msg}"
    );
    assert!(
        msg.contains("data"),
        "a developer must still be able to tell malformed JSON from a wrong shape: {msg}"
    );
}

/// #1675 — `DhtError::Transport` must not be *able* to carry raw peer text.
///
/// This is a placement property, not an outcome property, so asserting "the rendered error is clean"
/// would be satisfied by a sanitizer at any one call site and would keep passing if that sanitizer
/// moved. Instead the property is carried by the TYPE, and the load-bearing half of the proof is the
/// `compile_fail` doctest on `DhtError::transport` (`src/error.rs`), which asserts that passing a
/// runtime `String` does not build at all. That is the part a later refactor cannot quietly undo.
/// What this test adds is the behavioural half: that the neutralization is real, and that it escapes
/// rather than deletes.
#[test]
fn a_transport_error_neutralizes_peer_text_it_was_given() {
    let hostile = dig_nat::SafeText::from_untrusted("no route to peer\nERROR forged");
    let err = DhtError::transport(hostile);

    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains('\n'),
            "forged a line break: {rendered:?}"
        );
        // CONTROL: escaped, not deleted — the operator still learns what failed.
        assert!(
            rendered.contains("no route to peer"),
            "the diagnosis was deleted rather than neutralized: {rendered}"
        );
    }
}

/// A literal this crate wrote itself passes through untouched, so the typed variant costs nothing in
/// readability for the overwhelmingly common case.
#[test]
fn a_transport_error_from_our_own_literal_reads_normally() {
    let err = DhtError::transport("connection refused");

    assert!(err.to_string().contains("connection refused"));
    assert!(matches!(err, DhtError::Transport(_)));
}
