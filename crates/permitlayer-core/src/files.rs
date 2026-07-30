//! Encoding helpers for file-like connector payloads.

/// Decode Gmail-style URL-safe base64 that MAY carry `=` padding.
///
/// Gmail's `messages.attachments.get` returns `data` as base64url; the
/// core decoder ([`crate::agent::base64_url_no_pad_decode`]) is no-pad, so
/// strip any trailing `=` first. Returns `None` on any non-alphabet byte.
pub fn decode_base64url_maybe_padded(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    crate::agent::base64_url_no_pad_decode(trimmed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decode_padded_and_unpadded_base64url() {
        // "hello" → aGVsbG8 (no pad) / aGVsbG8= would be standard; base64url
        // of "hi" is "aGk" (no pad). Verify padded input decodes.
        let unpadded = crate::agent::base64_url_no_pad_encode(b"hi");
        let padded = format!("{unpadded}=");
        assert_eq!(decode_base64url_maybe_padded(&unpadded).unwrap(), b"hi");
        assert_eq!(decode_base64url_maybe_padded(&padded).unwrap(), b"hi");
    }
}
