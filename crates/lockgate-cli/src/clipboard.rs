//! Copying to the system clipboard over OSC 52.
//!
//! OSC 52 is an escape sequence the terminal itself acts on, so it needs no
//! platform clipboard library and — the reason it is worth preferring — it works
//! unchanged over SSH, where a native clipboard call would set the clipboard on
//! the wrong machine.
//!
//! This is **write-only**. OSC 52 can also *query* the clipboard, but the reply
//! arrives on stdin mixed into the key stream, and most terminals disable reads
//! for good reason: any program that can write to your terminal could otherwise
//! exfiltrate whatever you last copied. So `y` reaches the system clipboard and
//! `p` reads our own register. Pasting *into* the TUI is the terminal's own
//! paste, which arrives as ordinary keystrokes while inserting.

use std::io::{self, IsTerminal, Write};

/// Terminals cap how much they will accept in one sequence, and the limits are
/// neither advertised nor consistent. 64 KiB of text (about 87 KiB once
/// base64'd) is comfortably under every limit worth caring about, and far more
/// than anyone yanks out of an HTTP header.
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ClipboardError {
    /// Larger than a terminal will reliably accept.
    TooLarge(usize),
    /// stdout is a pipe or a file. An escape sequence there is not a clipboard
    /// write, it is corruption of whatever is reading us.
    NotATerminal,
    Io(String),
}

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClipboardError::TooLarge(n) => {
                write!(f, "too large for the terminal clipboard ({n} bytes)")
            }
            ClipboardError::NotATerminal => write!(f, "not running on a terminal"),
            ClipboardError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Put `text` on the system clipboard.
pub fn copy(text: &str) -> Result<(), ClipboardError> {
    let sequence = osc52(text)?;
    if !io::stdout().is_terminal() {
        return Err(ClipboardError::NotATerminal);
    }
    // Straight to stdout: the TUI already owns it, and the terminal reads the
    // sequence out of the same stream it reads the rest of our drawing from.
    let mut out = io::stdout();
    out.write_all(sequence.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| ClipboardError::Io(e.to_string()))
}

/// Build the escape sequence, without touching the terminal.
///
/// Sent plain, including under tmux. It is tempting to wrap it in tmux's DCS
/// passthrough envelope, and a lot of code does — but that is the wrong default
/// on both counts:
///
/// - `set-clipboard` defaults to `external`, meaning tmux *itself* intercepts
///   OSC 52 and re-emits it to the outer terminal. Plain works.
/// - `allow-passthrough` defaults to **off**, so a wrapped sequence is silently
///   discarded by tmux and never reaches anything.
///
/// So wrapping breaks the default configuration and plain fixes it. tmux only
/// forwards when the *outer* terminal's terminfo advertises `Ms`; the inner
/// `default-terminal` is irrelevant to that decision. If someone has set
/// `set-clipboard off`, they want tmux out of the way and should turn on
/// `allow-passthrough` — but that is their choice to make, not ours to force by
/// emitting a sequence the default config throws away.
fn osc52(text: &str) -> Result<String, ClipboardError> {
    if text.len() > MAX_BYTES {
        return Err(ClipboardError::TooLarge(text.len()));
    }
    // `c` selects the clipboard proper rather than the X primary selection.
    // BEL terminates rather than ST: both are legal, BEL is accepted by more
    // terminals.
    Ok(format!("\x1b]52;c;{}\x07", base64(text.as_bytes())))
}

/// Standard base64 (RFC 4648), padded.
///
/// Hand-rolled to keep the dependency surface at zero: it is a dozen lines and
/// the encoder — unlike a decoder — has no error cases to get wrong.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // Pack up to three bytes into 24 bits, then read back four 6-bit groups.
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let packed = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            // Groups past the end of the input are padding, not zeroes.
            if i > chunk.len() {
                out.push('=');
            } else {
                let index = (packed >> (18 - 6 * i)) & 0b11_1111;
                out.push(ALPHABET[index as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648's own vectors, which cover all three padding cases.
    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "encoding {input:?}");
        }
    }

    #[test]
    fn base64_handles_non_ascii_bytes() {
        // Multi-byte UTF-8 is just bytes to the encoder.
        assert_eq!(base64("é".as_bytes()), "w6k=");
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn sequence_carries_the_payload() {
        let seq = osc52("foobar").unwrap();
        assert_eq!(seq, "\x1b]52;c;Zm9vYmFy\x07");
    }

    /// No tmux passthrough envelope, ever. `allow-passthrough` is off by
    /// default, so a wrapped sequence would be discarded — whereas tmux's own
    /// `set-clipboard external` (also the default) forwards the plain one.
    #[test]
    fn never_wraps_for_tmux() {
        let seq = osc52("foobar").unwrap();
        assert!(
            !seq.contains("\x1bPtmux"),
            "wrapping breaks the default tmux config: {seq:?}"
        );
        assert!(seq.starts_with("\x1b]52;"), "{seq:?}");
    }

    #[test]
    fn oversized_payloads_are_refused_rather_than_truncated() {
        let big = "x".repeat(MAX_BYTES + 1);
        assert_eq!(
            osc52(&big),
            Err(ClipboardError::TooLarge(MAX_BYTES + 1)),
            "a silently truncated clipboard is worse than a reported failure"
        );
        // Right at the limit is still fine.
        assert!(osc52(&"x".repeat(MAX_BYTES)).is_ok());
    }

    #[test]
    fn empty_text_still_produces_a_valid_sequence() {
        assert_eq!(osc52("").unwrap(), "\x1b]52;c;\x07");
    }
}

#[cfg(test)]
mod interop_tests {
    use super::*;

    /// A realistic yank — a bearer token out of a header — encoded to the exact
    /// bytes a terminal expects. Cross-checked against a reference base64
    /// implementation rather than against our own output.
    #[test]
    fn encodes_a_real_header_value() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let expected = "QXV0aG9yaXphdGlvbjogQmVhcmVyIGV5SmhiR2NpT2lKSVV6STFOaUo5LnBheWxvYWQuc2ln";
        assert_eq!(base64(text.as_bytes()), expected);
        assert_eq!(osc52(text).unwrap(), format!("\x1b]52;c;{expected}\x07"));
    }
}
