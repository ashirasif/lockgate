//! `Content-Encoding`: decoding bodies for reading, re-encoding them to send.
//!
//! Captured bodies are stored **exactly as they arrived**, compressed and all.
//! That is deliberate: a proxy that silently rewrites what came off the wire is
//! lying about what happened, and it would make the stored `Content-Length` a
//! fiction. The cost is that most real traffic is unreadable in its stored form
//! — a gzipped JSON response is binary noise — so decoding happens here, at the
//! boundary where a body is shown to someone rather than where it is recorded.
//!
//! The other direction matters just as much. An intercepted response that was
//! decoded for editing is plaintext by the time the operator is done with it;
//! forwarding it under its original `content-encoding` header would send
//! plaintext that the client will try to gunzip and reject. So an edited body
//! is re-encoded on the way out, and `Content-Length` is corrected to match.
//!
//! Every failure path here degrades to *the original bytes*. A truncated,
//! mislabelled or oversized body still renders — as noise, but it renders. In a
//! proxy the bytes that arrived are the evidence, and refusing to show them
//! because they will not decompress is the one outcome with no upside.

use hudsucker::hyper::HeaderMap;
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderValue};
use std::io::Read;

/// Ceiling on what one body may decompress to.
///
/// Compression ratios above 1000:1 are trivial to construct — a few hundred
/// bytes of gzip can claim gigabytes — and the far side of this proxy is by
/// definition not trusted. Hitting the cap yields the original bytes rather
/// than a partial decode, because half a JSON body is more misleading than an
/// obviously compressed one.
const MAX_DECODED: usize = 64 * 1024 * 1024;

/// The codings we can read and write.
///
/// `zstd` is deliberately absent: it is still rare in browser traffic and the
/// usable crate pulls a C library, which is a poor trade for the coverage it
/// adds. An unrecognised coding is not an error — the body is shown as it
/// arrived, which is honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Gzip,
    /// `deflate`. Sent both as a zlib stream and, by some servers, raw — so
    /// decoding tries both before giving up.
    Deflate,
    Brotli,
}

impl Coding {
    /// Parse a `Content-Encoding` value, for callers holding header pairs
    /// rather than a `HeaderMap` — the stored form does not keep one.
    pub fn from_header_value(value: &str) -> Option<Self> {
        Self::parse(value)
    }

    fn parse(value: &str) -> Option<Self> {
        // A comma-separated list means the codings were applied in order. Only
        // the single-coding case is handled: stacked encodings are vanishingly
        // rare in practice, and guessing at them would risk mangling a body.
        match value.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Coding::Gzip),
            "deflate" => Some(Coding::Deflate),
            "br" => Some(Coding::Brotli),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Brotli => "br",
        }
    }
}

/// The coding a message declares, if it is one we handle.
pub fn coding_of(headers: &HeaderMap) -> Option<Coding> {
    let value = headers.get(CONTENT_ENCODING)?.to_str().ok()?;
    // `identity` and unknown codings both mean "leave it alone".
    Coding::parse(value)
}

/// The body as text-bearing bytes: decompressed if it was compressed, and the
/// original otherwise.
///
/// Never fails. A body that will not decode comes back untouched.
pub fn decoded(headers: &HeaderMap, body: &Bytes) -> Bytes {
    let Some(coding) = coding_of(headers) else {
        return body.clone();
    };
    if body.is_empty() {
        return body.clone();
    }
    match decode(coding, body) {
        Some(plain) => Bytes::from(plain),
        None => body.clone(),
    }
}

/// Decode a body whose coding is already known.
///
/// Never fails, on the same reasoning as [`decoded`]: a body that will not
/// decompress comes back as it arrived.
pub fn decode_body(coding: Coding, body: &Bytes) -> Bytes {
    if body.is_empty() {
        return body.clone();
    }
    match decode(coding, body) {
        Some(plain) => Bytes::from(plain),
        None => body.clone(),
    }
}

fn decode(coding: Coding, body: &[u8]) -> Option<Vec<u8>> {
    match coding {
        Coding::Gzip => read_capped(flate2::read::GzDecoder::new(body)),
        // Some servers send a raw deflate stream despite the spec calling for
        // zlib framing, so a zlib failure is retried raw before giving up.
        Coding::Deflate => read_capped(flate2::read::ZlibDecoder::new(body))
            .or_else(|| read_capped(flate2::read::DeflateDecoder::new(body))),
        Coding::Brotli => read_capped(brotli::Decompressor::new(body, 4096)),
    }
}

/// Read a decoder to completion, or give up at [`MAX_DECODED`].
fn read_capped(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    // `take` bounds the *decompressed* stream, which is the side an attacker
    // controls the size of.
    let mut limited = reader.take(MAX_DECODED as u64 + 1);
    limited.read_to_end(&mut out).ok()?;
    if out.len() > MAX_DECODED {
        return None;
    }
    Some(out)
}

fn encode(coding: Coding, body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    match coding {
        Coding::Gzip => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).ok()?;
            e.finish().ok()
        }
        Coding::Deflate => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).ok()?;
            e.finish().ok()
        }
        Coding::Brotli => {
            let mut out = Vec::new();
            let mut e = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            e.write_all(body).ok()?;
            drop(e);
            Some(out)
        }
    }
}

/// Prepare an edited body to go on the wire, and correct the headers to match.
///
/// Call this on a message parsed back from text a human (or an agent) edited.
/// The body arriving here is plaintext, because that is what was displayed; if
/// the headers still declare a coding, it has to be re-applied or the far side
/// will try to decompress plaintext.
///
/// `Content-Length` is always corrected, coding or not — an edit changes the
/// length, and a stale value truncates or hangs the next request. If the coding
/// cannot be applied the header is dropped rather than left lying: sending
/// plaintext labelled `gzip` is worse than sending plaintext.
pub fn encode_for_wire(headers: &mut HeaderMap, body: Bytes) -> Bytes {
    let body = match coding_of(headers) {
        None => body,
        Some(coding) => match encode(coding, &body) {
            Some(encoded) => Bytes::from(encoded),
            None => {
                headers.remove(CONTENT_ENCODING);
                body
            }
        },
    };

    // Only when it was already declared: adding one to a message that had none
    // changes how the far end frames it.
    if let (true, Ok(value)) = (
        headers.contains_key(CONTENT_LENGTH),
        HeaderValue::from_str(&body.len().to_string()),
    ) {
        headers.insert(CONTENT_LENGTH, value);
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn headers_with(coding: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_ENCODING, coding.parse().unwrap());
        h
    }

    /// Big enough that deflate encodes it rather than emitting a literal block.
    /// A tiny payload survives compression readable and would fake a pass.
    fn payload() -> String {
        let mut s = String::from("{\"items\":[");
        for i in 0..200 {
            s.push_str(&format!("{{\"id\":{i},\"name\":\"needle\"}},"));
        }
        s.push_str("null]}");
        s
    }

    fn gzip(text: &str) -> Bytes {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(text.as_bytes()).unwrap();
        Bytes::from(e.finish().unwrap())
    }

    #[test]
    fn every_supported_coding_round_trips() {
        let text = payload();
        for coding in [Coding::Gzip, Coding::Deflate, Coding::Brotli] {
            let compressed = encode(coding, text.as_bytes()).expect("encode");
            assert!(
                compressed.len() < text.len(),
                "{coding:?} should actually compress this"
            );
            let back = decode(coding, &compressed).expect("decode");
            assert_eq!(String::from_utf8(back).unwrap(), text, "{coding:?}");
        }
    }

    #[test]
    fn a_gzipped_body_becomes_readable() {
        let text = payload();
        let body = gzip(&text);
        assert!(!String::from_utf8_lossy(&body).contains("needle"));

        let out = decoded(&headers_with("gzip"), &body);
        assert_eq!(String::from_utf8(out.to_vec()).unwrap(), text);
    }

    #[test]
    fn the_coding_name_is_matched_loosely() {
        let body = gzip("hello");
        for name in ["gzip", "GZIP", " gzip ", "x-gzip"] {
            assert_eq!(
                decoded(&headers_with(name), &body),
                Bytes::from("hello"),
                "{name:?} should be recognised"
            );
        }
    }

    /// Raw deflate is out of spec but real, so both framings must work.
    #[test]
    fn deflate_accepts_zlib_and_raw_framing() {
        let text = payload();

        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(text.as_bytes()).unwrap();
        let zlib = Bytes::from(zlib.finish().unwrap());

        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(text.as_bytes()).unwrap();
        let raw = Bytes::from(raw.finish().unwrap());

        for (label, body) in [("zlib", zlib), ("raw", raw)] {
            let out = decoded(&headers_with("deflate"), &body);
            assert_eq!(
                String::from_utf8(out.to_vec()).unwrap(),
                text,
                "{label} framing"
            );
        }
    }

    /// The rule that makes this safe to put on a display path: whatever
    /// arrived, something renders.
    #[test]
    fn anything_that_will_not_decode_comes_back_untouched() {
        let garbage = Bytes::from_static(b"not compressed at all");
        for coding in ["gzip", "deflate", "br"] {
            assert_eq!(
                decoded(&headers_with(coding), &garbage),
                garbage,
                "{coding} should fall back to the raw bytes"
            );
        }

        // A truncated stream is the common real case — a body cut short by a
        // dropped connection.
        let truncated = gzip(&payload()).slice(..20);
        assert_eq!(decoded(&headers_with("gzip"), &truncated), truncated);
    }

    #[test]
    fn an_unknown_or_absent_coding_is_left_alone() {
        let body = Bytes::from_static(b"plain");
        assert_eq!(decoded(&HeaderMap::new(), &body), body);
        for coding in ["identity", "zstd", "compress", ""] {
            assert_eq!(decoded(&headers_with(coding), &body), body, "{coding:?}");
        }
    }

    #[test]
    fn an_empty_body_is_not_a_decode_failure() {
        let empty = Bytes::new();
        assert_eq!(decoded(&headers_with("gzip"), &empty), empty);
    }

    /// The far side is not trusted, and a few hundred bytes can claim
    /// gigabytes.
    #[test]
    fn a_decompression_bomb_is_refused_rather_than_expanded() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        // Well past the cap, from a tiny compressed payload.
        let chunk = vec![b'A'; 1024 * 1024];
        for _ in 0..(MAX_DECODED / chunk.len()) + 2 {
            e.write_all(&chunk).unwrap();
        }
        let bomb = Bytes::from(e.finish().unwrap());
        assert!(bomb.len() < 200 * 1024, "should be a small payload");

        // Falls back to the raw bytes rather than allocating past the cap.
        assert_eq!(decoded(&headers_with("gzip"), &bomb), bomb);
    }

    #[test]
    fn an_edited_body_is_re_encoded_and_measured() {
        let mut headers = headers_with("gzip");
        headers.insert(CONTENT_LENGTH, "999".parse().unwrap());

        let text = payload();
        let out = encode_for_wire(&mut headers, Bytes::from(text.clone()));

        assert!(
            out.starts_with(&[0x1f, 0x8b]),
            "should be gzip-framed again"
        );
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
            out.len().to_string(),
            "length must describe the encoded body"
        );
        // And it is the same body coming back.
        assert_eq!(
            String::from_utf8(decoded(&headers, &out).to_vec()).unwrap(),
            text
        );
    }

    #[test]
    fn a_body_with_no_coding_is_only_re_measured() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, "1".parse().unwrap());
        let out = encode_for_wire(&mut headers, Bytes::from_static(b"hello"));
        assert_eq!(out, Bytes::from_static(b"hello"));
        assert_eq!(headers.get(CONTENT_LENGTH).unwrap(), "5");
    }

    /// Absent means the sender did not declare one; inventing it changes how
    /// the far end frames the message.
    #[test]
    fn a_missing_content_length_is_not_invented() {
        let mut headers = HeaderMap::new();
        encode_for_wire(&mut headers, Bytes::from_static(b"hello"));
        assert!(!headers.contains_key(CONTENT_LENGTH));
    }

    /// Round trip through the display path: decode, edit, send. This is the
    /// sequence an intercepted response actually takes.
    #[test]
    fn decode_edit_encode_is_a_faithful_round_trip() {
        let mut headers = headers_with("br");
        headers.insert(CONTENT_LENGTH, "0".parse().unwrap());
        let original = Bytes::from(encode(Coding::Brotli, payload().as_bytes()).unwrap());

        let shown = decoded(&headers, &original);
        let edited = Bytes::from(
            String::from_utf8(shown.to_vec())
                .unwrap()
                .replace("needle", "haystack"),
        );
        let sent = encode_for_wire(&mut headers, edited);

        let received = decoded(&headers, &sent);
        let received = String::from_utf8(received.to_vec()).unwrap();
        assert!(received.contains("haystack"));
        assert!(!received.contains("needle"));
    }
}
