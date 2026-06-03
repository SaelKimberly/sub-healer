use std::mem::MaybeUninit;

use base64::Engine;

use crate::urlx::SchemeX;

/// Max bytes per feed() call.
const INPUT_CHUNK_SIZE: usize = 65536;

/// Max bytes of decoded text carried between chunks (pending URL boundary split).
const CARRY_OVER_SIZE: usize = 262144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingState {
    Unknown,
    StdB64,
    UrlSafeB64,
    Raw,
}

/// Streaming base64 decoder that detects encoding, aligns to 4-byte boundaries,
/// and splits on URL boundaries (\n). All internal buffers are fixed-size to
/// prevent unbounded growth.
pub struct StreamingDecoder {
    state: EncodingState,
    /// Leftover input bytes (0-3) after 4-byte alignment.
    pending_input: [MaybeUninit<u8>; 4],
    pending_input_len: usize,
    /// Partial decoded text from previous chunk (no newline found yet).
    carry_over: Box<[MaybeUninit<u8>]>,
    carry_over_len: usize,
}

impl StreamingDecoder {
    /// Create a new decoder. Allocates fixed heap buffers (zero-init-free via
    /// `Box::new_uninit_slice`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: EncodingState::Unknown,
            pending_input: [MaybeUninit::uninit(); 4],
            pending_input_len: 0,
            carry_over: Box::new_uninit_slice(CARRY_OVER_SIZE),
            carry_over_len: 0,
        }
    }

    /// Feed one chunk of raw input data. Returns any complete URLs extracted.
    ///
    /// Internally aligns input to 4-byte base64 boundaries, detects encoding
    /// and decodes, splits on `\n`, and passes complete text regions through
    /// `normalize_extras` + `SchemeX::slice_input`.
    ///
    /// **Chunks larger than `INPUT_CHUNK_SIZE` bytes are truncated** (only the
    /// first `INPUT_CHUNK_SIZE` bytes are processed; callers should slice).
    #[must_use]
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        if chunk.is_empty() && self.pending_input_len == 0 {
            return Vec::new();
        }

        let chunk = if chunk.len() > INPUT_CHUNK_SIZE {
            tracing::warn!(
                chunk_len = chunk.len(),
                max = INPUT_CHUNK_SIZE,
                "Input chunk exceeds max size, truncating"
            );
            &chunk[..INPUT_CHUNK_SIZE]
        } else {
            chunk
        };
        let total_len = self.pending_input_len + chunk.len();
        let mut work: [u8; INPUT_CHUNK_SIZE + 4] = [0u8; INPUT_CHUNK_SIZE + 4];

        // Prepend pending bytes
        for i in 0..self.pending_input_len {
            work[i] = unsafe { self.pending_input[i].assume_init() };
        }
        work[self.pending_input_len..][..chunk.len()].copy_from_slice(chunk);
        self.pending_input_len = 0;

        // Align to 4-byte base64 boundary
        let aligned_len = (total_len / 4) * 4;
        let remainder = total_len - aligned_len;

        // Save trailing bytes as pending for next call
        #[allow(clippy::needless_range_loop)]
        for i in 0..remainder {
            self.pending_input[i] = MaybeUninit::new(work[aligned_len + i]);
        }
        self.pending_input_len = remainder;

        let input = &work[..aligned_len];
        let decoded = self.process_aligned(input);
        self.process_decoded(&decoded)
    }

    /// Flush any remaining buffered data. Call once after the last `feed()`.
    ///
    /// Returns any final URLs from the last partial line.
    #[must_use]
    pub fn finalize(&mut self) -> Vec<String> {
        let mut result = Vec::new();

        // Process leftover pending_input bytes (may be < 4)
        if self.pending_input_len > 0 {
            let mut buf = [0u8; 4];
            for i in 0..self.pending_input_len {
                buf[i] = unsafe { self.pending_input[i].assume_init() };
            }
            let decoded = self.process_aligned(&buf[..self.pending_input_len]);
            self.pending_input_len = 0;
            result.extend(self.process_decoded(&decoded));
        }

        // Flush remaining carry_over as complete text
        if self.carry_over_len > 0 {
            let carry = self.carry_over_slice();
            result.extend(process_text(carry));
            self.carry_over_len = 0;
        }

        result
    }

    // ── internal helpers ──

    /// Detect encoding and decode one 4-byte-aligned portion.
    fn process_aligned(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        // Trim trailing whitespace and '=' padding for base64 decode attempts.
        // Raw passthrough keeps original data (trailing \n is a URL separator).
        let trimmed = match data.iter().rposition(|&b| !b.is_ascii_whitespace() && b != b'=') {
            Some(pos) => &data[..=pos],
            None => &[],
        };

        match self.state {
            EncodingState::Unknown => {
                if let Ok(decoded) =
                    base64::prelude::BASE64_STANDARD_NO_PAD.decode(trimmed)
                {
                    self.state = EncodingState::StdB64;
                    decoded
                } else if let Ok(decoded) =
                    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(trimmed)
                {
                    self.state = EncodingState::UrlSafeB64;
                    decoded
                } else {
                    self.state = EncodingState::Raw;
                    data.to_vec()
                }
            }
            EncodingState::StdB64 => {
                match base64::prelude::BASE64_STANDARD_NO_PAD.decode(trimmed) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        // Fallback: try URL-safe before giving up
                        if let Ok(decoded) =
                            base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(trimmed)
                        {
                            self.state = EncodingState::UrlSafeB64;
                            decoded
                        } else {
                            self.state = EncodingState::Raw;
                            data.to_vec()
                        }
                    }
                }
            }
            EncodingState::UrlSafeB64 => {
                match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(trimmed) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        if let Ok(decoded) =
                            base64::prelude::BASE64_STANDARD_NO_PAD.decode(trimmed)
                        {
                            self.state = EncodingState::StdB64;
                            decoded
                        } else {
                            self.state = EncodingState::Raw;
                            data.to_vec()
                        }
                    }
                }
            }
            EncodingState::Raw => data.to_vec(),
        }
    }

    /// Process decoded bytes: lossy UTF-8, prepend carry_over, split on last
    /// `\n`, extract URLs from complete portion, save remainder as carry_over.
    fn process_decoded(&mut self, decoded: &[u8]) -> Vec<String> {
        if decoded.is_empty() && self.carry_over_len == 0 {
            return Vec::new();
        }

        // Lossy UTF-8 conversion (same as preprocess_sub_data)
        let decoded_str = if let Ok(s) = simdutf8::basic::from_utf8(decoded) {
            s
        } else {
            let s = String::from_utf8_lossy(decoded).into_owned();
            return self.process_text_owned(s);
        };

        if self.carry_over_len == 0 {
            self.process_str(decoded_str)
        } else {
            let carry_bytes = self.carry_over_slice();
            let combined_len = self.carry_over_len + decoded_str.len();
            let mut combined = String::with_capacity(combined_len);
            // SAFETY: carry_over bytes are valid UTF-8 (came from previous decoded chunks)
            unsafe {
                combined.as_mut_vec().extend_from_slice(carry_bytes);
            }
            combined.push_str(decoded_str);
            self.carry_over_len = 0;

            self.process_text_owned(combined)
        }
    }

    /// Helper: split on last \n, extract URLs, save carry_over.
    /// Takes ownership of the string for splitting.
    fn process_text_owned(&mut self, full_text: String) -> Vec<String> {
        if full_text.is_empty() {
            return Vec::new();
        }

        if let Some(last_nl) = full_text.rfind('\n') {
            let complete = &full_text[..last_nl];
            let remaining = &full_text[last_nl + 1..];

            let urls = process_str(complete);

            self.set_carry_over_str(remaining);

            urls
        } else {
            self.set_carry_over_str(&full_text);
            Vec::new()
        }
    }

    /// Process a &str (no carry_over involved): split on last \n, extract URLs,
    /// save carry_over.
    fn process_str(&mut self, text: &str) -> Vec<String> {
        if text.is_empty() {
            return Vec::new();
        }
        if let Some(last_nl) = text.rfind('\n') {
            let complete = &text[..last_nl];
            let remaining = &text[last_nl + 1..];
            let urls = process_text(complete.as_bytes());
            self.set_carry_over_str(remaining);
            urls
        } else {
            self.set_carry_over_str(text);
            Vec::new()
        }
    }

    fn set_carry_over_str(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len();
        if len > CARRY_OVER_SIZE {
            tracing::warn!(
                carry_over_len = len,
                "Carry-over buffer overflow, force-flushing partial data"
            );
            for (i, &b) in bytes[..CARRY_OVER_SIZE].iter().enumerate() {
                self.carry_over[i] = MaybeUninit::new(b);
            }
            self.carry_over_len = CARRY_OVER_SIZE;
            return;
        }
        for (i, &b) in bytes.iter().enumerate() {
            self.carry_over[i] = MaybeUninit::new(b);
        }
        self.carry_over_len = len;
    }

    fn carry_over_slice(&self) -> &[u8] {
        if self.carry_over_len == 0 {
            return &[];
        }
        // SAFETY: first carry_over_len bytes are initialized
        unsafe {
            std::slice::from_raw_parts(
                self.carry_over.as_ptr() as *const u8,
                self.carry_over_len,
            )
        }
    }
}

impl Default for StreamingDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── text processing (shared between decoder and finalize) ──

/// Process a complete text segment: normalize extras, extract URLs via
/// SchemeX, filter comments and empty lines.
fn process_text(text: &[u8]) -> Vec<String> {
    let normalized = crate::normalize_extras(text);
    let s = String::from_utf8_lossy(normalized.as_ref());
    process_str_inner(&s)
}

/// Process a &str (already normalized) through line splitting + URL extraction.
/// Non-mutating version (no carry_over interaction — standalone text).
fn process_str_inner(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|line| {
            let s = line.trim_start();
            if s.starts_with('#') || s.starts_with("//") || s.is_empty() {
                Vec::new()
            } else {
                s.split("<br/>")
                    .flat_map(|segment| {
                        SchemeX::slice_input(segment)
                            .into_iter()
                            .map(|(_, url)| url.to_string())
                    })
                    .collect()
            }
        })
        .collect()
}

/// Same as `process_str_inner` but used internally with process_str which
/// already does the same logic. Kept for `process_text_owned` to call.
fn process_str(text: &str) -> Vec<String> {
    process_str_inner(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data() {
        let mut d = StreamingDecoder::new();
        assert!(d.feed(b"").is_empty());
        assert!(d.finalize().is_empty());
    }

    #[test]
    fn raw_text_passthrough() {
        let mut d = StreamingDecoder::new();
        let urls1 = d.feed(b"trojan://abc\nhysteria2://def\n");
        let urls2 = d.finalize();
        let total = urls1.len() + urls2.len();
        assert!(total >= 2, "expected >=2 URLs, got {}", total);
        assert!(urls1.iter().chain(urls2.iter()).any(|u| u.starts_with("trojan://")));
        assert!(urls1.iter().chain(urls2.iter()).any(|u| u.starts_with("hysteria2://")));
    }

    #[test]
    fn base64_std_single_chunk() {
        // Use padded base64 so encoded length is a multiple of 4 → clean alignment
        let data = b"trojan://abc\n";
        let encoded = base64::prelude::BASE64_STANDARD.encode(data);
        assert_eq!(encoded.len() % 4, 0, "padded base64");
        let mut d = StreamingDecoder::new();
        let urls = d.feed(encoded.as_bytes());
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("trojan://"));
    }

    #[test]
    fn base64_urlsafe_single_chunk() {
        let data = b"trojan://abc\n";
        let encoded = base64::prelude::BASE64_URL_SAFE.encode(data);
        assert_eq!(encoded.len() % 4, 0, "padded base64");
        let mut d = StreamingDecoder::new();
        let urls = d.feed(encoded.as_bytes());
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("trojan://"));
    }

    #[test]
    fn base64_std_trailing_eq_stripped() {
        // Input with length not multiple of 3 triggers base64 padding (=)
        let raw = b"trojan://abcd"; // 13 bytes → padded with ==
        let encoded = base64::prelude::BASE64_STANDARD.encode(raw);
        assert!(encoded.ends_with("=="), "padded: {encoded:?}");
        let mut d = StreamingDecoder::new();
        let urls = d.feed(encoded.as_bytes());
        let urls2 = d.finalize();
        assert_eq!(urls.len() + urls2.len(), 1,
            "trailing == stripped before decode");
    #[test]
    fn decode_across_chunk_boundary() {
        let data = b"trojan://abc\nhy2://def\n";
        let encoded = base64::prelude::BASE64_STANDARD_NO_PAD.encode(data);
        let mid = (encoded.len() / 4) * 4; // 4-byte aligned split
        let mut d = StreamingDecoder::new();

        let urls1 = d.feed(encoded[..mid].as_bytes());
        let urls2 = d.feed(encoded[mid..].as_bytes());
        let urls3 = d.finalize();

        let all: Vec<String> = urls1.into_iter().chain(urls2).chain(urls3).collect();
        assert_eq!(all.len(), 2, "two URLs across 3 calls");
        assert!(all.iter().any(|u| u.starts_with("trojan://")));
        assert!(all.iter().any(|u| u.starts_with("hy2://")));
    }

    #[test]
    fn url_boundary_across_chunks() {
        let mut d = StreamingDecoder::new();
        let urls1 = d.feed(b"trojan://abc\nhy");
        let urls2 = d.feed(b"2://def\n");
        let urls3 = d.finalize();
        let all: Vec<String> = urls1.into_iter().chain(urls2).chain(urls3).collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn comment_lines_skipped() {
        let mut d = StreamingDecoder::new();
        let urls1 = d.feed(b"# comment\n// another\ntrojan://abc\n");
        let urls2 = d.finalize();
        let total = urls1.len() + urls2.len();
        assert!(total >= 1,
            "expected trojan URL, got {} from feed + finalize", total);
    }
    }

    #[test]
    fn br_tag_splitting() {
        let mut d = StreamingDecoder::new();
        // Need multiple-of-4 total length for alignment.
        // "trojan://abc<br/>hy2://def\n" = 27 bytes, pad to 28 with \n
        let urls = d.feed(b"trojan://abc<br/>hy2://def\n\n");
        assert!(urls.len() >= 2, "expected >=2 URLs from <br/> split, got {}", urls.len());
        assert!(urls.iter().any(|u| u.starts_with("trojan://")));
        assert!(urls.iter().any(|u| u.starts_with("hy2://")));
    }

    #[test]
    fn finalize_flushes_carry_over() {
        let mut d = StreamingDecoder::new();
        let urls = d.feed(b"trojan://abc");
        assert!(urls.is_empty(), "no newline -> no URLs yet");

        let urls = d.finalize();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].starts_with("trojan://"));
    }

    #[test]
    fn pending_input_accumulates_across_chunks() {
        let mut d = StreamingDecoder::new();
        // Input length not multiple of 4 creates pending bytes
        let urls1 = d.feed(b"abc"); // 3 bytes → pending
        assert!(urls1.is_empty());
        let urls2 = d.feed(b"d"); // 1 byte → completes to 4
        assert!(urls2.is_empty(), "still no URL in raw data");
        // The combined 4 bytes are raw, not base64 → passthrough
    }

    #[test]
    fn finalize_processes_remainder() {
        let mut d = StreamingDecoder::new();
        // Input not multiple of 4 → trailing bytes are pending
        let urls1 = d.feed(b"trojan://abc\nhy2://def\n"); // 25 bytes, 24 aligned
        let urls2 = d.finalize();
        assert_eq!(urls1.len() + urls2.len(), 2,
            "feed + finalize should yield all URLs");
    }

    #[test]
    fn large_raw_text_yields_all_urls() {
        // 5 lines with URL scheme that has no substring collision
        let lines: Vec<String> = (0..5)
            .map(|i| format!("trojan://node{i}\n"))
            .collect();
        let data = lines.concat();
        let total = data.len();
        let mid = (total / 2 / 4) * 4; // aligned split

        let mut d = StreamingDecoder::new();
        let urls1 = d.feed(data[..mid].as_bytes());
        let urls2 = d.feed(data[mid..].as_bytes());
        let urls3 = d.finalize();

        let all = urls1.len() + urls2.len() + urls3.len();
        assert_eq!(all, 5, "all 5 URLs extracted across chunks");
    }
}
