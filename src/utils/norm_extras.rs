use std::borrow::Cow;

use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

/// This function is used to normalize the `extra` query part of V2ray URL.
///
/// It will try to recover JSON with a very permissive parser, and reencode it to urlencoded.
///
/// This fixes following issues:
/// - not encoded extras (raw JSON)
/// - python dicts: str(dict(...) instead of json.dumps(dict(...))
/// - multiline JSON / python dict
/// - JSON with missing quotes
/// - truncated JSON (if you have a good luck, there may be just missing brackets at the end)
///
/// After this normalizing step, all V2ray URLs should be valid on a single line
/// When no extras found, no data copy will be performed
#[must_use]
pub fn normalize_extras(span: &[u8]) -> Cow<'_, [u8]> {
    const EXTRA_PREFIX: &str = "extra=";
    const EXTRA_PREFIX_LEN: usize = 6;
    let finder = bstr::Finder::new(EXTRA_PREFIX);
    let mut result: Vec<u8>;
    {
        // Every slice may (or may not) start with valid or invalid JSON.
        // If we can extract valid JSON from the beginning, we have to store valid version here.
        // In that case, slice will be likely turned into owned version (corrected JSON + tail)
        // Otherwise, it will be kept as is.
        let mut slices: Vec<Cow<'_, [u8]>> = Vec::new();

        let mut suffix: &[u8] = span;
        let prefix: &[u8];

        let Some(first_found) = finder.find(suffix) else {
            return Cow::Borrowed(span);
        };
        (prefix, suffix) = suffix.split_at(first_found + EXTRA_PREFIX_LEN);

        let mut tail: &[u8] = suffix;
        while let Some(pos) = finder.find(tail) {
            (suffix, tail) = tail.split_at(pos + EXTRA_PREFIX_LEN);
            slices.push(Cow::Borrowed(suffix));
        }
        if !tail.is_empty() {
            slices.push(Cow::Borrowed(tail));
        }

        let out_size = slices
            .par_iter_mut()
            .map(|slice| {
                if let Ok((tail, json)) =
                    super::permissive_json::permissive_json_core(slice.as_ref())
                    && let Ok(data) = simd_json::to_string(&json)
                {
                    let mut data = urlencoding::encode(data.as_str()).as_bytes().to_owned();
                    if !tail.is_empty() {
                        data.reserve_exact(tail.len());
                        data.extend_from_slice(tail);
                    }
                    *slice = Cow::Owned(data);
                }
                slice.len()
            })
            .sum::<usize>();
        result = Vec::with_capacity(out_size + prefix.len());
        result.extend_from_slice(prefix);
        for slice in slices {
            result.extend_from_slice(slice.as_ref());
        }
    }
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encode_not_encoded() {
        let s = "extra={'a':'b'}";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":"b"}
        assert_eq!(x, "extra=%7B%22a%22%3A%22b%22%7D");
    }

    #[test]
    fn test_not_valid_encoded() {
        // -> invalid json, urlencoded: extra={'a':'b'}
        let s = "extra=%7B%27a%27%3A%27b%27%7D";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":"b"}
        assert_eq!(x, "extra=%7B%22a%22%3A%22b%22%7D");
    }

    #[test]
    fn test_not_valid_not_encoded() {
        // -> invalid json, multiline, not encoded
        let s = "extra={
            'a': True
        }";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // -> valid json, urlencoded: extra={"a":true}
        assert_eq!(x, "extra=%7B%22a%22%3Atrue%7D");
    }

    #[test]
    fn test_extra_plus_as_whitespace() {
        // Form-urlencoded `+` in extra JSON (common in Telegram URLs)
        // `+` should be treated as whitespace by permissive_json_core
        // The URL before extra= is preserved verbatim, only the extra value is re-encoded
        let s = "vless://host:443?type=xhttp&extra=%7B%22a%22%3A+1%2C+%22b%22%3A+%22c%22%7D";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        assert_eq!(
            x,
            // After normalization: + stripped, valid JSON, URL-encoded
            "vless://host:443?type=xhttp&extra=%7B%22a%22%3A1%2C%22b%22%3A%22c%22%7D"
        );
    }

    #[test]
    fn test_b3a_leading_plus_normalize() {
        let s = "vless://uuid@host:443?type=xhttp&mode=stream-one&extra={\"scMaxEachPostBytes\":+1000000,+\"scMaxConcurrentPosts\":+100,+\"scMinPostsIntervalMs\":+30}&path=/stream&host=example.com&sni=example.com#By EbraSha";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // After normalize: + stripped, keys alphabetical (simd_json orders), URL-encoded
        // Keys: scMaxConcurrentPosts < scMaxEachPostBytes < scMinPostsIntervalMs
        assert_eq!(
            x,
            "vless://uuid@host:443?type=xhttp&mode=stream-one&extra=%7B%22scMaxConcurrentPosts%22%3A100%2C%22scMaxEachPostBytes%22%3A1000000%2C%22scMinPostsIntervalMs%22%3A30%7D&path=/stream&host=example.com&sni=example.com#By EbraSha"
        );
    }

    #[test]
    fn test_b3a_leading_plus_normalize_url_encoded() {
        // Exact B3a pattern from NDJSON: leading +, already URL-encoded
        let s = "vless://uuid@host:443?type=xhttp&extra=%7B%22scMaxEachPostBytes%22%3A%2B1000000%2C%2B%22scMaxConcurrentPosts%22%3A%2B100%7D&host=example.com#Test";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // After normalize: + stripped, keys alphabetical (simd_json), URL-encoded
        assert_eq!(
            x,
            "vless://uuid@host:443?type=xhttp&extra=%7B%22scMaxConcurrentPosts%22%3A100%2C%22scMaxEachPostBytes%22%3A1000000%7D&host=example.com#Test"
        );
    }

    #[test]
    fn test_b3b_single_quotes_normalize() {
        // Exact B3b pattern from NDJSON: single-quoted keys, Python booleans
        let s = "vless://uuid@host:443?mode=stream-one&extra={'headers': {}, 'noGRPCHeader': True, 'xmux': {'maxConnections': '3'}}&host=example.com&type=xhttp&sni=example.com#By EbraSha";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // '3' is parsed as string "3" (not number 3), True→true, URL-encoded
        // Keys alphabetical: headers < maxConnections < noGRPCHeader
        assert_eq!(
            x,
            "vless://uuid@host:443?mode=stream-one&extra=%7B%22headers%22%3A%7B%7D%2C%22noGRPCHeader%22%3Atrue%2C%22xmux%22%3A%7B%22maxConnections%22%3A%223%22%7D%7D&host=example.com&type=xhttp&sni=example.com#By EbraSha"
        );
    }

    #[test]
    fn test_b3b_single_quotes_normalize_url_encoded() {
        // Exact B3b pattern from NDJSON: single quotes in URL-encoded form
        let s = "vless://uuid@host:443?mode=stream-one&extra=%7B%27headers%27%3A%20%7B%7D%2C%20%27noGRPCHeader%27%3A%20True%2C%20%27xmux%27%3A%20%7B%27maxConnections%27%3A%20%273%27%7D%7D&host=example.com&type=xhttp&sni=example.com#By EbraSha";
        let n = super::normalize_extras(s.as_bytes());
        let x = unsafe { str::from_utf8_unchecked(n.as_ref()) };
        // Same result as non-encoded version
        assert_eq!(
            x,
            "vless://uuid@host:443?mode=stream-one&extra=%7B%22headers%22%3A%7B%7D%2C%22noGRPCHeader%22%3Atrue%2C%22xmux%22%3A%7B%22maxConnections%22%3A%223%22%7D%7D&host=example.com&type=xhttp&sni=example.com#By EbraSha"
        );
    }
}
