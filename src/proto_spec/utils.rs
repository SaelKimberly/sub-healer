use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;

use crate::urlx::{HostSpec, PortSpec, RawUrlX};

/// Parse host:port from a string, returning (HostSpec, PortSpec)
pub fn parse_hostport(s: &str) -> Result<(HostSpec, PortSpec), Cow<'static, str>> {
    let (tail, (host, port)) = crate::utils::host_port_spec(s.as_bytes().into())
        .map_err(|_| format!("Invalid hostport: {s}"))?;
    if !tail.is_empty() {
        let tail_str = unsafe { std::str::from_utf8_unchecked(tail.into_fragment()) };
        // Lenient: if tail contains query-like chars (= or &), strip it
        if !tail_str.contains('=') && !tail_str.contains('&') {
            return Err(format!(
                "Invalid hostport: {s} (non-empty tail: {tail_str})"
            )
            .into());
        }
    }
    Ok((host.to_owned(), port))
}

/// Parse host from a string (no port)
pub fn parse_host(s: &str) -> Result<HostSpec, Cow<'static, str>> {
    let (tail, host) = crate::utils::host_port::host(s.as_bytes().into())
        .map_err(|_| format!("Invalid host: {s}"))?;
    if !tail.is_empty() {
        return Err(format!(
            "Invalid host: {s} (non-empty tail: {})",
            unsafe { std::str::from_utf8_unchecked(tail.into_fragment()) }
        )
        .into());
    }
    Ok(host.to_owned())
}

/// Parse port from string
pub fn parse_port(s: &str) -> Result<PortSpec, Cow<'static, str>> {
    let (tail, port) = crate::utils::host_port::port_specs(s.as_bytes().into())
        .map_err(|_| format!("Invalid port: {s}"))?;
    if !tail.is_empty() {
        return Err(format!(
            "Invalid port: {s} (non-empty tail: {})",
            unsafe { std::str::from_utf8_unchecked(tail.into_fragment()) }
        )
        .into());
    }
    Ok(port)
}

/// Base64 decode a string (tries URL-safe then standard)
pub fn decode_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let data = urlencoding::decode_binary(data.as_bytes());
    let data = data.trim_end_with(|c| c == '=' || c.is_whitespace());
    'block: {
        let e = match base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data) {
            Ok(r) => break 'block Ok(r),
            Err(e) => e,
        };
        if let Ok(r) = base64::prelude::BASE64_STANDARD_NO_PAD.decode(data) {
            break 'block Ok(r);
        }
        Err(e)
    }
}

/// Parse query string into key-value pairs
pub fn parse_query(query: Option<&str>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let query_str = query.unwrap_or("");
    if query_str.is_empty() {
        return map;
    }
    for pair in query_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

/// Compute credential hash: rapidhash of "host:port:username:password"
pub fn compute_cred_hash(
    host: Option<&HostSpec>,
    port: Option<&PortSpec>,
    username: &str,
    password: &str,
) -> u64 {
    let host_s = host.map(|h| h.to_str().into_owned()).unwrap_or_default();
    let port_s = port.map(|p| p.to_string()).unwrap_or_default();
    if host_s.is_empty() && port_s.is_empty() && username.is_empty() && password.is_empty() {
        return 0;
    }
    let cred_data = format!("{host_s}:{port_s}:{username}:{password}");
    rapidhash::v3::rapidhash_v3(cred_data.as_bytes())
}

/// Decode fragment (remarks) from raw URL
pub fn decode_fragment(raw: &RawUrlX<'_>) -> Result<Option<String>, crate::proto_spec::ParseError> {
    raw.fragment()
        .map_err(|e| crate::proto_spec::ParseError::InvalidConf("remarks".into(), e.to_string().into()))
        .map(|f| f.map(|s| s.to_string()))
}

// ========================================
// Coercion helpers for TryFrom<RawUrlX>
// ========================================

/// Try to coerce a serde_json::Value to u16 (number, string, etc.)
pub fn coerce_u16(val: &serde_json::Value) -> Option<u16> {
    val.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| val.as_str().and_then(|s| s.parse::<u16>().ok()))
        .or_else(|| val.as_f64().and_then(|f| {
            if f >= 0.0 && f <= u16::MAX as f64 {
                Some(f as u16)
            } else {
                None
            }
        }))
}

/// Try to coerce a serde_json::Value to bool (bool, string "true"/"1"/"yes", etc.)
pub fn coerce_bool(val: &serde_json::Value) -> Option<bool> {
    val.as_bool().or_else(|| {
        val.as_str().and_then(|s| match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" | "y" => Some(true),
            "false" | "0" | "no" | "off" | "n" => Some(false),
            _ => None,
        })
    })
}

/// Try to coerce a serde_json::Value to String
pub fn coerce_string(val: &serde_json::Value) -> Option<String> {
    val.as_str().map(|s| s.to_string()).or_else(|| {
        if val.is_number() {
            Some(val.to_string())
        } else {
            None
        }
    })
}

/// Try to coerce a serde_json::Value to u64
pub fn coerce_u64(val: &serde_json::Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| val.as_f64().and_then(|f| {
            if f >= 0.0 && f <= u64::MAX as f64 {
                Some(f as u64)
            } else {
                None
            }
        }))
}
