use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;
use rustls::pki_types::{IpAddr::V4, IpAddr::V6};

use crate::urlx::{HostSpec, PortSpec, RawUrlX, TinyText};

use super::ParseError;

/// Check that a host is not loopback, private, or localhost.
///
/// # Errors
///
/// Returns an error if the host is a loopback/private IP or "localhost".
fn validate_host_not_private(host: &HostSpec) -> Result<(), ParseError> {
    match host {
        HostSpec::DnsName(name) => {
            let name = name.as_ref().to_ascii_lowercase();
            if name == "localhost" || name.ends_with(".localhost") {
                return Err(ParseError::InvalidPrivateHost("localhost".into()));
            }
        }
        HostSpec::IpAddress(V4(ip)) => {
            let addr = std::net::Ipv4Addr::from(*ip);
            if addr.is_loopback() || addr.is_private() || addr.is_link_local() {
                return Err(ParseError::InvalidPrivateHost(addr.to_string().into()));
            }
        }
        HostSpec::IpAddress(V6(ip)) => {
            let addr = std::net::Ipv6Addr::from(*ip);
            if addr.is_loopback() || addr.is_unique_local() || addr.is_unicast_link_local() {
                return Err(ParseError::InvalidPrivateHost(addr.to_string().into()));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse host:port from a string, returning (`HostSpec`, `PortSpec`)
///
/// # Errors
///
/// Returns an error if the string is not a valid host:port specification.
pub fn parse_hostport(s: &str) -> Result<(HostSpec, PortSpec), ParseError> {
    // Strip decorative prefixes like @@ or $*@
    let s = s.trim_start_matches('@');
    let s = s.trim_start_matches("$*@");
    let (tail, (host, port)) = crate::utils::host_port_spec(s.as_bytes().into())
        .map_err(|_| ParseError::InvalidHostPort(format!("Invalid hostport: {s}").into()))?;
    let host = host.to_owned();
    validate_host_not_private(&host)?;
    if !tail.is_empty() {
        let tail_str = unsafe { std::str::from_utf8_unchecked(tail.into_fragment()) };
        // Lenient: if tail contains query-like chars (= or &), strip it
        if !tail_str.contains('=') && !tail_str.contains('&') {
            return Err(ParseError::InvalidHostPort(
                format!("Invalid hostport: {s} (non-empty tail: {tail_str})").into(),
            ));
        }
    }
    Ok((host, port))
}

/// Parse host from a string (no port)
///
/// # Errors
///
/// If the string is not a valid host.
pub fn parse_host(s: &str) -> Result<HostSpec, ParseError> {
    let (tail, host) = crate::utils::host_port::host(s.as_bytes().into())
        .map_err(|_| ParseError::InvalidHost(format!("Invalid host: {s}").into()))?;
    let host = host.to_owned();
    validate_host_not_private(&host)?;
    if !tail.is_empty() {
        return Err(ParseError::InvalidHost(
            format!(
                "Invalid host: {s} (non-empty tail: {})",
                unsafe { std::str::from_utf8_unchecked(tail.into_fragment()) }
            )
            .into(),
        ));
    }
    Ok(host)
}

/// Parse port from string
///
/// # Errors
///
/// If the string is not a valid port.
pub fn parse_port(s: &str) -> Result<PortSpec, Cow<'static, str>> {
    let (tail, port) = crate::utils::host_port::port_specs(s.as_bytes().into())
        .map_err(|_| format!("Invalid port: {s}"))?;
    if !tail.is_empty() {
        return Err(format!("Invalid port: {s} (non-empty tail: {})", unsafe {
            std::str::from_utf8_unchecked(tail.into_fragment())
        })
        .into());
    }
    Ok(port)
}

/// Base64 decode a string (tries URL-safe then standard)
///
/// Silently strips trailing non-base64 characters (Telegram annotation text, emoji, etc.)
/// and stray backtick characters that sometimes appear mid-base64 in subscription data.
/// Returns the decoded bytes or an error.
///
/// # Errors
/// Returns a `base64::DecodeError` if the input is not valid base64.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Strip Telegram annotation text appended to the base64 (emoji, Persian, Chinese, etc.)
    // Remove stray backtick characters that sometimes appear mid-base64 in subscription data
    let data: String = data.chars().filter(|&c| c != '`').collect();
    let end = data
        .bytes()
        .position(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
        .unwrap_or(data.len());
    let mut data = &data[..end];
    // After the last padding marker (`==` or `=`), strip ASCII annotation text too.
    // E.g. `...base64==Irancell&Mci...` — the `Irancell` is valid base64 chars but is annotation.
    if let Some(pos) = data.rfind("==") {
        data = &data[..pos + 2];
    } else if let Some(pos) = data.rfind('=') {
        data = &data[..=pos];
    }
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
#[must_use]
pub fn parse_query(query: Option<&str>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let query_str = query.unwrap_or("");
    if query_str.is_empty() {
        return map;
    }
    for pair in query_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let decoded = urlencoding::decode(v).unwrap_or(Cow::Borrowed(v));
            map.insert(k.to_string(), decoded.into_owned());
        }
    }
    map
}

/// Compute credential hash: rapidhash of "host:port:username:password"
#[must_use]
pub fn compute_cred_hash(
    host: Option<&HostSpec>,
    port: Option<u16>,
    port_spec: Option<&PortSpec>,
    username: &str,
    password: &str,
) -> u64 {
    let host_s = host.map(|h| h.to_str().into_owned()).unwrap_or_default();
    let port_s = port_spec
        .map(std::string::ToString::to_string)
        .or_else(|| port.map(|p| p.to_string()))
        .unwrap_or_default();
    if host_s.is_empty() && port_s.is_empty() && username.is_empty() && password.is_empty() {
        return 0;
    }
    let cred_data = format!("{host_s}:{port_s}:{username}:{password}");
    rapidhash::v3::rapidhash_v3(cred_data.as_bytes())
}

/// Decode fragment (remarks) from raw URL
///
/// # Errors
/// - If the fragment is not valid UTF-8
pub fn decode_fragment(raw: &RawUrlX<'_>) -> Result<Option<TinyText>, crate::proto_spec::ParseError> {
    raw.fragment().map_err(|e| {
        crate::proto_spec::ParseError::InvalidConf("remarks".into(), e.to_string().into())
    })
}

// ========================================
// Coercion helpers for TryFrom<RawUrlX>
// ========================================

/// Try to coerce a `serde_json::Value` to u16 (number, string, etc.)
#[must_use]
pub fn coerce_u16(val: &serde_json::Value) -> Option<u16> {
    val.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| val.as_str().and_then(|s| s.parse::<u16>().ok()))
        .or_else(|| {
            val.as_f64().and_then(|f| {
                (f.is_finite() && (f >= 0.0 && f <= f64::from(u16::MAX)))
                    .then(|| unsafe { f.to_int_unchecked::<u16>() })
            })
        })
}

/// Try to coerce a `serde_json::Value` to bool (bool, string "true"/"1"/"yes", etc.)
#[must_use]
pub fn coerce_bool(val: &serde_json::Value) -> Option<bool> {
    val.as_bool().or_else(|| {
        val.as_str()
            .and_then(|s| match s.trim().to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "y" => Some(true),
                "false" | "0" | "no" | "off" | "n" => Some(false),
                _ => None,
            })
    })
}

/// Try to coerce a `serde_json::Value` to String
#[must_use]
pub fn coerce_string(val: &serde_json::Value) -> Option<String> {
    val.as_str()
        .map(std::string::ToString::to_string)
        .or_else(|| {
            if val.is_number() {
                Some(val.to_string())
            } else {
                None
            }
        })
}

/// Try to coerce a `serde_json::Value` to u64
#[must_use]
pub fn coerce_u64(val: &serde_json::Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| {
            val.as_f64().and_then(|f| {
                if f >= 0.0 {
                    Some(unsafe { f.to_int_unchecked() })
                } else {
                    None
                }
            })
        })
}
