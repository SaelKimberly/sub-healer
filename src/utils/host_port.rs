use std::str::FromStr;

use nom::{
    Input, Offset, Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric0, alphanumeric1, char, digit1, hex_digit0, u16},
    combinator::recognize,
    error::{Error, ErrorKind},
    multi::separated_list1,
    sequence::{delimited, preceded, separated_pair},
};
use rustls::pki_types::{DnsName, IpAddr, Ipv4Addr, Ipv6Addr, ServerName};

use crate::{PortSpec, RawResult, Span};

trait XNom<'a>: Sized {
    fn xnom<T>(
        self,
        p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T>;
}

impl<'a> XNom<'a> for Span<'a> {
    fn xnom<T>(
        self,
        mut p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T> {
        p.parse(self)
    }
}

impl<'a> XNom<'a> for &'a [u8] {
    fn xnom<T>(
        self,
        mut p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T> {
        p.parse(Span::new(self))
    }
}

impl<'a> XNom<'a> for &'a str {
    fn xnom<T>(
        self,
        mut p: impl Parser<Span<'a>, Output = T, Error = nom::error::Error<Span<'a>>>,
    ) -> RawResult<'a, T> {
        p.parse(Span::new(self.as_bytes()))
    }
}

#[inline]
fn _unchecked_str<'a>(s: Span<'a>) -> &'a str {
    unsafe { str::from_utf8_unchecked(&s) }
}

pub fn dns_name<'a>(span: Span<'a>) -> RawResult<'a, DnsName<'a>> {
    recognize(preceded(
        alphanumeric1,
        separated_list1(alt((char('.'), char('-'), char('_'))), alphanumeric0),
    ))
    // .map(_unchecked_str
    .map_res(|c: Span| {
        let raw = unsafe { str::from_utf8_unchecked(&c) };
        DnsName::try_from_str(raw)
            .inspect_err(|_| tracing::trace!("Invalid DNS name detected: {raw}"))
    })
    .parse(span)
}

pub fn ipv4<'a>(span: Span<'a>) -> RawResult<'a, Ipv4Addr> {
    let (tail, raw_ip) = recognize((
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
        char('.'),
        digit1,
    ))
    .map(_unchecked_str)
    .parse(span)?;

    let Ok(ip) = <std::net::Ipv4Addr as FromStr>::from_str(raw_ip).inspect_err(|e| {
        tracing::trace!("Invalid IPv4 address: {raw_ip} ({e})");
    }) else {
        crate::nom_bail!(span, Verify)
    };

    Ok((tail, ip.into()))
}

pub fn ipv6<'a>(span: Span<'a>) -> RawResult<'a, Ipv6Addr> {
    let (tail, raw_ip) = alt((
        recognize(preceded(tag("::ffff:"), ipv4)),
        recognize(separated_list1(tag(":"), hex_digit0)),
    ))
    .map(_unchecked_str)
    .parse(span)?;

    let Ok(ip) = <std::net::Ipv6Addr as FromStr>::from_str(raw_ip).inspect_err(|e| {
        tracing::trace!("Invalid IPv6 address: {raw_ip} ({e})");
    }) else {
        crate::nom_bail!(span, Verify)
    };

    Ok((tail, ip.into()))
}

pub fn host<'a>(span: Span<'a>) -> RawResult<'a, ServerName<'a>> {
    alt((
        ipv4.map(IpAddr::V4).map(ServerName::IpAddress),
        delimited(tag("["), ipv6, tag("]"))
            .map(IpAddr::V6)
            .map(ServerName::IpAddress),
        dns_name.map(ServerName::DnsName),
    ))
    .parse(span)
    .inspect_err(|_| tracing::trace!("Failed to parse host name"))
}

/// Hysteria2 port hopping feature parser (single port or range of ports collection)
pub fn port_specs<'a>(span: Span<'a>) -> RawResult<'a, PortSpec> {
    let mut spec = PortSpec::new();
    let mut base = span;
    loop {
        let (tail, p1) = u16.parse(base)?;
        let tail = if let Ok((tail, p2)) = tail.xnom(preceded(tag("-"), u16)) {
            spec.add_range(p1..p2);
            tail
        } else {
            spec.add(p1);
            tail
        };
        match tag(",").parse(tail) {
            RawResult::Ok((tail, _)) => base = tail,
            _ => break Ok((tail, spec.sort())),
        }
    }
}

/// Designed specifically for Hysteria2 port hopping feature
pub fn host_port_spec<'a>(span: Span<'a>) -> RawResult<'a, (ServerName<'a>, PortSpec)> {
    if let Ok((tail, host_port)) = separated_pair(host, tag(":"), port_specs).parse(span) {
        Ok((tail, host_port))
    } else if let Ok((_, mut parts)) =
        span.xnom(separated_list1(tag(":"), hex_digit0.map(_unchecked_str)))
    {
        let Some(last_part) = parts.pop() else {
            return Err(nom::Err::Error(Error::new(span, ErrorKind::Verify)));
        };

        let raw_ip = parts.join(":");
        let ip = <std::net::Ipv6Addr as FromStr>::from_str(&raw_ip).map_err(|e| {
            tracing::trace!("Invalid IPv6 address: {raw_ip} ({e})");
            nom::Err::Error(Error::new(span, ErrorKind::Verify))
        })?;

        let port_area = span.take_from((*span.fragment()).offset(last_part.as_bytes()));
        let (tail, port) = port_specs(port_area)?;

        Ok((tail, (ServerName::IpAddress(IpAddr::V6(ip.into())), port)))
    } else {
        crate::nom_bail!(span, Verify)
    }
}

#[cfg(test)]
mod tests {
    use crate::Span;

    #[test]
    fn test_port_spec() {
        let s = "100-120,122";
        let (_, spec) = super::port_specs(Span::new(s.as_bytes())).unwrap();

        assert_eq!(spec.length(), 22);
        assert_eq!(
            spec.iter().collect::<Vec<_>>(),
            &[
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
                116, 117, 118, 119, 120, 122
            ]
        );
    }
}
