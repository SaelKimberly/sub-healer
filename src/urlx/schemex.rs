use std::{str::FromStr, sync::LazyLock};

use aho_corasick::AhoCorasick;

use super::TinyText;

#[derive(Debug, Clone, Hash, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum SchemeX {
    Vless,
    Vmess,
    Hysteria,
    Hysteria2,
    SS,
    SSR,
    Trojan,
    TUIC,
    Warp,
    AnyTLS,
    Https,
    Tg,
    SlipnetEnc,
    Slipnet,
    WireGuard,
    Unknown(TinyText),
}
impl SchemeX {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::SS => "ss",
            Self::SSR => "ssr",
            Self::Hysteria2 => "hy2",
            Self::Hysteria => "hy",
            Self::Trojan => "trojan",
            Self::TUIC => "tuic",
            Self::Warp => "warp",
            Self::AnyTLS => "anytls",
            Self::Https => "https",
            Self::Tg => "tg",
            Self::Slipnet => "slipnet",
            Self::SlipnetEnc => "slipnet-enc",
            Self::WireGuard => "wireguard",
            Self::Unknown(s) => s.as_str(),
        }
    }

    pub fn slice_input(s: &str) -> Vec<(Self, &str)> {
        static SCHEMA_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build([
                    "vless://",
                    "vmess://",
                    "trojan://",
                    "hhysteria2://",
                    "hhysteria://",
                    "hysteria2://",
                    "hysteria://",
                    "hy2://",
                    "hy://",
                    "warp://",
                    "anytls://",
                    "ss://",
                    "ssr://",
                    "https://",
                    "tg://",
                    "slipnet://",
                    "tuic://",
                    "wireguard://",
                    "slipnet-enc://",
                ])
                .unwrap()
        });

        let mut last = None;

        let mut chunks = Vec::new();
        for m in SCHEMA_AC.find_iter(s) {
            let schema_area = s.get(m.range()).unwrap().split_once("://").unwrap().0;
            let Ok(schema) = Self::from_str(schema_area);

            if let Some((schema, begin)) = last.replace((schema, m.range().start)) {
                let end = m.range().start;
                chunks.push((schema, s.get(begin..end).unwrap()));
            }
        }

        if let Some((schema, begin)) = last.take() {
            chunks.push((schema, s.get(begin..).unwrap()));
        }
        chunks
    }
}

impl std::fmt::Display for SchemeX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SchemeX {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! checked_enum {
            (
                $input: expr,
                $variant: ident => $pat: literal $(, $pat2: literal)*;
                $($variant2: ident => $pat3: literal $(, $pat4:literal)*;)*
            ) => {{
                let scheme = match s.to_ascii_lowercase().as_str() {
                    $pat $(| $pat2)* => Self::$variant,
                    $($pat3 $(| $pat4)* => Self::$variant2,)*
                    _ => Self::Unknown(s.into()),
                };
                #[cfg(test)]
                match scheme { Self::$variant => (), $(Self::$variant2 => (),)* Self::Unknown(_) => (), }
                scheme
            }}
        }

        let scheme = checked_enum!(
            s.strip_suffix("://").unwrap_or(s),
            Vless => "vless";
            Vmess => "vmess";
            SS => "shadowsocks", "ss";
            SSR => "ssr";
            Hysteria2 => "hhysteria2", "hysteria2", "hhy2", "hy2";
            Hysteria => "hhysteria", "hysteria", "hhy", "hy";
            Trojan => "trojan";
            TUIC => "tuic";
            Warp => "warp";
            AnyTLS => "anytls";
            Https => "https";
            Tg => "tg";
            Slipnet => "slipnet";
            SlipnetEnc => "slipnet-enc";
            WireGuard => "wireguard";
        );

        Ok(scheme)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_input() {
        let input = include_str!("/home/user/oss/sub-healer/v2ray.txt");

        let chunks = SchemeX::slice_input(input);
        for (schema, c) in &chunks {
            let c = c.lines().collect::<Vec<_>>().join("");
            eprintln!("{schema:>15}| {c}");
        }
        eprintln!("Total: {}", chunks.len());
    }
}
