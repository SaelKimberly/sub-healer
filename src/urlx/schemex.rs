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
    MTProto,
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
            Self::MTProto => "http",
            Self::Unknown(s) => s.as_str(),
        }
    }

    pub fn slice_input<'a>(s: &'a str) -> Vec<(SchemeX, &'a str)> {
        static KNOWN_SCHEMAS: &[&str] = &[
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
        ];

        let mut slice = Option::<(&'static str, &'a str)>::None;
        let mut result = Vec::<(&'static str, &'a str)>::with_capacity(1);

        // 1: Find first schema in line
        if let Some(prefix) = s.split_inclusive("://").next() {
            for schema in KNOWN_SCHEMAS {
                if let Some(prefix) = prefix.strip_suffix(schema) {
                    let s = if prefix.is_empty() {
                        s
                    } else {
                        s.strip_prefix(prefix)
                            .expect("Prefix is always a part of line")
                    };
                    slice.replace((schema, s));
                    break;
                }
            }
        }

        while let Some((schema, sx)) = slice.take() {
            if sx.is_empty() || sx.len() < 5 {
                result.push((schema, sx));
                break;
            }

            // try to find another known schema in the area of current url (longest first)
            let mut min_schema_pos = Option::<(usize, &'static str)>::None;

            for s in KNOWN_SCHEMAS {
                let idx = sx.floor_char_boundary(5);
                let Some(pos) = sx[idx..].find(s).map(|p| p + idx) else {
                    continue;
                };
                if let Some((current, found)) = min_schema_pos.as_mut() {
                    if pos < *current {
                        *current = pos;
                        *found = s;
                    }
                } else {
                    min_schema_pos = Some((pos, *s));
                }
            }

            if let Some((min_schema_pos, another_schema)) = min_schema_pos {
                let (prefix, schema_and_tail) = sx.split_at(min_schema_pos);
                result.push((schema, prefix));
                _ = slice.replace((another_schema, schema_and_tail));
            } else {
                result.push((schema, sx));
                break;
            }
        }

        result
            .into_iter()
            .map(|(schema, slice)| {
                (
                    <SchemeX as std::str::FromStr>::from_str(schema).unwrap(),
                    slice,
                )
            })
            .collect()
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
        let r = match s.strip_suffix("://").unwrap_or(s) {
            "vless" => SchemeX::Vless,
            "vmess" => SchemeX::Vmess,
            "shadowsocks" | "ss" => SchemeX::SS,
            "ssr" => SchemeX::SSR,
            "hhysteria2" | "hysteria2" | "hhy2" | "hy2" => SchemeX::Hysteria2,
            "hhysteria" | "hysteria" | "hhy" | "hy" => SchemeX::Hysteria,
            "trojan" => SchemeX::Trojan,
            "tuic" => SchemeX::TUIC,
            "warp" => SchemeX::Warp,
            "anytls" => SchemeX::AnyTLS,
            "https" => SchemeX::MTProto,
            _ => SchemeX::Unknown(s.into()),
        };
        Ok(r)
    }
}
