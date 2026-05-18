use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};

use crate::urlx::{RawUrlX, SchemeX, UrlX};
use crate::urlx::try_accept_raw;

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
    "slipnet://",
    "tg://",
    "wireguard://",
];

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Data<'a> {
    Raw {
        scheme: Cow<'static, str>,
        url: Cow<'a, str>,
    },
    Url(UrlX),
}

#[derive(Debug, Clone)]
pub struct Line<'a> {
    pub(crate) row: usize,
    pub(crate) url: Data<'a>,
    pub(crate) wrn: Option<Vec<Cow<'static, str>>>,
    pub(crate) err: Option<Cow<'static, str>>,
}

impl<'a> Line<'a> {
    fn parse_raw(self) -> Self {
        let Self {
            row,
            url: Data::Raw { scheme, url },
            mut wrn,
            err: None,
        } = self
        else {
            return self;
        };

        let url: Cow<'a, str> = {
            let norm = url
                .as_ref()
                .replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&amp&", "&")
                .replace("&amp%3B", "&")
                .replace("?amp;", "?")
                .replace("?amp%3B", "?");
            if norm != url {
                wrn.get_or_insert_default()
                    .push("Detected HTML entities".into());
            }

            let norm = norm.replace("security=", "&security=");

            let norm = norm
                .split("&")
                .filter(|chunk| !chunk.is_empty())
                .collect::<Vec<_>>()
                .join("&");

            if norm != url {
                wrn.get_or_insert_default()
                    .push("Detected HTML entities".into());
                Cow::Owned(norm)
            } else {
                url
            }
        };

        // SchemeX::from_str is Infallible
        let scheme_enum = SchemeX::from_str(scheme.as_ref()).unwrap();
        if matches!(scheme_enum, SchemeX::Unknown(_)) {
            wrn.get_or_insert_default()
                .push(format!("Unknown protocol schema: {scheme_enum}").into());
        }

        let raw: RawUrlX = url.as_ref().into();
        let Ok(urlx) = try_accept_raw(raw) else {
            return Self {
                row,
                url: Data::Raw { scheme, url },
                wrn,
                err: Some("no protocol matched".into()),
            };
        };

        Self {
            row,
            url: Data::Url(urlx),
            wrn,
            err: None,
        }
    }
}

#[derive(Clone)]
pub struct Lines<'a> {
    source: url::Url,
    basic: Arc<str>,
    inner: Vec<Line<'a>>,
    raw: Vec<Line<'a>>,
}

fn _split_at_scheme<'a>(
    (i, s): (usize, &'a str),
    schemas: &[&'static str],
) -> Vec<(usize, Cow<'static, str>, &'a str)> {
    let mut slice = Option::<(Cow<'static, str>, &'a str)>::None;
    let mut result = Vec::<(usize, Cow<'static, str>, &'a str)>::with_capacity(1);

    // 1: Find first schema in line (any word://, not just KNOWN_SCHEMAS)
    if let Some(prefix) = s.split_inclusive("://").next() {
        let before = prefix.strip_suffix("://").unwrap_or(prefix);
        let scheme_word = before
            .split_whitespace()
            .last()
            .filter(|w| !w.is_empty());
        if let Some(sw) = scheme_word {
            let rest = if before.trim().is_empty() {
                s.trim_start()
            } else {
                s.strip_prefix(before.trim_end())
                    .unwrap_or(s)
            };
            let cow_scheme = KNOWN_SCHEMAS
                .iter()
                .find(|k| **k == format!("{}://", sw))
                .map(|k| Cow::Borrowed(k.strip_suffix("://").unwrap_or(k)))
                .unwrap_or_else(|| Cow::Owned(sw.to_string()));
            slice.replace((cow_scheme, rest));
        }
    }

    while let Some((schema, sx)) = slice.take() {
        if sx.is_empty() || sx.len() < 5 {
            result.push((i, schema, sx));
            break;
        }

        // try to find another known schema in the area of current url (longest first)
        let mut min_schema_pos = Option::<(usize, Cow<'static, str>)>::None;

        for s in schemas {
            let idx = sx.floor_char_boundary(5);
            let Some(pos) = sx[idx..].find(s).map(|p| p + idx) else {
                continue;
            };
            if let Some((current, found)) = min_schema_pos.as_mut() {
                if pos < *current {
                    *current = pos;
                    *found = Cow::Borrowed(s);
                }
            } else {
                min_schema_pos = Some((pos, Cow::Borrowed(s)));
            }
        }

        if let Some((min_schema_pos, another_schema)) = min_schema_pos {
            let (prefix, schema_and_tail) = sx.split_at(min_schema_pos);
            result.push((i, schema, prefix));
            _ = slice.replace((another_schema, schema_and_tail));
        } else {
            result.push((i, schema, sx));
            break;
        }
    }

    result
}

enum VisitResult {
    Visited(Line<'static>),
    Raw(Line<'static>),
}

impl<'a> Lines<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &Line<'a>> {
        self.inner.iter()
    }

    pub fn raw_entries(&self) -> &[Line<'a>] {
        &self.raw
    }

    pub fn source(&self) -> &url::Url {
        &self.source
    }

    pub fn preview_line(&self, row: usize) -> Option<&str> {
        self.basic.lines().nth(row).map(|l| {
            if l.len() > 200 {
                let idx = l.ceil_char_boundary(200);
                &l[..idx]
            } else {
                l
            }
        })
    }

    pub(crate) fn new_raw(url: &url::Url, content: &'a str) -> Self {
        let this = Self {
            source: url.clone(),
            basic: Arc::from(content),
            raw: Vec::new(),
            inner: content
                .lines()
                .enumerate()
                .par_bridge()
                .flat_map(|(idx, line)| line.split("<br/>").map(move |s| (idx, s)).par_bridge())
                .flat_map(|s| _split_at_scheme(s, KNOWN_SCHEMAS))
                .map(|(i, s, sx)| Line {
                    row: i,
                    url: Data::Raw {
                        scheme: s,
                        url: Cow::Borrowed(sx),
                    },
                    wrn: None,
                    err: None,
                })
                .collect(),
        };
        tracing::info!("{} lines parsed", this.inner.len());
        this
    }

    pub(crate) fn processed(self) -> Lines<'static> {
        let results: Vec<VisitResult> = self
            .inner
            .into_par_iter()
            .map(Line::parse_raw)
            .map(Self::_visit_line)
            .collect();

        let mut visited_lines = Vec::new();
        let mut raw_lines = Vec::new();
        for r in results {
            match r {
                VisitResult::Visited(l) => visited_lines.push(l),
                VisitResult::Raw(l) => raw_lines.push(l),
            }
        }

        visited_lines.sort_by_key(|u| u.row);
        raw_lines.sort_by_key(|u| u.row);

        tracing::info!(
            "Processed {} lines ({} raw)",
            visited_lines.len(),
            raw_lines.len()
        );
        Lines {
            source: self.source,
            basic: self.basic,
            inner: visited_lines,
            raw: raw_lines,
        }
    }

    fn _visit_line(line: Line<'a>) -> VisitResult {
        let Line {
            row,
            url,
            wrn,
            err,
        } = line;

        match url {
            Data::Url(urlx) => VisitResult::Visited(Line {
                row,
                url: Data::Url(urlx),
                wrn,
                err: None,
            }),
            Data::Raw { scheme, url } => VisitResult::Raw(Line {
                row,
                url: Data::Raw {
                    scheme,
                    url: Cow::Owned(url.into_owned()),
                },
                wrn,
                err,
            }),
        }
    }
}