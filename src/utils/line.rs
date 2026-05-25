use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;

use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};

use crate::proto_spec::{ProtocolConfig, ProtoSpec};
use crate::urlx::{RawUrlX, SchemeX};

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Data<'a> {
    Raw {
        scheme: Cow<'static, str>,
        url: Cow<'a, str>,
    },
    Url(ProtocolConfig),
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
                .split('&')
                .filter(|chunk| !chunk.is_empty())
                .collect::<Vec<_>>()
                .join("&");

            if norm == url {
                url
            } else {
                wrn.get_or_insert_default()
                    .push("Detected HTML entities".into());
                Cow::Owned(norm)
            }
        };

        // SchemeX::from_str is Infallible
        let scheme_enum = SchemeX::from_str(scheme.as_ref()).unwrap();
        if matches!(scheme_enum, SchemeX::Unknown(_)) {
            wrn.get_or_insert_default()
                .push(format!("Unknown protocol schema: {scheme_enum}").into());
        }

        let raw: RawUrlX = url.as_ref().into();
        match ProtocolConfig::try_parse(&raw) {
            Ok(config) => Self {
                row,
                url: Data::Url(config),
                wrn,
                err: None,
            },
            Err(e) => Self {
                row,
                url: Data::Raw { scheme, url },
                wrn,
                err: Some(e.to_string().into()),
            },
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

enum VisitResult {
    Visited(Line<'static>),
    Raw(Line<'static>),
}

impl<'a> Lines<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &Line<'a>> {
        self.inner.iter()
    }

    #[must_use]
    pub fn raw_entries(&self) -> &[Line<'a>] {
        &self.raw
    }

    #[must_use]
    pub const fn source(&self) -> &url::Url {
        &self.source
    }

    #[must_use]
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
                .flat_map(|(idx, segment)| {
                    let s = segment.trim_start();
                    if s.starts_with('#') || s.starts_with("//") || s.is_empty() {
                        Vec::new()
                    } else {
                        SchemeX::slice_input(s)
                            .into_iter()
                            .map(move |(scheme, url)| {
                                (idx, Cow::Owned(scheme.as_str().to_string()), url)
                            })
                            .collect()
                    }
                })
                .map(|(i, scheme, url)| Line {
                    row: i,
                    url: Data::Raw { scheme, url },
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
        let Line { row, url, wrn, err } = line;

        match url {
            Data::Url(config) => VisitResult::Visited(Line {
                row,
                url: Data::Url(config),
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
