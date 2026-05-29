use std::borrow::Cow;
use std::sync::Arc;
use rayon::iter::{ParallelBridge, ParallelIterator};
use crate::proto_spec::FallbackInfo;
use crate::urlx::SchemeX;
#[derive(Debug, Clone)]
pub enum Data<'a> {
    Raw {
        scheme: Cow<'static, str>,
        url: Cow<'a, str>,
    },
}

#[derive(Debug, Clone)]
pub struct Line<'a> {
    pub(crate) row: usize,
    pub(crate) url: Data<'a>,
    pub(crate) wrn: Option<Vec<Cow<'static, str>>>,
    pub(crate) err: Option<Cow<'static, str>>,
    pub fallback: Option<FallbackInfo>,
}


#[derive(Clone)]
pub struct Lines<'a> {
    source: url::Url,
    basic: Arc<str>,
    inner: Vec<Line<'a>>,
    raw: Vec<Line<'a>>,
}
impl<'a> Lines<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &Line<'a>> {
        self.inner.iter()
    }
    #[must_use]
    pub fn raw_entries(&self) -> &[Line<'a>] {
        &self.raw
    }
    /// Iterate over entries that were parsed via schema fallback.
    pub fn fallback_entries(&self) -> impl Iterator<Item = (&FallbackInfo, usize)> {
        self.inner.iter().filter_map(|l| l.fallback.as_ref().map(|f| (f, l.row)))
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
                    fallback: None,
                })
                .collect(),
        };
        tracing::info!("{} lines parsed", this.inner.len());
        this
    }
    /// Convert owned representation (lifetime `'a` → `'static`) without parsing.
    pub(crate) fn processed(self) -> Lines<'static> {
        let Lines { source, basic, inner, .. } = self;
        tracing::info!("{} lines in processed output", inner.len());
        Lines {
            source,
            basic,
            inner: inner
                .into_iter()
                .map(|l| {
                    let Line { row, url, wrn, err, fallback } = l;
                    let Data::Raw { scheme, url } = url;
                    Line {
                        row,
                        url: Data::Raw {
                            scheme,
                            url: Cow::Owned(url.into_owned()),
                        },
                        wrn,
                        err,
                        fallback,
                    }
                })
                .collect(),
            raw: Vec::new(),
        }
    }
}