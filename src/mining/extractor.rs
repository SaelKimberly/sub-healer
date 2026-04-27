use std::{borrow::Cow, sync::LazyLock};

use htmlize::unescape as unescape_html;
use regex::Regex;

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]").unwrap()
});

static PROXY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:vmess://|vless://|ss://|ssr://|trojan://|hy2://|hysteria2://)[^\s<>]+")
        .unwrap()
});

static BASE64_PROXY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:ss://|ssr://|vmess://|trojan://|vless://)").unwrap());

pub fn extract_links(html: &str) -> (Vec<String>, Vec<String>) {
    let urls = URL_RE
        .find_iter(html)
        .filter_map(|m| {
            let s = m.as_str();
            if s.contains("vmess://")
                || s.contains("vless://")
                || s.contains("ss://")
                || s.contains("ssr://")
                || s.contains("trojan://")
                || s.contains("hy2://")
                || s.contains("hysteria2://")
            {
                None
            } else {
                Some(unescape_html_entities(s))
            }
        })
        .collect();

    let proxies = PROXY_RE
        .find_iter(html)
        .map(|m| unescape_html_entities(m.as_str()))
        .collect();

    (urls, proxies)
}

pub fn contains_proxy_prefix(text: &str) -> bool {
    BASE64_PROXY_RE.is_match(text)
}

pub fn unescape_html_entities(s: &str) -> String {
    match unescape_html(s) {
        Cow::Owned(s) => s,
        Cow::Borrowed(_) => s.to_string(),
    }
}

pub fn extract_links_from_html(html: &str) -> (Vec<String>, Vec<String>) {
    extract_links(html)
}
