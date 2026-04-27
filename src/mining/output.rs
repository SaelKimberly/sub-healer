use std::borrow::Cow;
use std::path::Path;

use anyhow::Result;
use htmlize::unescape as unescape_html;
use yaml_rust2::{Yaml, YamlLoader};

fn unescape_html_entities(s: &str) -> String {
    match unescape_html(s) {
        Cow::Owned(s) => s,
        Cow::Borrowed(_) => s.to_string(),
    }
}

#[derive(Debug, Default)]
pub struct ExistingData {
    pub airport_sub: Vec<String>,
    pub clash_sub: Vec<String>,
    pub v2_sub: Vec<String>,
}

fn lookup_arr<T: std::borrow::Borrow<yaml_rust2::yaml::Hash>>(hash: T, key: &str) -> Vec<String> {
    let hash = hash.borrow();
    let aliases = match key {
        "airport_sub" => ["airport_sub", "机场订阅"],
        "clash_sub" => ["clash_sub", "clash订阅"],
        "v2_sub" => ["v2_sub", "v2订阅"],
        _ => return Vec::new(),
    };

    for alias in aliases {
        if let Some(Yaml::Array(arr)) = hash.get(&Yaml::String(alias.into())) {
            return arr
                .iter()
                .filter_map(|v| match v {
                    Yaml::String(s) => Some(unescape_html_entities(s)),
                    _ => None,
                })
                .collect();
        }
    }
    Vec::new()
}

pub fn load_existing(path: &Path) -> Option<ExistingData> {
    let content = std::fs::read_to_string(path).ok()?;
    let docs = YamlLoader::load_from_str(&content).ok()?;
    let doc = docs.first()?;

    let hash = match doc {
        Yaml::Hash(h) => h,
        _ => return None,
    };

    Some(ExistingData {
        airport_sub: lookup_arr(hash, "airport_sub"),
        clash_sub: lookup_arr(hash, "clash_sub"),
        v2_sub: lookup_arr(hash, "v2_sub"),
    })
}

pub fn write_yaml(
    path: &Path,
    airport_sub: &[String],
    clash_sub: &[String],
    v2_sub: &[String],
) -> Result<()> {
    use std::borrow::Cow;
    use yaml_rust2::Yaml;
    use yaml_rust2::yaml::Hash;

    let unescape_html = |s: &str| -> String {
        match htmlize::unescape(s) {
            Cow::Owned(s) => s,
            Cow::Borrowed(_) => s.to_string(),
        }
    };

    let unquote = |s: &str| -> String {
        let s = urlencoding::decode(s)
            .map(|d| d.into_owned())
            .unwrap_or_else(|_| s.to_string());
        unescape_html(&s)
    };

    let mut root = Hash::new();
    root.insert(
        Yaml::String("airport_sub".into()),
        Yaml::Array(
            airport_sub
                .iter()
                .map(|s| Yaml::String(unquote(s)))
                .collect(),
        ),
    );
    root.insert(
        Yaml::String("clash_sub".into()),
        Yaml::Array(clash_sub.iter().map(|s| Yaml::String(unquote(s))).collect()),
    );
    root.insert(
        Yaml::String("v2_sub".into()),
        Yaml::Array(v2_sub.iter().map(|s| Yaml::String(unquote(s))).collect()),
    );

    let doc = Yaml::Hash(root);
    let mut out = String::new();
    {
        let mut emitter = yaml_rust2::YamlEmitter::new(&mut out);
        emitter.dump(&doc).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if let Some(s) = out.strip_prefix("---\n") {
        std::fs::write(path, s)?;
    } else {
        std::fs::write(path, out)?;
    }
    Ok(())
}

pub fn write_url_txt(path: &Path, urls: &[String]) -> Result<()> {
    let content = urls.join("\n") + "\n";
    std::fs::write(path, content)?;
    Ok(())
}

pub fn write_v2ray_txt(path: &Path, proxies: &[String]) -> Result<()> {
    let decode_and_unescape = |s: &str| -> String {
        let s = urlencoding::decode(s)
            .unwrap_or(std::borrow::Cow::Borrowed(s))
            .into_owned();
        match htmlize::unescape(&s) {
            std::borrow::Cow::Owned(s) => s,
            std::borrow::Cow::Borrowed(_) => s,
        }
    };

    let content = proxies
        .iter()
        .map(|p| decode_and_unescape(p))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(path, content)?;
    Ok(())
}
