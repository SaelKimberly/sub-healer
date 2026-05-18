use std::path::Path;

use anyhow::{Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

pub fn load_config(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).context("Failed to read config.yaml")?;
    let docs = YamlLoader::load_from_str(&content).context("Failed to parse YAML")?;

    let Some(Yaml::Hash(h)) = docs.first() else {
        return Err(anyhow::anyhow!("Invalid or empty config file"));
    };
    let Some(Yaml::Array(list)) = h.get(&Yaml::String("tgchannel".into())) else {
        return Err(anyhow::anyhow!(
            "Invalid or missing tgchannel in config file"
        ));
    };

    let result: Vec<String> = list
        .iter()
        .filter_map(|v| match v {
            Yaml::String(s) => Some(s),
            _ => None,
        })
        .map(|url| {
            let channel_name = url.rsplit_once('/').map_or(url.as_str(), |(_, url)| url);

            format!("https://t.me/s/{channel_name}")
        })
        .collect();

    Ok(result)
}

pub fn load_subscriptions(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).context("Failed to read config.yaml")?;
    let docs = YamlLoader::load_from_str(&content).context("Failed to parse YAML")?;

    let Some(Yaml::Hash(h)) = docs.first() else {
        return Err(anyhow::anyhow!("Invalid or empty config file"));
    };

    let subs = h
        .get(&Yaml::String("subscriptions".into()))
        .and_then(|v| v.as_vec())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|v| match v {
            Yaml::String(s) => Some(s.to_string()),
            _ => None,
        })
        .collect();

    Ok(subs)
}
