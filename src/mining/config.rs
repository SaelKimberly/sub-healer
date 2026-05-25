use std::path::Path;

use anyhow::{Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

pub trait ConfigSource {
    fn sources(&self) -> Result<(Vec<String>, Vec<String>), anyhow::Error>;
}

pub struct YamlConfigSource {
    channels: Vec<String>,
    subscriptions: Vec<String>,
}

impl YamlConfigSource {
    pub fn from_path(path: &Path) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path).context("Failed to read config file")?;
        let docs = YamlLoader::load_from_str(&content).context("Failed to parse YAML")?;

        let Some(Yaml::Hash(h)) = docs.first() else {
            return Err(anyhow::anyhow!("Invalid or empty config file"));
        };

        let channels = {
            let Some(Yaml::Array(list)) = h.get(&Yaml::String("tgchannel".into())) else {
                return Err(anyhow::anyhow!(
                    "Invalid or missing tgchannel in config file"
                ));
            };
            list.iter()
                .filter_map(|v| match v {
                    Yaml::String(s) => Some(s.as_str()),
                    _ => None,
                })
                .map(|url| {
                    let channel_name = url.rsplit_once('/').map_or(url, |(_, name)| name);
                    format!("https://t.me/s/{channel_name}")
                })
                .collect()
        };

        let subscriptions = h
            .get(&Yaml::String("subscriptions".into()))
            .and_then(|v| v.as_vec())
            .map(|list| {
                list.iter()
                    .filter_map(|v| match v {
                        Yaml::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self { channels, subscriptions })
    }
}

impl ConfigSource for YamlConfigSource {
    fn sources(&self) -> Result<(Vec<String>, Vec<String>), anyhow::Error> {
        Ok((self.channels.clone(), self.subscriptions.clone()))
    }
}

pub fn load_config(path: &Path) -> Result<Vec<String>> {
    let source = YamlConfigSource::from_path(path)?;
    Ok(source.channels)
}

pub fn load_subscriptions(path: &Path) -> Result<Vec<String>> {
    let source = YamlConfigSource::from_path(path)?;
    Ok(source.subscriptions)
}
