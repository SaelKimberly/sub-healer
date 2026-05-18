use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::mining::registry::{SourceRegistry, TimestampedProxy};

pub async fn fetch_timestamped_subs(
    client: &reqwest::Client,
    registry: &SourceRegistry,
    config_path: &Path,
) -> Result<Vec<TimestampedProxy>> {
    let subscriptions = super::config::load_subscriptions(config_path)?;

    if subscriptions.is_empty() {
        tracing::info!("No subscriptions configured");
        return Ok(Vec::new());
    }

    let current_ts = super::get_current_timestamp();
    let current_dt = chrono::DateTime::from_timestamp(current_ts, 0).unwrap_or_default();
    let mut proxies = Vec::new();

    for sub_url_str in &subscriptions {
        let url = match url::Url::parse(sub_url_str) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(url = %sub_url_str, error = %e, "Invalid subscription URL");
                continue;
            }
        };

        let data = match url.scheme() {
            "https" | "http" => match download_sub_data(client, &url).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(url = %sub_url_str, error = %e, "Failed to download subscription");
                    continue;
                }
            },
            "file" => {
                let path = match url.to_file_path() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::error!(url = %sub_url_str, "Invalid file URL: not an absolute path");
                        continue;
                    }
                };
                match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "Failed to read subscription file");
                        continue;
                    }
                }
            }
            other => {
                tracing::error!(scheme = %other, url = %sub_url_str, "Unsupported subscription URL scheme");
                continue;
            }
        };

        let lines = crate::parse_sub(&url, &data);

        let source = match registry.lookup(sub_url_str) {
            Some(s) => s,
            None => {
                tracing::warn!(url = %sub_url_str, "Source not found in registry (should not happen)");
                continue;
            }
        };

        // Emit unparseable URL events from this subscription
        for line in lines.raw_entries() {
            if let crate::utils::line::Data::Raw { scheme, url } = &line.url {
                tracing::warn!(
                    target: "mining::unparseable",
                    raw_url = %url.as_ref(),
                    scheme = %scheme.as_ref(),
                    error = line.err.as_deref().unwrap_or("unknown"),
                    source_id = source.id,
                    source_type = "subscription",
                    timestamp = current_ts,
                );
            }
        }

        for line in lines.iter() {
            if let crate::utils::line::Line {
                url: crate::utils::line::Data::Url(urlx),
                err: None,
                ..
            } = line
            {
                proxies.push(TimestampedProxy::new(
                    urlx.clone(),
                    current_dt,
                    Arc::clone(&source),
                    None,
                ));
            }
        }
    }

    tracing::info!(count = proxies.len(), "Fetched subscription proxies");
    Ok(proxies)
}

async fn download_sub_data(client: &reqwest::Client, url: &url::Url) -> Result<Vec<u8>> {
    let req = if matches!(
        url.host_str(),
        Some("raw.githubusercontent.com" | "github.com")
    ) && let Ok(auth) = std::env::var("GITHUB_TOKEN")
    {
        client.get(url.as_str()).bearer_auth(auth)
    } else {
        client.get(url.as_str())
    };

    let resp = req
        .send()
        .await
        .context("Subscription HTTP request failed")?
        .error_for_status()
        .context("Subscription HTTP error status")?;

    Ok(resp.bytes().await.context("Failed to read subscription response body")?.to_vec())
}
