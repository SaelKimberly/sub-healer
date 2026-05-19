use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::mining::registry::{SourceMetadata, SourceRegistry};
use crate::utils::line::{Data, Line, Lines};

/// # Errors
///
/// - If the database upsert fails
pub fn process_sub_lines(
    lines: &Lines,
    source: &Arc<SourceMetadata>,
    conn: &rusqlite::Connection,
    source_type_label: &str,
    ts: i64,
) -> Result<usize> {
    for line in lines.raw_entries() {
        if let Data::Raw { scheme, url } = &line.url {
            tracing::warn!(
                target: "mining::unparseable",
                raw_url = %url.as_ref(),
                scheme = %scheme.as_ref(),
                error = line.err.as_deref().unwrap_or("unknown"),
                source_id = source.id,
                source_type = source_type_label,
                timestamp = ts,
            );
        }
    }

    let mut count = 0usize;
    for line in lines.iter() {
        let Line {
            url: Data::Url(urlx),
            err: None,
            ..
        } = line
        else {
            continue;
        };
        crate::db::upsert_server(conn, urlx, source.id, ts)
            .context("Subscription upsert failed (aborting)")?;
        count += 1;
    }

    Ok(count)
}

pub async fn fetch_timestamped_subs(
    client: reqwest::Client,
    registry: &SourceRegistry,
    config_path: &Path,
    conn: rusqlite::Connection,
) -> Result<usize> {
    let subscriptions = super::config::load_subscriptions(config_path)?;

    if subscriptions.is_empty() {
        tracing::info!("No subscriptions configured");
        return Ok(0);
    }

    let current_ts = super::get_current_timestamp();
    let mut total = 0usize;

    for sub_url_str in &subscriptions {
        let url = match url::Url::parse(sub_url_str) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(url = %sub_url_str, error = %e, "Invalid subscription URL");
                continue;
            }
        };

        let data = match url.scheme() {
            "https" | "http" => match download_sub_data(&client, &url).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(url = %sub_url_str, error = %e, "Failed to download subscription");
                    continue;
                }
            },
            "file" => {
                let Ok(path) = url.to_file_path() else {
                    tracing::error!(url = %sub_url_str, "Invalid file URL: not an absolute path");
                    continue;
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

        let Some(source) = registry.lookup(sub_url_str) else {
            tracing::warn!(url = %sub_url_str, "Source not found in registry (should not happen)");
            continue;
        };

        let count = process_sub_lines(&lines, &source, &conn, "subscription", current_ts)?;
        total += count;
    }

    tracing::info!(count = total, "Fetched subscription proxies");
    Ok(total)
}

/// # Errors
///
/// Will return `Err` if the request fails.
pub async fn download_sub_data(client: &reqwest::Client, url: &url::Url) -> Result<Vec<u8>> {
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

    Ok(resp
        .bytes()
        .await
        .context("Failed to read subscription response body")?
        .to_vec())
}
