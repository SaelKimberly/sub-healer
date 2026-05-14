// Copyright 2024 v2ray-heal authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Error types for proxy fetching operations
#[derive(Debug, Error)]
pub enum FetchError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// IO error (file operations, etc.)
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// URL parsing failed
    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),

    /// Proxy URL parsing failed
    #[error("Proxy URL parse error: {0}")]
    ProxyParseError(String),

    /// Telegram-specific error
    #[error("Telegram error: {0}")]
    TelegramError(String),

    /// Subscription-specific error
    #[error("Subscription error: {0}")]
    SubscriptionError(String),

    /// Source not found in registry
    #[error("Source not found: {0}")]
    SourceNotFound(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// Other error
    #[error("Error: {0}")]
    Other(String),
}

impl From<&str> for FetchError {
    fn from(s: &str) -> Self {
        FetchError::Other(s.to_string())
    }
}

impl From<String> for FetchError {
    fn from(s: String) -> Self {
        FetchError::Other(s)
    }
}
