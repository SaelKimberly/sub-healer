// Copyright 2024 v2ray-heal authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::mining::error::FetchError;
use crate::mining::registry::TimestampedProxy;

/// Trait for proxy streams
/// Both Telegram and Subscription fetchers implement this trait
pub trait ProxyStream: Stream<Item = Result<TimestampedProxy, FetchError>> + Unpin + Send {}

impl<T> ProxyStream for T where T: Stream<Item = Result<TimestampedProxy, FetchError>> + Unpin + Send {}
