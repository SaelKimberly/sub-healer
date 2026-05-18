use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::Mutex;

use serde_json::json;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

pub struct UnparseableLayer {
    writer: Mutex<Option<BufWriter<std::fs::File>>>,
}

impl UnparseableLayer {
    pub fn new() -> Self {
        let path = std::env::var("V2RAY_HEAL_UNPARSEABLE_LOG")
            .unwrap_or_else(|_| "unparseable.ndjson".to_string());
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        Self {
            writer: Mutex::new(file.map(BufWriter::new)),
        }
    }
}

impl<S> Layer<S> for UnparseableLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: Context<'_, S>,
    ) {
        if event.metadata().target() != "mining::unparseable" {
            return;
        }

        let mut guard = match self.writer.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let writer = match guard.as_mut() {
            Some(w) => w,
            None => return,
        };

        let mut visitor = UnparseableVisitor::default();
        event.record(&mut visitor);

        let obj = json!({
            "raw_url": visitor.raw_url,
            "scheme": visitor.scheme,
            "error": visitor.error,
            "source_id": visitor.source_id,
            "source_type": visitor.source_type,
            "timestamp": visitor.timestamp,
        });

        if let Ok(line) = serde_json::to_string(&obj) {
            let _ = writeln!(writer, "{line}");
            let _ = writer.flush();
        }
    }
}

#[derive(Default)]
struct UnparseableVisitor {
    raw_url: Option<String>,
    scheme: Option<String>,
    error: Option<String>,
    source_type: Option<String>,
    source_id: Option<i64>,
    timestamp: Option<i64>,
}

impl tracing::field::Visit for UnparseableVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "raw_url" => self.raw_url = Some(value.to_string()),
            "scheme" => self.scheme = Some(value.to_string()),
            "error" => self.error = Some(value.to_string()),
            "source_type" => self.source_type = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        match field.name() {
            "source_id" => self.source_id = Some(value),
            "timestamp" => self.timestamp = Some(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        if matches!(
            name,
            "raw_url" | "scheme" | "error" | "source_type"
        ) {
            let s = format!("{value:?}");
            match name {
                "raw_url" => self.raw_url = Some(s),
                "scheme" => self.scheme = Some(s),
                "error" => self.error = Some(s),
                "source_type" => self.source_type = Some(s),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tracing_subscriber::prelude::*;

    #[test]
    fn test_unparseable_layer_filters_by_target() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("unparseable-test-{ts}.ndjson"));
        let _ = std::fs::remove_file(&tmp);

        // SAFETY: single-threaded test, no concurrent env access
        unsafe { std::env::set_var("V2RAY_HEAL_UNPARSEABLE_LOG", tmp.to_str().unwrap()) };
        let layer = UnparseableLayer::new();

        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);

        tracing::warn!(
            target: "mining::unparseable",
            raw_url = "vless://bad@example.com:invalid",
            scheme = "vless",
            error = "invalid port",
            source_id = 42i64,
            source_type = "telegram",
            timestamp = 1234567890i64,
        );

        tracing::warn!(
            target: "mining::tg_channel",
            raw_url = "ss://some@thing",
            scheme = "ss",
            error = "filtered",
            source_id = 99i64,
            source_type = "telegram",
            timestamp = 999i64,
        );

        drop(guard);

        let content = std::fs::read_to_string(&tmp).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1, "only matching-target events should be written");

        let parsed: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["raw_url"], "vless://bad@example.com:invalid");
        assert_eq!(parsed["scheme"], "vless");
        assert_eq!(parsed["error"], "invalid port");
        assert_eq!(parsed["source_id"], 42);
        assert_eq!(parsed["source_type"], "telegram");
        assert_eq!(parsed["timestamp"], 1234567890);

        let _ = std::fs::remove_file(&tmp);
        // SAFETY: single-threaded test, no concurrent env access
        unsafe { std::env::remove_var("V2RAY_HEAL_UNPARSEABLE_LOG") };
    }
}
