use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt;

/// Mutex-guarded file writer shared across tracing layer clones.
#[derive(Clone)]
pub struct PipelineLogWriter {
    writer: Arc<Mutex<BufWriter<std::fs::File>>>,
}

impl PipelineLogWriter {
    /// Create a new `PipelineLogWriter` that appends to `path`.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be opened or created.
    #[must_use]
    pub fn new(path: &Path) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open pipeline log file");
        Self {
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
        }
    }
}

impl Write for PipelineLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.lock().unwrap().flush()
    }
}

impl<'a> fmt::MakeWriter<'a> for PipelineLogWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
