//! JSON-lines alert output.

use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use super::AlertSink;
use crate::alert::Alert;

/// Writes one JSON object per line.
pub struct JsonLines {
    name: String,
    out: Box<dyn Write + Send>,
}

impl JsonLines {
    /// Writes to standard output, flushing after each alert.
    pub fn stdout() -> Self {
        Self::new("stdout", Box::new(io::stdout()))
    }

    /// Appends to `path`, creating it if needed.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the file cannot be opened.
    pub fn append(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::new(
            &path.display().to_string(),
            Box::new(BufWriter::new(file)),
        ))
    }

    /// Wraps any writer.
    pub fn new(name: &str, out: Box<dyn Write + Send>) -> Self {
        Self {
            name: name.to_owned(),
            out,
        }
    }
}

impl AlertSink for JsonLines {
    fn name(&self) -> &str {
        &self.name
    }

    fn emit(&mut self, alert: &Alert) -> io::Result<()> {
        writeln!(self.out, "{}", alert.to_json())?;
        self.out.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::alert::Severity;
    use crate::time::Timestamp;

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn one_object_per_line() {
        let buf = Shared::default();
        let mut s = JsonLines::new("mem", Box::new(buf.clone()));
        let a = Alert::new(Timestamp(0), "dns", "x", Severity::Low, "m");
        s.emit(&a).unwrap();
        s.emit(&a).unwrap();
        s.flush().unwrap();
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(s.name(), "mem");
    }
}
