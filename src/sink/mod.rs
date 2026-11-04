//! Alert outputs.

pub mod jsonl;
pub mod syslog;

use crate::alert::Alert;

/// Destination for alerts.
pub trait AlertSink: Send {
    /// Short name used in error messages.
    fn name(&self) -> &str;

    /// Delivers one alert.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from the underlying transport.
    fn emit(&mut self, alert: &Alert) -> std::io::Result<()>;

    /// Flushes buffered output.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from the underlying transport.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Collects alerts in memory; useful for embedding and tests.
#[derive(Debug, Clone, Default)]
pub struct Collector(std::sync::Arc<std::sync::Mutex<Vec<Alert>>>);

impl Collector {
    /// Copies the alerts collected so far.
    pub fn alerts(&self) -> Vec<Alert> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AlertSink for Collector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn emit(&mut self, alert: &Alert) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(alert.clone());
        Ok(())
    }
}
