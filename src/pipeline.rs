//! Multithreaded capture -> parse -> detect -> sink pipeline.
//!
//! Stages are connected by bounded channels. Offline replay applies
//! back-pressure (nothing is lost); live capture never blocks the capture
//! thread and counts dropped frames instead.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::alert::{Alert, Severity};
use crate::capture::{CaptureError, Frame, Next, PacketSource};
use crate::detect::Engine;
use crate::sink::AlertSink;
use crate::stats::SharedStats;
use crate::summary::PacketSummary;
use crate::time::Timestamp;

const CHECKPOINT_EVERY: Duration = Duration::from_secs(30);
const PACING_SLICE: Duration = Duration::from_millis(50);

/// Lock-free counters updated by every stage.
#[derive(Debug, Default)]
pub struct Counters {
    /// Frames read from the source.
    pub captured: AtomicU64,
    /// Frames dropped because the parse queue was full (live only).
    pub capture_dropped: AtomicU64,
    /// Frames successfully parsed.
    pub parsed: AtomicU64,
    /// Frames that failed to parse.
    pub parse_errors: AtomicU64,
    /// Parsed packets dropped because the detect queue was full (live only).
    pub parse_dropped: AtomicU64,
    /// Alerts produced by detectors (after cooldown).
    pub alerts: AtomicU64,
    /// Alerts suppressed by the cooldown.
    pub suppressed: AtomicU64,
    /// Alerts below the minimum severity.
    pub filtered: AtomicU64,
    /// Failed sink writes.
    pub sink_errors: AtomicU64,
}

/// Plain copy of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// See [`Counters::captured`].
    pub captured: u64,
    /// See [`Counters::capture_dropped`].
    pub capture_dropped: u64,
    /// See [`Counters::parsed`].
    pub parsed: u64,
    /// See [`Counters::parse_errors`].
    pub parse_errors: u64,
    /// See [`Counters::parse_dropped`].
    pub parse_dropped: u64,
    /// See [`Counters::alerts`].
    pub alerts: u64,
    /// See [`Counters::suppressed`].
    pub suppressed: u64,
    /// See [`Counters::filtered`].
    pub filtered: u64,
    /// See [`Counters::sink_errors`].
    pub sink_errors: u64,
}

impl Counters {
    /// Reads all counters.
    pub fn snapshot(&self) -> Snapshot {
        let r = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Snapshot {
            captured: r(&self.captured),
            capture_dropped: r(&self.capture_dropped),
            parsed: r(&self.parsed),
            parse_errors: r(&self.parse_errors),
            parse_dropped: r(&self.parse_dropped),
            alerts: r(&self.alerts),
            suppressed: r(&self.suppressed),
            filtered: r(&self.filtered),
            sink_errors: r(&self.sink_errors),
        }
    }
}

fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Pipeline tuning.
#[derive(Debug, Clone)]
pub struct Options {
    /// Capacity of each inter-stage channel.
    pub capacity: usize,
    /// Replay speed multiplier; `None` replays as fast as possible.
    pub speed: Option<f64>,
    /// Alerts below this severity are counted but not emitted.
    pub min_severity: Severity,
    /// Statistics for the dashboard, if enabled.
    pub stats: Option<SharedStats>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            capacity: 8192,
            speed: None,
            min_severity: Severity::Info,
            stats: None,
        }
    }
}

/// Final result of a pipeline run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// Counter values at shutdown.
    pub counters: Snapshot,
    /// Non-fatal problems (sink or checkpoint failures).
    pub warnings: Vec<String>,
}

/// Errors that stop the pipeline.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The packet source failed.
    #[error("capture: {0}")]
    Capture(#[from] CaptureError),
    /// A stage thread panicked.
    #[error("{0} thread panicked")]
    Panicked(&'static str),
}

/// Handle to running pipeline threads.
pub struct Pipeline {
    capture: JoinHandle<Result<(), CaptureError>>,
    parse: JoinHandle<()>,
    detect: JoinHandle<Vec<String>>,
    sink: JoinHandle<Vec<String>>,
    counters: Arc<Counters>,
}

impl Pipeline {
    /// Spawns all stages. Setting `stop` ends capture; the remaining stages
    /// drain their queues and exit.
    ///
    /// # Errors
    ///
    /// Returns the OS error if a thread cannot be spawned.
    pub fn start(
        source: Box<dyn PacketSource>,
        engine: Engine,
        sinks: Vec<Box<dyn AlertSink>>,
        opts: Options,
        stop: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        let counters = Arc::new(Counters::default());
        let cap = opts.capacity.max(1);
        let (frame_tx, frame_rx) = mpsc::sync_channel::<Frame>(cap);
        let (pkt_tx, pkt_rx) = mpsc::sync_channel::<PacketSummary>(cap);
        let (alert_tx, alert_rx) = mpsc::sync_channel::<Alert>(cap);
        let live = source.is_live();

        let c = Arc::clone(&counters);
        let speed = opts.speed.filter(|s| s.is_finite() && *s > 0.0);
        let capture = spawn("hnids-capture", move || {
            capture_stage(source, &frame_tx, &c, &stop, speed)
        })?;
        let c = Arc::clone(&counters);
        let parse = spawn("hnids-parse", move || {
            parse_stage(&frame_rx, &pkt_tx, &c, live);
        })?;
        let c = Arc::clone(&counters);
        let stats = opts.stats.clone();
        let detect = spawn("hnids-detect", move || {
            detect_stage(engine, &pkt_rx, &alert_tx, &c, stats.as_ref())
        })?;
        let c = Arc::clone(&counters);
        let sink = spawn("hnids-sink", move || {
            sink_stage(sinks, &alert_rx, &c, opts.min_severity, opts.stats.as_ref())
        })?;
        Ok(Self {
            capture,
            parse,
            detect,
            sink,
            counters,
        })
    }

    /// Shared counters for progress display.
    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    /// True once every stage has exited.
    pub fn is_finished(&self) -> bool {
        self.capture.is_finished()
            && self.parse.is_finished()
            && self.detect.is_finished()
            && self.sink.is_finished()
    }

    /// Waits for all stages and returns the final report.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] if the source failed or a stage panicked.
    pub fn join(self) -> Result<Report, PipelineError> {
        let captured = self
            .capture
            .join()
            .map_err(|_| PipelineError::Panicked("capture"))?;
        self.parse
            .join()
            .map_err(|_| PipelineError::Panicked("parse"))?;
        let mut warnings = self
            .detect
            .join()
            .map_err(|_| PipelineError::Panicked("detect"))?;
        warnings.extend(
            self.sink
                .join()
                .map_err(|_| PipelineError::Panicked("sink"))?,
        );
        captured?;
        Ok(Report {
            counters: self.counters.snapshot(),
            warnings,
        })
    }
}

fn spawn<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::io::Result<JoinHandle<T>> {
    thread::Builder::new().name(name.to_owned()).spawn(f)
}

/// Sleeps until `target` in short slices; returns false if `stop` was set.
fn sleep_until(target: Instant, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now >= target {
            return true;
        }
        thread::sleep((target - now).min(PACING_SLICE));
    }
}

fn capture_stage(
    mut source: Box<dyn PacketSource>,
    tx: &SyncSender<Frame>,
    counters: &Counters,
    stop: &AtomicBool,
    speed: Option<f64>,
) -> Result<(), CaptureError> {
    let live = source.is_live();
    let mut origin: Option<(Timestamp, Instant)> = None;
    while !stop.load(Ordering::Relaxed) {
        let frame = match source.next_frame()? {
            Next::Frame(f) => f,
            Next::Idle => continue,
            Next::End => break,
        };
        inc(&counters.captured);
        if let Some(speed) = speed {
            let (t0, w0) = *origin.get_or_insert((frame.ts, Instant::now()));
            let offset = frame.ts.since(t0).div_f64(speed);
            if !sleep_until(w0 + offset, stop) {
                break;
            }
        }
        if live {
            match tx.try_send(frame) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => inc(&counters.capture_dropped),
                Err(TrySendError::Disconnected(_)) => break,
            }
        } else if tx.send(frame).is_err() {
            break;
        }
    }
    Ok(())
}

fn parse_stage(
    rx: &Receiver<Frame>,
    tx: &SyncSender<PacketSummary>,
    counters: &Counters,
    live: bool,
) {
    for frame in rx {
        let Ok(pkt) = PacketSummary::from_frame(frame.ts, &frame.data, frame.wire_len) else {
            inc(&counters.parse_errors);
            continue;
        };
        inc(&counters.parsed);
        if live {
            match tx.try_send(pkt) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => inc(&counters.parse_dropped),
                Err(TrySendError::Disconnected(_)) => return,
            }
        } else if tx.send(pkt).is_err() {
            return;
        }
    }
}

fn detect_stage(
    mut engine: Engine,
    rx: &Receiver<PacketSummary>,
    tx: &SyncSender<Alert>,
    counters: &Counters,
    stats: Option<&SharedStats>,
) -> Vec<String> {
    let mut alerts = Vec::new();
    let mut last_checkpoint = Instant::now();
    let mut warnings = Vec::new();
    let checkpoint = |engine: &mut Engine, warnings: &mut Vec<String>| {
        for w in engine.checkpoint() {
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
    };
    for pkt in rx {
        if let Some(s) = stats {
            s.lock().observe(&pkt);
        }
        engine.process(&pkt, &mut alerts);
        counters
            .suppressed
            .store(engine.suppressed(), Ordering::Relaxed);
        for alert in alerts.drain(..) {
            inc(&counters.alerts);
            if tx.send(alert).is_err() {
                break;
            }
        }
        if last_checkpoint.elapsed() >= CHECKPOINT_EVERY {
            checkpoint(&mut engine, &mut warnings);
            last_checkpoint = Instant::now();
        }
    }
    checkpoint(&mut engine, &mut warnings);
    warnings
}

fn sink_stage(
    mut sinks: Vec<Box<dyn AlertSink>>,
    rx: &Receiver<Alert>,
    counters: &Counters,
    min: Severity,
    stats: Option<&SharedStats>,
) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();
    for alert in rx {
        if alert.severity < min {
            inc(&counters.filtered);
            continue;
        }
        for sink in &mut sinks {
            if let Err(e) = sink.emit(&alert) {
                inc(&counters.sink_errors);
                let w = format!("sink {}: {e}", sink.name());
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
        }
        if let Some(s) = stats {
            s.lock().push_alert(alert);
        }
    }
    for sink in &mut sinks {
        if let Err(e) = sink.flush() {
            warnings.push(format!("sink {}: {e}", sink.name()));
        }
    }
    warnings
}
