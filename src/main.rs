//! `hnids` command-line interface.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use home_network_ids::alert::Severity;
use home_network_ids::capture::{self, live::LiveCapture, PacketSource};
use home_network_ids::config::Config;
use home_network_ids::dashboard::{self, View};
use home_network_ids::detect::inventory::Inventory;
use home_network_ids::detect::Engine;
use home_network_ids::oui::OuiTable;
use home_network_ids::pipeline::{Options, Pipeline, Report};
use home_network_ids::sink::{jsonl::JsonLines, syslog::Syslog, AlertSink};
use home_network_ids::stats::SharedStats;

/// Home network intrusion detection: port scans, ARP spoofing, rogue devices
/// and DNS anomalies from a raw socket or a capture file.
#[derive(Parser)]
#[command(name = "hnids", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture from a network interface (needs CAP_NET_RAW).
    Live {
        /// Interface to capture on, e.g. eth0 or wlan0.
        #[arg(short, long)]
        interface: String,
        /// Do not enable promiscuous mode.
        #[arg(long)]
        no_promisc: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Replay a pcap or pcapng file through the detectors.
    Replay {
        /// Capture file (.pcap or .pcapng, Ethernet link type).
        file: PathBuf,
        /// Replay at N x recorded speed instead of as fast as possible.
        #[arg(long, value_name = "N")]
        speed: Option<f64>,
        #[command(flatten)]
        common: Common,
    },
    /// List devices in the persistent inventory.
    Inventory {
        /// Inventory file (default: from config or hnids-inventory.json).
        #[arg(long, value_name = "FILE")]
        inventory: Option<PathBuf>,
        /// Configuration file.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Print the default configuration or validate a file.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the default configuration as TOML.
    Default,
    /// Validate a configuration file.
    Check {
        /// File to validate.
        file: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Level> for Severity {
    fn from(l: Level) -> Self {
        match l {
            Level::Info => Self::Info,
            Level::Low => Self::Low,
            Level::Medium => Self::Medium,
            Level::High => Self::High,
            Level::Critical => Self::Critical,
        }
    }
}

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)]
struct Common {
    /// Rule configuration (TOML).
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Write JSON-lines alerts to FILE ("-" for stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    alerts: Option<PathBuf>,
    /// Only emit alerts at or above this severity.
    #[arg(long, value_enum, value_name = "LEVEL")]
    min_severity: Option<Level>,
    /// Also send alerts to syslog: unix:/dev/log or udp:HOST:PORT.
    #[arg(long, value_name = "TARGET")]
    syslog: Option<String>,
    /// Device inventory file.
    #[arg(long, value_name = "FILE")]
    inventory: Option<PathBuf>,
    /// Show the live terminal dashboard.
    #[arg(short, long)]
    dashboard: bool,
    /// Exit with status 2 if any alert was emitted.
    #[arg(long)]
    fail_on_alert: bool,
    /// Do not print the end-of-run summary to stderr.
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hnids: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Live {
            interface,
            no_promisc,
            common,
        } => {
            let source = LiveCapture::open(&interface, !no_promisc).with_context(|| {
                format!("cannot capture on {interface} (run as root or grant CAP_NET_RAW: sudo setcap cap_net_raw,cap_net_admin=eip $(command -v hnids))")
            })?;
            detect(Box::new(source), &interface, None, &common)
        }
        Command::Replay {
            file,
            speed,
            common,
        } => {
            if let Some(s) = speed {
                if !(s.is_finite() && s > 0.0) {
                    bail!("--speed must be a positive number");
                }
            }
            let source = capture::open_file(&file)
                .with_context(|| format!("cannot open {}", file.display()))?;
            let label = file.file_name().map_or_else(
                || file.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            detect(source, &label, speed, &common)
        }
        Command::Inventory {
            inventory,
            config,
            json,
        } => {
            let cfg = load_config(config.as_deref())?;
            let path = inventory.unwrap_or(cfg.inventory.path);
            show_inventory(&path, json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Config { action } => {
            match action {
                ConfigAction::Default => print!("{}", Config::default_toml()),
                ConfigAction::Check { file } => {
                    Config::load(&file)?;
                    println!("{}: ok", file.display());
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    Ok(match path {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    })
}

fn build_sinks(cfg: &Config, common: &Common) -> Result<Vec<Box<dyn AlertSink>>> {
    let mut sinks: Vec<Box<dyn AlertSink>> = Vec::new();
    let target = common.alerts.clone().or_else(|| cfg.output.alerts.clone());
    match target {
        Some(p) if p.as_os_str() == "-" => {
            if common.dashboard {
                bail!("--alerts - cannot be combined with --dashboard (the dashboard owns the terminal)");
            }
            sinks.push(Box::new(JsonLines::stdout()));
        }
        Some(p) => sinks
            .push(Box::new(JsonLines::append(&p).with_context(|| {
                format!("cannot open alert file {}", p.display())
            })?)),
        None if !common.dashboard => sinks.push(Box::new(JsonLines::stdout())),
        None => {}
    }
    let syslog = common.syslog.clone().or_else(|| {
        cfg.output
            .syslog
            .enabled
            .then(|| cfg.output.syslog.target.clone())
    });
    if let Some(t) = syslog {
        sinks.push(Box::new(
            Syslog::connect(&t, cfg.output.syslog.facility)
                .with_context(|| format!("cannot connect to syslog {t}"))?,
        ));
    }
    Ok(sinks)
}

fn detect(
    source: Box<dyn PacketSource>,
    label: &str,
    speed: Option<f64>,
    common: &Common,
) -> Result<ExitCode> {
    let mut cfg = load_config(common.config.as_deref())?;
    if let Some(p) = &common.inventory {
        cfg.inventory.path.clone_from(p);
    }
    if let Some(l) = common.min_severity {
        cfg.output.min_severity = l.into();
    }
    if common.dashboard && !std::io::stdout().is_terminal() {
        bail!("--dashboard needs an interactive terminal");
    }
    let oui = Arc::new(match &cfg.inventory.oui_file {
        Some(p) => OuiTable::with_file(p)
            .with_context(|| format!("cannot read OUI file {}", p.display()))?,
        None => OuiTable::builtin(),
    });
    let engine = Engine::from_config(&cfg, Arc::clone(&oui))?;
    let sinks = build_sinks(&cfg, common)?;

    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(sig, Arc::clone(&stop))
            .context("cannot install signal handler")?;
    }
    let stats = common.dashboard.then(|| SharedStats::new(oui));
    let opts = Options {
        capacity: cfg.pipeline.channel_capacity,
        speed,
        min_severity: cfg.output.min_severity,
        stats: stats.clone(),
    };
    let pipeline = Pipeline::start(source, engine, sinks, opts, Arc::clone(&stop))
        .context("cannot start pipeline")?;

    if let Some(stats) = stats {
        let view = View {
            source: label.to_owned(),
            counters: pipeline.counters(),
            stats,
        };
        dashboard::run(&view, &stop, &|| pipeline.is_finished())?;
    }
    let report = pipeline.join()?;
    if !common.quiet {
        print_summary(label, &report);
    }
    let emitted = report.counters.alerts - report.counters.filtered;
    Ok(if common.fail_on_alert && emitted > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn print_summary(label: &str, report: &Report) {
    let c = report.counters;
    eprintln!(
        "hnids: {label}: {} packets, {} parse errors, {} dropped, {} alerts ({} suppressed by cooldown, {} below min severity)",
        c.captured,
        c.parse_errors,
        c.capture_dropped + c.parse_dropped,
        c.alerts - c.filtered,
        c.suppressed,
        c.filtered
    );
    for w in &report.warnings {
        eprintln!("hnids: warning: {w}");
    }
}

fn show_inventory(path: &Path, json: bool) -> Result<()> {
    let inv = Inventory::load(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inv)?);
        return Ok(());
    }
    if inv.is_empty() {
        println!("no devices in {}", path.display());
        return Ok(());
    }
    println!(
        "{:<17}  {:<20}  {:<32}  {:>8}  LAST SEEN",
        "MAC", "VENDOR", "IPS", "PACKETS"
    );
    for d in inv.devices() {
        let ips: Vec<String> = d.ips.iter().map(ToString::to_string).collect();
        let last = home_network_ids::time::Timestamp::from_secs_micros(d.last_seen, 0).to_string();
        println!(
            "{:<17}  {:<20}  {:<32}  {:>8}  {}",
            d.mac,
            d.vendor.as_deref().unwrap_or("-"),
            ips.join(","),
            d.packets,
            last.get(..19).unwrap_or(&last)
        );
    }
    println!("{} device(s)", inv.len());
    Ok(())
}
