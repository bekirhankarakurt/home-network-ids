//! Live terminal dashboard (ratatui): hosts, alerts and traffic.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row, Sparkline, Table,
};
use ratatui::{Frame, Terminal};

use crate::alert::Severity;
use crate::pipeline::{Counters, Snapshot};
use crate::stats::{SharedStats, Stats};

const TICK: Duration = Duration::from_millis(200);

/// What the dashboard displays besides the statistics.
pub struct View {
    /// Source description (interface or file).
    pub source: String,
    /// Pipeline counters.
    pub counters: Arc<Counters>,
    /// Statistics updated by the pipeline.
    pub stats: SharedStats,
}

/// Restores the terminal even if drawing fails.
struct TermGuard;

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

/// Runs the dashboard until the user quits or `stop` is set and the pipeline
/// has finished. Pressing `q`, `Esc` or `Ctrl-C` sets `stop`.
///
/// # Errors
///
/// Returns terminal I/O errors.
pub fn run(view: &View, stop: &AtomicBool, finished: &dyn Fn() -> bool) -> io::Result<()> {
    terminal::enable_raw_mode()?;
    let guard = TermGuard;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.clear()?;
    let started = Instant::now();
    loop {
        let done = finished();
        let snap = view.counters.snapshot();
        {
            let stats = view.stats.lock();
            term.draw(|f| draw(f, view, &stats, snap, done, started.elapsed()))?;
        }
        if stop.load(Ordering::Relaxed) && done {
            break;
        }
        if event::poll(TICK)? {
            if let Event::Key(k) = event::read()? {
                let ctrl_c =
                    k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
                if k.kind == KeyEventKind::Press
                    && (matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c)
                {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    drop(term);
    drop(guard);
    Ok(())
}

fn severity_color(s: Severity) -> Color {
    match s {
        Severity::Info => Color::Gray,
        Severity::Low => Color::Cyan,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::LightRed,
        Severity::Critical => Color::Magenta,
    }
}

/// Formats a byte count with binary prefixes.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n;
    let mut unit = 0;
    let mut rem = 0;
    while v >= 1024 && unit < UNITS.len() - 1 {
        rem = v % 1024;
        v /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v}.{} {}", rem * 10 / 1024, UNITS[unit])
    }
}

fn draw(f: &mut Frame, view: &View, stats: &Stats, snap: Snapshot, done: bool, elapsed: Duration) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Percentage(40),
        ])
        .split(f.area());
    draw_header(f, rows[0], view, stats, snap, done, elapsed);
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(rows[1]);
    draw_hosts(f, mid[0], stats);
    draw_traffic(f, mid[1], stats);
    draw_alerts(f, rows[2], stats);
}

fn draw_header(
    f: &mut Frame,
    area: Rect,
    view: &View,
    stats: &Stats,
    snap: Snapshot,
    done: bool,
    elapsed: Duration,
) {
    let badge = if done {
        Span::styled(" DONE ", Style::default().fg(Color::Black).bg(Color::Green))
    } else {
        Span::styled(
            " LIVE ",
            Style::default().fg(Color::Black).bg(Color::LightRed),
        )
    };
    let dropped = snap.capture_dropped + snap.parse_dropped;
    let line = Line::from(vec![
        badge,
        Span::raw(format!(
            "  {}  |  pkts {}  bytes {}  hosts {}  |  parse errors {}  dropped {}  |  alerts {}  suppressed {}  |  {}s",
            view.source,
            snap.captured,
            human_bytes(stats.bytes),
            stats.host_count(),
            snap.parse_errors,
            dropped,
            snap.alerts,
            snap.suppressed,
            elapsed.as_secs()
        )),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" hnids - home network IDS  [q] quit ");
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_hosts(f: &mut Frame, area: Rect, stats: &Stats) {
    let visible = usize::from(area.height.saturating_sub(3));
    let rows = stats.top_hosts(visible).into_iter().map(|h| {
        Row::new(vec![
            Cell::from(h.mac.to_string()),
            Cell::from(h.ip.map(|i| i.to_string()).unwrap_or_default()),
            Cell::from(h.vendor.clone().unwrap_or_else(|| {
                if h.mac.is_locally_administered() {
                    "(random)".into()
                } else {
                    "?".into()
                }
            })),
            Cell::from(h.packets.to_string()),
            Cell::from(human_bytes(h.bytes)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(15),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["MAC", "IP", "Vendor", "Pkts", "Bytes"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Hosts ({}) ", stats.host_count())),
    );
    f.render_widget(table, area);
}

fn draw_traffic(f: &mut Frame, area: Rect, stats: &Stats) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let width = usize::from(parts[0].width.saturating_sub(2));
    let series = stats.timeline(width);
    let peak = series.iter().copied().max().unwrap_or(0);
    let spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Packets/s (peak {peak}) ")),
        )
        .data(&series)
        .style(Style::default().fg(Color::Green));
    f.render_widget(spark, parts[0]);

    let protos = stats.protocols();
    let bars: Vec<Bar> = protos
        .iter()
        .map(|(p, n)| Bar::default().label(Line::from(p.label())).value(*n))
        .collect();
    let chart = BarChart::default()
        .block(Block::default().borders(Borders::ALL).title(" Protocols "))
        .data(BarGroup::default().bars(&bars))
        .bar_width(8)
        .bar_gap(1)
        .bar_style(Style::default().fg(Color::Cyan));
    f.render_widget(chart, parts[1]);
}

fn draw_alerts(f: &mut Frame, area: Rect, stats: &Stats) {
    let visible = usize::from(area.height.saturating_sub(3));
    let rows = stats.recent_alerts().take(visible).map(|a| {
        let ts = a.ts.to_string();
        let time = ts.get(11..19).unwrap_or(&ts).to_owned();
        Row::new(vec![
            Cell::from(time),
            Cell::from(a.severity.as_str()).style(
                Style::default()
                    .fg(severity_color(a.severity))
                    .add_modifier(Modifier::BOLD),
            ),
            Cell::from(a.kind),
            Cell::from(a.message.clone()),
        ])
    });
    let counts: Vec<String> = Severity::ALL
        .iter()
        .rev()
        .map(|s| format!("{} {}", s.as_str(), stats.alerts_with(*s)))
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["Time", "Severity", "Kind", "Message"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Alerts  [{}] ", counts.join("  "))),
    );
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oui::OuiTable;
    use crate::summary::PacketSummary;
    use crate::synth;
    use ratatui::backend::TestBackend;

    #[test]
    fn bytes_format() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn renders_fixture_state() {
        let stats = SharedStats::new(Arc::new(OuiTable::builtin()));
        for (ts, frame) in synth::portscan() {
            stats
                .lock()
                .observe(&PacketSummary::from_frame(ts, &frame, frame.len()).unwrap());
        }
        stats.lock().push_alert(crate::alert::Alert::new(
            crate::time::Timestamp(0),
            "portscan",
            "syn_scan",
            Severity::High,
            "scan seen",
        ));
        let view = View {
            source: "portscan.pcap".into(),
            counters: Arc::new(Counters::default()),
            stats,
        };
        let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
        term.draw(|f| {
            draw(
                f,
                &view,
                &view.stats.lock(),
                Snapshot::default(),
                true,
                Duration::ZERO,
            );
        })
        .unwrap();
        let text: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        for needle in ["Hosts", "Raspberry Pi", "scan seen", "Protocols", "DONE"] {
            assert!(text.contains(needle), "missing {needle}");
        }
    }
}
