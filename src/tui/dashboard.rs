//! `badger status`'s live dashboard: pure state fed a `StatusReport`-shaped
//! snapshot once a second, plus its rendering. The real 1-second sampling
//! loop and terminal glue live in `commands::status` (mirrors the
//! `tui::explorer` / `commands::analyze` split) — everything here is plain
//! method calls and a pure render function, so it's fully unit-testable
//! without a terminal or a real `/proc`.

use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::analyze::disk::DiskTotals;
use crate::commands::status::StatusReport;
use crate::output::humanize_bytes;
use crate::sys::cpu::LoadAvg;
use crate::sys::hwmon::HwmonChip;
use crate::sys::mem::MemInfo;
use crate::sys::power::Battery;
use crate::sys::psi::SystemPsi;

/// How many ticks of history each series keeps (~2 minutes at the
/// dashboard's 1-second refresh).
const HISTORY_LEN: usize = 120;

/// Kept in sync with `sys::health`'s `BTRFS_UNALLOCATED_LOW_PCT` threshold
/// (private to that module) — below this, btrfs can refuse writes with
/// disk space still reported as free.
const BTRFS_UNALLOCATED_LOW_PCT: f64 = 5.0;

/// Pure state for the live dashboard: the latest snapshot plus rolling
/// history for everything rendered as a sparkline. No terminal or `/proc`
/// I/O here — `on_tick` is fed an already-built `StatusReport` and hog list.
pub struct DashboardState {
    ticks: u64,
    health_score: u8,
    health_reasons: Vec<String>,
    kernel: String,
    scx: Option<String>,
    cpu_total_pct: f64,
    cpu_total_history: VecDeque<f64>,
    cpu_per_core_pct: Vec<f64>,
    load: LoadAvg,
    mem: MemInfo,
    mem_used_pct_history: VecDeque<f64>,
    disk_totals: DiskTotals,
    disk_read_history: VecDeque<f64>,
    disk_write_history: VecDeque<f64>,
    net_rx_history: VecDeque<f64>,
    net_tx_history: VecDeque<f64>,
    hottest_temp: Option<(String, f64)>,
    temps: Vec<HwmonChip>,
    battery: Option<Battery>,
    psi: SystemPsi,
    hogs: Vec<(u32, String, f64)>,
}

impl DashboardState {
    pub fn new() -> DashboardState {
        DashboardState {
            ticks: 0,
            health_score: 100,
            health_reasons: Vec::new(),
            kernel: String::new(),
            scx: None,
            cpu_total_pct: 0.0,
            cpu_total_history: VecDeque::new(),
            cpu_per_core_pct: Vec::new(),
            load: LoadAvg::default(),
            mem: MemInfo::default(),
            mem_used_pct_history: VecDeque::new(),
            disk_totals: DiskTotals {
                total: 0,
                used: 0,
                available: 0,
                fs_kind: String::new(),
                btrfs_unallocated: None,
            },
            disk_read_history: VecDeque::new(),
            disk_write_history: VecDeque::new(),
            net_rx_history: VecDeque::new(),
            net_tx_history: VecDeque::new(),
            hottest_temp: None,
            temps: Vec::new(),
            battery: None,
            psi: SystemPsi::default(),
            hogs: Vec::new(),
        }
    }

    pub fn ticks(&self) -> u64 {
        self.ticks
    }

    /// Folds in one tick's snapshot: updates every "latest" field and
    /// pushes onto each series' rolling history. `hogs` comes from the
    /// caller's `ProcCpuTracker` (per-process CPU tracking needs many
    /// samples over a window, which doesn't fit this struct's per-tick
    /// shape) — passed in already computed rather than recomputed here.
    pub fn on_tick(&mut self, report: &StatusReport, hogs: Vec<(u32, String, f64)>) {
        self.ticks += 1;
        self.health_score = report.health_score;
        self.health_reasons = report.health_reasons.clone();
        self.kernel = report.kernel.clone();
        self.scx = report.scx.clone();

        self.cpu_total_pct = report.cpu_total_pct;
        push_history(&mut self.cpu_total_history, report.cpu_total_pct);
        self.cpu_per_core_pct = report.cpu_per_core_pct.clone();
        self.load = report.load;

        self.mem = report.mem;
        push_history(&mut self.mem_used_pct_history, mem_used_pct(&report.mem));

        self.disk_totals = report.disk_totals.clone();
        let read_total: f64 = report.disk_rates.iter().map(|d| d.read_bytes_per_sec).sum();
        let write_total: f64 = report
            .disk_rates
            .iter()
            .map(|d| d.write_bytes_per_sec)
            .sum();
        push_history(&mut self.disk_read_history, read_total);
        push_history(&mut self.disk_write_history, write_total);

        let rx_total: f64 = report.net_rates.iter().map(|n| n.rx_bytes_per_sec).sum();
        let tx_total: f64 = report.net_rates.iter().map(|n| n.tx_bytes_per_sec).sum();
        push_history(&mut self.net_rx_history, rx_total);
        push_history(&mut self.net_tx_history, tx_total);

        self.hottest_temp = report.hottest_temp.clone();
        self.temps = report.temps.clone();
        self.battery = report.battery.clone();
        self.psi = report.psi;
        self.hogs = hogs;
    }
}

impl Default for DashboardState {
    fn default() -> DashboardState {
        DashboardState::new()
    }
}

fn mem_used_pct(mem: &MemInfo) -> f64 {
    if mem.total == 0 {
        0.0
    } else {
        mem.total.saturating_sub(mem.available) as f64 * 100.0 / mem.total as f64
    }
}

fn push_history(hist: &mut VecDeque<f64>, value: f64) {
    hist.push_back(value);
    while hist.len() > HISTORY_LEN {
        hist.pop_front();
    }
}

fn history_vec(hist: &VecDeque<f64>) -> Vec<f64> {
    hist.iter().copied().collect()
}

/// 8 Unicode block-height characters, lowest to highest, used for both the
/// sparkline and the per-core/fill bars.
const BLOCK_LEVELS: [char; 8] = [
    '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}',
];

/// Renders the trailing `width` points of `data` as a single-line
/// sparkline, scaled to `data`'s own min/max — not a fixed 0-100 range,
/// since callers include unbounded byte rates alongside percentages. Flat
/// data (min == max) renders as the lowest bar rather than dividing by
/// zero. Fewer than `width` points just uses what's there.
pub fn sparkline(data: &[f64], width: usize) -> String {
    if width == 0 || data.is_empty() {
        return String::new();
    }
    let start = data.len().saturating_sub(width);
    let slice = &data[start..];
    let min = slice.iter().copied().fold(f64::INFINITY, f64::min);
    let max = slice.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;
    slice
        .iter()
        .map(|&v| {
            let level = if range <= 0.0 {
                0
            } else {
                (((v - min) / range) * (BLOCK_LEVELS.len() - 1) as f64).round() as usize
            };
            BLOCK_LEVELS[level.min(BLOCK_LEVELS.len() - 1)]
        })
        .collect()
}

/// A single block-height character for a 0-100 percentage (per-core
/// mini-bars).
fn level_char(pct: f64) -> char {
    let level =
        ((pct.clamp(0.0, 100.0) / 100.0) * (BLOCK_LEVELS.len() - 1) as f64).round() as usize;
    BLOCK_LEVELS[level.min(BLOCK_LEVELS.len() - 1)]
}

/// A `width`-wide fill bar for a 0-100 percentage, using full block
/// characters.
fn fill_bar(pct: f64, width: usize) -> String {
    let filled = ((pct.clamp(0.0, 100.0) / 100.0) * width as f64).round() as usize;
    "\u{2588}".repeat(filled.min(width))
}

/// Health score color: >=90 green, >=70 yellow, else red.
fn health_color(score: u8) -> Color {
    if score >= 90 {
        Color::Green
    } else if score >= 70 {
        Color::Yellow
    } else {
        Color::Red
    }
}

/// Abstract quit check, decoupled from crossterm's event type: q, Esc, or
/// Ctrl-C (raw mode swallows SIGINT, so Ctrl-C needs its own mapping).
pub fn is_quit_key(key: KeyEvent) -> bool {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return true;
    }
    matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
}

fn temps_line(state: &DashboardState) -> String {
    match &state.hottest_temp {
        None => "Temps: (none found)".to_string(),
        Some((label, celsius)) => {
            let mut out = format!("Temps: hottest {label} {celsius:.0}\u{b0}C");
            let extra: Vec<String> = state
                .temps
                .iter()
                .flat_map(|chip| chip.readings.iter())
                .filter(|r| &r.label != label)
                .take(3)
                .map(|r| format!("{}: {:.0}\u{b0}C", r.label, r.celsius))
                .collect();
            if !extra.is_empty() {
                out.push_str("  |  ");
                out.push_str(&extra.join("  "));
            }
            out
        }
    }
}

fn psi_line(psi: &SystemPsi) -> String {
    let part = |m: &Option<crate::sys::psi::PsiMetric>| match m {
        Some(m) => format!(
            "{:.1}/{:.1}/{:.1}",
            m.some.avg10, m.some.avg60, m.some.avg300
        ),
        None => "n/a".to_string(),
    };
    format!(
        "PSI (avg10/60/300): cpu {} | mem {} | io {}",
        part(&psi.cpu),
        part(&psi.memory),
        part(&psi.io),
    )
}

/// Sparkline width for a given terminal width: enough room left for labels
/// on an 80-column terminal, growing on a wider one.
fn spark_width(total_width: u16) -> usize {
    (total_width as usize).saturating_sub(24).clamp(10, 80)
}

pub fn render(frame: &mut Frame, state: &DashboardState, colors: bool) {
    let area = frame.area();
    let width = spark_width(area.width);
    let mut lines: Vec<Line> = Vec::new();

    let score_style = if colors {
        Style::default().fg(health_color(state.health_score))
    } else {
        Style::default()
    };
    let mut header = format!("Health: {}/100", state.health_score);
    if !state.health_reasons.is_empty() {
        let top: Vec<&str> = state
            .health_reasons
            .iter()
            .take(2)
            .map(|s| s.as_str())
            .collect();
        header.push_str(&format!(" \u{2014} {}", top.join("; ")));
    }
    lines.push(Line::styled(header, score_style));
    lines.push(Line::from(format!(
        "Kernel: {}  |  scx: {}",
        state.kernel,
        state.scx.as_deref().unwrap_or("unsupported")
    )));
    lines.push(Line::from(""));

    lines.push(Line::from(format!(
        "CPU  {:>5.1}%  {}",
        state.cpu_total_pct,
        sparkline(&history_vec(&state.cpu_total_history), width)
    )));
    if !state.cpu_per_core_pct.is_empty() {
        let bars: String = state
            .cpu_per_core_pct
            .iter()
            .map(|&p| level_char(p))
            .collect();
        lines.push(Line::from(format!("cores {bars}")));
    }
    lines.push(Line::from(format!(
        "load {:.2} {:.2} {:.2}",
        state.load.one, state.load.five, state.load.fifteen
    )));
    lines.push(Line::from(""));

    let mem_pct = mem_used_pct(&state.mem);
    lines.push(Line::from(format!(
        "Mem  {} / {} ({:.0}% used)  {}",
        humanize_bytes(state.mem.total.saturating_sub(state.mem.available)),
        humanize_bytes(state.mem.total),
        mem_pct,
        fill_bar(mem_pct, 20),
    )));
    lines.push(Line::from(format!(
        "     {}",
        sparkline(&history_vec(&state.mem_used_pct_history), width)
    )));
    lines.push(Line::from(format!(
        "Swap {} / {}",
        humanize_bytes(state.mem.swap_total.saturating_sub(state.mem.swap_free)),
        humanize_bytes(state.mem.swap_total),
    )));
    lines.push(Line::from(""));

    let disk_used_pct = if state.disk_totals.total == 0 {
        0.0
    } else {
        state.disk_totals.used as f64 * 100.0 / state.disk_totals.total as f64
    };
    let mut disk_line = format!(
        "Disk ({}) {} / {} ({:.0}% used)  {}",
        state.disk_totals.fs_kind,
        humanize_bytes(state.disk_totals.used),
        humanize_bytes(state.disk_totals.total),
        disk_used_pct,
        fill_bar(disk_used_pct, 20),
    );
    if let Some(unallocated) = state.disk_totals.btrfs_unallocated {
        let unalloc_pct = unallocated as f64 * 100.0 / state.disk_totals.total.max(1) as f64;
        if unalloc_pct < BTRFS_UNALLOCATED_LOW_PCT {
            disk_line.push_str(&format!("  (low unallocated: {unalloc_pct:.1}%)"));
        }
    }
    lines.push(Line::from(disk_line));
    lines.push(Line::from(format!(
        "read  {:>10}/s  {}",
        humanize_bytes(state.disk_read_history.back().copied().unwrap_or(0.0) as u64),
        sparkline(&history_vec(&state.disk_read_history), width)
    )));
    lines.push(Line::from(format!(
        "write {:>10}/s  {}",
        humanize_bytes(state.disk_write_history.back().copied().unwrap_or(0.0) as u64),
        sparkline(&history_vec(&state.disk_write_history), width)
    )));
    lines.push(Line::from(""));

    lines.push(Line::from(format!(
        "rx  {:>10}/s  {}",
        humanize_bytes(state.net_rx_history.back().copied().unwrap_or(0.0) as u64),
        sparkline(&history_vec(&state.net_rx_history), width)
    )));
    lines.push(Line::from(format!(
        "tx  {:>10}/s  {}",
        humanize_bytes(state.net_tx_history.back().copied().unwrap_or(0.0) as u64),
        sparkline(&history_vec(&state.net_tx_history), width)
    )));
    lines.push(Line::from(""));

    lines.push(Line::from(temps_line(state)));

    if let Some(b) = &state.battery {
        lines.push(Line::from(format!(
            "Battery: {}% ({})",
            b.capacity, b.status
        )));
    }

    if state.psi.cpu.is_some() || state.psi.memory.is_some() || state.psi.io.is_some() {
        lines.push(Line::from(psi_line(&state.psi)));
    }

    if !state.hogs.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Alerts:"));
        for (pid, name, avg) in &state.hogs {
            lines.push(Line::from(format!(
                "  pid {pid:<7} {name:<20} avg {avg:.1}%"
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("q/esc/ctrl-c quit"));

    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::disk::DiskTotals;
    use crate::sys::cpu::LoadAvg;
    use crate::sys::disk::DeviceRate;
    use crate::sys::hwmon::{HwmonChip, TempReading};
    use crate::sys::mem::MemInfo;
    use crate::sys::net::IfaceRate;
    use crate::sys::power::Battery;
    use crate::sys::psi::{PsiLine, PsiMetric, SystemPsi};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn report() -> StatusReport {
        StatusReport {
            health_score: 95,
            health_reasons: vec!["CPU pressure high (avg10 30.0%)".to_string()],
            cpu_total_pct: 42.5,
            cpu_per_core_pct: vec![10.0, 90.0],
            load: LoadAvg {
                one: 1.0,
                five: 0.8,
                fifteen: 0.5,
            },
            mem: MemInfo {
                total: 16_000_000_000,
                available: 8_000_000_000,
                swap_total: 2_000_000_000,
                swap_free: 2_000_000_000,
            },
            psi: SystemPsi {
                cpu: Some(PsiMetric {
                    some: PsiLine {
                        avg10: 30.0,
                        avg60: 10.0,
                        avg300: 5.0,
                    },
                    full: None,
                }),
                memory: None,
                io: None,
            },
            disk_totals: DiskTotals {
                total: 100_000_000_000,
                used: 40_000_000_000,
                available: 60_000_000_000,
                fs_kind: "ext4".to_string(),
                btrfs_unallocated: None,
            },
            disk_rates: vec![DeviceRate {
                name: "sda".to_string(),
                read_bytes_per_sec: 1024.0,
                write_bytes_per_sec: 512.0,
            }],
            net_rates: vec![IfaceRate {
                name: "eth0".to_string(),
                rx_bytes_per_sec: 2048.0,
                tx_bytes_per_sec: 1024.0,
            }],
            temps: vec![HwmonChip {
                name: "coretemp".to_string(),
                readings: vec![TempReading {
                    label: "Package id 0".to_string(),
                    celsius: 55.0,
                }],
            }],
            hottest_temp: Some(("Package id 0".to_string(), 55.0)),
            battery: Some(Battery {
                capacity: 80,
                status: "Discharging".to_string(),
            }),
            kernel: "7.1.3-1-cachyos".to_string(),
            scx: Some("disabled".to_string()),
            failed_units: Some(0),
        }
    }

    fn draw_sized(state: &DashboardState, width: u16, height: u16) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state, true)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn draw(state: &DashboardState) -> Buffer {
        draw_sized(state, 80, 24)
    }

    fn full_text(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // --- sparkline ---

    #[test]
    fn test_sparkline_empty_data_is_empty_string() {
        assert_eq!(sparkline(&[], 10), "");
    }

    #[test]
    fn test_sparkline_zero_width_is_empty_string() {
        assert_eq!(sparkline(&[1.0, 2.0], 0), "");
    }

    #[test]
    fn test_sparkline_flat_data_uses_lowest_bar() {
        assert_eq!(sparkline(&[5.0, 5.0, 5.0], 3), "\u{2581}\u{2581}\u{2581}");
    }

    #[test]
    fn test_sparkline_scales_across_full_range() {
        assert_eq!(
            sparkline(&[0.0, 50.0, 100.0], 3),
            "\u{2581}\u{2585}\u{2588}"
        );
    }

    #[test]
    fn test_sparkline_takes_last_width_points_only() {
        assert_eq!(sparkline(&[1.0, 2.0, 3.0, 4.0, 5.0], 2), "\u{2581}\u{2588}");
    }

    #[test]
    fn test_sparkline_width_larger_than_data_uses_all_points() {
        assert_eq!(sparkline(&[10.0, 20.0], 5).chars().count(), 2);
    }

    // --- level_char / fill_bar ---

    #[test]
    fn test_level_char_extremes_and_clamping() {
        assert_eq!(level_char(0.0), '\u{2581}');
        assert_eq!(level_char(100.0), '\u{2588}');
        assert_eq!(level_char(-10.0), '\u{2581}');
        assert_eq!(level_char(150.0), '\u{2588}');
    }

    #[test]
    fn test_fill_bar_scales_to_width() {
        assert_eq!(fill_bar(50.0, 10), "\u{2588}".repeat(5));
        assert_eq!(fill_bar(0.0, 10), "");
        assert_eq!(fill_bar(100.0, 10), "\u{2588}".repeat(10));
    }

    // --- health_color ---

    #[test]
    fn test_health_color_thresholds() {
        assert_eq!(health_color(100), Color::Green);
        assert_eq!(health_color(90), Color::Green);
        assert_eq!(health_color(89), Color::Yellow);
        assert_eq!(health_color(70), Color::Yellow);
        assert_eq!(health_color(69), Color::Red);
        assert_eq!(health_color(0), Color::Red);
    }

    // --- is_quit_key ---

    #[test]
    fn test_is_quit_key_matches_q_esc_ctrl_c() {
        assert!(is_quit_key(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE
        )));
        assert!(is_quit_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(is_quit_key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
    }

    #[test]
    fn test_is_quit_key_false_for_other_keys() {
        assert!(!is_quit_key(KeyEvent::new(
            KeyCode::Char('j'),
            KeyModifiers::NONE
        )));
    }

    // --- DashboardState::on_tick ---

    #[test]
    fn test_on_tick_records_latest_values() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), Vec::new());
        assert_eq!(state.health_score, 95);
        assert_eq!(state.cpu_total_pct, 42.5);
        assert_eq!(state.ticks(), 1);
    }

    #[test]
    fn test_on_tick_accumulates_history_and_caps_at_history_len() {
        let mut state = DashboardState::new();
        for _ in 0..(HISTORY_LEN + 10) {
            state.on_tick(&report(), Vec::new());
        }
        assert_eq!(state.cpu_total_history.len(), HISTORY_LEN);
        assert_eq!(state.ticks(), (HISTORY_LEN + 10) as u64);
    }

    // --- render ---

    #[test]
    fn test_render_shows_health_score_and_reasons() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("Health: 95/100"));
        assert!(text.contains("CPU pressure high"));
    }

    #[test]
    fn test_render_shows_kernel_and_scx() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("Kernel: 7.1.3-1-cachyos"));
        assert!(text.contains("scx: disabled"));
    }

    #[test]
    fn test_render_shows_cpu_and_mem_bars_and_sparkline_chars() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(text.contains("CPU"));
        assert!(text.contains("Mem"));
        assert!(text.contains('\u{2588}'));
        assert!(text.contains('\u{2581}'));
    }

    #[test]
    fn test_render_omits_alerts_section_when_no_hogs() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), Vec::new());
        let text = full_text(&draw(&state));
        assert!(!text.contains("Alerts:"));
    }

    #[test]
    fn test_render_shows_alert_row_when_hogs_present() {
        let mut state = DashboardState::new();
        state.on_tick(&report(), vec![(1234, "chrome".to_string(), 92.5)]);
        let text = full_text(&draw_sized(&state, 80, 30));
        assert!(text.contains("Alerts:"));
        assert!(text.contains("1234"));
        assert!(text.contains("chrome"));
        assert!(text.contains("92.5"));
    }

    #[test]
    fn test_render_shows_battery_line_only_when_present() {
        let mut with_batt = DashboardState::new();
        with_batt.on_tick(&report(), Vec::new());
        assert!(full_text(&draw(&with_batt)).contains("Battery: 80%"));

        let mut r = report();
        r.battery = None;
        let mut without = DashboardState::new();
        without.on_tick(&r, Vec::new());
        assert!(!full_text(&draw(&without)).contains("Battery:"));
    }

    #[test]
    fn test_render_shows_psi_line_when_present_and_omits_when_absent() {
        let mut with_psi = DashboardState::new();
        with_psi.on_tick(&report(), Vec::new());
        assert!(full_text(&draw(&with_psi)).contains("PSI"));

        let mut r = report();
        r.psi = SystemPsi::default();
        let mut without = DashboardState::new();
        without.on_tick(&r, Vec::new());
        assert!(!full_text(&draw(&without)).contains("PSI"));
    }
}
