//! `badger status`: a one-shot snapshot of system health, CPU/memory/disk/
//! network use, temperatures, and CachyOS-specific state (plain text or
//! `--json`). Rates (CPU%, disk/net throughput) need two counter samples,
//! so this takes one, waits briefly, then takes another — the same
//! approach `top` uses for its first real reading. A later phase's live
//! dashboard TUI polls the same `sys::*` samplers continuously instead of
//! doing a single before/after pair.

use std::time::Duration;

use serde::Serialize;

use crate::ctx::Ctx;
use crate::output::{self, Mode};
use crate::sys::{cachyos, cpu, disk, health, hwmon, mem, net, power, procs, psi};
use crate::tui::{self, dashboard};

/// How long to wait between the two samples used to compute rates.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

pub struct StatusOutput {
    pub rendered: String,
}

/// Everything read from `/proc` that needs a second sample to turn into a
/// rate. Process CPU tracking (`sys::procs`) isn't included here: sustained
/// hogs need many samples over a window, which a one-shot command can't
/// provide — that's for the live dashboard.
pub(crate) struct Samples {
    cpu: cpu::CpuSample,
    disk: disk::DiskSample,
    net: net::NetSample,
}

pub(crate) fn take_samples(ctx: &Ctx) -> Samples {
    Samples {
        cpu: cpu::read_cpu_sample(ctx).unwrap_or_default(),
        disk: disk::read_diskstats(ctx).unwrap_or_default(),
        net: net::read_net_dev(ctx).unwrap_or_default(),
    }
}

#[derive(Serialize)]
pub struct StatusReport {
    pub health_score: u8,
    pub health_reasons: Vec<String>,
    pub cpu_total_pct: f64,
    pub cpu_per_core_pct: Vec<f64>,
    pub load: cpu::LoadAvg,
    pub mem: mem::MemInfo,
    pub psi: psi::SystemPsi,
    pub disk_totals: crate::analyze::disk::DiskTotals,
    pub disk_rates: Vec<disk::DeviceRate>,
    pub net_rates: Vec<net::IfaceRate>,
    pub temps: Vec<hwmon::HwmonChip>,
    pub hottest_temp: Option<(String, f64)>,
    pub battery: Option<power::Battery>,
    pub kernel: String,
    pub scx: Option<String>,
    pub failed_units: Option<usize>,
}

/// The failed-systemd-units count for a report. A sandboxed Ctx never
/// shells out for real (see core::runner::runner_for); skip the call
/// entirely rather than exercising the FakeRunner-errors-without-canned-
/// output path on every status run.
pub(crate) fn fetch_failed_units(ctx: &Ctx) -> Option<usize> {
    if ctx.sandboxed {
        None
    } else {
        cachyos::failed_units(ctx)
    }
}

/// Builds the full status report from a pair of samples `interval_secs`
/// apart. Split out from `run` so tests can drive it with fabricated
/// samples instead of a real 500ms sleep. `failed_units` is passed in
/// rather than fetched here because it forks `systemctl`: the one-shot
/// path fetches it once, the live dashboard refreshes it only every few
/// ticks through the session's cache.
pub(crate) fn build_report(
    ctx: &Ctx,
    before: &Samples,
    after: &Samples,
    interval_secs: f64,
    failed_units: Option<usize>,
) -> anyhow::Result<StatusReport> {
    let cpu_pcts = cpu::cpu_percent(&before.cpu, &after.cpu);
    let cpu_total_pct = cpu_pcts.first().copied().unwrap_or(0.0);
    let cpu_per_core_pct = cpu_pcts.get(1..).unwrap_or(&[]).to_vec();

    let load = cpu::read_loadavg(ctx).unwrap_or_default();
    let cores = after.cpu.cores.len().max(1) as f64;

    let mem_info = mem::read_meminfo(ctx).unwrap_or_default();
    let mem_available_pct = if mem_info.total == 0 {
        0.0
    } else {
        mem_info.available as f64 * 100.0 / mem_info.total as f64
    };

    let psi_all = psi::read_all(ctx);

    let disk_totals = disk::root_fill(ctx)?;
    let disk_used_pct = if disk_totals.total == 0 {
        0.0
    } else {
        disk_totals.used as f64 * 100.0 / disk_totals.total as f64
    };
    let btrfs_unallocated_pct = disk_totals
        .btrfs_unallocated
        .map(|u| u as f64 * 100.0 / disk_totals.total.max(1) as f64);
    let disk_rates = disk::disk_rates(&before.disk, &after.disk, interval_secs);

    let net_rates = net::net_rates(&before.net, &after.net, interval_secs);

    let temps = hwmon::read_hwmon(ctx);
    let hottest_temp = hwmon::hottest(&temps);

    let battery = power::read_battery(ctx);
    let kernel = cachyos::kernel_release(ctx).unwrap_or_default();
    let scx = cachyos::scx_scheduler(ctx);

    let health_inputs = health::HealthInputs {
        psi_cpu_avg10: psi_all.cpu.map(|p| p.some.avg10),
        psi_mem_avg10: psi_all.memory.map(|p| p.some.avg10),
        psi_io_avg10: psi_all.io.map(|p| p.some.avg10),
        load_per_core: load.one / cores,
        mem_available_pct,
        disk_used_pct,
        btrfs_unallocated_pct,
        failed_units,
        hottest_temp_c: hottest_temp.as_ref().map(|(_, c)| *c),
    };
    let (health_score, health_reasons) = health::health_score(&health_inputs);

    Ok(StatusReport {
        health_score,
        health_reasons,
        cpu_total_pct,
        cpu_per_core_pct,
        load,
        mem: mem_info,
        psi: psi_all,
        disk_totals,
        disk_rates,
        net_rates,
        temps,
        hottest_temp,
        battery,
        kernel,
        scx,
        failed_units,
    })
}

pub fn run(ctx: &Ctx, mode: Mode) -> anyhow::Result<StatusOutput> {
    let before = take_samples(ctx);
    std::thread::sleep(SAMPLE_INTERVAL);
    let after = take_samples(ctx);
    let report = build_report(
        ctx,
        &before,
        &after,
        SAMPLE_INTERVAL.as_secs_f64(),
        fetch_failed_units(ctx),
    )?;

    let rendered = match mode {
        Mode::Json => serde_json::to_string(&report)?,
        Mode::Human => render_human(&report),
    };
    Ok(StatusOutput { rendered })
}

/// How long each dashboard tick waits before sampling again — the live
/// counterpart of `SAMPLE_INTERVAL`, just repeated instead of one-shot.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Interactive `badger status`: a live dashboard refreshed once a second,
/// reusing the same `take_samples`/`build_report` pair the one-shot report
/// uses (each tick's samples become the next tick's "before"). Per-process
/// CPU tracking runs alongside on the same 1-second cadence, so
/// `proc_cpu_window_secs` doubles as a tick count.
pub fn run_dashboard(
    ctx: &Ctx,
    proc_cpu_threshold: f64,
    proc_cpu_window_secs: u64,
) -> anyhow::Result<StatusOutput> {
    let mut session = dashboard::DashboardSession::new(proc_cpu_threshold, proc_cpu_window_secs);
    let mut terminal = tui::init_terminal()?;
    let result = drive_dashboard(&mut terminal, &mut session, ctx);
    tui::restore_terminal(&mut terminal)?;
    result?;
    // Nothing gets journaled or deleted here, unlike analyze's explorer —
    // there's no summary to print once the terminal is back to normal.
    Ok(StatusOutput {
        rendered: String::new(),
    })
}

/// Polls for key events in slices of up to 100ms until either `budget`
/// elapses (returns `true`, time for the next tick) or a quit key arrives
/// (returns `false`) — same short-poll pattern as `analyze`'s
/// `drive_explorer`, just budgeted per tick instead of run to completion.
fn wait_for_next_tick(budget: Duration) -> anyhow::Result<bool> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(true);
        }
        if !crossterm::event::poll(remaining.min(Duration::from_millis(100)))? {
            continue;
        }
        let crossterm::event::Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind == crossterm::event::KeyEventKind::Release {
            continue;
        }
        if dashboard::is_quit_key(key) {
            return Ok(false);
        }
    }
}

/// Drives the dashboard's tick loop against a real terminal: draws
/// immediately, then alternates waiting-for-a-tick-or-quit with sampling and
/// redrawing. All state transitions live on `DashboardSession`/
/// `DashboardState` (unit-tested separately); this loop is only the
/// sampling/terminal glue.
fn drive_dashboard(
    terminal: &mut tui::Term,
    session: &mut dashboard::DashboardSession,
    ctx: &Ctx,
) -> anyhow::Result<()> {
    let colors = tui::colors_enabled_now();
    terminal.draw(|f| dashboard::render(f, session.state(), colors))?;

    let mut prev = take_samples(ctx);
    loop {
        if !wait_for_next_tick(TICK_INTERVAL)? {
            return Ok(());
        }

        let curr = take_samples(ctx);
        // failed_units forks systemctl, so the session caches it and only
        // re-fetches every 10th tick instead of once a second.
        let failed_units = session.failed_units_for_tick(|| fetch_failed_units(ctx));
        let report = build_report(ctx, &prev, &curr, TICK_INTERVAL.as_secs_f64(), failed_units)?;
        let proc_sample = procs::sample_all(ctx);
        session.on_tick(&report, proc_sample, TICK_INTERVAL.as_secs_f64());
        prev = curr;

        terminal.draw(|f| dashboard::render(f, session.state(), colors))?;
    }
}

fn render_human(r: &StatusReport) -> String {
    let mut out = format!("Health: {}/100", r.health_score);
    if r.health_reasons.is_empty() {
        out.push_str(" (all good)");
    } else {
        for reason in &r.health_reasons {
            out.push_str(&format!("\n  - {reason}"));
        }
    }

    out.push_str(&format!("\n\nCPU: {:.1}% total", r.cpu_total_pct));
    for (i, pct) in r.cpu_per_core_pct.iter().enumerate() {
        let bar = "#".repeat((pct / 5.0).round() as usize);
        out.push_str(&format!("\n  core{i:<2} {pct:>5.1}%  {bar}"));
    }

    out.push_str(&format!(
        "\n\nLoad: {:.2} {:.2} {:.2}",
        r.load.one, r.load.five, r.load.fifteen
    ));

    let mem_used = r.mem.total.saturating_sub(r.mem.available);
    let mem_available_pct = if r.mem.total == 0 {
        0.0
    } else {
        r.mem.available as f64 * 100.0 / r.mem.total as f64
    };
    out.push_str(&format!(
        "\nMemory: {} used of {} ({mem_available_pct:.0}% available)",
        output::humanize_bytes(mem_used),
        output::humanize_bytes(r.mem.total),
    ));
    let swap_used = r.mem.swap_total.saturating_sub(r.mem.swap_free);
    out.push_str(&format!(
        "\nSwap: {} used of {}",
        output::humanize_bytes(swap_used),
        output::humanize_bytes(r.mem.swap_total),
    ));

    let psi_part = |m: &Option<psi::PsiMetric>| match m {
        Some(m) => format!(
            "{:.1}/{:.1}/{:.1}",
            m.some.avg10, m.some.avg60, m.some.avg300
        ),
        None => "n/a".to_string(),
    };
    out.push_str(&format!(
        "\nPSI (avg10/60/300): cpu {} | mem {} | io {}",
        psi_part(&r.psi.cpu),
        psi_part(&r.psi.memory),
        psi_part(&r.psi.io),
    ));

    out.push_str(&format!(
        "\n\nDisk ({}): {} used of {}, {} available",
        r.disk_totals.fs_kind,
        output::humanize_bytes(r.disk_totals.used),
        output::humanize_bytes(r.disk_totals.total),
        output::humanize_bytes(r.disk_totals.available),
    ));
    if let Some(u) = r.disk_totals.btrfs_unallocated {
        out.push_str(&format!(", {} unallocated", output::humanize_bytes(u)));
    }
    if r.disk_rates.is_empty() {
        out.push_str("\n  IO: (no devices)");
    } else {
        for d in &r.disk_rates {
            out.push_str(&format!(
                "\n  {}: read {}/s, write {}/s",
                d.name,
                output::humanize_bytes(d.read_bytes_per_sec as u64),
                output::humanize_bytes(d.write_bytes_per_sec as u64),
            ));
        }
    }

    out.push_str("\n\nNetwork:");
    if r.net_rates.is_empty() {
        out.push_str(" (no interfaces)");
    } else {
        for n in &r.net_rates {
            out.push_str(&format!(
                "\n  {}: rx {}/s, tx {}/s",
                n.name,
                output::humanize_bytes(n.rx_bytes_per_sec as u64),
                output::humanize_bytes(n.tx_bytes_per_sec as u64),
            ));
        }
    }

    out.push_str("\n\nTemps:");
    match &r.hottest_temp {
        Some((label, celsius)) => out.push_str(&format!(" hottest {label} {celsius:.0}°C")),
        None => out.push_str(" (none found)"),
    }

    if let Some(b) = &r.battery {
        out.push_str(&format!("\nBattery: {}% ({})", b.capacity, b.status));
    }

    out.push_str(&format!("\n\nKernel: {}", r.kernel));
    match &r.scx {
        Some(s) => out.push_str(&format!(" | scx: {s}")),
        None => out.push_str(" | scx: unsupported"),
    }

    match r.failed_units {
        Some(0) => out.push_str("\nFailed units: none"),
        Some(n) => out.push_str(&format!("\nFailed units: {n}")),
        None => out.push_str("\nFailed units: unknown"),
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    fn fixture_ctx(root: &Path) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            home: root.join("home/user"),
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            dry_run: false,
            debug: false,
            config: Config::default(),
            sandboxed: true,
            available_commands: None,
            fake_command_output: None,
        }
    }

    /// Writes just enough of a fabricated system under `ctx.root` for
    /// `take_samples`/`build_report` to produce deterministic, non-empty
    /// output: /proc/stat, /proc/loadavg, /proc/meminfo, /proc/diskstats,
    /// /proc/net/dev, /proc/self/mounts (ext4), one hwmon chip, one
    /// battery, kernel osrelease, and sched_ext disabled.
    fn write_system(ctx: &Ctx, cpu_user: u64, cpu_idle: u64, sectors_read: u64, rx_bytes: u64) {
        std::fs::create_dir_all(ctx.root.join("proc/self")).unwrap();
        std::fs::write(
            ctx.root.join("proc/stat"),
            format!("cpu  {cpu_user} 0 0 {cpu_idle} 0 0 0 0\n"),
        )
        .unwrap();
        std::fs::write(ctx.root.join("proc/loadavg"), "1.0 1.0 1.0 1/100 999\n").unwrap();
        std::fs::write(
            ctx.root.join("proc/meminfo"),
            "MemTotal:       10000000 kB\nMemAvailable:    8000000 kB\nSwapTotal:  2000000 kB\nSwapFree:   2000000 kB\n",
        )
        .unwrap();
        std::fs::write(
            ctx.root.join("proc/diskstats"),
            format!("   8       0 sda 0 0 {sectors_read} 0 0 0 0 0 0 0 0\n"),
        )
        .unwrap();
        std::fs::create_dir_all(ctx.root.join("proc/net")).unwrap();
        std::fs::write(
            ctx.root.join("proc/net/dev"),
            format!(
                "Inter-|   Receive\n face |bytes\neth0: {rx_bytes} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
            ),
        )
        .unwrap();
        std::fs::write(
            ctx.root.join("proc/self/mounts"),
            format!("/dev/fake0 {} ext4 rw 0 0\n", ctx.root.display()),
        )
        .unwrap();
        std::fs::create_dir_all(ctx.root.join("proc/sys/kernel")).unwrap();
        std::fs::write(
            ctx.root.join("proc/sys/kernel/osrelease"),
            "7.1.3-1-cachyos\n",
        )
        .unwrap();
        std::fs::create_dir_all(ctx.root.join("sys/kernel/sched_ext")).unwrap();
        std::fs::write(ctx.root.join("sys/kernel/sched_ext/state"), "disabled\n").unwrap();
        let hwmon_dir = ctx.root.join("sys/class/hwmon/hwmon0");
        std::fs::create_dir_all(&hwmon_dir).unwrap();
        std::fs::write(hwmon_dir.join("name"), "acpitz").unwrap();
        std::fs::write(hwmon_dir.join("temp1_input"), "45000").unwrap();
        let battery_dir = ctx.root.join("sys/class/power_supply/BAT0");
        std::fs::create_dir_all(&battery_dir).unwrap();
        std::fs::write(battery_dir.join("type"), "Battery").unwrap();
        std::fs::write(battery_dir.join("capacity"), "80").unwrap();
        std::fs::write(battery_dir.join("status"), "Discharging").unwrap();
    }

    #[test]
    fn test_build_report_computes_exact_rates_and_health_score() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_system(&ctx, 1000, 9000, 1000, 1000);
        let before = take_samples(&ctx);
        // 500 ticks of extra busy time over the interval; 100 extra
        // sectors read (100*512=51200 bytes); 2000 extra rx bytes.
        write_system(&ctx, 1500, 9000, 1100, 3000);
        let after = take_samples(&ctx);

        let report = build_report(&ctx, &before, &after, 2.0, fetch_failed_units(&ctx)).unwrap();

        // total delta = 500 (busy) + 0 (idle unchanged) = 500; busy delta 500
        // -> 100%.
        assert_eq!(report.cpu_total_pct, 100.0);
        assert_eq!(report.load.one, 1.0);
        assert_eq!(report.mem.total, 10_000_000 * 1024);
        assert_eq!(report.disk_totals.fs_kind, "ext4");
        assert_eq!(report.disk_rates.len(), 1);
        assert_eq!(report.disk_rates[0].read_bytes_per_sec, 100.0 * 512.0 / 2.0);
        assert_eq!(report.net_rates.len(), 1);
        assert_eq!(report.net_rates[0].rx_bytes_per_sec, 2000.0 / 2.0);
        assert_eq!(report.hottest_temp, Some(("temp1".to_string(), 45.0)));
        assert_eq!(
            report.battery,
            Some(crate::sys::power::Battery {
                capacity: 80,
                status: "Discharging".to_string(),
            })
        );
        assert_eq!(report.kernel, "7.1.3-1-cachyos");
        assert_eq!(report.scx, Some("disabled".to_string()));
        assert_eq!(report.failed_units, None);
        // mem_available_pct 80%, load_per_core 1.0 (no cores parsed, so
        // cores.max(1) == 1) -> nothing crosses a health threshold.
        assert_eq!(report.health_score, 100);
        assert_eq!(report.health_reasons, Vec::<String>::new());
    }

    #[test]
    fn test_build_report_serializes_to_json() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_system(&ctx, 0, 0, 0, 0);
        let before = take_samples(&ctx);
        let after = take_samples(&ctx);

        let report = build_report(&ctx, &before, &after, 1.0, None).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["health_score"], 100);
        assert_eq!(parsed["kernel"], "7.1.3-1-cachyos");
    }

    #[test]
    fn test_render_human_contains_health_score_line() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_system(&ctx, 0, 0, 0, 0);
        let before = take_samples(&ctx);
        let after = take_samples(&ctx);
        let report = build_report(&ctx, &before, &after, 1.0, None).unwrap();

        let rendered = render_human(&report);
        assert!(rendered.contains("Health: 100/100"));
        assert!(rendered.contains("Kernel: 7.1.3-1-cachyos"));
    }

    #[test]
    fn test_run_takes_two_samples_and_returns_human_output() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        write_system(&ctx, 0, 0, 0, 0);

        let output = run(&ctx, Mode::Human).unwrap();
        assert!(output.rendered.contains("Health:"));
    }
}
