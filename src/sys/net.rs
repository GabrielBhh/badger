//! Network interface throughput (`/proc/net/dev`). Same raw-sample +
//! pure-delta shape as `sys::cpu` and `sys::disk`.

use crate::ctx::Ctx;

/// Raw rx/tx byte counters for one network interface.
#[derive(Debug, Clone, PartialEq)]
pub struct IfaceStat {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A full `/proc/net/dev` sample, one `IfaceStat` per interface (loopback
/// excluded — see `parse_net_dev`).
pub type NetSample = Vec<IfaceStat>;

/// Parses `/proc/net/dev`. Skips the two header lines and the loopback
/// interface (`lo`); `rx_bytes` is the first Receive field, `tx_bytes` the
/// first Transmit field (index 8 of the 16 numeric fields after the
/// interface name).
pub fn parse_net_dev(text: &str) -> NetSample {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_string();
        if name == "lo" || name.is_empty() {
            continue;
        }
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let (Some(rx), Some(tx)) = (fields.first(), fields.get(8)) else {
            continue;
        };
        let (Ok(rx_bytes), Ok(tx_bytes)) = (rx.parse::<u64>(), tx.parse::<u64>()) else {
            continue;
        };
        out.push(IfaceStat {
            name,
            rx_bytes,
            tx_bytes,
        });
    }
    out
}

/// Reads and parses `<root>/proc/net/dev`.
pub fn read_net_dev(ctx: &Ctx) -> anyhow::Result<NetSample> {
    let text = std::fs::read_to_string(ctx.root.join("proc/net/dev"))?;
    Ok(parse_net_dev(&text))
}

/// Bytes/sec rx/tx rate for one interface.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct IfaceRate {
    pub name: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Byte-per-second rx/tx rates for every interface present in both samples.
/// `interval_secs <= 0.0` reports 0.0 rather than dividing by zero.
pub fn net_rates(prev: &NetSample, curr: &NetSample, interval_secs: f64) -> Vec<IfaceRate> {
    curr.iter()
        .filter_map(|c| {
            let p = prev.iter().find(|p| p.name == c.name)?;
            let rate = |prev_bytes: u64, curr_bytes: u64| -> f64 {
                if interval_secs <= 0.0 {
                    return 0.0;
                }
                curr_bytes.saturating_sub(prev_bytes) as f64 / interval_secs
            };
            Some(IfaceRate {
                name: c.name.clone(),
                rx_bytes_per_sec: rate(p.rx_bytes, c.rx_bytes),
                tx_bytes_per_sec: rate(p.tx_bytes, c.tx_bytes),
            })
        })
        .collect()
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

    const FIXTURE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  854957    6713    0    0    0     0          0         0   854957    6713    0    0    0     0       0          0
enp12s0: 2049475718 1721269    0 2791    0     0          0      4685 255721630 1297025    0    0    0     0       0          0
 wlan0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

    // --- parse_net_dev ---

    #[test]
    fn test_parse_net_dev_skips_loopback() {
        let got = parse_net_dev(FIXTURE);
        assert!(!got.iter().any(|i| i.name == "lo"));
    }

    #[test]
    fn test_parse_net_dev_reads_rx_and_tx_bytes() {
        let got = parse_net_dev(FIXTURE);
        let eth = got.iter().find(|i| i.name == "enp12s0").unwrap();
        assert_eq!(eth.rx_bytes, 2049475718);
        assert_eq!(eth.tx_bytes, 255721630);
    }

    #[test]
    fn test_parse_net_dev_empty_text_is_empty() {
        assert_eq!(parse_net_dev(""), vec![]);
    }

    // --- net_rates ---

    #[test]
    fn test_net_rates_computes_exact_bytes_per_sec() {
        let prev = vec![IfaceStat {
            name: "eth0".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
        }];
        let curr = vec![IfaceStat {
            name: "eth0".to_string(),
            rx_bytes: 3000,
            tx_bytes: 2500,
        }];
        let got = net_rates(&prev, &curr, 2.0);
        assert_eq!(
            got,
            vec![IfaceRate {
                name: "eth0".to_string(),
                rx_bytes_per_sec: 1000.0,
                tx_bytes_per_sec: 250.0,
            }]
        );
    }

    #[test]
    fn test_net_rates_skips_interfaces_not_in_both_samples() {
        let prev = vec![];
        let curr = vec![IfaceStat {
            name: "eth0".to_string(),
            rx_bytes: 10,
            tx_bytes: 10,
        }];
        assert_eq!(net_rates(&prev, &curr, 1.0), vec![]);
    }

    #[test]
    fn test_net_rates_zero_interval_is_zero_not_a_panic() {
        let prev = vec![IfaceStat {
            name: "eth0".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
        }];
        let curr = vec![IfaceStat {
            name: "eth0".to_string(),
            rx_bytes: 100,
            tx_bytes: 100,
        }];
        let got = net_rates(&prev, &curr, 0.0);
        assert_eq!(got[0].rx_bytes_per_sec, 0.0);
    }

    // --- read_net_dev ---

    #[test]
    fn test_read_net_dev_reads_through_ctx_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        std::fs::create_dir_all(ctx.root.join("proc/net")).unwrap();
        std::fs::write(ctx.root.join("proc/net/dev"), FIXTURE).unwrap();

        let got = read_net_dev(&ctx).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn test_read_net_dev_missing_file_is_an_error() {
        let sandbox = tempfile::tempdir().unwrap();
        let ctx = fixture_ctx(sandbox.path());
        assert!(read_net_dev(&ctx).is_err());
    }
}
