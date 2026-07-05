//! Overall system health score: a single 0-100 number plus the reasons
//! behind any deduction, computed by a pure function over the other `sys`
//! samplers' outputs so it's exhaustively testable without touching the
//! filesystem.

/// Everything the score needs, already extracted from the individual
/// samplers so this module doesn't depend on their types directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct HealthInputs {
    pub psi_cpu_avg10: Option<f64>,
    pub psi_mem_avg10: Option<f64>,
    pub psi_io_avg10: Option<f64>,
    /// 1-minute load average divided by core count.
    pub load_per_core: f64,
    pub mem_available_pct: f64,
    pub disk_used_pct: f64,
    /// btrfs unallocated space as a percentage of total disk size; `None`
    /// on a non-btrfs filesystem.
    pub btrfs_unallocated_pct: Option<f64>,
    pub failed_units: Option<usize>,
    pub hottest_temp_c: Option<f64>,
}

/// Deduction thresholds, documented here rather than scattered as magic
/// numbers below.
mod thresholds {
    pub const PSI_AVG10_HIGH: f64 = 20.0;
    pub const LOAD_PER_CORE_HIGH: f64 = 1.5;
    pub const LOAD_PER_CORE_VERY_HIGH: f64 = 2.0;
    pub const MEM_AVAILABLE_LOW_PCT: f64 = 20.0;
    pub const MEM_AVAILABLE_CRITICAL_PCT: f64 = 10.0;
    pub const DISK_FULL_PCT: f64 = 85.0;
    pub const DISK_ALMOST_FULL_PCT: f64 = 95.0;
    pub const BTRFS_UNALLOCATED_LOW_PCT: f64 = 5.0;
    pub const TEMP_HIGH_C: f64 = 85.0;
}

/// Scores `inputs` starting from 100 and deducting for each condition that
/// crosses a threshold, returning the floored (never negative) score and
/// the human-readable reason for every deduction that applied. Only the
/// worse of a "high"/"very high" pair (load, memory, disk) is deducted, not
/// both.
pub fn health_score(inputs: &HealthInputs) -> (u8, Vec<String>) {
    use thresholds::*;

    let mut score: i64 = 100;
    let mut reasons = Vec::new();
    let mut deduct = |points: i64, reason: String| {
        score -= points;
        reasons.push(reason);
    };

    if let Some(v) = inputs.psi_cpu_avg10
        && v > PSI_AVG10_HIGH
    {
        deduct(15, format!("CPU pressure high (avg10 {v:.1}%)"));
    }
    if let Some(v) = inputs.psi_mem_avg10
        && v > PSI_AVG10_HIGH
    {
        deduct(15, format!("Memory pressure high (avg10 {v:.1}%)"));
    }
    if let Some(v) = inputs.psi_io_avg10
        && v > PSI_AVG10_HIGH
    {
        deduct(10, format!("IO pressure high (avg10 {v:.1}%)"));
    }

    if inputs.load_per_core > LOAD_PER_CORE_VERY_HIGH {
        deduct(
            20,
            format!(
                "Load average very high ({:.2} per core)",
                inputs.load_per_core
            ),
        );
    } else if inputs.load_per_core > LOAD_PER_CORE_HIGH {
        deduct(
            10,
            format!("Load average high ({:.2} per core)", inputs.load_per_core),
        );
    }

    if inputs.mem_available_pct < MEM_AVAILABLE_CRITICAL_PCT {
        deduct(
            20,
            format!(
                "Memory available critical ({:.0}%)",
                inputs.mem_available_pct
            ),
        );
    } else if inputs.mem_available_pct < MEM_AVAILABLE_LOW_PCT {
        deduct(
            10,
            format!("Memory available low ({:.0}%)", inputs.mem_available_pct),
        );
    }

    if inputs.disk_used_pct > DISK_ALMOST_FULL_PCT {
        deduct(
            20,
            format!("Disk almost full ({:.0}% used)", inputs.disk_used_pct),
        );
    } else if inputs.disk_used_pct > DISK_FULL_PCT {
        deduct(
            10,
            format!("Disk getting full ({:.0}% used)", inputs.disk_used_pct),
        );
    }

    if let Some(v) = inputs.btrfs_unallocated_pct
        && v < BTRFS_UNALLOCATED_LOW_PCT
    {
        deduct(10, format!("Btrfs unallocated space low ({v:.1}%)"));
    }

    if let Some(n) = inputs.failed_units
        && n > 0
    {
        deduct(10, format!("{n} failed systemd unit(s)"));
    }

    if let Some(t) = inputs.hottest_temp_c
        && t > TEMP_HIGH_C
    {
        deduct(15, format!("Temperature high ({t:.0}°C)"));
    }

    (score.clamp(0, 100) as u8, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> HealthInputs {
        HealthInputs {
            psi_cpu_avg10: Some(0.0),
            psi_mem_avg10: Some(0.0),
            psi_io_avg10: Some(0.0),
            load_per_core: 0.2,
            mem_available_pct: 60.0,
            disk_used_pct: 40.0,
            btrfs_unallocated_pct: Some(30.0),
            failed_units: Some(0),
            hottest_temp_c: Some(50.0),
        }
    }

    #[test]
    fn test_healthy_system_scores_100_with_no_reasons() {
        let (score, reasons) = health_score(&healthy());
        assert_eq!(score, 100);
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_missing_optional_inputs_do_not_deduct() {
        let inputs = HealthInputs {
            psi_cpu_avg10: None,
            psi_mem_avg10: None,
            psi_io_avg10: None,
            btrfs_unallocated_pct: None,
            failed_units: None,
            hottest_temp_c: None,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 100);
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_cpu_pressure_deducts_15() {
        let inputs = HealthInputs {
            psi_cpu_avg10: Some(25.0),
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 85);
        assert_eq!(reasons, vec!["CPU pressure high (avg10 25.0%)"]);
    }

    #[test]
    fn test_mem_pressure_deducts_15() {
        let inputs = HealthInputs {
            psi_mem_avg10: Some(30.0),
            ..healthy()
        };
        let (score, _) = health_score(&inputs);
        assert_eq!(score, 85);
    }

    #[test]
    fn test_io_pressure_deducts_10() {
        let inputs = HealthInputs {
            psi_io_avg10: Some(21.0),
            ..healthy()
        };
        let (score, _) = health_score(&inputs);
        assert_eq!(score, 90);
    }

    #[test]
    fn test_psi_at_exact_threshold_does_not_deduct() {
        let inputs = HealthInputs {
            psi_cpu_avg10: Some(20.0),
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 100);
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_load_high_deducts_10() {
        let inputs = HealthInputs {
            load_per_core: 1.6,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 90);
        assert_eq!(reasons, vec!["Load average high (1.60 per core)"]);
    }

    #[test]
    fn test_load_very_high_deducts_20_not_both() {
        let inputs = HealthInputs {
            load_per_core: 2.5,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 80);
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0], "Load average very high (2.50 per core)");
    }

    #[test]
    fn test_mem_low_deducts_10() {
        let inputs = HealthInputs {
            mem_available_pct: 15.0,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 90);
        assert_eq!(reasons, vec!["Memory available low (15%)"]);
    }

    #[test]
    fn test_mem_critical_deducts_20_not_both() {
        let inputs = HealthInputs {
            mem_available_pct: 5.0,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 80);
        assert_eq!(reasons.len(), 1);
    }

    #[test]
    fn test_disk_full_deducts_10() {
        let inputs = HealthInputs {
            disk_used_pct: 90.0,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 90);
        assert_eq!(reasons, vec!["Disk getting full (90% used)"]);
    }

    #[test]
    fn test_disk_almost_full_deducts_20_not_both() {
        let inputs = HealthInputs {
            disk_used_pct: 97.0,
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 80);
        assert_eq!(reasons.len(), 1);
    }

    #[test]
    fn test_btrfs_unallocated_low_deducts_10() {
        let inputs = HealthInputs {
            btrfs_unallocated_pct: Some(3.0),
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 90);
        assert_eq!(reasons, vec!["Btrfs unallocated space low (3.0%)"]);
    }

    #[test]
    fn test_failed_units_deducts_10() {
        let inputs = HealthInputs {
            failed_units: Some(2),
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 90);
        assert_eq!(reasons, vec!["2 failed systemd unit(s)"]);
    }

    #[test]
    fn test_temp_high_deducts_15() {
        let inputs = HealthInputs {
            hottest_temp_c: Some(90.0),
            ..healthy()
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 85);
        assert_eq!(reasons, vec!["Temperature high (90°C)"]);
    }

    #[test]
    fn test_score_floors_at_zero_with_many_deductions() {
        let inputs = HealthInputs {
            psi_cpu_avg10: Some(99.0),
            psi_mem_avg10: Some(99.0),
            psi_io_avg10: Some(99.0),
            load_per_core: 5.0,
            mem_available_pct: 1.0,
            disk_used_pct: 99.0,
            btrfs_unallocated_pct: Some(0.0),
            failed_units: Some(5),
            hottest_temp_c: Some(100.0),
        };
        let (score, reasons) = health_score(&inputs);
        assert_eq!(score, 0);
        assert_eq!(reasons.len(), 9);
    }
}
