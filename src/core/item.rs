use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Safe,
    Moderate,
    Risky,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub path: Option<PathBuf>,
    pub label: String,
    pub bytes: u64,
    pub selectable: bool,
    pub whitelisted: bool,
}

impl Candidate {
    /// Builds a candidate with the tier's default selectability: Safe-risk
    /// items start selectable, Moderate/Risky start off until something
    /// (a person, or a later phase) opts them in.
    pub fn new(path: Option<PathBuf>, label: String, bytes: u64, risk: Risk) -> Candidate {
        Candidate {
            path,
            label,
            bytes,
            selectable: risk == Risk::Safe,
            whitelisted: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Group {
    pub rule_id: String,
    pub title: String,
    pub risk: Risk,
    pub requires_sudo: bool,
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_candidate_defaults_selectable() {
        let c = Candidate::new(None, "thumbnails".to_string(), 1024, Risk::Safe);
        assert!(c.selectable);
        assert!(!c.whitelisted);
    }

    #[test]
    fn test_moderate_candidate_defaults_unselectable() {
        let c = Candidate::new(None, "journal".to_string(), 0, Risk::Moderate);
        assert!(!c.selectable);
    }

    #[test]
    fn test_risky_candidate_defaults_unselectable() {
        let c = Candidate::new(None, "risky".to_string(), 0, Risk::Risky);
        assert!(!c.selectable);
    }
}
