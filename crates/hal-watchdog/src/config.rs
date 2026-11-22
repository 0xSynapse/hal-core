use serde::Deserialize;
use std::fmt;
use std::path::Path;

/// Deterministic threshold configuration for `hal-watchdog` loaded from `watchdog.toml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WatchdogConfig {
    pub version: u32,
    pub denial_burst_threshold: usize,
    pub denial_window_ms: u64,
    pub lease_conflict_threshold: usize,
    pub lease_window_ms: u64,
    pub pf_drop_burst_threshold: usize,
    pub pf_window_ms: u64,
    pub global_escalate_frozen_agents: usize,
    pub sensor_divergence_limit_c: f64,
}

#[derive(Debug)]
pub enum WatchdogConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Validation(String),
}

impl fmt::Display for WatchdogConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read watchdog config: {e}"),
            Self::Toml(e) => write!(f, "invalid watchdog config TOML: {e}"),
            Self::Validation(msg) => write!(f, "watchdog config validation failed: {msg}"),
        }
    }
}

impl std::error::Error for WatchdogConfigError {}

impl From<std::io::Error> for WatchdogConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for WatchdogConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl WatchdogConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, WatchdogConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, WatchdogConfigError> {
        let cfg: Self = toml::from_str(toml_str)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), WatchdogConfigError> {
        if self.version != 1 {
            return Err(WatchdogConfigError::Validation(format!(
                "unsupported watchdog config version {}",
                self.version
            )));
        }
        if self.denial_burst_threshold == 0
            || self.denial_window_ms == 0
            || self.lease_conflict_threshold == 0
            || self.lease_window_ms == 0
            || self.pf_drop_burst_threshold == 0
            || self.pf_window_ms == 0
            || self.global_escalate_frozen_agents == 0
        {
            return Err(WatchdogConfigError::Validation(
                "all watchdog threshold and window values must be > 0".to_string(),
            ));
        }
        if !self.sensor_divergence_limit_c.is_finite() || self.sensor_divergence_limit_c <= 0.0 {
            return Err(WatchdogConfigError::Validation(
                "sensor_divergence_limit_c must be finite and > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_repo_watchdog_config_and_rejects_zero_thresholds() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/watchdog.toml");
        let cfg = WatchdogConfig::from_file(path).expect("repo watchdog.toml should be valid");
        assert_eq!(cfg.denial_burst_threshold, 3);
        assert_eq!(cfg.lease_conflict_threshold, 3);
        assert_eq!(cfg.pf_drop_burst_threshold, 5);

        let bad = r#"
version = 1
denial_burst_threshold = 0
denial_window_ms = 1000
lease_conflict_threshold = 3
lease_window_ms = 1000
pf_drop_burst_threshold = 5
pf_window_ms = 1000
global_escalate_frozen_agents = 2
sensor_divergence_limit_c = 5.0
"#;
        assert!(matches!(
            WatchdogConfig::from_toml_str(bad),
            Err(WatchdogConfigError::Validation(_))
        ));
    }
}
