//! Independent deterministic anomaly detector and circuit breaker (`hal-watchdog`).
//! Runs zero AI code and enforces surgical per-agent freeze & monotonic global degradation.

pub mod config;
pub mod detector;
pub mod runner;

pub use config::{WatchdogConfig, WatchdogConfigError};
pub use detector::{WatchdogAction, WatchdogEngine};
pub use runner::{WatchdogError, WatchdogRunner, WatchdogTickReport};
