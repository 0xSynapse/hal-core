use crate::detector::{WatchdogAction, WatchdogEngine};
use hal_audit::{read_records_from_seq, AuditError};
use hal_bus::BusClient;
use hal_proto::wire::{BusRequest, BusResponse};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum WatchdogError {
    Audit(AuditError),
    Io(io::Error),
    Bus { code: String, reason: String },
}

impl fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(e) => write!(f, "watchdog audit verification error: {e}"),
            Self::Io(e) => write!(f, "watchdog I/O error: {e}"),
            Self::Bus { code, reason } => write!(f, "hal-bus error ({code}): {reason}"),
        }
    }
}

impl std::error::Error for WatchdogError {}

impl From<AuditError> for WatchdogError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

impl From<io::Error> for WatchdogError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Summary of a single incremental audit scan & circuit-breaker dispatch pass.
#[derive(Debug, Clone)]
pub struct WatchdogTickReport {
    pub records_scanned: usize,
    pub actions: Vec<WatchdogAction>,
    pub last_seq: u64,
}

/// Independent polling loop runner that verifies hash-chained audit records and pushes
/// corrective freeze/degradation commands over the `hal-watchdog` UDS endpoint.
pub struct WatchdogRunner {
    audit_path: PathBuf,
    bus_watchdog_socket: PathBuf,
    engine: WatchdogEngine,
    last_seq: u64,
}

impl WatchdogRunner {
    #[must_use]
    pub fn new(
        audit_path: impl AsRef<Path>,
        bus_watchdog_socket: impl AsRef<Path>,
        engine: WatchdogEngine,
    ) -> Self {
        Self {
            audit_path: audit_path.as_ref().to_path_buf(),
            bus_watchdog_socket: bus_watchdog_socket.as_ref().to_path_buf(),
            engine,
            last_seq: 0,
        }
    }

    #[must_use]
    pub fn engine(&self) -> &WatchdogEngine {
        &self.engine
    }

    #[must_use]
    pub fn engine_mut(&mut self) -> &mut WatchdogEngine {
        &mut self.engine
    }

    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Reads newly appended verified audit records and dispatches any emitted actions to `hal-bus`.
    pub fn tick(&mut self) -> Result<WatchdogTickReport, WatchdogError> {
        let records = read_records_from_seq(&self.audit_path, self.last_seq)?;
        let scanned = records.len();
        let mut emitted = Vec::new();
        for rec in &records {
            self.last_seq = rec.seq;
            emitted.extend(self.engine.observe_audit_record(rec));
        }
        self.dispatch_actions(&emitted)?;
        Ok(WatchdogTickReport {
            records_scanned: scanned,
            actions: emitted,
            last_seq: self.last_seq,
        })
    }

    /// Pushes arbitrary externally detected `WatchdogAction` items (e.g. from PF or sensor monitors)
    /// onto `hal-bus`.
    pub fn dispatch_actions(&self, actions: &[WatchdogAction]) -> Result<(), WatchdogError> {
        if actions.is_empty() {
            return Ok(());
        }
        let mut client = BusClient::connect(&self.bus_watchdog_socket)?;
        for action in actions {
            let req = match action {
                WatchdogAction::FreezeAgent {
                    agent_id,
                    rule,
                    reason,
                } => BusRequest::FreezeAgent {
                    target_agent_id: agent_id.clone(),
                    reason: format!("{rule}: {reason}"),
                },
                WatchdogAction::DegradeSystemMode { mode, rule, reason } => {
                    BusRequest::SetSystemMode {
                        mode: *mode,
                        reason: format!("{rule}: {reason}"),
                    }
                }
            };
            match client.call(&req)? {
                BusResponse::AgentFrozen { .. } | BusResponse::ModeUpdated { .. } => {}
                BusResponse::Error { code, reason } => {
                    return Err(WatchdogError::Bus { code, reason });
                }
                other => {
                    return Err(WatchdogError::Bus {
                        code: "UNEXPECTED_RESPONSE".to_string(),
                        reason: format!("unexpected bus response: {other:?}"),
                    });
                }
            }
        }
        Ok(())
    }
}
