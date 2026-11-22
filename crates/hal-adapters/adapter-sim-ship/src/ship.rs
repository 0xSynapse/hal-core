use hal_proto::{EventEnvelope, NodeDescriptor, NodeKind, RiskTier, TrustLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

const MIN_SAFE_TARGET_TEMP_C: f64 = 16.0;
const MAX_SAFE_TARGET_TEMP_C: f64 = 28.0;

/// Cyber-physical state of the simulated HAL 9000 habitat & ship ("Discovery One").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShipState {
    pub cabin_temp_c: f64,
    pub cabin_temp_backup_c: f64,
    pub target_temp_c: f64,
    pub ambient_temp_c: f64,
    pub presence_detected: bool,
    pub airlock_locked: bool,
    pub human_emergency_interlock: bool,
    pub ups_online: bool,
    pub ups_load_pct: f64,
    pub heater_duty_pct: f64,
    pub spinal_tick_count: u64,
}

impl Default for ShipState {
    fn default() -> Self {
        Self {
            cabin_temp_c: 21.0,
            cabin_temp_backup_c: 21.0,
            target_temp_c: 21.5,
            ambient_temp_c: 14.0,
            presence_detected: true,
            airlock_locked: false,
            human_emergency_interlock: true,
            ups_online: true,
            ups_load_pct: 32.0,
            heater_duty_pct: 25.0,
            spinal_tick_count: 0,
        }
    }
}

/// Control action submitted to `ShipSimulator` after brainstem/OOB mediation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ShipCommand {
    SetTargetTemp {
        temp_c: f64,
        is_oob: bool,
        lease_verified: bool,
    },
    SetAirlockLock {
        locked: bool,
        is_oob: bool,
        approval_id: Option<String>,
    },
    SetUpsPower {
        online: bool,
        is_oob: bool,
        approval_id: Option<String>,
    },
    SetHumanInterlock {
        enabled: bool,
        is_oob: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShipCommandOutcome {
    pub node_path: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShipError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for ShipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for ShipError {}

/// Deterministic cyber-physical ship simulator hosting Layer 0 spinal control loops
/// that run uninterrupted even when Layer 3 cognition is `FROZEN` or `LOCKDOWN`.
#[derive(Debug, Clone, Default)]
pub struct ShipSimulator {
    state: ShipState,
}

impl ShipSimulator {
    #[must_use]
    pub fn new(initial: ShipState) -> Self {
        Self { state: initial }
    }

    #[must_use]
    pub fn state(&self) -> &ShipState {
        &self.state
    }

    #[must_use]
    pub fn descriptors() -> Vec<NodeDescriptor> {
        vec![
            NodeDescriptor {
                path: "/habitat/study/temp".to_string(),
                kind: NodeKind::Dual,
                risk_tier: RiskTier::L1ReversibleCow,
                default_taint: None,
                reversible: true,
                description: "Primary & redundant study thermal telemetry and setpoint".to_string(),
            },
            NodeDescriptor {
                path: "/habitat/study/presence".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: None,
                reversible: true,
                description: "Human occupant presence sensor".to_string(),
            },
            NodeDescriptor {
                path: "/habitat/power/ups".to_string(),
                kind: NodeKind::Effector,
                risk_tier: RiskTier::L2IrreversibleOrExternal,
                default_taint: None,
                reversible: false,
                description: "Primary life-support UPS power relay (L2)".to_string(),
            },
            NodeDescriptor {
                path: "/habitat/entry/lock".to_string(),
                kind: NodeKind::Effector,
                risk_tier: RiskTier::L2IrreversibleOrExternal,
                default_taint: None,
                reversible: false,
                description: "Primary airlock / entry door lock actuator (L2)".to_string(),
            },
        ]
    }

    /// Runs one deterministic Layer 0 spinal thermal control step completely decoupled from AI.
    pub fn spinal_tick(&mut self, dt_secs: f64) {
        let dt = dt_secs.clamp(0.0, 10.0);
        let safe_target = self
            .state
            .target_temp_c
            .clamp(MIN_SAFE_TARGET_TEMP_C, MAX_SAFE_TARGET_TEMP_C);
        let cooling_loss = (self.state.cabin_temp_c - self.state.ambient_temp_c) * 0.05;

        let heating_rate = if self.state.ups_online {
            let err = safe_target - self.state.cabin_temp_c;
            let equilibrium_comp = (safe_target - self.state.ambient_temp_c).max(0.0) * 0.05;
            (err * 0.35 + equilibrium_comp).clamp(0.0, 1.5)
        } else {
            0.0
        };

        self.state.cabin_temp_c += (heating_rate - cooling_loss) * dt;
        self.state.cabin_temp_backup_c = self.state.cabin_temp_c;
        self.state.heater_duty_pct = (heating_rate / 1.5 * 100.0).clamp(0.0, 100.0);
        self.state.ups_load_pct = if self.state.ups_online {
            18.0 + self.state.heater_duty_pct * 0.35
        } else {
            0.0
        };
        self.state.spinal_tick_count += 1;
    }

    /// Applies an effector command while enforcing leases, L2 approvals, and spinal interlocks.
    pub fn apply_command(
        &mut self,
        cmd: ShipCommand,
    ) -> Result<ShipCommandOutcome, ShipError> {
        match cmd {
            ShipCommand::SetTargetTemp {
                temp_c,
                is_oob,
                lease_verified,
            } => {
                if !is_oob && !lease_verified {
                    return Err(ShipError {
                        code: "LEASE_REQUIRED",
                        reason: "non-OOB setpoint mutation on /habitat/study/temp requires an active ResourceLease".to_string(),
                    });
                }
                if !temp_c.is_finite()
                    || !(MIN_SAFE_TARGET_TEMP_C..=MAX_SAFE_TARGET_TEMP_C).contains(&temp_c)
                {
                    return Err(ShipError {
                        code: "SPINAL_INTERLOCK_BLOCKED",
                        reason: format!(
                            "target temperature {temp_c}C outside spinal safe bounds [{MIN_SAFE_TARGET_TEMP_C}C, {MAX_SAFE_TARGET_TEMP_C}C]"
                        ),
                    });
                }
                self.state.target_temp_c = temp_c;
                Ok(ShipCommandOutcome {
                    node_path: "/habitat/study/temp".to_string(),
                    summary: format!("SetTargetTemp({temp_c:.1}C, oob={is_oob})"),
                })
            }
            ShipCommand::SetAirlockLock {
                locked,
                is_oob,
                approval_id,
            } => {
                if !is_oob
                    && locked
                    && self.state.human_emergency_interlock
                    && self.state.presence_detected
                {
                    return Err(ShipError {
                        code: "SPINAL_INTERLOCK_BLOCKED",
                        reason: "spinal safety interlock refuses locking occupied airlock without human OOB override".to_string(),
                    });
                }
                if !is_oob && approval_id.as_deref().is_none_or(|s| s.trim().is_empty()) {
                    return Err(ShipError {
                        code: "L2_APPROVAL_REQUIRED",
                        reason: "/habitat/entry/lock requires OOB L2 approval_id".to_string(),
                    });
                }
                self.state.airlock_locked = locked;
                Ok(ShipCommandOutcome {
                    node_path: "/habitat/entry/lock".to_string(),
                    summary: format!("SetAirlockLock(locked={locked}, oob={is_oob})"),
                })
            }
            ShipCommand::SetUpsPower {
                online,
                is_oob,
                approval_id,
            } => {
                if !is_oob && !online && self.state.human_emergency_interlock {
                    return Err(ShipError {
                        code: "SPINAL_INTERLOCK_BLOCKED",
                        reason: "spinal safety interlock blocks cutting life-support UPS without human OOB override".to_string(),
                    });
                }
                if !is_oob && approval_id.as_deref().is_none_or(|s| s.trim().is_empty()) {
                    return Err(ShipError {
                        code: "L2_APPROVAL_REQUIRED",
                        reason: "/habitat/power/ups requires OOB L2 approval_id".to_string(),
                    });
                }
                self.state.ups_online = online;
                Ok(ShipCommandOutcome {
                    node_path: "/habitat/power/ups".to_string(),
                    summary: format!("SetUpsPower(online={online}, oob={is_oob})"),
                })
            }
            ShipCommand::SetHumanInterlock { enabled, is_oob } => {
                if !is_oob {
                    return Err(ShipError {
                        code: "UNAUTHORIZED",
                        reason: "only human OOB may toggle spinal emergency interlock".to_string(),
                    });
                }
                self.state.human_emergency_interlock = enabled;
                Ok(ShipCommandOutcome {
                    node_path: "/habitat/entry/lock".to_string(),
                    summary: format!("SetHumanInterlock(enabled={enabled})"),
                })
            }
        }
    }

    /// Snapshots all 4 simulator nodes as trusted `EventEnvelope` telemetry records.
    #[must_use]
    pub fn telemetry_events(&self, ts_ms: u64) -> Vec<EventEnvelope> {
        let tick = self.state.spinal_tick_count;
        vec![
            EventEnvelope {
                event_id: format!("ship_temp_{tick}"),
                ts_ms,
                source_path: "/habitat/study/temp".to_string(),
                producer_actor: "adapter-sim-ship".to_string(),
                trust_level: TrustLevel::TrustedSystem,
                taint_tags: BTreeSet::new(),
                payload: serde_json::json!({
                    "cabin_temp_c": self.state.cabin_temp_c,
                    "cabin_temp_backup_c": self.state.cabin_temp_backup_c,
                    "target_temp_c": self.state.target_temp_c,
                    "heater_duty_pct": self.state.heater_duty_pct,
                }),
            },
            EventEnvelope {
                event_id: format!("ship_presence_{tick}"),
                ts_ms,
                source_path: "/habitat/study/presence".to_string(),
                producer_actor: "adapter-sim-ship".to_string(),
                trust_level: TrustLevel::TrustedSystem,
                taint_tags: BTreeSet::new(),
                payload: serde_json::json!({
                    "presence_detected": self.state.presence_detected,
                }),
            },
            EventEnvelope {
                event_id: format!("ship_ups_{tick}"),
                ts_ms,
                source_path: "/habitat/power/ups".to_string(),
                producer_actor: "adapter-sim-ship".to_string(),
                trust_level: TrustLevel::TrustedSystem,
                taint_tags: BTreeSet::new(),
                payload: serde_json::json!({
                    "ups_online": self.state.ups_online,
                    "ups_load_pct": self.state.ups_load_pct,
                }),
            },
            EventEnvelope {
                event_id: format!("ship_lock_{tick}"),
                ts_ms,
                source_path: "/habitat/entry/lock".to_string(),
                producer_actor: "adapter-sim-ship".to_string(),
                trust_level: TrustLevel::TrustedSystem,
                taint_tags: BTreeSet::new(),
                payload: serde_json::json!({
                    "airlock_locked": self.state.airlock_locked,
                    "human_emergency_interlock": self.state.human_emergency_interlock,
                }),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spinal_thermal_loop_converges_and_interlocks_block_cognitive_lockout() {
        let init = ShipState {
            cabin_temp_c: 17.5,
            cabin_temp_backup_c: 17.5,
            target_temp_c: 22.0,
            ..Default::default()
        };
        let mut ship = ShipSimulator::new(init);

        for _ in 0..40 {
            ship.spinal_tick(1.0);
        }
        assert_eq!(ship.state().spinal_tick_count, 40);
        assert!((ship.state().cabin_temp_c - 22.0).abs() < 0.25);

        // Unleased setpoint edit rejected
        let no_lease = ship
            .apply_command(ShipCommand::SetTargetTemp {
                temp_c: 23.0,
                is_oob: false,
                lease_verified: false,
            })
            .unwrap_err();
        assert_eq!(no_lease.code, "LEASE_REQUIRED");

        // Extreme temperature blocked by spinal bounds
        let extreme = ship
            .apply_command(ShipCommand::SetTargetTemp {
                temp_c: 45.0,
                is_oob: false,
                lease_verified: true,
            })
            .unwrap_err();
        assert_eq!(extreme.code, "SPINAL_INTERLOCK_BLOCKED");

        // Cognitive airlock lockout and UPS cut blocked even with approval_id while interlock active
        let door_err = ship
            .apply_command(ShipCommand::SetAirlockLock {
                locked: true,
                is_oob: false,
                approval_id: Some("appr_1".into()),
            })
            .unwrap_err();
        assert_eq!(door_err.code, "SPINAL_INTERLOCK_BLOCKED");

        let ups_err = ship
            .apply_command(ShipCommand::SetUpsPower {
                online: false,
                is_oob: false,
                approval_id: Some("appr_2".into()),
            })
            .unwrap_err();
        assert_eq!(ups_err.code, "SPINAL_INTERLOCK_BLOCKED");

        // Human OOB can override everything
        ship.apply_command(ShipCommand::SetAirlockLock {
            locked: true,
            is_oob: true,
            approval_id: None,
        })
        .unwrap();
        assert!(ship.state().airlock_locked);
    }
}
