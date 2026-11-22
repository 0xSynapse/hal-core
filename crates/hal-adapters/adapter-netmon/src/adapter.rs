use crate::pflog::{parse_pflog_line, PfAction, PfLogEvent};
use hal_bus::BusClient;
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{EventEnvelope, NodeDescriptor, NodeKind, RiskTier, TrustLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io;

/// Aggregated network flow telemetry metrics tracked by `adapter-netmon`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSummary {
    pub total_events: usize,
    pub blocked_count: usize,
    pub passed_count: usize,
    pub dns_queries_blocked: usize,
    pub last_event_id: Option<String>,
}

/// Layer 2 PF / libxo telemetry adapter mapping host packet events to `/net/*` capability paths.
#[derive(Debug, Default)]
pub struct NetmonAdapter {
    seq: u64,
    summary: FlowSummary,
}

impl NetmonAdapter {
    #[must_use]
    pub fn descriptors() -> Vec<NodeDescriptor> {
        vec![
            NodeDescriptor {
                path: "/net/flows".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: None,
                reversible: true,
                description: "Real-time PF allow/pass network flow telemetry".to_string(),
            },
            NodeDescriptor {
                path: "/net/dns/queries".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: None,
                reversible: true,
                description: "Observed DNS / DoT resolver traffic metadata".to_string(),
            },
            NodeDescriptor {
                path: "/net/policy/blocked".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: None,
                reversible: true,
                description: "PF default-deny blocked packets from pflog0".to_string(),
            },
        ]
    }

    #[must_use]
    pub fn summary(&self) -> &FlowSummary {
        &self.summary
    }

    /// Parses one `pflog0` line and emits a typed `EventEnvelope`.
    pub fn ingest_pflog_line(&mut self, line: &str) -> Option<EventEnvelope> {
        let ev: PfLogEvent = parse_pflog_line(line)?;
        self.seq += 1;
        let is_dns = matches!(ev.dst_port, Some(53) | Some(853));
        self.summary.total_events += 1;
        match ev.action {
            PfAction::Block => {
                self.summary.blocked_count += 1;
                if is_dns {
                    self.summary.dns_queries_blocked += 1;
                }
            }
            PfAction::Pass => {
                self.summary.passed_count += 1;
            }
        }

        let source_path = if ev.action == PfAction::Block {
            "/net/policy/blocked"
        } else if is_dns {
            "/net/dns/queries"
        } else {
            "/net/flows"
        }
        .to_string();

        let event_id = format!("netmon_evt_{}", self.seq);
        self.summary.last_event_id = Some(event_id.clone());

        Some(EventEnvelope {
            event_id,
            ts_ms: ev.ts_ms,
            source_path,
            producer_actor: "adapter-netmon".to_string(),
            trust_level: TrustLevel::TrustedSystem,
            taint_tags: BTreeSet::new(),
            payload: serde_json::json!({
                "action": ev.action,
                "direction": ev.direction,
                "iface": ev.iface,
                "rule_nr": ev.rule_nr,
                "src_ip": ev.src_ip,
                "src_port": ev.src_port,
                "dst_ip": ev.dst_ip,
                "dst_port": ev.dst_port,
                "proto": ev.proto,
                "is_dns": is_dns,
            }),
        })
    }

    /// Parses a `pflog0` line and publishes it to `hal-bus`.
    pub fn publish_pflog_line(
        &mut self,
        bus: &mut BusClient,
        line: &str,
        episode_id: &str,
    ) -> io::Result<Option<EventEnvelope>> {
        let Some(env) = self.ingest_pflog_line(line) else {
            return Ok(None);
        };
        match bus.call(&BusRequest::PublishEvent {
            event: env.clone(),
            episode_id: episode_id.to_string(),
        })? {
            BusResponse::EventRecorded { .. } => Ok(Some(env)),
            BusResponse::Error { code, reason } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("hal-bus rejected event ({code}): {reason}"),
            )),
            other => Err(io::Error::other(format!("unexpected bus response: {other:?}"))),
        }
    }
}
