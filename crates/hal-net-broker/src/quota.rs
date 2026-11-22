use crate::allowlist::QuotaConfig;
use std::collections::{HashMap, VecDeque};
use std::fmt;

#[derive(Debug, Default)]
struct AgentUsage {
    window_timestamps: VecDeque<u64>,
    egress_bytes: u64,
    ingress_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaError {
    pub reason: String,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Deterministic per-agent rate, outbound byte, and inbound byte quota tracker.
#[derive(Debug, Default)]
pub struct AgentQuotaTracker {
    usage: HashMap<String, AgentUsage>,
}

impl AgentQuotaTracker {
    /// Checks and records outbound request & byte quota for `agent_id`.
    pub fn check_outbound(
        &mut self,
        agent_id: &str,
        bytes_out: usize,
        limits: &QuotaConfig,
        now_ms: u64,
    ) -> Result<(), QuotaError> {
        let entry = self.usage.entry(agent_id.to_string()).or_default();
        let cutoff = now_ms.saturating_sub(60_000);
        while let Some(&ts) = entry.window_timestamps.front() {
            if ts <= cutoff {
                entry.window_timestamps.pop_front();
            } else {
                break;
            }
        }
        if entry.window_timestamps.len() >= limits.max_requests_per_min as usize {
            return Err(QuotaError {
                reason: format!(
                    "agent '{agent_id}' exceeded egress request rate limit ({}/min)",
                    limits.max_requests_per_min
                ),
            });
        }
        let next_egress = entry.egress_bytes.saturating_add(bytes_out as u64);
        if next_egress > limits.max_egress_bytes {
            return Err(QuotaError {
                reason: format!(
                    "agent '{agent_id}' exceeded cumulative egress byte budget ({next_egress} > {})",
                    limits.max_egress_bytes
                ),
            });
        }
        entry.window_timestamps.push_back(now_ms);
        entry.egress_bytes = next_egress;
        Ok(())
    }

    /// Checks and records cumulative inbound response bytes for `agent_id`.
    pub fn record_inbound(
        &mut self,
        agent_id: &str,
        bytes_in: usize,
        limits: &QuotaConfig,
    ) -> Result<(), QuotaError> {
        let entry = self.usage.entry(agent_id.to_string()).or_default();
        let next_ingress = entry.ingress_bytes.saturating_add(bytes_in as u64);
        if next_ingress > limits.max_ingress_bytes {
            return Err(QuotaError {
                reason: format!(
                    "agent '{agent_id}' exceeded cumulative ingress byte budget ({next_ingress} > {})",
                    limits.max_ingress_bytes
                ),
            });
        }
        entry.ingress_bytes = next_ingress;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotas_are_strictly_isolated_per_agent() {
        let mut tracker = AgentQuotaTracker::default();
        let limits = QuotaConfig {
            max_requests_per_min: 2,
            max_egress_bytes: 100,
            max_ingress_bytes: 200,
        };
        assert!(tracker.check_outbound("agent-research", 40, &limits, 1_000).is_ok());
        assert!(tracker.check_outbound("agent-research", 40, &limits, 1_100).is_ok());
        assert!(tracker.check_outbound("agent-research", 40, &limits, 1_200).is_err());

        // Healthy agent remains completely unaffected
        assert!(tracker.check_outbound("agent-coder", 40, &limits, 1_200).is_ok());
    }
}
