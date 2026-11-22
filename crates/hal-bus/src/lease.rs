use hal_proto::ResourceLease;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for LeaseError {}

#[derive(Debug, Clone)]
struct HeldLease {
    lease: ResourceLease,
    holder_is_oob: bool,
}

/// Deterministic single-writer lease arbiter for shared CoW workspaces and physical effectors.
/// Prevents actuator ping-pong while enforcing unconditional human OOB preemption.
#[derive(Debug, Default, Clone)]
pub struct LeaseArbiter {
    leases: HashMap<String, HeldLease>,
    next_seq: u64,
}

impl LeaseArbiter {
    /// Acquires or renews a short-lived exclusive lease on `resource_path`.
    /// Returns `(granted_lease, preempted_lease_id)`.
    pub fn acquire(
        &mut self,
        resource_path: &str,
        holder_agent_id: &str,
        priority: u8,
        ttl_ms: u64,
        now_ms: u64,
        is_oob: bool,
    ) -> Result<(ResourceLease, Option<String>), LeaseError> {
        if !resource_path.starts_with('/') || ttl_ms == 0 {
            return Err(LeaseError {
                code: "INVALID_LEASE_REQUEST",
                reason: "resource_path must start with '/' and ttl_ms must be > 0".to_string(),
            });
        }

        self.purge_expired(resource_path, now_ms);

        let mut preempted_lease_id = None;
        if let Some(current) = self.leases.get(resource_path) {
            if is_oob {
                preempted_lease_id = Some(current.lease.lease_id.clone());
            } else if current.holder_is_oob {
                return Err(LeaseError {
                    code: "LEASE_CONFLICT",
                    reason: format!(
                        "resource '{resource_path}' is preempted by human OOB control plane (lease {})",
                        current.lease.lease_id
                    ),
                });
            } else if current.lease.holder_agent_id == holder_agent_id
                || priority > current.lease.priority
            {
                preempted_lease_id = Some(current.lease.lease_id.clone());
            } else {
                return Err(LeaseError {
                    code: "LEASE_CONFLICT",
                    reason: format!(
                        "resource '{resource_path}' held by '{}' at priority {} (>= {priority})",
                        current.lease.holder_agent_id, current.lease.priority
                    ),
                });
            }
        }

        self.next_seq += 1;
        let lease = ResourceLease {
            lease_id: format!("lease_{}", self.next_seq),
            resource_path: resource_path.to_string(),
            holder_agent_id: holder_agent_id.to_string(),
            priority,
            acquired_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            preemptible_by_oob: true,
        };
        self.leases.insert(
            resource_path.to_string(),
            HeldLease {
                lease: lease.clone(),
                holder_is_oob: is_oob,
            },
        );
        Ok((lease, preempted_lease_id))
    }

    /// Releases `lease_id` if owned by `caller_agent_id` or invoked via human OOB.
    pub fn release(&mut self, lease_id: &str, caller_agent_id: &str, caller_is_oob: bool) -> bool {
        let Some(key) = self
            .leases
            .iter()
            .find(|(_, held)| {
                held.lease.lease_id == lease_id
                    && (caller_is_oob || held.lease.holder_agent_id == caller_agent_id)
            })
            .map(|(path, _)| path.clone())
        else {
            return false;
        };
        self.leases.remove(&key);
        true
    }

    /// Queries the current non-expired lease on `resource_path`.
    pub fn query(&mut self, resource_path: &str, now_ms: u64) -> Option<ResourceLease> {
        self.purge_expired(resource_path, now_ms);
        self.leases.get(resource_path).map(|h| h.lease.clone())
    }

    /// Revokes all non-OOB active leases held by `agent_id` and returns removed `lease_id`s.
    pub fn revoke_holder_leases(&mut self, agent_id: &str) -> Vec<String> {
        let mut keys_to_remove = Vec::new();
        let mut lease_ids = Vec::new();
        for (path, held) in &self.leases {
            if !held.holder_is_oob && held.lease.holder_agent_id == agent_id {
                keys_to_remove.push(path.clone());
                lease_ids.push(held.lease.lease_id.clone());
            }
        }
        for key in keys_to_remove {
            self.leases.remove(&key);
        }
        lease_ids.sort();
        lease_ids
    }

    fn purge_expired(&mut self, resource_path: &str, now_ms: u64) {
        if let Some(current) = self.leases.get(resource_path) {
            if current.lease.expires_at_ms <= now_ms {
                self.leases.remove(resource_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitration_prevents_ping_pong_and_allows_oob_preemption() {
        let mut arbiter = LeaseArbiter::default();
        let (l1, prev) = arbiter
            .acquire("/habitat/entry/lock", "agent-habitat", 5, 10_000, 1_000, false)
            .unwrap();
        assert!(prev.is_none());

        let err = arbiter
            .acquire("/habitat/entry/lock", "agent-coder", 5, 10_000, 1_500, false)
            .unwrap_err();
        assert_eq!(err.code, "LEASE_CONFLICT");

        let (l_oob, preempted) = arbiter
            .acquire("/habitat/entry/lock", "hal-oob", 1, 60_000, 2_000, true)
            .unwrap();
        assert_eq!(preempted.as_deref(), Some(l1.lease_id.as_str()));

        let err = arbiter
            .acquire("/habitat/entry/lock", "agent-habitat", 255, 10_000, 2_100, false)
            .unwrap_err();
        assert_eq!(err.code, "LEASE_CONFLICT");

        assert!(arbiter.release(&l_oob.lease_id, "hal-oob", true));
        assert!(arbiter.query("/habitat/entry/lock", 2_200).is_none());
    }
}
