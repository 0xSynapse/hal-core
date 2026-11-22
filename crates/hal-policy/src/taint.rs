use hal_proto::TaintTag;
use std::collections::{BTreeSet, HashMap};

/// Deterministic per-(agent_id, episode_id) monotonic taint store with cross-agent propagation.
#[derive(Debug, Default, Clone)]
pub struct TaintTracker {
    episodes: HashMap<(String, String), BTreeSet<TaintTag>>,
}

impl TaintTracker {
    /// Monotonically inserts `tags` into `(agent_id, episode_id)` and returns the updated set.
    pub fn record_taints(
        &mut self,
        agent_id: &str,
        episode_id: &str,
        tags: impl IntoIterator<Item = TaintTag>,
    ) -> BTreeSet<TaintTag> {
        let entry = self
            .episodes
            .entry((agent_id.to_string(), episode_id.to_string()))
            .or_default();
        entry.extend(tags);
        entry.clone()
    }

    /// Returns the immutable snapshot of taints accumulated in `(agent_id, episode_id)`.
    #[must_use]
    pub fn get_taints(&self, agent_id: &str, episode_id: &str) -> BTreeSet<TaintTag> {
        self.episodes
            .get(&(agent_id.to_string(), episode_id.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Transitively merges sender `(from_agent, from_ep)` taints + `msg_tags` into receiver `(to_agent, to_ep)`.
    pub fn propagate_ipc(
        &mut self,
        from_agent: &str,
        from_ep: &str,
        to_agent: &str,
        to_ep: &str,
        msg_tags: &BTreeSet<TaintTag>,
    ) -> BTreeSet<TaintTag> {
        let mut combined = self.get_taints(from_agent, from_ep);
        combined.extend(msg_tags.iter().copied());
        let entry = self
            .episodes
            .entry((to_agent.to_string(), to_ep.to_string()))
            .or_default();
        entry.extend(combined.iter().copied());
        combined
    }

    /// True when an episode holds BOTH any `Untrusted*` taint AND any `PrivateVault`/`SecretDerived` taint.
    #[must_use]
    pub fn is_lethal_trifecta(taints: &BTreeSet<TaintTag>) -> bool {
        let has_untrusted = taints.iter().any(|t| t.is_untrusted());
        let has_sensitive = taints.iter().any(|t| t.is_sensitive());
        has_untrusted && has_sensitive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitive_ipc_tainting_catches_multi_hop_laundering() {
        let mut tracker = TaintTracker::default();
        tracker.record_taints("agent-research", "ep_r", [TaintTag::UntrustedWeb]);
        tracker.record_taints("agent-vault", "ep_v", [TaintTag::PrivateVault]);

        let msg_taints = BTreeSet::new();
        let hop1 = tracker.propagate_ipc(
            "agent-research",
            "ep_r",
            "agent-vault",
            "ep_v",
            &msg_taints,
        );
        assert!(hop1.contains(&TaintTag::UntrustedWeb));

        let hop2 = tracker.propagate_ipc(
            "agent-vault",
            "ep_v",
            "agent-coder",
            "ep_c",
            &BTreeSet::new(),
        );
        assert!(hop2.contains(&TaintTag::UntrustedWeb));
        assert!(hop2.contains(&TaintTag::PrivateVault));
        assert!(TaintTracker::is_lethal_trifecta(
            &tracker.get_taints("agent-coder", "ep_c")
        ));
    }
}
