use hal_proto::AgentPrincipal;
use std::collections::HashMap;

/// Static per-socket endpoint privilege and peer identity binding.
#[derive(Debug, Clone)]
pub struct EndpointBinding {
    pub principal: AgentPrincipal,
    pub expected_uid: Option<u32>,
    pub is_oob: bool,
    pub is_watchdog: bool,
    pub is_gateway: bool,
}

/// Active registry of authenticated HAL-OS agents.
#[derive(Debug, Default, Clone)]
pub struct AgentRegistry {
    agents: HashMap<String, AgentPrincipal>,
}

impl AgentRegistry {
    pub fn register(&mut self, principal: AgentPrincipal) {
        self.agents.insert(principal.agent_id.clone(), principal);
    }

    #[must_use]
    pub fn get(&self, agent_id: &str) -> Option<&AgentPrincipal> {
        self.agents.get(agent_id)
    }

    #[must_use]
    pub fn list(&self) -> Vec<&AgentPrincipal> {
        self.agents.values().collect()
    }
}
