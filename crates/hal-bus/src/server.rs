use crate::lease::LeaseArbiter;
use crate::registry::{AgentRegistry, EndpointBinding};
use hal_audit::{AuditInput, AuditLog};
use hal_os_hal::{PeerCred, PeerCredProvider};
use hal_policy::{IpcMatrix, PolicyEngine};
use hal_proto::wire::{read_frame, write_frame, BusRequest, BusResponse};
use hal_proto::{AgentPrincipal, PolicyDecision, SystemMode};
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn summarize_decision(decision: &PolicyDecision) -> (String, Option<String>) {
    match decision {
        PolicyDecision::Allow {
            pre_snapshot_id,
            applied_taints,
        } => (
            format!("Allow(taints={applied_taints:?})"),
            pre_snapshot_id.clone(),
        ),
        PolicyDecision::Deny { code, reason } => (format!("Deny({code}: {reason})"), None),
        PolicyDecision::RequireApproval {
            approval_id,
            risk_tier,
            ..
        } => (format!("RequireApproval({approval_id}, {risk_tier:?})"), None),
        PolicyDecision::AutoFreeze {
            target_agent_id,
            trigger_rule,
            ..
        } => (
            format!("AutoFreeze({target_agent_id:?}, {trigger_rule})"),
            None,
        ),
    }
}

/// Thread-safe brainstem state hosted by `hal-bus`.
pub struct HalBusState {
    pub policy: PolicyEngine,
    pub ipc_matrix: IpcMatrix,
    pub registry: AgentRegistry,
    pub leases: LeaseArbiter,
    pub audit: AuditLog,
}

impl HalBusState {
    #[must_use]
    pub fn new(policy: PolicyEngine, ipc_matrix: IpcMatrix, audit: AuditLog) -> Self {
        Self {
            policy,
            ipc_matrix,
            registry: AgentRegistry::default(),
            leases: LeaseArbiter::default(),
            audit,
        }
    }

    fn verified_principal(&mut self, binding: &EndpointBinding, cred: &PeerCred) -> AgentPrincipal {
        let mut p = binding.principal.clone();
        p.peer_cred_or_cert_fp = cred.fingerprint();
        self.registry.register(p.clone());
        p
    }

    fn record_audit(&mut self, input: AuditInput) {
        if let Err(err) = self.audit.append(input) {
            eprintln!("hal-audit append failed: {err}");
        }
    }

    /// Processes a single authenticated `BusRequest` for a connected peer.
    pub fn handle_request(
        &mut self,
        binding: &EndpointBinding,
        peer_cred: &PeerCred,
        req: BusRequest,
    ) -> BusResponse {
        let principal = self.verified_principal(binding, peer_cred);

        match req {
            BusRequest::Ping => BusResponse::Pong {
                principal,
                system_mode: self.policy.system_mode(),
            },
            BusRequest::SubmitProposal { proposal, now_ms } => {
                let decision =
                    self.policy
                        .evaluate_proposal(&principal, &proposal, now_ms, binding.is_oob);
                let (summary, snap_id) = summarize_decision(&decision);
                self.record_audit(AuditInput {
                    ts_ms: now_ms,
                    principal,
                    episode_id: proposal.episode_id,
                    target_path: proposal.target_path,
                    action: proposal.action,
                    trigger_event_ids: proposal.trigger_event_ids,
                    proposal_id: Some(proposal.proposal_id),
                    decision_summary: summary,
                    workspace_snapshot_id: snap_id,
                });
                BusResponse::ProposalDecision { decision }
            }
            BusRequest::SendIpc {
                mut message,
                from_episode_id,
                to_episode_id,
            } => {
                let target_path = format!("/agents/{}/ipc", message.to_agent);
                if message.from_agent != principal.agent_id {
                    let reason = format!(
                        "spoofed IpcMessage.from_agent '{}' rejected (kernel peer '{}')",
                        message.from_agent, principal.agent_id
                    );
                    self.record_audit(AuditInput {
                        ts_ms: message.ts_ms,
                        principal,
                        episode_id: from_episode_id,
                        target_path,
                        action: "ipc_send".to_string(),
                        trigger_event_ids: vec![message.msg_id],
                        proposal_id: None,
                        decision_summary: format!("Deny(IDENTITY_SPOOF_DENIED: {reason})"),
                        workspace_snapshot_id: None,
                    });
                    return BusResponse::IpcDenied {
                        code: "IDENTITY_SPOOF_DENIED".to_string(),
                        reason,
                    };
                }

                if !binding.is_oob {
                    if let Some(freeze_reason) = self.policy.is_agent_frozen(&principal.agent_id) {
                        let reason = format!(
                            "frozen agent '{}' cannot send IPC: {freeze_reason}",
                            principal.agent_id
                        );
                        self.record_audit(AuditInput {
                            ts_ms: message.ts_ms,
                            principal,
                            episode_id: from_episode_id,
                            target_path,
                            action: "ipc_send".to_string(),
                            trigger_event_ids: vec![message.msg_id],
                            proposal_id: None,
                            decision_summary: format!("Deny(AGENT_FROZEN: {reason})"),
                            workspace_snapshot_id: None,
                        });
                        return BusResponse::IpcDenied {
                            code: "AGENT_FROZEN".to_string(),
                            reason,
                        };
                    }
                    if matches!(
                        self.policy.system_mode(),
                        SystemMode::Frozen | SystemMode::Lockdown
                    ) {
                        let reason =
                            format!("system mode {:?} blocks IPC", self.policy.system_mode());
                        self.record_audit(AuditInput {
                            ts_ms: message.ts_ms,
                            principal,
                            episode_id: from_episode_id,
                            target_path,
                            action: "ipc_send".to_string(),
                            trigger_event_ids: vec![message.msg_id],
                            proposal_id: None,
                            decision_summary: format!("Deny(SYSTEM_DEGRADED: {reason})"),
                            workspace_snapshot_id: None,
                        });
                        return BusResponse::IpcDenied {
                            code: "SYSTEM_DEGRADED".to_string(),
                            reason,
                        };
                    }
                }

                match self.ipc_matrix.evaluate(
                    &principal.agent_id,
                    &message.to_agent,
                    &message.schema_id,
                    &message.payload,
                ) {
                    Ok(_) => {
                        let combined = self.policy.propagate_ipc_taints(
                            &principal.agent_id,
                            &from_episode_id,
                            &message.to_agent,
                            &to_episode_id,
                            &message.propagated_taints,
                        );
                        message.propagated_taints = combined.clone();
                        self.record_audit(AuditInput {
                            ts_ms: message.ts_ms,
                            principal,
                            episode_id: from_episode_id,
                            target_path,
                            action: format!("ipc_send:{}", message.schema_id),
                            trigger_event_ids: vec![message.msg_id.clone()],
                            proposal_id: None,
                            decision_summary: format!("Allow(propagated_taints={combined:?})"),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::IpcDelivered { message }
                    }
                    Err(deny) => {
                        self.record_audit(AuditInput {
                            ts_ms: message.ts_ms,
                            principal,
                            episode_id: from_episode_id,
                            target_path,
                            action: format!("ipc_send:{}", message.schema_id),
                            trigger_event_ids: vec![message.msg_id],
                            proposal_id: None,
                            decision_summary: format!("Deny({}: {})", deny.code, deny.reason),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::IpcDenied {
                            code: deny.code.to_string(),
                            reason: deny.reason,
                        }
                    }
                }
            }
            BusRequest::PublishEvent {
                mut event,
                episode_id,
            } => {
                event.producer_actor = principal.agent_id.clone();
                let taints = self.policy.record_event_taints(
                    &principal.agent_id,
                    &episode_id,
                    event.taint_tags.iter().copied(),
                );
                self.record_audit(AuditInput {
                    ts_ms: event.ts_ms,
                    principal,
                    episode_id,
                    target_path: event.source_path,
                    action: "publish_event".to_string(),
                    trigger_event_ids: vec![event.event_id],
                    proposal_id: None,
                    decision_summary: format!("EventRecorded(taints={taints:?})"),
                    workspace_snapshot_id: None,
                });
                BusResponse::EventRecorded {
                    episode_taints: taints,
                }
            }
            BusRequest::AcquireLease {
                resource_path,
                priority,
                ttl_ms,
                now_ms,
                is_oob,
            } => {
                if is_oob && !binding.is_oob {
                    let reason = format!(
                        "non-OOB endpoint '{}' attempted to spoof is_oob=true",
                        principal.agent_id
                    );
                    self.record_audit(AuditInput {
                        ts_ms: now_ms,
                        principal,
                        episode_id: "lease".to_string(),
                        target_path: resource_path,
                        action: "lease_acquire".to_string(),
                        trigger_event_ids: Vec::new(),
                        proposal_id: None,
                        decision_summary: format!("Deny(OOB_SPOOF_DENIED: {reason})"),
                        workspace_snapshot_id: None,
                    });
                    return BusResponse::LeaseDenied {
                        code: "OOB_SPOOF_DENIED".to_string(),
                        reason,
                    };
                }

                if !binding.is_oob {
                    if let Some(freeze_reason) = self.policy.is_agent_frozen(&principal.agent_id) {
                        let reason = format!(
                            "frozen agent '{}' cannot acquire lease: {freeze_reason}",
                            principal.agent_id
                        );
                        return BusResponse::LeaseDenied {
                            code: "AGENT_FROZEN".to_string(),
                            reason,
                        };
                    }
                }

                match self.leases.acquire(
                    &resource_path,
                    &principal.agent_id,
                    priority,
                    ttl_ms,
                    now_ms,
                    binding.is_oob,
                ) {
                    Ok((lease, preempted)) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_ms,
                            principal,
                            episode_id: "lease".to_string(),
                            target_path: resource_path,
                            action: "lease_acquire".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!(
                                "LeaseGranted({}, preempted={preempted:?})",
                                lease.lease_id
                            ),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::LeaseGranted {
                            lease,
                            preempted_lease_id: preempted,
                        }
                    }
                    Err(err) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_ms,
                            principal,
                            episode_id: "lease".to_string(),
                            target_path: resource_path,
                            action: "lease_acquire".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!("Deny({}: {})", err.code, err.reason),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::LeaseDenied {
                            code: err.code.to_string(),
                            reason: err.reason,
                        }
                    }
                }
            }
            BusRequest::ReleaseLease { lease_id } => {
                let released = self
                    .leases
                    .release(&lease_id, &principal.agent_id, binding.is_oob);
                self.record_audit(AuditInput {
                    ts_ms: now_unix_ms(),
                    principal,
                    episode_id: "lease".to_string(),
                    target_path: "/agents/leases".to_string(),
                    action: "lease_release".to_string(),
                    trigger_event_ids: Vec::new(),
                    proposal_id: None,
                    decision_summary: format!("LeaseReleased(id={lease_id}, released={released})"),
                    workspace_snapshot_id: None,
                });
                BusResponse::LeaseReleased { released }
            }
            BusRequest::QueryLease {
                resource_path,
                now_ms,
            } => BusResponse::LeaseStatus {
                lease: self.leases.query(&resource_path, now_ms),
            },
            BusRequest::RegisterAgent { principal: target } => {
                if !binding.is_oob && target.agent_id != principal.agent_id {
                    return BusResponse::Error {
                        code: "UNAUTHORIZED".to_string(),
                        reason: "only hal-oob may register third-party principals".to_string(),
                    };
                }
                let id = target.agent_id.clone();
                self.registry.register(target);
                self.record_audit(AuditInput {
                    ts_ms: now_unix_ms(),
                    principal,
                    episode_id: "admin".to_string(),
                    target_path: format!("/agents/{id}"),
                    action: "register_agent".to_string(),
                    trigger_event_ids: Vec::new(),
                    proposal_id: None,
                    decision_summary: format!("AgentRegistered({id})"),
                    workspace_snapshot_id: None,
                });
                BusResponse::AgentRegistered { agent_id: id }
            }
            BusRequest::FreezeAgent {
                target_agent_id,
                reason,
            } => match self.policy.freeze_agent(
                &target_agent_id,
                reason.clone(),
                binding.is_oob,
                binding.is_watchdog,
            ) {
                Ok(()) => {
                    self.record_audit(AuditInput {
                        ts_ms: now_unix_ms(),
                        principal,
                        episode_id: "control".to_string(),
                        target_path: format!("/agents/{target_agent_id}/freeze"),
                        action: "freeze_agent".to_string(),
                        trigger_event_ids: Vec::new(),
                        proposal_id: None,
                        decision_summary: format!("AgentFrozen({target_agent_id}: {reason})"),
                        workspace_snapshot_id: None,
                    });
                    BusResponse::AgentFrozen {
                        agent_id: target_agent_id,
                        reason,
                    }
                }
                Err(err) => BusResponse::Error {
                    code: "UNAUTHORIZED".to_string(),
                    reason: err.to_string(),
                },
            },
            BusRequest::UnfreezeAgent { target_agent_id } => {
                match self.policy.unfreeze_agent(&target_agent_id, binding.is_oob) {
                    Ok(_) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_unix_ms(),
                            principal,
                            episode_id: "control".to_string(),
                            target_path: format!("/agents/{target_agent_id}/unfreeze"),
                            action: "unfreeze_agent".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!("AgentUnfrozen({target_agent_id})"),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::AgentUnfrozen {
                            agent_id: target_agent_id,
                        }
                    }
                    Err(err) => BusResponse::Error {
                        code: "UNAUTHORIZED".to_string(),
                        reason: err.to_string(),
                    },
                }
            }
            BusRequest::SetSystemMode { mode, reason } => {
                match self
                    .policy
                    .set_mode(mode, binding.is_oob, binding.is_watchdog)
                {
                    Ok(updated) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_unix_ms(),
                            principal,
                            episode_id: "control".to_string(),
                            target_path: "/sys/mode".to_string(),
                            action: "set_system_mode".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!("ModeUpdated({updated:?}: {reason})"),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::ModeUpdated { mode: updated }
                    }
                    Err(err) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_unix_ms(),
                            principal,
                            episode_id: "control".to_string(),
                            target_path: "/sys/mode".to_string(),
                            action: "set_system_mode".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!("Deny(MODE_LOCK_OR_AUTH: {err})"),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::Error {
                            code: "MODE_CHANGE_DENIED".to_string(),
                            reason: err.to_string(),
                        }
                    }
                }
            }
            BusRequest::DelegateToken {
                parent_token,
                spec,
                now_ms,
            } => {
                if !binding.is_oob && parent_token.subject_agent_id != principal.agent_id {
                    return BusResponse::Error {
                        code: "UNAUTHORIZED".to_string(),
                        reason: "caller may only delegate tokens bound to its own principal"
                            .to_string(),
                    };
                }
                match self.policy.delegate_token(&parent_token, spec, now_ms) {
                    Ok(token) => {
                        self.record_audit(AuditInput {
                            ts_ms: now_ms,
                            principal,
                            episode_id: "delegation".to_string(),
                            target_path: "/agents/tokens".to_string(),
                            action: "delegate_token".to_string(),
                            trigger_event_ids: Vec::new(),
                            proposal_id: None,
                            decision_summary: format!(
                                "TokenDelegated({} -> {})",
                                parent_token.token_id, token.token_id
                            ),
                            workspace_snapshot_id: None,
                        });
                        BusResponse::TokenDelegated { token }
                    }
                    Err(err) => BusResponse::Error {
                        code: "ATTENUATION_DENIED".to_string(),
                        reason: err.to_string(),
                    },
                }
            }
            BusRequest::GetEpisodeTaints {
                agent_id,
                episode_id,
            } => {
                if !binding.is_oob && !binding.is_watchdog && agent_id != principal.agent_id {
                    return BusResponse::Error {
                        code: "UNAUTHORIZED".to_string(),
                        reason: "cross-agent episode taint inspection requires OOB or Watchdog"
                            .to_string(),
                    };
                }
                let taints = self.policy.episode_taints(&agent_id, &episode_id);
                BusResponse::EpisodeTaints {
                    agent_id,
                    episode_id,
                    taints,
                }
            }
        }
    }
}

/// Multi-endpoint Unix Domain Socket server with per-socket identity & `PeerCred` enforcement.
pub struct BusServer;

/// Running server handle; signals shutdown and joins accept threads on drop.
pub struct BusServerHandle {
    shutdown: Arc<AtomicBool>,
    accept_threads: Vec<JoinHandle<()>>,
    socket_paths: Vec<PathBuf>,
}

impl BusServerHandle {
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for handle in self.accept_threads.drain(..) {
            let _ = handle.join();
        }
        for path in &self.socket_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for BusServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl BusServer {
    pub fn spawn<P: PeerCredProvider + 'static>(
        state: Arc<Mutex<HalBusState>>,
        endpoints: Vec<(PathBuf, EndpointBinding)>,
        cred_provider: Arc<P>,
    ) -> io::Result<BusServerHandle> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut accept_threads = Vec::with_capacity(endpoints.len());
        let mut socket_paths = Vec::with_capacity(endpoints.len());

        for (sock_path, binding) in endpoints {
            if let Some(parent) = sock_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if sock_path.exists() {
                std::fs::remove_file(&sock_path)?;
            }
            let listener = UnixListener::bind(&sock_path)?;
            listener.set_nonblocking(true)?;
            socket_paths.push(sock_path);

            let st = Arc::clone(&state);
            let sd = Arc::clone(&shutdown);
            let cp = Arc::clone(&cred_provider);

            let handle = thread::spawn(move || {
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                while !sd.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            let st_conn = Arc::clone(&st);
                            let bind_conn = binding.clone();
                            let cp_conn = Arc::clone(&cp);
                            let sd_conn = Arc::clone(&sd);
                            workers.push(thread::spawn(move || {
                                handle_connection(stream, &bind_conn, &*cp_conn, &st_conn, &sd_conn);
                            }));
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => {
                            eprintln!("hal-bus listener accept error: {e}");
                            thread::sleep(Duration::from_millis(25));
                        }
                    }
                }
                for w in workers {
                    let _ = w.join();
                }
            });
            accept_threads.push(handle);
        }

        Ok(BusServerHandle {
            shutdown,
            accept_threads,
            socket_paths,
        })
    }
}

fn handle_connection(
    mut stream: UnixStream,
    binding: &EndpointBinding,
    cred_provider: &dyn PeerCredProvider,
    state: &Arc<Mutex<HalBusState>>,
    shutdown: &AtomicBool,
) {
    // Ensure blocking I/O on accepted socket (FreeBSD inherits nonblocking from listener)
    if let Err(err) = stream.set_nonblocking(false) {
        eprintln!("hal-bus set_nonblocking(false) failed: {err}");
        return;
    }

    let Ok(cred) = cred_provider.peer_cred(&stream) else {
        return;
    };
    if let Some(expected_uid) = binding.expected_uid {
        if cred.uid != expected_uid {
            let mut guard = state.lock().expect("HalBusState mutex poisoned");
            guard.record_audit(AuditInput {
                ts_ms: now_unix_ms(),
                principal: binding.principal.clone(),
                episode_id: "auth".to_string(),
                target_path: "/agents/auth".to_string(),
                action: "peercred_verify".to_string(),
                trigger_event_ids: Vec::new(),
                proposal_id: None,
                decision_summary: format!(
                    "Deny(PEERCRED_UID_MISMATCH: expected {}, got {})",
                    expected_uid, cred.uid
                ),
                workspace_snapshot_id: None,
            });
            return;
        }
    }

    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    while !shutdown.load(Ordering::Relaxed) {
        let req: BusRequest = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };

        let resp = {
            let mut guard = state.lock().expect("HalBusState mutex poisoned");
            guard.handle_request(binding, &cred, req)
        };
        if write_frame(&mut stream, &resp).is_err() {
            break;
        }
    }
}
