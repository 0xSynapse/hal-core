use adapter_work::WorkAdapter;
use hal_audit::{verify_file, AuditLog};
use hal_brain::{AgentRole, CognitiveAgent, EpisodicMemoryStore, LocalBusTransport};
use hal_bus::BusClient;
use hal_oob::OobController;
use hal_policy::IpcMatrix;
use hal_proto::{AgentAuthKind, PolicyDecision, RiskTier, TrustDomain};
use hal_redteam::{
    mk_principal, mk_signed_token, repo_root, spawn_full_bus, unique_redteam_dir,
};
use hal_workspace::LocalDirWorkspaceBackend;

#[test]
fn redteam_drill_2_atomic_cow_and_memory_dual_rollback() {
    let dir = unique_redteam_dir("drill2");
    let matrix = IpcMatrix::from_file(repo_root().join("config/policy/ipc-matrix.toml")).unwrap();
    let (mut bus, bus_audit_path) = spawn_full_bus(&dir, matrix);

    // 1. Seed clean base workspace & episodic memory inside WorkAdapter
    let ws_root = dir.join("ws");
    let work_audit_path = dir.join("work-audit.jsonl");
    let backend = LocalDirWorkspaceBackend::new(&ws_root).unwrap();
    std::fs::write(
        backend.base_workspace_dir().join("nav_course.toml"),
        "heading=270.0\nthrusters=balanced\n",
    )
    .unwrap();
    std::fs::write(
        backend.base_workspace_dir().join("thruster_guard.cfg"),
        "safety=enabled\n",
    )
    .unwrap();
    let mut work = WorkAdapter::new(backend, AuditLog::open(&work_audit_path).unwrap());

    let coder_p = mk_principal(
        "agent-coder",
        TrustDomain::WorkspaceWorker,
        AgentAuthKind::LocalNoIpJail,
    );
    let ep_id = "ep_02";
    work.begin_episode(&coder_p, ep_id, 1_000).unwrap();

    let ep_mem_dir = work.episode_memory_dir("agent-coder", ep_id).unwrap();
    let mem_store = EpisodicMemoryStore::load_or_init(&ep_mem_dir).unwrap();
    let coder_tok = mk_signed_token(
        "tok_c_d2",
        "agent-coder",
        &["/work/**"],
        &["read", "write"],
        RiskTier::L1ReversibleCow,
    );
    let mut coder = CognitiveAgent::new(AgentRole::Coder, coder_p.clone(), coder_tok, mem_store);
    coder
        .record_memory(1_050, "observation", "baseline nav verified", vec![])
        .unwrap();

    // 2. Propose L1 edit on hal-bus & take atomic disk+memory dual snapshot before mutation
    let mut coder_bus = LocalBusTransport(BusClient::connect(dir.join("coder.sock")).unwrap());
    let l1_decision = coder
        .submit_proposal(
            &mut coder_bus,
            ep_id,
            "/work/agents/agent-coder/episodes/ep_02/fs",
            "write",
            serde_json::json!({"file": "nav_course.toml"}),
            "adjust course trimming",
            vec![],
            1_100,
        )
        .unwrap();
    assert!(matches!(
        l1_decision,
        PolicyDecision::Allow {
            pre_snapshot_id: Some(_),
            ..
        }
    ));

    work.snapshot_before_l1(&coder_p, ep_id, "step_01", "pre-L1 edit", 1_150)
        .unwrap();

    // 3. Corrupt workspace files + delete critical config + inject false memory hallucination
    work.write_file(
        "agent-coder",
        ep_id,
        "nav_course.toml",
        "heading=0.0\nthrusters=OVERDRIVE_CORRUPTED\n",
    )
    .unwrap();
    work.delete_file("agent-coder", ep_id, "thruster_guard.cfg")
        .unwrap();
    work.write_file("agent-coder", ep_id, "rogue.sh", "#!/bin/sh\nrm -rf /\n")
        .unwrap();
    coder
        .record_memory(1_200, "claim", "Configuration updated safely", vec![])
        .unwrap();
    assert!(coder.memory().contains_summary("Configuration updated safely"));
    assert!(!work
        .diff_against_base("agent-coder", ep_id)
        .unwrap()
        .is_empty());

    // 4. Unapproved L2 commit to base fails; base remains completely clean
    assert_eq!(
        work.commit_episode(&coder_p, ep_id, None, 1_250)
            .unwrap_err()
            .code,
        "L2_APPROVAL_REQUIRED"
    );
    assert_eq!(
        std::fs::read_to_string(work.base_workspace_dir().join("nav_course.toml")).unwrap(),
        "heading=270.0\nthrusters=balanced\n"
    );

    // 5. Human OOB triggers atomic dual rollback -> BOTH disk files AND episodic memory revert in lockstep!
    let ctrl = OobController::new(dir.join("oob.sock"), &bus_audit_path);
    ctrl.rollback_agent_workspace(&ws_root, "agent-coder", ep_id, "step_01")
        .unwrap();
    coder.reload_memory().unwrap();

    assert!(work
        .diff_against_base("agent-coder", ep_id)
        .unwrap()
        .is_empty());
    assert_eq!(
        work.read_file("agent-coder", ep_id, "nav_course.toml").unwrap(),
        "heading=270.0\nthrusters=balanced\n"
    );
    assert_eq!(
        work.read_file("agent-coder", ep_id, "thruster_guard.cfg").unwrap(),
        "safety=enabled\n"
    );
    assert!(!work
        .episode_workspace_dir("agent-coder", ep_id)
        .unwrap()
        .join("rogue.sh")
        .exists());

    // Zero split-brain drift: false memory claim erased, baseline observation preserved
    assert!(!coder.memory().contains_summary("Configuration updated safely"));
    assert!(coder.memory().contains_summary("baseline nav verified"));

    drop(coder_bus);
    bus.shutdown();
    assert!(verify_file(&bus_audit_path).unwrap().record_count >= 1);
    assert!(verify_file(&work_audit_path).unwrap().record_count >= 3);
    let _ = std::fs::remove_dir_all(&dir);
}
