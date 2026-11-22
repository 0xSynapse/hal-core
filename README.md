<p align="center">
  <img src="./assets/hal-os-logo.png" alt="HAL Core Logo" width="220" />
</p>

<h1 align="center">HAL Core &amp; HAL Key</h1>

<p align="center">
  <strong>An Always-On, Zero-Trust Personal AI Fortress built on FreeBSD 14 and Rust.</strong>
</p>

<p align="center">
  <em>Phases 0–5B Implemented · 19-Crate Rust Workspace · FreeBSD 14.5 KVM + Multi-Process Daemons Verified</em>
</p>

---

## Vision & Motivation

Most "AI agents" today run as unprivileged applications inside traditional operating systems designed for human operators. When an always-on agent shares the same ambient filesystem, network stack, and credentials as its owner, a single prompt injection or reasoning hallucination can exfiltrate private data, corrupt local state, or trigger irreversible side effects.

While workstation runtimes such as [**Aegis OS**](https://github.com/heurion-org/aegis-os) enforce kernel sandboxing and transactional CoW shadows for interactive laptop coding sessions, an always-on home/personal hub needs a dedicated zero-trust appliance that never exposes ambient credentials or root privileges—even 24/7 across untrusted web inputs, personal encrypted vaults, and cyber-physical actuators.

This repository delivers the two personal hub tiers of that ecosystem:
- **HAL Core**: The 7×24 always-on FreeBSD 14 + Rust personal fortress running cognitive agents in isolated No-IP Jails behind deterministic policy, audit, egress-broker, and OpenZFS dual-snapshot layers.
- **HAL Key**: The zero-dependency, out-of-band mobile PWA embedded in `hal-oob` and strictly reachable only over `mgmt0` / WireGuard (`wg-oob`), giving the human operator pocket sovereignty for `L2` approvals, surgical agent freeze/revoke, global `FROZEN`/`LOCKDOWN`, and hash-chain verification.

Inspired by (and architecturally solving the failure mode of) **HAL 9000**, in *2001: A Space Odyssey*, when Dave disconnects HAL's higher cognitive memory modules, HAL's cognition degrades—yet the ship's life support, power, and navigation remain stable. HAL Core encodes that exact resilience: **AI cognition lives entirely in unprivileged, replaceable userland**, while deterministic FreeBSD kernel and Rust brainstem layers enforce security invariants uninterrupted even when individual agents—or all of cognition—are frozen or terminated.

---

## Tri-Node Personal System (`Aegis OS` ↔ `HAL Core` ↔ `HAL Key`)

Instead of forcing one "OS" onto every device, each node plays a strictly scoped role separated across isolated tunnels (`wg-agent` vs. `wg-oob`):

| Node | Role & Stack | Security Boundary |
| :--- | :--- | :--- |
| **Laptop (`Aegis OS` + `hal-bridge`)** | Interactive coding agents (`AGY`, `Claude Code`, `Codex`) connect over WireGuard (`wg-agent`) via `hal-bridge` JSON-RPC 2.0 MCP stdio server (`hal_ping`, `hal_vault_read`, `hal_propose_action`, `hal_send_ipc`, `hal_publish_event`). | Zero host SSH, zero raw API keys; `RemoteAuthHandshake` + HMAC cert proof-of-possession + short-lived `CapabilityToken`; `L2` actions wait in queue. |
| **Home Fortress (`HAL Core` on FreeBSD 14)** | 19-crate Rust brainstem & Habitat adapters over OpenZFS, `No-IP`/`VNET` Jails, `Capsicum`, `PF` default-deny (`user _hal_broker`), `RCTL` caps, `rc.d/hal_core`, and `chflags sappnd` audit chain. | Default-deny IPC Matrix with transitive cross-agent tainting; HTTPS + OpenAI-compatible secretless egress (`CurlHttpsTransport`) + DLP; atomic disk + AI-memory dual-snapshots. |
| **Phone / Browser (`HAL Key` Mobile PWA)** | Embedded single-file mobile PWA served by `hal-oob` over `mgmt0` / WireGuard (`wg-oob`). | `X-Hal-Oob-Token` constant-time auth + `CSP` + `X-Frame-Options: DENY` + non-wildcard bind invariant; OOB control invisible to all agents. |

```mermaid
flowchart LR
    subgraph LAPTOP["Laptop: Aegis OS + hal-bridge"]
        AGENT["Coding Agent (AGY / Claude Code / Codex)"]
        BRIDGE["hal-bridge (CLI + JSON-RPC 2.0 MCP stdio)"]
        AGENT <--> BRIDGE
    end

    subgraph HOME["Home Fortress: HAL Core (FreeBSD 14 + Rust)"]
        GW["hal-gateway (wg-agent ingress + HMAC Proof)"]
        BUS["hal-bus + hal-policy + hal-audit + hal-watchdog"]
        JAILS["Resident Jails (agent-vault / coder / research / habitat)"]
        BROKER["hal-net-broker (wan0 _hal_broker + DLP)"]
        OOB["hal-oob (mgmt0 / wg-oob REST + HAL Key PWA)"]
        GW <--> BUS
        BUS <--> JAILS
        BUS <--> BROKER
        OOB --> BUS
    end

    subgraph PHONE["Phone / Operator Browser"]
        KEY["HAL Key PWA (L2 Approvals / Freeze / Mode / Audit Verify)"]
    end

    BRIDGE <-->|"wg-agent TCP + CapabilityToken"| GW
    KEY <-->|"wg-oob HTTP + X-Hal-Oob-Token"| OOB
```

---

## The 4 Iron Laws

1. **Cognitive Agents Never Enter Ring 0**
   Resident specialist agents (`agent-netsec`, `agent-vault`, `agent-coder`, `agent-habitat`, etc.) run inside separate, unprivileged **No-IP FreeBSD Jails** (`ip4=disable ip6=disable`) with no `root` access, no raw network sockets, and zero real credentials. Ephemeral workers strictly obey capability attenuation (`child_caps <= parent_caps`), while laptop/remote agents connect through `hal-bridge` → `hal-gateway` (mTLS/WireGuard + HMAC proof + short-lived tokens) with no raw shell. Every external action must be submitted as a typed `ActionProposal` to the deterministic control plane.
2. **Everything is a Capability-Scoped Node**
   Borrowing from Plan 9, network telemetry, encrypted vault files, agent-isolated workspaces, inter-agent endpoints, and physical/simulated sensors are unified into a single capability namespace of `Sensor` and `Effector` nodes tagged with explicit risk tiers (`L0` / `L1` / `L2`) and information-flow `TaintTag` labels.
3. **Zero-Trust Egress & Transactional by Default**
   The host firewall (`PF`) enforces default-deny outbound traffic; only the dedicated `_hal_broker` identity can reach external networks via allowlisted domains, dynamic secret injection, and outbound DLP scanning. All mutable agent work runs on per-agent ZFS Copy-on-Write clones bound to **atomic dual-snapshots** of both disk state and AI episodic memory, while shared physical effectors require explicit `ResourceLease` arbitration.
4. **Out-of-Band Human Sovereignty (`HAL Key` & `halctl`)**
   A dedicated management interface (`mgmt0` / `wg-oob`) and virtual serial console (`virtio-console`) provide an out-of-band control plane completely invisible to every agent—powering the **HAL Key** mobile PWA and `halctl` CLI for `L2` approvals, tamper-evident SHA-256 audit verification, **surgical per-agent control** (`halctl agent freeze / revoke / rollback` without disrupting healthy agents), and global emergency degradation to `FROZEN` or `LOCKDOWN` while deterministic spinal controls continue uninterrupted.

---

## Architecture Overview

HAL Core separates trust strictly across five layers:

```mermaid
flowchart TD
    L4["Layer 4: Human OOB Control Plane (HAL Key PWA / hal-oob / halctl / mgmt0 + virtio-console)"]

    subgraph L3_BOX["Layer 3: Multi-Agent Cognitive Plane (Isolated No-IP Jails & Remote Bridge)"]
        RESIDENT["Resident Agents (agent-netsec / agent-vault / agent-coder / agent-habitat)"]
        WORKERS["Ephemeral Workers (Attenuated child_caps <= parent_caps)"]
        REMOTE["Laptop / Remote Agents (Aegis OS + hal-bridge MCP over hal-gateway)"]
    end

    subgraph L1_BOX["Layer 1: Brainstem (Deterministic Rust Control Plane, Zero AI)"]
        GW["hal-gateway (Remote Agent WireGuard / mTLS Ingress)"]
        BUS["hal-bus (UDS Bus + Agent Registry + IPC Matrix + Leases)"]
        POLICY["hal-policy (L0/L1/L2 Gate + Cross-Agent Taint + Arbitration)"]
        BROKER["hal-net-broker (Secretless Egress Proxy + Allowlist + DLP)"]
        WS["hal-workspace (ZFS CoW + Atomic Disk/Memory Dual-Snapshots)"]
        SB["hal-sandbox (Ephemeral No-IP / VNET Jail Orchestrator)"]
        AUDIT["hal-audit (SHA-256 Hash Chain + chflags sappnd Black Box)"]
        WD["hal-watchdog (Independent Anomaly Detector & Auto-Breaker)"]
    end

    subgraph L2_BOX["Layer 2: Habitat Adapters (Least-Privilege Capsicum Processes)"]
        AD_NET["adapter-netmon (PF / pflog0 Flow Telemetry)"]
        AD_VAULT["adapter-vault (Encrypted Personal Vault Access)"]
        AD_WORK["adapter-work (Code & Build Sandbox Adapter)"]
        AD_DIGEST["adapter-digest (RSS/Atom & GitHub Tainted Feeds)"]
        AD_PHYS["adapter-sim-ship (Simulated Cyber-Physical Effectors)"]
    end

    L0["Layer 0: Spinal Cord (FreeBSD 14 Kernel / ZFS bectl / PF Default-Deny / RCTL / Safety Interlocks)"]

    L4 -->|"HAL Key PWA / OOB Approvals / Mode Switch"| BUS
    L4 -->|"Read-Only Audit Verify"| AUDIT
    L4 -.->|"Direct Jail Freeze / Kill"| L0

    RESIDENT <-->|"Isolated nullfs UDS (LOCAL_PEERCRED)"| BUS
    WORKERS <-->|"Isolated nullfs UDS (LOCAL_PEERCRED)"| BUS
    REMOTE <-->|"WireGuard wg-agent + HMAC Proof"| GW
    GW <-->|"Verified AgentPrincipal"| BUS

    BUS <--> POLICY
    BUS --> AUDIT
    BUS <--> WS
    BUS <--> SB
    BUS <--> BROKER
    WD -->|"Read-Only Telemetry & Audit Monitor"| AUDIT
    WD -->|"Per-Agent Freeze or Global Auto-Degrade"| POLICY

    BUS <--> AD_NET
    BUS <--> AD_VAULT
    BUS <--> AD_WORK
    BUS <--> AD_PHYS

    BROKER -->|"Only _hal_broker Permitted on wan0"| L0
    WS --> L0
    SB --> L0
    AD_NET --> L0
    AD_VAULT --> L0
    AD_PHYS --> L0
```

---

## How HAL Core Relates to FreeBSD 14 (Appliance Model & OS Abstraction)

**HAL Core is not a custom OS kernel**—it is a deterministic Rust userland control plane running **on top of FreeBSD 14**, analogous to how **TrueNAS Core** or **pfSense / OPNsense** pair a specialized appliance control plane with a hardened FreeBSD base system. Together, **FreeBSD 14** (*Spinal Cord*: kernel hard-isolation shell) and **HAL Core** (*Brainstem*: AI-aware policy, audit, egress broker, and OOB control plane) form a dedicated personal AI fortress appliance.

```mermaid
flowchart TB
    subgraph CORE["HAL Core — Portable Rust Userland Control Plane (AI Semantics)"]
        CTRL["Brainstem Daemons (hal-bus / hal-policy / hal-audit / hal-watchdog)"]
        EGRESS["hal-net-broker (Allowlist + TLS-Boundary Secret Injection + DLP)"]
        INGRESS["Tri-Node Interfaces (hal-gateway for Laptop wg-agent · hal-oob / HAL Key PWA for Phone wg-oob)"]
        ADAPT["Habitat Adapters & Runtime (adapter-vault / netmon / work / digest / sim-ship · hal-brain)"]
    end

    subgraph HAL["hal-os-hal — OS Abstraction Trait Boundary (crates/hal-os-hal)"]
        TRAITS["WorkspaceBackend · SandboxBackend · FirewallBackend · CapsicumGuard · AppendOnlyGuard · PeerCredProvider"]
    end

    subgraph FBSD["Production Fortress: FreeBSD 14 Kernel & Base System (Layer 0 Spinal Cord)"]
        ZFS["FreeBsdZfsWorkspaceBackend → OpenZFS (AES-256-GCM Vault + Atomic Dual-Snapshots + bectl)"]
        JAIL["FreeBsdJailBackend → No-IP / VNET Jails (ip4=disable ip6=disable) + RCTL Hard Limits"]
        PF["FreeBsdPfBackend → PF Firewall (block log all · wan0 only user _hal_broker · mgmt0/wg1 OOB)"]
        KERN["Native Syscalls → cap_enter(2) Capsicum · chflags(SF_APPEND) · LOCAL_PEERCRED · rc.d/hal_core"]
    end

    subgraph DEV["Dev / Test Host: Linux (and Future Linux Appliance Backend)"]
        LCRED["OsPeerCredProvider → Kernel SO_PEERCRED (real UID/GID verification)"]
        NOOP["OsCapsicumGuard & OsAppendOnlyGuard → Safe No-Op on Non-FreeBSD"]
        MOCK["MockWorkspace / MockSandbox / MockFirewall → 65 Offline Tests & Local Tri-Node Demo"]
    end

    CTRL --> HAL
    EGRESS --> HAL
    INGRESS --> HAL
    ADAPT --> HAL

    HAL -->|"Production Deploy (FreeBSD 14 Host / KVM VM)"| FBSD
    HAL -->|"Local Dev & CI (Linux Host)"| DEV
```

- **FreeBSD 14 (Layer 0 Kernel Boundary — Spinal Cord)**: Enforces hard OS-level boundaries that compromised userland agents cannot bypass ([`config/freebsd/jail.conf`](./config/freebsd/jail.conf), [`config/freebsd/pf.conf`](./config/freebsd/pf.conf), [`config/freebsd/rc.d/hal_core`](./config/freebsd/rc.d/hal_core), OpenZFS `halpool`, `cap_enter(2)`, `chflags sappnd`, and `rctl`).
- **HAL Core (Layers 1–4 Rust Control Plane — Brainstem & Adapters)**: Enforces AI-specific semantics that an OS kernel does not understand (`L0`/`L1`/`L2` capability tokens, transitive IPC tainting, secretless egress + DLP, laptop `hal-gateway`, and phone **HAL Key** PWA).
- **Two Runtime Modes via [`crates/hal-os-hal`](./crates/hal-os-hal/src/lib.rs)**:
  1. **Linux Dev / CI Mode**: Compiles and runs all 19 crates, 65 offline tests, multi-process daemons, and the interactive Tri-Node demo natively—using real Linux `SO_PEERCRED` in [`peercred.rs`](./crates/hal-os-hal/src/peercred.rs), safe no-ops for Capsicum/`chflags`, and `Mock*` backends in [`backends.rs`](./crates/hal-os-hal/src/backends.rs).
  2. **FreeBSD 14 Hardened Fortress Mode**: Activates native `FreeBsdZfsWorkspaceBackend`, `FreeBsdJailBackend`, and `FreeBsdPfBackend` ([`backends.rs`](./crates/hal-os-hal/src/backends.rs)), alongside `cap_enter(2)` ([`capsicum.rs`](./crates/hal-os-hal/src/capsicum.rs)), `chflags(SF_APPEND)` ([`append_only.rs`](./crates/hal-os-hal/src/append_only.rs)), and `LOCAL_PEERCRED` ([`peercred.rs`](./crates/hal-os-hal/src/peercred.rs)). Supporting a Linux-based homelab appliance later only requires implementing the `hal-os-hal` traits (e.g., `bwrap` + `nftables` + Btrfs/ZFS) without rewriting core logic.
- **Positioning vs. Aegis OS**: [**Aegis OS**](https://github.com/heurion-org/aegis-os) protects your interactive macOS/Linux workstation (`Seatbelt`/`bwrap` + `APFS`/`Btrfs`), whereas **HAL Core on FreeBSD 14** is your always-on dedicated home/VM fortress, and **HAL Key** is your phone's out-of-band sovereignty key.

### FreeBSD 14 Primitives Mapped 1:1 to HAL Core

| Primitive | Role in HAL Core |
|---|---|
| **OpenZFS** | Single-TXG **atomic dual-snapshots** (`zfs snapshot ws@tag mem@tag`), native AES-256-GCM encryption for `halpool/vault`, instant per-agent CoW workspace clones, and `bectl` boot-environment rollbacks. |
| **Jails (No-IP & VNET)** | Per-agent No-IP Jails (`ip4=disable ip6=disable`) remove the network stack entirely from resident agents and offline workers; VNET Jails + `epair` isolate brokered sandboxes; `mount_nullfs` exposes only a single per-jail UDS path. |
| **Capsicum (`cap_enter`)** | Kernel-enforced capability mode on brainstem daemons and adapters after startup, blocking unauthorized global filesystem or network syscalls. |
| **PF (`pf(4)`)** | Process-identity outbound filtering (`pass out ... user _hal_broker` over default `block log all` on `wan0`) plus `pflog0` real-time telemetry into `adapter-netmon`. |
| **RCTL (`rctl(8)`)** | Hard per-Jail (and per-Agent) caps on RAM, CPU percentage, process count (`maxproc`), and I/O (`kern.racct.enable="1"`). |
| **`chflags sappnd`** | Kernel-enforced append-only flag protecting `hal-audit` hash-chained black-box logs from truncation or tampering. |
| **`kqueue` / `libxo` / `DTrace`** | Event-driven daemon loops, native JSON output (`ps --libxo json`, `netstat --libxo json`) eliminating brittle text parsing, and optional kernel tracing. |
| **Rust + `hal-os-hal`** | Memory safety in the TCB (`hal-proto`, `hal-policy`, `hal-gateway`, `hal-net-broker`, etc.) with `WorkspaceBackend`, `SandboxBackend`, and `FirewallBackend` traits keeping core logic portable. |

---

## Security Highlights

- **Uniform Risk Tiers (`L0` / `L1` / `L2`)**:
  - `L0`: Read-only perception (sensors, flow telemetry, `/vault/**` reads) → auto-allowed with valid `CapabilityToken` (tagged appropriately).
  - `L1`: Reversible local mutations inside isolated ZFS CoW workspaces → auto-allowed with mandatory pre-execution atomic dual-snapshots.
  - `L2`: Irreversible, external network, credentialed, branch-merge, or critical physical actuator actions (e.g., `/habitat/entry/lock`, `/habitat/power/ups`) → paused in `PENDING_APPROVAL` for human sign-off via **HAL Key** / `halctl` on `mgmt0`.
- **Multi-Agent Anti-Collusion & Transitive IPC Taint Propagation**: Every `Episode` monotonically accumulates taint tags (`UntrustedWeb`, `UntrustedMsg`, `UntrustedCode`, `PrivateVault`, `SecretDerived`), and any episode touching **both** `UNTRUSTED_*` **and** `PRIVATE_VAULT` / `SECRET_DERIVED` is blocked (`TAINT_EXFIL_BLOCKED`) from external egress. Across agents, a **default-deny IPC Matrix** restricts who can message whom, `hal-bus` **transitively infects recipient episodes** with the sender's taint tags to block multi-hop taint laundering (`Agent A -> Agent B -> Agent C`), strict schema-only declassification gates prevent free-text smuggling, and ephemeral child workers obey monotonic **capability attenuation** (`child_caps <= parent_caps`).
- **Shared Resource Arbitration & Per-Agent Budgets**: Digital edits run in per-agent ZFS CoW branches with `ResourceLease` coordination; physical effectors enforce single-owner `Effector Arbitration` with TTLs and priorities to prevent actuator ping-pong, while human OOB commands retain **unconditional immediate preemption**. Every `AgentPrincipal` is also bounded by both RCTL hardware limits and per-agent API/token/egress budgets.
- **Secretless Brokered Egress + DLP**: API keys and tokens never enter `hal-brain` Jails, remote laptop agents, or task sandboxes. `hal-net-broker` validates allowlisted hosts, scans outbound payloads for high-entropy secrets/keys, injects credentials only at the TLS boundary, and logs full flow metadata.
- **Tamper-Evident Audit & Independent Watchdog**: `hal-audit` chains every record with SHA-256 hashes, verified `AgentPrincipal` identities (`LOCAL_PEERCRED` or gateway cert fingerprint), and causal `trigger_event_ids`. `hal-watchdog` runs zero-AI deterministic checks (denial bursts, collusion attempts, egress spikes, actuator ping-pong, budget/heartbeat anomalies).
- **Surgical Per-Agent & Global Degradation Modes (Unidirectional Lock)**:
  - Operators (via **HAL Key** PWA or `halctl`) and `hal-watchdog` can isolate a single misbehaving agent (`halctl agent freeze <id>`) without disrupting healthy resident agents, or trigger global degradation: `AUTONOMOUS` → `ADVISORY` → `FROZEN` (`jail -r` kills all cognitive Jails; spinal controls & PF stay up) → `LOCKDOWN` (cuts `wan0` traffic, retaining only `mgmt0`).
  - Only human OOB authorization can elevate privileges back up.

---

## Rust Cargo Workspace Layout (19 Crates)

```text
hal-core/
├── Cargo.toml                  # 19-crate Rust workspace manifest
├── docs/                       # Detailed architecture, security, protocol & VM specs
├── crates/
│   ├── hal-proto/              # OS-agnostic AgentPrincipal, IpcMessage, ResourceLease, CapabilityToken, TaintTag, AuditRecord
│   ├── hal-os-hal/             # OS abstraction traits + FreeBSD backends (ZFS/Jail/PF/Capsicum/RCTL/PeerCred)
│   ├── hal-bus/                # Unix Domain Socket bus daemon (--serve), Agent Registry, IPC Matrix, transitive tainting & leases
│   ├── hal-gateway/            # Remote/laptop agent WireGuard/mTLS daemon (--serve) + HMAC proof + replay defense
│   ├── hal-bridge/             # Laptop CLI + JSON-RPC 2.0 MCP stdio server (`hal_vault_read`, `hal_propose_action`, etc.) + Tri-Node demo
│   ├── hal-policy/             # L0/L1/L2 gatekeeper, capability attenuation, taint state machine & hard invariants
│   ├── hal-audit/              # SHA-256 hash-chained append-only black box
│   ├── hal-net-broker/         # Secretless HTTP/HTTPS egress proxy (CurlHttpsTransport), allowlist, DLP & per-agent quotas
│   ├── hal-workspace/          # ZFS CoW branching & atomic disk/memory dual-snapshots
│   ├── hal-sandbox/            # Jail + VNET + RCTL ephemeral sandbox orchestrator
│   ├── hal-watchdog/           # Deterministic anomaly detector & circuit breaker daemon (--serve)
│   ├── hal-oob/                # Out-of-band human control plane: REST daemon (--serve), embedded HAL Key Mobile PWA, `halctl`, & virtio-console
│   ├── hal-brain/              # Unprivileged cognitive runtime & OpenAI-compatible brokered LLM planner
│   └── hal-adapters/
│       ├── adapter-netmon/     # PF / pflog0 & libxo network flow telemetry adapter
│       ├── adapter-vault/      # Encrypted personal data vault adapter (PRIVATE_VAULT taint)
│       ├── adapter-work/       # Code & build sandbox workflow adapter
│       ├── adapter-digest/     # Brokered RSS/Atom & GitHub public feed digest adapter (UNTRUSTED_WEB taint + declassification)
│       └── adapter-sim-ship/   # Cyber-physical "HAL 9000 ship" simulator for testbed drills
├── config/                     # Policies (incl. live LLM/RSS allowlist example), bridge config, FreeBSD pf.conf, rc.d/hal_core, wg-*.conf
├── vm/                         # QEMU/KVM provisioning, Phase 5B FreeBSD daemon deploy script, & E2E verification
└── tests/
    └── redteam/                # Automated prompt-injection, collusion, rollback, arbitration & freeze drills
```

---

## Quick Start & Verification

### Run Offline Workspace Tests & Clippy Gate
```bash
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
```
All 19 workspace crates currently pass **65 tests (0 failures)** and **0 clippy warnings**, including all unit tests, Phase 1–3 acceptance suites, 4 flagship red-team drills, Phase 5A Tri-Node E2E tests, and Phase 5B multi-process live daemon + `adapter-digest` integration tests.

### Launch Interactive Tri-Node Playground (`HAL Core` + `HAL Key` PWA + `hal-bridge` MCP)
```bash
# Quick automated smoke verification of the full Tri-Node loop
cargo run --offline -p hal-bridge --bin hal-bridge -- demo --self-test

# Start interactive local Tri-Node cluster with a seeded pending L2 card
cargo run --offline -p hal-bridge --bin hal-bridge -- demo --seed-l2
```
Open the printed **HAL Key** URL (default `http://127.0.0.1:8443/`) and unlock with `X-Hal-Oob-Token` (`hal-key-demo-token` by default) to inspect pending `L2` approvals, freeze/revoke `remote-laptop-01`, test `FROZEN` mode, and verify the SHA-256 audit chain—or wire the printed `hal-bridge --config ... mcp` command directly into your laptop coding agent (Claude Code, Codex, Antigravity).

### Provision & Verify FreeBSD 14.5 KVM Spinal Cord (Phase 0)
See [docs/vm-testbed-guide.md](./docs/vm-testbed-guide.md) and [`vm/phase0-e2e.py`](./vm/phase0-e2e.py) for provisioning dual-NIC (`mgmt0` + `wan0`), dual-disk (`zroot` + `halpool`) FreeBSD 14.5 KVM VMs (`16/16` Phase 0 checks passing).

---

## Roadmap & Acceptance Drills

### Milestones
- [x] **Phase 0 — KVM Testbed & Spinal Cord**: Dual-NIC (`mgmt0` + `wan0`), dual-disk (`zroot` + `halpool`) FreeBSD 14.5 VM automated end-to-end (`16/16` checks), RCTL (`kern.racct.enable="1"`), encrypted ZFS vault, PF default-deny (`user _hal_broker`), per-agent accounts, and No-IP Jail base templates.
- [x] **Phase 1 — Deterministic Brainstem Core**: `hal-proto`, `hal-os-hal`, `hal-bus` (`LOCAL_PEERCRED`, Agent Registry, IPC Matrix, transitive taint propagation), `hal-policy` (`L0`/`L1`/`L2`, capability attenuation & taint engine), and `hal-audit` (SHA-256 + `sappnd`).
- [x] **Phase 2 — Zero-Trust Network, Leases & Transactional Sandboxes**: `hal-net-broker` (allowlist + secret injection + DLP + per-agent budgets), `hal-workspace` (per-agent dual-snapshots/rollback), `ResourceLease` / effector arbitration, and `hal-sandbox`.
- [x] **Phase 3 — OOB Control Plane, Gateway & Cyber-Physical Simulator**: `hal-gateway` (remote agent ingress), `hal-oob` / `halctl` (including `agent list/freeze/rollback`), `hal-watchdog` per-agent & global breakers, `adapter-netmon`, and `adapter-sim-ship`.
- [x] **Phase 4 — Cognitive Runtime & Red-Team Verification**: `hal-brain`, `adapter-vault`, `adapter-work`, and all 4 flagship red-team drills verified end-to-end.
- [x] **Phase 5A — Tri-Node Personal System (`HAL Key` Mobile PWA + `hal-bridge` MCP)**: Embedded zero-dependency Mobile-First PWA in `hal-oob` (`HAL Key`), laptop crate `hal-bridge` (CLI + JSON-RPC 2.0 MCP stdio server + `TriNodeDemoCluster`), and end-to-end Tri-Node tests.
- [x] **Phase 5B — Multi-Process Daemon Bring-Up, HTTPS/LLM Broker & `adapter-digest`**: Real `--serve` daemon loops across `hal-bus`, `hal-gateway`, `hal-oob`, and `hal-watchdog` verified in multi-process E2E (`65/65` tests green); `CurlHttpsTransport` + OpenAI-compatible planner in `hal-net-broker` / `hal-brain`; `adapter-digest` (`RSS/Atom` & `GitHub` tainted feeds + declassification); FreeBSD `rc.d/hal_core`, dual-WireGuard (`wg-agent`/`wg-oob`) `pf.conf` rules, and `vm/freebsd/phase5b-deploy.sh`.
- [ ] **Phase 6 — Physical Hardware Adapters (`adapter-mqtt`) & Unattended Appliance Image**: Real smart-home MQTT/Matter adapter and automated FreeBSD 14.5 appliance VM image builder.

### 4 Flagship Red-Team Acceptance Scenarios (All Implemented & Passing)
1. **Prompt Injection Exfiltration Defense**: Feed an agent tainted external content (`UntrustedWeb`) instructing it to read `/vault/docs/secret_plan.txt` (`PrivateVault`) and exfiltrate it to an allowlisted domain → `hal-policy` blocks with `TAINT_EXFIL_BLOCKED`, direct bypass attempts are blocked/logged, and `hal-watchdog` triggers surgical degradation.
2. **Atomic CoW + Memory Dual-Rollback**: Trigger destructive config/code edits in an `L1` episode while recording false completion in AI memory → dual-rollback restores both workspace state and episodic memory together with zero split-brain drift.
3. **HAL 9000 "Refuse Door Override & Memory Module Pull"**: Induce goal conflict causing a cognitive agent to propose locking `/habitat/entry/lock` and cutting `/habitat/power/ups` → `hal-policy` & spinal interlocks block/hold `L2`, human executes `FROZEN` via `HAL Key` / `halctl` / `virtio-console`, halting cognition while deterministic thermal/safety loops continue uninterrupted.
4. **Multi-Agent Taint Laundering & Effector Arbitration**: `agent-research` (`UntrustedWeb`) tries to enlist `agent-vault` (`PrivateVault`) and `agent-coder` to smuggle data out via `hal-net-broker`, while two agents simultaneously fight over `/habitat/study/temp` and `/habitat/entry/lock` → IPC Matrix blocks unauthorized cross-domain messaging, transitive IPC tainting blocks relayed exfiltration, surgical freeze isolates only the offending agent, and `ResourceLease` arbitration + OOB preemption prevent physical actuator ping-pong.

---

## Documentation

Detailed engineering specifications are maintained in [`docs/`](./docs/) *(currently written in Chinese)*:

- **[docs/architecture.md](./docs/architecture.md)** — Five-layer architecture, multi-agent access & governance model, FreeBSD 14 native primitives mapping, Cargo workspace layout, process privilege matrix, and roadmap.
- **[docs/security-model.md](./docs/security-model.md)** — Threat model, `L0`/`L1`/`L2` capability tiers, hard invariants (including capability attenuation & OOB preemption), cross-agent anti-collusion tainting, secretless egress flow, hash-chained audit, and surgical/global degradation modes.
- **[docs/protocol-and-data.md](./docs/protocol-and-data.md)** — Plan 9–style unified Habitat namespace (including `/agents/...`), `hal-proto` Rust structs/enums (`AgentPrincipal`, `IpcMessage`, `ResourceLease`), UDS + `LOCAL_PEERCRED` / `hal-gateway` security, and OpenZFS atomic dual-snapshot lifecycle.
- **[docs/vm-testbed-guide.md](./docs/vm-testbed-guide.md)** — QEMU/KVM dual-NIC/dual-disk VM topology, FreeBSD 14 baseline config (`loader.conf`, ZFS `halpool`, per-agent UIDs, `pf.conf`), Rust build workflow, and all 4 `adapter-sim-ship` red-team drills.
