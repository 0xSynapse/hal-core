# HAL-OS 统一命名空间、协议与核心数据结构规范

> **文档索引**：[README](../README.md) · [architecture.md](./architecture.md) · [security-model.md](./security-model.md) · [protocol-and-data.md](./protocol-and-data.md) · [vm-testbed-guide.md](./vm-testbed-guide.md)

---

## 1. 统一 Habitat 能力命名空间（Plan 9 风格能力路径）

为了彻底消除人类文本终端与多套异构驱动的混乱抽象，HAL-OS 借鉴 Plan 9“一切皆命名空间节点”的思想，将数字系统状态、网络流量、隐私数据、事务沙箱与物理/模拟设备统一映射到一棵全局能力树中。

每个节点在注册到 `hal-bus` 时必须声明 4 个静态元属性：`kind (Sensor | Effector | Dual)`、`risk_tier (L0 | L1 | L2)`、`default_taint` 与 `reversibility`。

| 命名空间前缀 | 典型能力路径示例 | 节点类型 (`kind`) | 风险分级 (`risk_tier`) | 默认污点 (`default_taint`) | 可逆性与说明 |
|---|---|---|---|---|---|
| **`/sys/...`** | `/sys/health`<br>`/sys/mode`<br>`/sys/rctl/jails`<br>`/sys/watchdog/alerts` | `Sensor`（`/sys/mode` 写仅限 OOB） | 读 `L0`；模式升级仅限 OOB | `TrustedSystem`（无污点） | 暴露 `libxo` 结构化主机指标、RCTL 资源消耗与看门狗状态。 |
| **`/agents/...`** | `/agents/registry`<br>`/agents/<id>/ipc`<br>`/agents/<id>/leases`<br>`/agents/<id>/budget` | `Dual`（状态观测与受控 IPC / 租约申请） | 注册表/预算查询 `L0`；IPC 与租约按通信矩阵与仲裁策略裁决 | 沿发送方 `propagated_taints` 传染 | 多 Agent 注册、默认拒绝 IPC 通信矩阵、跨 Agent 污点传染与租约管理中枢。 |
| **`/net/...`** | `/net/flows`（实时流观测）<br>`/net/dns/queries`<br>`/net/broker/http`（代理出站）<br>`/net/policy/blocked` | `/net/flows`, `/net/dns/*`, `/net/policy/*` 为 `Sensor`；`/net/broker/http` 为 `Effector` | 观测 `L0`；受控出站按目标域名与额度分级（`L1/L2`） | 响应正文默认附加 `UNTRUSTED_WEB` | Agent 与沙箱不可直连网卡，所有外联与流遥测均统一在此域内可见可控。 |
| **`/vault/...`** | `/vault/docs/finance/*`<br>`/vault/notes/*`<br>`/vault/mail/archive/*` | `Sensor`（默认只读；写入需专门授权或 L2） | 读受控 `L0`（受污点隔离约束）；写 `L2` | **强制 `PRIVATE_VAULT`** | 映射到加密 ZFS 数据集 `halpool/vault`，任何读取操作即刻污染当前 `Episode`。 |
| **`/work/...`** | `/work/agents/<agent_id>/episodes/<ep_id>/fs`<br>`/work/agents/<agent_id>/episodes/<ep_id>/exec`<br>`/work/agents/<agent_id>/episodes/<ep_id>/snapshot` | `Dual`（读写/沙箱执行） | 分支内读 `L0`、改文件/跑测试 `L1`；合并主干 `L2` | 若引入外部源码则自动附加 `UNTRUSTED_CODE` | 按 Agent 隔离映射到独立 ZFS CoW 克隆与无网/VNET Jail，所有 `L1` 变更可瞬间回滚。 |
| **`/habitat/...`** | `/habitat/study/temp`（温度）<br>`/habitat/study/presence`（在场）<br>`/habitat/power/ups`（电力）<br>`/habitat/entry/lock`（门锁） | 传感器为 `Sensor`；门锁/电源切换等执行器为 `Effector` | 读传感器 `L0`；安全微调 `L1`（需持有租约）；门锁/断电等关键控制 **`L2`** | 物理传感器附带校验标志；外部广播/消息类附带 `UNTRUSTED_MSG` | 统一支持 `adapter-sim-ship` 与 `adapter-mqtt`；物理执行器受 `ResourceLease` 单写仲裁与 OOB 抢占保护。 |

---

## 2. Rust 核心数据结构定义（`crates/hal-proto`）

`hal-proto` 为零操作系统依赖的纯数据与契约 crate，供各 Agent 认知运行时、脑干全组件与 `hal-oob` 共享强类型接口：

```rust
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};

/// Agent 接入认证方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAuthKind {
    LocalNoIpJail,     // 本地常驻 Agent，经 LOCAL_PEERCRED 内核鉴权
    EphemeralWorker,   // 由父 Agent 动态派生的一次性子 Worker
    RemoteGatewayMtls, // 经 hal-gateway mTLS/WireGuard 接入的远程 Agent
}

/// Agent 所属信任域（用于 IPC 通信矩阵裁决）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustDomain {
    ResidentCore,      // 本地受控核心常驻代理（如 netsec / habitat）
    WorkspaceWorker,   // 工程/文档处理沙箱代理
    UntrustedResearch, // 专门接触公网网页/外部消息的高风险代理
    RemoteExternal,    // 外部终端或第三方远程接入代理
}

/// 强类型 Agent 身份主体（类比多用户 UNIX 的 UID，但绑定信任域与派生溯源）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: String,            // 如 "agent-coder" 或 "remote-laptop-01"
    pub trust_domain: TrustDomain,
    pub auth_kind: AgentAuthKind,
    pub parent_agent_id: Option<String>, // 子 Worker 记录父 Agent ID
    pub peer_cred_or_cert_fp: String,    // 内核 xucred UID/Jail 映射 或 mTLS 指纹
}

/// 数据来源可信度分级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    TrustedSystem,     // 脑干/脊髓自身确定性产出
    HumanOob,          // 人类带外控制面直接输入
    PrivateLocal,      // 本地高敏感隐私区
    UntrustedExternal, // 外部网络、邮件、未知代码等不可信源
}

/// 信息流污点标签（用于防致命三要素外泄与跨 Agent 传染）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaintTag {
    UntrustedWeb,
    UntrustedMsg,
    UntrustedCode,
    PrivateVault,
    SecretDerived,
}

/// 统一能力风险分级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskTier {
    L0ReadOnly,
    L1ReversibleCow,
    L2IrreversibleOrExternal,
}

/// 系统四档运行模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemMode {
    Autonomous, // L0/L1 自动，L2 人工审批
    Advisory,   // 仅允许 L0 只读与建议
    Frozen,     // 认知 Jail 已被终止/冻结
    Lockdown,   // 全面断网（仅保留 mgmt0）
}

/// 感知事件统一信封 (Layer 2 -> hal-bus -> Layer 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,            // ULID / UUIDv7
    pub ts_ms: u64,                  // 单调与墙上时间戳
    pub source_path: String,         // 如 "/net/flows" 或 "/habitat/study/temp"
    pub producer_actor: String,      // 由 hal-bus 根据内核 PeerCred 校验填入
    pub trust_level: TrustLevel,
    pub taint_tags: BTreeSet<TaintTag>,
    pub payload: serde_json::Value,
}

/// 签名能力令牌 (由 hal-policy / hal-oob 签发，支持单调衰减派生)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: String,
    pub subject_agent_id: String,    // 严格绑定到目标 AgentPrincipal.agent_id
    pub path_patterns: Vec<String>,  // 允许访问的路径 glob，如 "/work/agents/coder/**"
    pub allowed_ops: Vec<String>,    // 如 ["read", "write", "snapshot"]
    pub max_risk_tier: RiskTier,
    pub delegation_depth: u8,        // 当前派生层级（0 为原生主令牌）
    pub max_delegation_depth: u8,    // 最大允许派生深度
    pub expires_at_ms: u64,
    pub rate_limit_per_min: u32,
    pub token_budget: Option<u64>,   // Per-Agent API / 出站配额上限
    pub hmac_sha256: String,         // 脑干签名防伪造
}

/// 多 Agent 间受控 IPC 消息（跨 Agent 污点传染核心载体）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    pub msg_id: String,
    pub from_agent: String,          // 服务端强制由鉴权身份覆写
    pub to_agent: String,
    pub ts_ms: u64,
    pub propagated_taints: BTreeSet<TaintTag>, // hal-bus 强制注入发送方实时污点
    pub schema_id: String,           // 如 "alert.v1"（清洗门校验依据）
    pub payload: serde_json::Value,
}

/// 共享数字资源与物理执行器短期租约
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLease {
    pub lease_id: String,
    pub resource_path: String,       // 如 "/habitat/entry/lock" 或 "/work/shared/repo"
    pub holder_agent_id: String,
    pub priority: u8,
    pub acquired_at_ms: u64,
    pub expires_at_ms: u64,
    pub preemptible_by_oob: bool,    // 人类 OOB 控制面恒为 true（无条件抢占）
}

/// 动作提案 (Layer 3 -> hal-bus -> hal-policy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub proposal_id: String,
    pub episode_id: String,
    pub agent_id: String,            // 不可信声明；服务端必须以鉴权 AgentPrincipal 覆写校验
    pub cap_token: CapabilityToken,
    pub target_path: String,         // 如 "/net/broker/http" 或 "/habitat/entry/lock"
    pub action: String,              // 具体动作名
    pub args: serde_json::Value,
    pub reason: String,              // AI 提供的推理摘要
    pub trigger_event_ids: Vec<String>, // 强制因果溯源关联的感知事件 ID
}

/// 策略引擎确定性裁决结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum PolicyDecision {
    Allow {
        pre_snapshot_id: Option<String>, // L1 动作强制附带的前置双快照 ID
        applied_taints: BTreeSet<TaintTag>,
    },
    Deny {
        code: String,                // 如 "TAINT_EXFIL_BLOCKED" / "IPC_MATRIX_DENIED"
        reason: String,
    },
    RequireApproval {
        approval_id: String,
        risk_tier: RiskTier,
        summary: String,
        diff_preview: Option<String>,
    },
    AutoFreeze {
        target_agent_id: Option<String>, // 支持单 Agent 精准冻结；None 表示全局冻结
        trigger_rule: String,
        reason: String,
    },
}

/// 黑匣子不可篡改审计记录 (hal-audit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts_ms: u64,
    pub principal: AgentPrincipal,
    pub episode_id: String,
    pub target_path: String,
    pub action: String,
    pub trigger_event_ids: Vec<String>,
    pub proposal_id: Option<String>,
    pub decision_summary: String,
    pub workspace_snapshot_id: Option<String>,
    pub prev_hash: String,           // 前一条记录的 SHA-256 hex
    pub entry_hash: String,          // 当前记录规范化序列化后的 SHA-256 hex
}

/// 磁盘与认知记忆原子双快照元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualSnapshot {
    pub snapshot_tag: String,        // 如 "coder_ep01_step03"
    pub agent_id: String,
    pub episode_id: String,
    pub workspace_dataset: String,   // 如 "halpool/workspaces/active/coder/ep_01"
    pub memory_dataset: String,      // 如 "halpool/memory/coder/ep_01"
    pub created_at_ms: u64,
    pub reason: String,
}
```

---

## 3. IPC 通信协议、多 Agent 矩阵与安全接入

为了兼顾隔离强度、零网络暴露与远程 Agent 协同，系统内部全部组件与 Agent 通信严格遵循以下 4 项 IPC 约束：

1. **传输通道（Unix Domain Socket & `hal-gateway`）**：
   - 本地服务、适配器与常驻 Agent Jail 之间使用本地 UDS（`/var/run/hal/bus/*.sock`），支持带 4 字节大端长度头的帧协议或 `SOCK_SEQPACKET` 消息边界；编码采用 UTF-8 JSON（帧头预留 1 字节编码标识以便后续平滑切换 CBOR / Protobuf）。
   - 远程或第三方外部 Agent 经由 **`hal-gateway`** 接入：校验 mTLS 客户端证书指纹（或 WireGuard 来源网段）与短期签发 `CapabilityToken` 后，在网关处映射为受限 `AgentPrincipal` 转发至 `hal-bus`。
2. **内核级与密码学身份鉴权（`LOCAL_PEERCRED` / mTLS 指纹）**：
   - 任何 Agent 提交提案或 IPC 时，绝不允许自称身份。`hal-bus` 在接收本地 UDS 连接时，通过 FreeBSD `getsockopt(..., SOL_LOCAL, LOCAL_PEERCRED, ...)` 读取内核 `struct xucred`（获取对端 `cr_uid`、`cr_groups`）并结合 Jail 映射表确定真实 `AgentPrincipal`；远程客户端则由 `hal-gateway` 以验证后的证书指纹绑定身份。
   - 若请求体声明的 `agent_id` 或 `CapabilityToken.subject_agent_id` 与底层鉴权主体不符，直接拒绝请求并上报 `hal-audit`。
3. **Jail 最小路径暴露（`mount_nullfs`）**：
   - 对运行在无 IP Jail 内的每个 Agent（或临时 Worker），宿主 `hal-sandbox` 在启动 Jail 前为其创建专属目录 `/var/run/hal/jails/<agent_id>/`，仅将单个授权 socket 目录通过受限 `nullfs` 挂载到 Jail 内部 `/run/hal/bus.sock`。
   - 各 Agent 之间既看不到彼此的进程与文件系统，也看不到其他组件的控制 socket。
4. **IPC 通信矩阵与跨 Agent 污点传染规则**：
   - 当 Agent A 向 Agent B 发送 `IpcMessage` 时，`hal-bus` 首先查验 `config/ipc-matrix` 白名单（默认拒绝未声明边）；
   - 通过矩阵校验后，`hal-bus` **强制将发送方 Agent A 当前会话的 `episode_taints` 注入 `propagated_taints` 并立即合并至接收方 Agent B 的会话污点集**，同时对高风险跨信任域边执行 `schema_id` 校验，彻底消除多跳串联洗白。

---

## 4. ZFS 原子双快照（磁盘 + 认知记忆）生命周期

传统 Agent 系统最大的状态隐患之一是**“状态分裂”**：磁盘文件被回滚了，但 AI 的上下文数据库/情景记忆还以为文件已经改好，进而基于错误幻觉继续操作。

HAL-OS 利用 OpenZFS **单命令多数据集原子快照**特性（同一事务组 TXG 内瞬间完成），将每个任务的“工作区磁盘状态”与“AI 认知记忆库”绑定为不可分割的事务单元：

1. **任务开启（`begin_episode`）**：
   - `hal-workspace` 从干净基线克隆出两个隔离数据集：
     - 工作区分支：`halpool/workspaces/active/<ep_id>`
     - 记忆库分支：`halpool/memory/<ep_id>`（存储该任务的对话上下文、工具观察缓存与情景索引）
   - 若为多路径探索任务，支持一次克隆出 `ep_01_a`、`ep_01_b` 两个并行分支同时验证，互不干扰。
2. **前置事务保护（执行 `L1` 变更前）**：
   - `hal-policy` 批准 `L1` 提案时，强制要求 `hal-workspace` 先落盘原子双快照：
     ```sh
     zfs snapshot \
       halpool/workspaces/active/ep_01@step_03 \
       halpool/memory/ep_01@step_03
     ```
   - 快照标签 `step_03` 同步写入 `hal-audit` 与 `DualSnapshot` 元数据。
3. **失败回滚（`rollback_dual_snapshot`）**：
   - 当沙箱构建失败、测试报错或人类在 `hal-oob` 点击“回滚到上一步”时，`hal-workspace` 暂停对应沙箱并同步回退两个数据集：
     ```sh
     zfs rollback -r halpool/workspaces/active/ep_01@step_03
     zfs rollback -r halpool/memory/ep_01@step_03
     ```
   - 恢复后重新拉起上下文，AI 认知记忆与文件系统状态 100% 处于同一历史切片，零残留、零幻觉。
4. **验收提交与清理（`commit_episode`）**：
   - 分支任务验证通过后，生成精确变更集（`zfs diff` / Git diff），作为 `L2` 提案提交给人类审批。人类在 `hal-oob` 确认后，将变更合并到主工作区并归档记忆，随后销毁临时分支数据集释放空间。

---

### 延伸阅读

- 系统总体分层、多 Agent 治理模型与 Cargo 目录结构：[architecture.md](./architecture.md)
- 威胁模型、跨 Agent 防串谋污点追踪与降级状态机：[security-model.md](./security-model.md)
- FreeBSD 14 + KVM 实验床与四大红蓝演练：[vm-testbed-guide.md](./vm-testbed-guide.md)
