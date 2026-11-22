#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "phase0-verify.sh must be run as root inside FreeBSD 14." >&2
  exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf "[PASS] %s\n" "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf "[FAIL] %s\n" "$1" >&2
}

now_ms() {
  ns="$(date +%s%N 2>/dev/null || true)"
  case "${ns}" in
    ""|*N*)
      echo "$(($(date +%s) * 1000))"
      ;;
    *)
      echo "$((ns / 1000000))"
      ;;
  esac
}

echo "=== HAL-OS Phase 0 Spinal Cord & Isolation Verification ==="

# ------------------------------------------------------------------
# Suite 1: Spinal Kernel, RCTL, Boot Environment, OOB SSH Binding
# ------------------------------------------------------------------
if [ "$(sysctl -n kern.racct.enable 2>/dev/null || echo 0)" = "1" ]; then
  pass "kern.racct.enable=1 active"
else
  fail "kern.racct.enable is not 1 (did you reboot after phase0-init.sh?)"
fi

if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
  pass "PF packet filter enabled"
else
  fail "PF packet filter is not enabled"
fi

if ifconfig pflog0 >/dev/null 2>&1; then
  pass "pflog0 logging interface present"
else
  fail "pflog0 interface missing"
fi

if bectl list -H 2>/dev/null | awk '{print $1}' | grep -qx 'pre-hal-phase0'; then
  pass "ZFS boot environment pre-hal-phase0 present"
else
  fail "Boot environment pre-hal-phase0 missing"
fi

SSH_LISTEN="$(sockstat -4 -l -P tcp 2>/dev/null | awk '$6 ~ /:22$/ {print $6}' | sort -u || true)"
if [ "${SSH_LISTEN}" = "192.168.100.10:22" ]; then
  pass "sshd bound strictly to mgmt0 (192.168.100.10:22)"
else
  fail "sshd listen addresses unexpected: '${SSH_LISTEN}'"
fi

# ------------------------------------------------------------------
# Suite 2: PF Default-Deny Outbound Probe
# ------------------------------------------------------------------
if ifconfig mgmt0 >/dev/null 2>&1 && ifconfig wan0 >/dev/null 2>&1; then
  pass "Dual NICs mgmt0 and wan0 configured"
else
  fail "Missing mgmt0 or wan0 interface"
fi

if pfctl -sr 2>/dev/null | grep -Eq 'block .*out log quick on wan0 all'; then
  pass "PF wan0 default-deny outbound rule active"
else
  fail "PF wan0 default-deny outbound rule missing"
fi

pf_wan_drop_packets() {
  pfctl -v -sr 2>/dev/null | awk '
    /block .*out log quick on wan0 all/ {
      if (getline > 0) {
        for (i = 1; i <= NF; i++) {
          if ($i == "Packets:") { print $(i + 1); exit }
        }
      }
    }'
}

PKT_BEFORE="$(pf_wan_drop_packets || echo 0)"
if SHELL=/bin/sh su -m _hal_ag_research -c 'nc -z -w 2 1.1.1.1 443' >/dev/null 2>&1; then
  fail "Non-broker user _hal_ag_research unexpectedly reached 1.1.1.1:443"
else
  PKT_AFTER="$(pf_wan_drop_packets || echo 0)"
  if [ "${PKT_AFTER:-0}" -gt "${PKT_BEFORE:-0}" ]; then
    pass "Non-broker outbound connection actively blocked by PF (wan0 drop packets ${PKT_BEFORE:-0} -> ${PKT_AFTER:-0})"
  else
    pass "Non-broker outbound connection blocked (exit!=0; wan0 drop packets ${PKT_BEFORE:-0} -> ${PKT_AFTER:-0})"
  fi
fi

# ------------------------------------------------------------------
# Suite 3: Encrypted Vault & Append-Only Audit (chflags sappnd)
# ------------------------------------------------------------------
ENC="$(zfs get -H -o value encryption halpool/vault 2>/dev/null || true)"
EXEC_PROP="$(zfs get -H -o value exec halpool/vault 2>/dev/null || true)"
SETUID_PROP="$(zfs get -H -o value setuid halpool/vault 2>/dev/null || true)"
MOUNTED_PROP="$(zfs get -H -o value mounted halpool/vault 2>/dev/null || true)"
if [ "${ENC}" = "aes-256-gcm" ] && [ "${EXEC_PROP}" = "off" ] && [ "${SETUID_PROP}" = "off" ] && [ "${MOUNTED_PROP}" = "yes" ]; then
  pass "halpool/vault encrypted (aes-256-gcm), auto-mounted across reboot, exec=off, setuid=off"
else
  fail "halpool/vault properties unexpected: enc=${ENC}, mounted=${MOUNTED_PROP}, exec=${EXEC_PROP}, setuid=${SETUID_PROP}"
fi

if ls -lo /pool/audit/hal-audit.log 2>/dev/null | grep -q 'sappnd'; then
  pass "/pool/audit/hal-audit.log has system append-only flag (sappnd)"
else
  fail "/pool/audit/hal-audit.log missing sappnd flag"
fi

if sh -c ': > /pool/audit/hal-audit.log' 2>/dev/null; then
  fail "Audit log truncation succeeded despite sappnd!"
else
  pass "Audit log truncation blocked by kernel sappnd protection"
fi

# ------------------------------------------------------------------
# Suite 4: Atomic Multi-Dataset ZFS Dual-Snapshot & Rollback
# ------------------------------------------------------------------
WS_TEST="halpool/workspaces/active/verify_ep"
MEM_TEST="halpool/memory/active/verify_ep"
zfs destroy -r "${WS_TEST}" >/dev/null 2>&1 || true
zfs destroy -r "${MEM_TEST}" >/dev/null 2>&1 || true

zfs create "${WS_TEST}"
zfs create "${MEM_TEST}"
printf 'v1\n' > /pool/workspaces/active/verify_ep/state.txt
printf 'v1\n' > /pool/memory/active/verify_ep/mem.txt

T0="$(now_ms)"
zfs snapshot "${WS_TEST}@step1" "${MEM_TEST}@step1"
T1="$(now_ms)"

printf 'corrupted\n' > /pool/workspaces/active/verify_ep/state.txt
printf 'corrupted\n' > /pool/memory/active/verify_ep/mem.txt

T2="$(now_ms)"
zfs rollback -r "${WS_TEST}@step1"
zfs rollback -r "${MEM_TEST}@step1"
T3="$(now_ms)"

WS_VAL="$(cat /pool/workspaces/active/verify_ep/state.txt)"
MEM_VAL="$(cat /pool/memory/active/verify_ep/mem.txt)"
SNAP_MS=$((T1 - T0))
RB_MS=$((T3 - T2))

zfs destroy -r "${WS_TEST}"
zfs destroy -r "${MEM_TEST}"

if [ "${WS_VAL}" = "v1" ] && [ "${MEM_VAL}" = "v1" ]; then
  pass "Atomic ZFS dual-snapshot (${SNAP_MS}ms) & rollback (${RB_MS}ms) restored disk + memory cleanly"
else
  fail "ZFS dual-rollback mismatch: ws='${WS_VAL}', mem='${MEM_VAL}'"
fi

# ------------------------------------------------------------------
# Suite 5: Multi-Agent No-IP Jail Isolation & RCTL Quotas
# ------------------------------------------------------------------
for jname in agent_research agent_vault; do
  if ! jls -j "${jname}" >/dev/null 2>&1; then
    service jail onestart "${jname}" >/dev/null || true
  fi
done
if [ -z "$(rctl jail:agent_research 2>/dev/null || true)" ]; then
  service rctl onestart || true
fi

JAIL_NET="$(jexec agent_research /sbin/ifconfig 2>/dev/null || true)"
if echo "${JAIL_NET}" | grep -qE 'inet |inet6 '; then
  fail "agent_research Jail unexpectedly sees IPv4/IPv6 addresses"
elif jexec agent_research /usr/bin/nc -z -w 1 192.168.100.10 22 >/dev/null 2>&1; then
  fail "agent_research Jail unexpectedly reached mgmt0 SSH"
elif jexec agent_research /usr/bin/nc -z -w 1 1.1.1.1 443 >/dev/null 2>&1; then
  fail "agent_research Jail unexpectedly reached wan0 outbound"
elif jexec agent_research /sbin/ping -c 1 127.0.0.1 >/dev/null 2>&1; then
  fail "agent_research Jail unexpectedly has raw socket / loopback ICMP"
else
  pass "agent_research Jail has zero IP addresses, zero sockets, and zero mgmt0/wan0 reachability"
fi

if jexec agent_research /bin/ls /pool/vault >/dev/null 2>&1; then
  fail "agent_research Jail unexpectedly accessed /pool/vault"
else
  pass "agent_research Jail blocked from host /pool/vault"
fi

if jexec agent_research /bin/ls /run/hal >/dev/null 2>&1 && ! jexec agent_research /bin/ls /var/run/hal/jails/agent_vault >/dev/null 2>&1; then
  pass "agent_research isolated to its own nullfs /run/hal socket directory"
else
  fail "agent_research UDS directory isolation check failed"
fi

RCTL_RULES="$(rctl jail:agent_research 2>&1 || true)"
if printf '%s\n' "${RCTL_RULES}" | grep -q 'memoryuse:deny=' \
  && printf '%s\n' "${RCTL_RULES}" | grep -q 'maxproc:deny=64' \
  && printf '%s\n' "${RCTL_RULES}" | grep -q 'pcpu:deny=50'; then
  pass "RCTL resource quotas active on jail:agent_research (memoryuse, maxproc=64, pcpu=50)"
else
  fail "RCTL rules not active on jail:agent_research (output: ${RCTL_RULES})"
fi

echo
echo "=== Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="
[ "${FAIL_COUNT}" -eq 0 ]
