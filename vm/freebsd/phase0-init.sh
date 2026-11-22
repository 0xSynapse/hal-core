#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "phase0-init.sh must be run as root inside FreeBSD 14." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CFG_DIR="${BUNDLE_ROOT}/config"

echo "=== HAL-OS Phase 0 Initialization (FreeBSD 14) ==="

# 1. Preserve clean Boot Environment before mutating system configs
if ! bectl list -H | awk '{print $1}' | grep -qx 'pre-hal-phase0'; then
  echo "[1/9] Creating ZFS boot environment snapshot pre-hal-phase0..."
  bectl create pre-hal-phase0
else
  echo "[1/9] Boot environment pre-hal-phase0 already exists."
fi

# 2. Expand zroot if vtbd0 was resized via qemu-img
echo "[2/9] Checking vtbd0 GPT / zroot expansion..."
gpart recover vtbd0 >/dev/null 2>&1 || true
ZFS_PART_IDX="$(gpart show -p vtbd0 2>/dev/null | awk '/freebsd-zfs/ {print $3}' | sed 's/vtbd0p//' | head -n 1 || true)"
if [ -n "${ZFS_PART_IDX}" ]; then
  gpart resize -i "${ZFS_PART_IDX}" vtbd0 >/dev/null 2>&1 || true
  zpool set autoexpand=on zroot >/dev/null 2>&1 || true
  zpool online -e zroot "vtbd0p${ZFS_PART_IDX}" >/dev/null 2>&1 || true
fi

# 3. Create dedicated halpool on /dev/vtbd1 and datasets
echo "[3/9] Configuring halpool datasets on vtbd1..."
mkdir -p /etc/zfs
if ! zpool list halpool >/dev/null 2>&1; then
  if [ ! -e /dev/vtbd1 ]; then
    echo "Error: /dev/vtbd1 not found. Attach the 32G halpool disk in QEMU." >&2
    exit 1
  fi
  zpool create -f -m none -o ashift=12 -O compression=lz4 -O atime=off halpool /dev/vtbd1
fi
zpool set cachefile=/etc/zfs/zpool.cache halpool

if [ ! -f /root/.hal-vault.key ]; then
  dd if=/dev/urandom of=/root/.hal-vault.key bs=32 count=1 >/dev/null 2>&1
  chmod 0400 /root/.hal-vault.key
fi

ensure_ds() {
  ds="$1"
  shift
  if ! zfs list "${ds}" >/dev/null 2>&1; then
    zfs create "$@" "${ds}"
  fi
}

ensure_ds halpool/vault \
  -o encryption=aes-256-gcm \
  -o keyformat=raw \
  -o keylocation=file:///root/.hal-vault.key \
  -o mountpoint=/pool/vault \
  -o exec=off \
  -o setuid=off

ensure_ds halpool/workspaces -o mountpoint=/pool/workspaces -o setuid=off
ensure_ds halpool/workspaces/base
ensure_ds halpool/workspaces/active

ensure_ds halpool/memory -o mountpoint=/pool/memory -o setuid=off
ensure_ds halpool/memory/base
ensure_ds halpool/memory/active

ensure_ds halpool/jails -o mountpoint=/pool/jails
ensure_ds halpool/jails/agents

ensure_ds halpool/audit -o mountpoint=/pool/audit -o exec=off -o setuid=off

# 4. Create dedicated least-privilege system users
echo "[4/9] Creating dedicated HAL-OS system accounts..."
ensure_user() {
  uname="$1"
  if ! pw usershow "${uname}" >/dev/null 2>&1; then
    pw useradd "${uname}" -s /usr/sbin/nologin -d /nonexistent -w no -c "HAL-OS ${uname}"
  fi
}

for u in \
  _hal_bus \
  _hal_gw \
  _hal_policy \
  _hal_broker \
  _hal_workspace \
  _hal_audit \
  _hal_watchdog \
  _hal_oob \
  _hal_ag_netsec \
  _hal_ag_vault \
  _hal_ag_coder \
  _hal_ag_habitat \
  _hal_ag_research
do
  ensure_user "${u}"
done

# 5. Delegate ZFS management strictly to _hal_workspace
echo "[5/9] Delegating ZFS workspace/memory rights to _hal_workspace..."
zfs allow _hal_workspace create,destroy,snapshot,clone,rollback,diff,mount,promote halpool/workspaces
zfs allow _hal_workspace create,destroy,snapshot,clone,rollback,diff,mount,promote halpool/memory
if ! grep -q '^vfs\.usermount=' /etc/sysctl.conf 2>/dev/null; then
  echo 'vfs.usermount=1' >> /etc/sysctl.conf
fi
sysctl vfs.usermount=1 >/dev/null 2>&1 || true

# 6. Initialize append-only black-box audit log (chflags sappnd)
echo "[6/9] Initializing append-only black-box audit log..."
if [ ! -f /pool/audit/hal-audit.log ]; then
  printf '{"seq":0,"event":"hal-audit-genesis"}\n' > /pool/audit/hal-audit.log
fi
chown _hal_audit:_hal_audit /pool/audit/hal-audit.log
chmod 0640 /pool/audit/hal-audit.log
chflags sappnd /pool/audit/hal-audit.log

# 7. Install kernel loader, rc.conf.local, PF, SSH OOB, Jail & policy templates
echo "[7/9] Installing FreeBSD spinal configs..."
touch /boot/loader.conf
while IFS= read -r line; do
  case "${line}" in
    ""|\#*) continue ;;
  esac
  key="${line%%=*}"
  grep -v "^${key}=" /boot/loader.conf > /boot/loader.conf.tmp || true
  mv /boot/loader.conf.tmp /boot/loader.conf
  echo "${line}" >> /boot/loader.conf
done < "${CFG_DIR}/freebsd/loader.conf"

cp "${CFG_DIR}/freebsd/rc.conf.hal" /etc/rc.conf.local

cp "${CFG_DIR}/freebsd/pf.conf" /etc/pf.conf
kldload -n pf >/dev/null 2>&1 || true
pfctl -nf /etc/pf.conf

mkdir -p /etc/ssh/sshd_config.d
cp "${CFG_DIR}/freebsd/sshd-hal-oob.conf" /etc/ssh/sshd_config.d/hal-oob.conf
touch /etc/ssh/sshd_config
grep -vE '^Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf$' /etc/ssh/sshd_config > /etc/ssh/sshd_config.tmp || true
{
  echo 'Include /etc/ssh/sshd_config.d/*.conf'
  cat /etc/ssh/sshd_config.tmp
} > /etc/ssh/sshd_config
rm -f /etc/ssh/sshd_config.tmp
service sshd onekeygen >/dev/null 2>&1 || true
sshd -t

if [ -f "${BUNDLE_ROOT}/ssh/authorized_keys" ]; then
  mkdir -p /root/.ssh
  chmod 0700 /root/.ssh
  if [ -f /root/.ssh/authorized_keys ]; then
    while IFS= read -r pub; do
      [ -z "${pub}" ] && continue
      grep -qxF "${pub}" /root/.ssh/authorized_keys || echo "${pub}" >> /root/.ssh/authorized_keys
    done < "${BUNDLE_ROOT}/ssh/authorized_keys"
  else
    cp "${BUNDLE_ROOT}/ssh/authorized_keys" /root/.ssh/authorized_keys
  fi
  chmod 0600 /root/.ssh/authorized_keys
fi

cp "${CFG_DIR}/freebsd/jail.conf" /etc/jail.conf
mkdir -p /etc/jail.conf.d
mkdir -p /usr/local/etc/hal-os
cp "${CFG_DIR}/policy/ipc-matrix.toml" /usr/local/etc/hal-os/ipc-matrix.toml

# Install persistent verification script and maintenance PF toggle
mkdir -p /usr/local/libexec/hal-os /usr/local/sbin
cp "${SCRIPT_DIR}/phase0-verify.sh" /usr/local/libexec/hal-os/phase0-verify.sh
chmod 0755 /usr/local/libexec/hal-os/phase0-verify.sh

cat <<'EOF' > /usr/local/sbin/hal-maint-net
#!/bin/sh
set -eu
case "${1:-status}" in
  on)
    printf 'pass out quick on wan0 proto tcp all keep state\npass out quick on wan0 proto udp to port 53 keep state\n' | pfctl -a hal_maint -f -
    echo "Maintenance outbound anchor 'hal_maint' ENABLED. Remember to run 'hal-maint-net off' afterwards."
    ;;
  off)
    pfctl -a hal_maint -F all
    echo "Maintenance outbound anchor 'hal_maint' DISABLED (strict zero-trust restored)."
    ;;
  status)
    pfctl -a hal_maint -sr
    ;;
  *)
    echo "Usage: hal-maint-net {on|off|status}" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 /usr/local/sbin/hal-maint-net

# 8. Provision two thin No-IP agent Jails (agent_research & agent_vault)
echo "[8/9] Provisioning thin No-IP Jails and RCTL quotas..."
provision_thin_jail() {
  jname="$1"
  jds="halpool/jails/agents/${jname}"
  jbase="/pool/jails/agents/${jname}"
  jroot="${jbase}/root"
  jusock="/var/run/hal/jails/${jname}"

  ensure_ds "${jds}" -o "mountpoint=${jbase}"
  mkdir -p \
    "${jroot}/bin" "${jroot}/sbin" "${jroot}/lib" "${jroot}/libexec" \
    "${jroot}/usr/bin" "${jroot}/usr/lib" "${jroot}/usr/libexec" \
    "${jroot}/dev" "${jroot}/etc" "${jroot}/tmp" "${jroot}/var" "${jroot}/run/hal" \
    "${jusock}"
  chmod 1777 "${jroot}/tmp"

  cat <<EOF > "${jbase}/fstab"
/bin            ${jroot}/bin            nullfs  ro  0 0
/sbin           ${jroot}/sbin           nullfs  ro  0 0
/lib            ${jroot}/lib            nullfs  ro  0 0
/libexec        ${jroot}/libexec        nullfs  ro  0 0
/usr/bin        ${jroot}/usr/bin        nullfs  ro  0 0
/usr/lib        ${jroot}/usr/lib        nullfs  ro  0 0
/usr/libexec    ${jroot}/usr/libexec    nullfs  ro  0 0
${jusock}       ${jroot}/run/hal        nullfs  rw  0 0
EOF

  cat <<EOF > "/etc/jail.conf.d/${jname}.conf"
${jname} {
  host.hostname = "${jname}.hal.local";
}
EOF
}

provision_thin_jail agent_research
provision_thin_jail agent_vault

cat <<'EOF' > /etc/rctl.conf
# HAL-OS Phase 0 per-Agent Jail hard resource quotas
jail:agent_research:memoryuse:deny=512M
jail:agent_research:maxproc:deny=64
jail:agent_research:pcpu:deny=50
jail:agent_vault:memoryuse:deny=512M
jail:agent_vault:maxproc:deny=64
jail:agent_vault:pcpu:deny=50
EOF

echo "[9/9] Initialization complete."
RACCT_NOW="$(sysctl -n kern.racct.enable 2>/dev/null || echo 0)"
if [ "${RACCT_NOW}" != "1" ]; then
  echo
  echo "ACTION REQUIRED: Reboot now to activate kern.racct.enable=\"1\", mgmt0/wan0, PF, and RCTL:"
  echo "  reboot"
  echo "After reboot, run:"
  echo "  sh /usr/local/libexec/hal-os/phase0-verify.sh"
else
  echo "kern.racct.enable is already 1. Run:"
  echo "  sh /usr/local/libexec/hal-os/phase0-verify.sh"
fi
