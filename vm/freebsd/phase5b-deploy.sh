#!/bin/sh
# Idempotent FreeBSD 14.5 deployment script for HAL Core & HAL Key brainstem binaries,
# policy configs, rc.d supervision script, and pf.conf verification.
# Run as root inside the FreeBSD 14.5 host/VM from the repository root (or BIN_DIR override).

set -eu

REPO_ROOT="${REPO_ROOT:-/root/hal-os}"
BIN_DIR="${BIN_DIR:-$REPO_ROOT/target/release}"
CONF_DEST="${CONF_DEST:-/usr/local/etc/hal-os}"
BIN_DEST="${BIN_DEST:-/usr/local/bin}"
RCD_DEST="${RCD_DEST:-/usr/local/etc/rc.d}"
AUDIT_LOG="${AUDIT_LOG:-/pool/audit/hal-audit.log}"

mkdir -p "$CONF_DEST" "$BIN_DEST" "$RCD_DEST" /var/run/hal/bus "$(dirname "$AUDIT_LOG")"

for bin in hal-bus hal-gateway hal-oob halctl hal-watchdog hal-net-broker adapter-digest; do
    src="$BIN_DIR/$bin"
    if [ ! -x "$src" ]; then
        echo "Missing compiled binary: $src" >&2
        exit 1
    fi
    install -m 0755 "$src" "$BIN_DEST/$bin"
done

for policy in ipc-matrix.toml gateway-peers.toml watchdog.toml egress-allowlist.toml; do
    install -m 0644 "$REPO_ROOT/config/policy/$policy" "$CONF_DEST/$policy"
done

if [ ! -f "$CONF_DEST/egress-allowlist.live.toml" ] && [ -f "$REPO_ROOT/config/policy/egress-allowlist.live.example.toml" ]; then
    install -m 0644 "$REPO_ROOT/config/policy/egress-allowlist.live.example.toml" "$CONF_DEST/egress-allowlist.live.toml"
fi

if [ ! -f "$CONF_DEST/secrets.env" ]; then
    cat <<'EOF' >"$CONF_DEST/secrets.env"
# Populate before running `service hal_core start` (chmod 0600 required)
HAL_TOKEN_SECRET=replace-with-32-byte-random-hex
HAL_OOB_TOKEN=replace-with-hal-key-operator-token
HAL_PEER_KEY_LAPTOP=replace-with-laptop-peer-proof-secret
EOF
    chmod 0600 "$CONF_DEST/secrets.env"
fi

install -m 0644 "$REPO_ROOT/config/freebsd/pf.conf" /etc/pf.conf
install -m 0555 "$REPO_ROOT/config/freebsd/rc.d/hal_core" "$RCD_DEST/hal_core"

if command -v pfctl >/dev/null 2>&1; then
    pfctl -nf /etc/pf.conf
fi

"$BIN_DEST/hal-bus" --ipc-matrix "$CONF_DEST/ipc-matrix.toml" --audit-log "$AUDIT_LOG" --check
"$BIN_DEST/hal-gateway" --config "$CONF_DEST/gateway-peers.toml" --check
"$BIN_DEST/hal-oob" --bind 192.168.100.10:8443 --bus-socket /var/run/hal/bus/oob.sock --audit-log "$AUDIT_LOG" --check
"$BIN_DEST/hal-watchdog" --config "$CONF_DEST/watchdog.toml" --check
"$BIN_DEST/adapter-digest" --check

echo "PHASE5B_FREEBSD_DEPLOY_OK"
