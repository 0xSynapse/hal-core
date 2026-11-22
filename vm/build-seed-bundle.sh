#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${HAL_IMAGES_DIR:-/var/tmp/hal-os-vm}"
OUT_TAR="${IMAGES_DIR}/hal-seed.tar"

SSH_PUBKEY="${HAL_SSH_PUBKEY:-}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--ssh-pubkey PATH] [--out PATH] [--help]

Packs config/ and vm/freebsd/ into an offline tar bundle attached read-only
as vtbd2 in QEMU, enabling zero-network Phase 0 bootstrap inside FreeBSD.

Options:
  --ssh-pubkey PATH   Embed an SSH public key for root over mgmt0
                      (or set HAL_SSH_PUBKEY=/path/to/key.pub)
  --out PATH          Output tar path (default: vm/images/hal-seed.tar)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-pubkey)
      [[ $# -ge 2 ]] || { echo "--ssh-pubkey requires a path" >&2; exit 2; }
      SSH_PUBKEY="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || { echo "--out requires a path" >&2; exit 2; }
      OUT_TAR="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

STAGE_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "$(dirname "${OUT_TAR}")" "${STAGE_DIR}/vm"
cp -R "${ROOT_DIR}/config" "${STAGE_DIR}/config"
cp -R "${ROOT_DIR}/vm/freebsd" "${STAGE_DIR}/vm/freebsd"
chmod +x "${STAGE_DIR}/vm/freebsd/"*.sh

if [[ -n "${SSH_PUBKEY}" ]]; then
  if [[ ! -f "${SSH_PUBKEY}" ]]; then
    echo "SSH public key file not found: ${SSH_PUBKEY}" >&2
    exit 1
  fi
  mkdir -p "${STAGE_DIR}/ssh"
  cp "${SSH_PUBKEY}" "${STAGE_DIR}/ssh/authorized_keys"
  chmod 0644 "${STAGE_DIR}/ssh/authorized_keys"
  echo "Embedded SSH public key from: ${SSH_PUBKEY}"
else
  echo "Note: No --ssh-pubkey supplied; key-only OOB SSH requires adding /root/.ssh/authorized_keys manually."
fi

tar -C "${STAGE_DIR}" -cf "${OUT_TAR}" .

echo "Created seed bundle: ${OUT_TAR}"
ls -lh "${OUT_TAR}"
echo "Inside FreeBSD guest, run:"
echo "  mkdir -p /tmp/hal && tar -xf /dev/vtbd2 -C /tmp/hal && sh /tmp/hal/vm/freebsd/phase0-init.sh"
