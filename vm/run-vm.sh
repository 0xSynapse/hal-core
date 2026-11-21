#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${ROOT_DIR}/vm/images"

SYS_DISK="${HAL_SYS_DISK:-${IMAGES_DIR}/freebsd14-sys.qcow2}"
DATA_DISK="${HAL_DATA_DISK:-${IMAGES_DIR}/halpool-data.qcow2}"
SEED_TAR="${HAL_SEED_TAR:-${IMAGES_DIR}/hal-seed.tar}"

NET_MODE="${HAL_NET_MODE:-user}"
MGMT_BRIDGE="${HAL_MGMT_BRIDGE:-virbr-hal-mgmt}"
ACCEL="${HAL_ACCEL:-auto}"
CPUS="${HAL_CPUS:-4}"
MEM_MB="${HAL_MEM_MB:-4096}"
OOB_SOCK="${HAL_OOB_SOCK:-/tmp/hal-os-oob.sock}"
SSH_FWD_PORT="${HAL_SSH_FWD_PORT:-2222}"
OOB_FWD_PORT="${HAL_OOB_FWD_PORT:-8443}"
DRY_RUN=0
USE_SEED=1

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Boots the HAL-OS FreeBSD 14 dual-NIC, dual-disk QEMU/KVM testbed.

Options:
  --net-mode user|bridge   mgmt0 isolation mode (default: user)
                           user   = QEMU SLIRP restrict=on (zero host root required)
                           bridge = libvirt Host-Only bridge (${MGMT_BRIDGE})
  --accel auto|kvm|tcg     CPU virtualization mode (default: auto)
  --cpus N                 vCPU count (default: ${CPUS})
  --mem MB                 RAM in MiB (default: ${MEM_MB})
  --no-seed                Do not attach vtbd2 hal-seed.tar
  --dry-run                Print the resolved qemu-system-x86_64 command and exit
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --net-mode)
      [[ $# -ge 2 ]] || { echo "--net-mode requires user|bridge" >&2; exit 2; }
      NET_MODE="$2"; shift 2 ;;
    --accel)
      [[ $# -ge 2 ]] || { echo "--accel requires auto|kvm|tcg" >&2; exit 2; }
      ACCEL="$2"; shift 2 ;;
    --cpus)
      [[ $# -ge 2 ]] || { echo "--cpus requires an integer" >&2; exit 2; }
      CPUS="$2"; shift 2 ;;
    --mem)
      [[ $# -ge 2 ]] || { echo "--mem requires MiB" >&2; exit 2; }
      MEM_MB="$2"; shift 2 ;;
    --no-seed) USE_SEED=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${NET_MODE}" in
  user|bridge) ;;
  *) echo "Invalid --net-mode: ${NET_MODE} (expected user or bridge)" >&2; exit 2 ;;
esac

if [[ "${ACCEL}" == "auto" ]]; then
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    ACCEL="kvm"
  else
    ACCEL="tcg"
    echo "Warning: /dev/kvm is not accessible; falling back to TCG software emulation." >&2
  fi
fi

case "${ACCEL}" in
  kvm) CPU_MODEL="host" ;;
  tcg) CPU_MODEL="qemu64" ;;
  *) echo "Invalid --accel: ${ACCEL} (expected auto, kvm, or tcg)" >&2; exit 2 ;;
esac

if [[ "${DRY_RUN}" -eq 0 ]]; then
  if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 not found on PATH" >&2
    exit 1
  fi
  if [[ ! -f "${SYS_DISK}" || ! -f "${DATA_DISK}" ]]; then
    echo "Missing VM disk images (${SYS_DISK} or ${DATA_DISK})." >&2
    echo "Run ./vm/fetch-freebsd-image.sh first." >&2
    exit 1
  fi
fi

CMD=(
  qemu-system-x86_64
  -name hal-os-freebsd14
  -machine "q35,accel=${ACCEL}"
  -cpu "${CPU_MODEL}"
  -smp "${CPUS}"
  -m "${MEM_MB}"
  -device virtio-rng-pci
  -drive "if=virtio,format=qcow2,file=${SYS_DISK}"
  -drive "if=virtio,format=qcow2,file=${DATA_DISK}"
)

if [[ "${USE_SEED}" -eq 1 && ( -f "${SEED_TAR}" || "${DRY_RUN}" -eq 1 ) ]]; then
  CMD+=(-drive "if=virtio,format=raw,readonly=on,file=${SEED_TAR}")
fi

if [[ "${NET_MODE}" == "user" ]]; then
  CMD+=(
    -netdev "user,id=net_mgmt,net=192.168.100.0/24,dhcpstart=192.168.100.10,restrict=on,hostfwd=tcp:127.0.0.1:${SSH_FWD_PORT}-:22,hostfwd=tcp:127.0.0.1:${OOB_FWD_PORT}-:8443"
  )
else
  CMD+=(
    -netdev "bridge,id=net_mgmt,br=${MGMT_BRIDGE}"
  )
fi

CMD+=(
  -device "virtio-net-pci,netdev=net_mgmt,mac=52:54:00:aa:01:01"
  -netdev "user,id=net_wan,net=10.0.2.0/24"
  -device "virtio-net-pci,netdev=net_wan,mac=52:54:00:aa:01:02"
  -chardev "socket,id=hal_oob_con,path=${OOB_SOCK},server=on,wait=off"
  -device virtio-serial-pci
  -device "virtconsole,chardev=hal_oob_con,name=org.halos.oob"
  -nographic
)

if [[ "${DRY_RUN}" -eq 1 ]]; then
  printf '%q ' "${CMD[@]}"
  printf '\n'
  exit 0
fi

exec "${CMD[@]}"
