#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGES_DIR="${HAL_IMAGES_DIR:-/var/tmp/hal-os-vm}"

FREEBSD_VERSION="${FREEBSD_VERSION:-14.5-RELEASE}"
SYS_DISK_SIZE="${SYS_DISK_SIZE:-16G}"
DATA_DISK_SIZE="${DATA_DISK_SIZE:-32G}"
SKIP_CHECKSUM="${SKIP_CHECKSUM:-0}"
FORCE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--force] [--help]

Downloads the official FreeBSD ${FREEBSD_VERSION} amd64 ZFS QCOW2 image, verifies
its SHA-256 checksum, expands the system disk to ${SYS_DISK_SIZE}, and creates
an empty ${DATA_DISK_SIZE} halpool data disk under vm/images/.

Environment variables:
  FREEBSD_VERSION   (default: ${FREEBSD_VERSION})
  SYS_DISK_SIZE     (default: ${SYS_DISK_SIZE})
  DATA_DISK_SIZE    (default: ${DATA_DISK_SIZE})
  SKIP_CHECKSUM=1   Skip SHA-256 verification (not recommended)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for cmd in curl xz qemu-img sha256sum awk; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required host command: ${cmd}" >&2
    exit 1
  fi
done

mkdir -p "${IMAGES_DIR}"

BASE_URL="https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_VERSION}/amd64/Latest"
XZ_NAME="FreeBSD-${FREEBSD_VERSION}-amd64-zfs.qcow2.xz"
XZ_FILE="${IMAGES_DIR}/${XZ_NAME}"
CHECKSUM_FILE="${IMAGES_DIR}/CHECKSUM.SHA256"
SYS_DISK="${IMAGES_DIR}/freebsd14-sys.qcow2"
DATA_DISK="${IMAGES_DIR}/halpool-data.qcow2"

echo "[1/4] Fetching FreeBSD ${FREEBSD_VERSION} checksum & image..."
curl -fL --retry 3 -o "${CHECKSUM_FILE}" "${BASE_URL}/CHECKSUM.SHA256"
if [[ ! -f "${XZ_FILE}" || "${FORCE}" -eq 1 ]]; then
  curl -fL --retry 3 -C - -o "${XZ_FILE}" "${BASE_URL}/${XZ_NAME}"
else
  echo "  -> Using cached ${XZ_FILE} (pass --force to re-download)"
fi

if [[ "${SKIP_CHECKSUM}" != "1" ]]; then
  echo "[2/4] Verifying SHA-256 checksum..."
  EXPECTED_SHA="$(awk -v target="(${XZ_NAME})" '$2 == target && $1 == "SHA256" { print $4 }' "${CHECKSUM_FILE}")"
  if [[ -z "${EXPECTED_SHA}" ]]; then
    echo "Could not find ${XZ_NAME} entry in ${CHECKSUM_FILE}" >&2
    exit 1
  fi
  ACTUAL_SHA="$(sha256sum "${XZ_FILE}" | awk '{print $1}')"
  if [[ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]]; then
    echo "SHA-256 mismatch!" >&2
    echo "  expected: ${EXPECTED_SHA}" >&2
    echo "  actual:   ${ACTUAL_SHA}" >&2
    exit 1
  fi
  echo "  -> SHA-256 OK (${ACTUAL_SHA})"
else
  echo "[2/4] Skipping SHA-256 verification (SKIP_CHECKSUM=1)"
fi

echo "[3/4] Preparing system disk (${SYS_DISK}, ${SYS_DISK_SIZE})..."
if [[ ! -f "${SYS_DISK}" || "${FORCE}" -eq 1 ]]; then
  xz -dkc "${XZ_FILE}" > "${SYS_DISK}.tmp"
  mv "${SYS_DISK}.tmp" "${SYS_DISK}"
  qemu-img resize "${SYS_DISK}" "${SYS_DISK_SIZE}"
else
  echo "  -> Keeping existing ${SYS_DISK} (pass --force to overwrite)"
fi

echo "[4/4] Preparing dedicated halpool data disk (${DATA_DISK}, ${DATA_DISK_SIZE})..."
if [[ ! -f "${DATA_DISK}" ]]; then
  qemu-img create -f qcow2 "${DATA_DISK}" "${DATA_DISK_SIZE}"
else
  echo "  -> Keeping existing ${DATA_DISK}"
fi

echo
echo "Done. Disk summary:"
qemu-img info "${SYS_DISK}" | sed 's/^/  /'
qemu-img info "${DATA_DISK}" | sed 's/^/  /'
echo
echo "Next steps:"
echo "  1. ./vm/build-seed-bundle.sh --ssh-pubkey ~/.ssh/id_ed25519.pub"
echo "  2. ./vm/run-vm.sh"
