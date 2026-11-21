#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NET_MODE="${HAL_NET_MODE:-user}"
REMOTE_DIR="${HAL_REMOTE_DIR:-/usr/src/hal-os}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --net-mode)
      [[ $# -ge 2 ]] || { echo "--net-mode requires user|bridge" >&2; exit 2; }
      NET_MODE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--net-mode user|bridge]"
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "${NET_MODE}" == "bridge" ]]; then
  SSH_TARGET="${HAL_SSH_TARGET:-root@192.168.100.10}"
  SSH_PORT="${HAL_SSH_PORT:-22}"
else
  SSH_TARGET="${HAL_SSH_TARGET:-root@127.0.0.1}"
  SSH_PORT="${HAL_SSH_PORT:-2222}"
fi

rsync -avz --delete \
  --exclude '/target/' \
  --exclude '/vm/images/' \
  --exclude '/.git/' \
  -e "ssh -p ${SSH_PORT}" \
  "${ROOT_DIR}/" "${SSH_TARGET}:${REMOTE_DIR}/"
