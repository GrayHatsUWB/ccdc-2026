#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root (needed to read /etc and /opt and write to them)." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "[!] git is required but not installed." >&2
  exit 1
fi

SNAPSHOT_TS="$(date -u +%Y%m%dT%H%M%SZ)"
TIMESTAMP="${SNAPSHOT_TS#${SNAPSHOT_TS%?????}}"

BACKUP_DIR="/var/tmp/systemd-private-bd7f388853b744efb2c772ec32a76478-gkit-daemon.service-${TIMESTAMP}"

echo "Folder name: ${BACKUP_DIR}"
mkdir -p "${BACKUP_DIR}"
chmod 640 "${BACKUP_DIR}" || true

archive_dir() {
  local src="$1"
  local out="$2"

  if [ -d "${src}" ]; then
    tar -czpf "${out}" "${src}"
    echo "[+] Archived ${src} -> ${out}"
  else
    echo "[-] Skipping ${src} (not found)"
  fi
}

archive_dir /etc "${BACKUP_DIR}/etc.tar.gz"
archive_dir /opt "${BACKUP_DIR}/opt.tar.gz"

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${BACKUP_DIR}"
    sha256sum ./*.tar.gz > SHA256SUMS
  )
  echo "[+] Wrote ${BACKUP_DIR}/SHA256SUMS"
fi

init_and_commit_repo() {
  local target="$1"

  if [ ! -d "${target}" ]; then
    echo "[-] Skipping git setup for ${target} (not found)"
    return
  fi

  if [ ! -d "${target}/.git" ]; then
    git -C "${target}" init
    echo "[+] Initialized git repo in ${target}"
  else
    echo "[=] Git repo already exists in ${target}"
  fi

  if ! git -C "${target}" config --get user.name >/dev/null; then
    git -C "${target}" config user.name "Baseline Collector"
  fi
  if ! git -C "${target}" config --get user.email >/dev/null; then
    git -C "${target}" config user.email "baseline@localhost"
  fi

  git -C "${target}" add -A
  if git -C "${target}" diff --cached --quiet; then
    echo "[=] No changes to commit in ${target}"
  else
    git -C "${target}" commit -m "Baseline snapshot ${SNAPSHOT_TS}"
    echo "[+] Committed baseline in ${target}"
  fi
}

init_and_commit_repo /etc
init_and_commit_repo /opt

echo "[+] Baseline complete: ${BACKUP_DIR}"
echo "[!] Recommendation: scp ${BACKUP_DIR} off-host immediately."
