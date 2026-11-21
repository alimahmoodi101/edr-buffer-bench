#!/usr/bin/env bash
# setup_vm.sh - one-time setup of the Ubuntu VM. Run from the repo root:
#     sudo ./scripts/setup_vm.sh
# Works on an Ubuntu 24.04 VM or Ubuntu 24.04 under WSL2.
# Tested on Ubuntu 24.04 (kernel 6.8). Ubuntu 22.04 needs libbpf >= 1.0,
# which apt does not ship, so use 24.04.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "run with sudo"; exit 1; fi

echo "== installing packages =="
apt-get update -qq
apt-get install -y \
	build-essential clang llvm make git pkg-config \
	libbpf-dev libelf-dev zlib1g-dev \
	linux-tools-common linux-tools-generic \
	stress-ng python3 python3-pandas python3-matplotlib python3-numpy
# kernel-specific tools: exists on a normal Ubuntu VM, not on WSL (that's fine,
# the Makefile uses the generic bpftool instead)
apt-get install -y "linux-tools-$(uname -r)" 2>/dev/null || echo "note: no linux-tools for $(uname -r), using generic bpftool"

echo "== checking the system =="
ok=1
kver=$(uname -r | cut -d. -f1-2)
if [[ $(printf '%s\n' "5.12" "$kver" | sort -V | head -1) != "5.12" ]]; then
	echo "!! kernel $kver is too old, need >= 5.12"; ok=0
else echo "ok  kernel $(uname -r)"; fi

if [[ -f /sys/kernel/btf/vmlinux ]]; then echo "ok  BTF available"
else echo "!! /sys/kernel/btf/vmlinux missing (kernel built without BTF)"; ok=0; fi

lb=$(dpkg-query -W -f='${Version}' libbpf-dev 2>/dev/null | sed 's/^[0-9]*://')
if [[ $(printf '%s\n' "1.0" "$lb" | sort -V | head -1) != "1.0" ]]; then
	echo "!! libbpf-dev $lb is too old, need >= 1.0 (use Ubuntu 24.04)"; ok=0
else echo "ok  libbpf $lb"; fi

cpus=$(nproc)
if [[ $cpus -ne 4 ]]; then echo "!! VM has $cpus vCPUs; the proposal says 4 - fix it in VM settings"
else echo "ok  4 vCPUs"; fi

if ! mountpoint -q /sys/kernel/tracing; then
	mount -t tracefs nodev /sys/kernel/tracing && echo "ok  mounted tracefs"
else echo "ok  tracefs mounted"; fi

[[ $ok -eq 1 ]] || { echo "fix the problems above first"; exit 1; }

echo "== building =="
sudo -u "${SUDO_USER:-root}" make
echo
echo "Done. Try:  sudo ./build/evdump --design prio --duration 5 --no-read"
