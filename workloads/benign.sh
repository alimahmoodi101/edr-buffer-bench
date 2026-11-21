#!/usr/bin/env bash
# benign.sh - a benign, I/O-heavy workload for the overhead runs. Prints the
# elapsed time in seconds (only that, on stdout) so the harness can compare
# runs with and without monitoring.
#
#   ./workloads/benign.sh compile   make -j<ncpu> of a generated 200-file C project
#   ./workloads/benign.sh copy      cp -r of a ~500 MB folder (5000 files)
#   ./workloads/benign.sh extract   tar xf of the same folder
#
# Inputs are generated once in $SANDBOX/benign/ and reused, and preparation
# and clean-up are never timed. /tmp is a RAM-backed tmpfs on this machine, so
# the inputs use ~1 GB of RAM while they exist; set BENIGN_MB to shrink them,
# and run ./workloads/cleanup.sh --all to free the space.
set -euo pipefail
source "$(dirname "$0")/common.sh"

mode="${1:-}"
mb="${BENIGN_MB:-500}"
dir="$SANDBOX/benign"
ncpu=$(nproc)

prep_compile() {
	local src="$dir/project"
	[[ -f "$src/Makefile" ]] && return
	log "generating C project in $src (one-time)"
	mkdir -p "$src"
	for ((f = 0; f < 200; f++)); do
		{
			echo "#include <string.h>"
			for ((k = 0; k < 40; k++)); do
				cat <<EOF
unsigned long f${f}_${k}(const unsigned char *p, unsigned long n) {
	unsigned long h = $((f * 100 + k + 1))u;
	for (unsigned long i = 0; i < n; i++) { h = (h << 5) ^ (h >> 3) ^ p[i] ^ ${k}u; if (h & 1) h *= 31u; }
	unsigned char t[64]; memset(t, (int)h, sizeof t);
	for (int j = 0; j < 64; j++) h += t[j] * (j + ${f}u);
	return h;
}
EOF
			done
		} > "$src/u$f.c"
	done
	cat > "$src/Makefile" <<'EOF'
SRC := $(wildcard u*.c)
OBJ := $(SRC:.c=.o)
all: $(OBJ)
%.o: %.c
	$(CC) -O2 -c $< -o $@
clean:
	rm -f $(OBJ)
EOF
}

prep_data() {
	[[ -f "$dir/data/.complete" ]] && return
	log "generating ${mb} MB of files in $dir/data (one-time)"
	rm -rf "$dir/data"
	mkdir -p "$dir/data"
	python3 -I - "$dir/data" "$mb" <<'EOF'
import os, sys
root, mb = sys.argv[1], int(sys.argv[2])
chunk = os.urandom(100 * 1024)               # 100 KiB per file
n = mb * 1024 * 1024 // len(chunk)
for i in range(n):
    d = os.path.join(root, "d%03d" % (i // 100))
    if i % 100 == 0:
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "f%05d.bin" % i), "wb") as f:
        f.write(chunk)
open(os.path.join(root, ".complete"), "w").close()
EOF
}

prep_tar() {
	prep_data
	[[ -f "$dir/data.tar" ]] && return
	log "creating $dir/data.tar (one-time)"
	tar cf "$dir/data.tar.tmp" -C "$dir" data && mv "$dir/data.tar.tmp" "$dir/data.tar"
}

timed() {           # run "$@" (its output to stderr), print elapsed seconds
	local t0 t1
	t0=$(now_us)
	"$@" >&2
	t1=$(now_us)
	awk -v us=$((t1 - t0)) 'BEGIN { printf "%.3f\n", us / 1e6 }'
}

case "$mode" in
compile)
	prep_compile
	make -s -C "$dir/project" clean
	timed make -s -C "$dir/project" -j"$ncpu"
	;;
copy)
	prep_data
	rm -rf "$dir/copy"
	timed cp -r "$dir/data" "$dir/copy"
	rm -rf "$dir/copy"
	;;
extract)
	prep_tar
	rm -rf "$dir/extract"
	mkdir -p "$dir/extract"
	timed tar xf "$dir/data.tar" -C "$dir/extract"
	rm -rf "$dir/extract"
	;;
*)
	die "usage: $0 compile|copy|extract" ;;
esac
give_back "$SANDBOX"
