# common.sh - sourced by the workload scripts. Not meant to be run directly.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO/build"
SANDBOX="${EDR_SANDBOX:-/tmp/edr_sandbox}"

die() { echo "$(basename "$0"): $*" >&2; exit 1; }
log() { echo "$(basename "$0"): $*" >&2; }

need_bin() {
	[[ -x "$BIN/$1" ]] || die "$BIN/$1 not found - run 'make' in $REPO first"
}

# microseconds since the epoch (bash 5 builtin, no subprocess)
now_us() { local t=${EPOCHREALTIME/./}; echo "$((10#$t))"; }

# sleep until an absolute time in microseconds (from now_us)
sleep_until_us() {
	local d=$(( $1 - $(now_us) ))
	(( d > 0 )) && sleep "$(printf '%d.%06d' $((d / 1000000)) $((d % 1000000)))"
	return 0
}

# Files written under sudo belong to root; hand them back to the real user
# so the analysis scripts can read and delete them without sudo.
give_back() {
	[[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null
	return 0
}
