#!/usr/bin/env bash
# Throughput and CPU-cost comparison of ARC and kernel WireGuard over the
# lib.sh topology (run as root on Linux with the wireguard module,
# wireguard-tools, ethtool, and iperf3 >= 3.16 so parallel streams run on
# separate threads).
#
# Each tunnel carries traffic from the client namespace to the "internet"
# namespace through the relay, which masquerades it. Rows:
#
#   plain routing     no tunnel: the environment's ceiling
#   arc               TUN offloads (TSO/GSO/GRO) on, as arc-client/relay run
#   arc, no offloads  the same with offloads disabled on both TUN devices
#   wireguard 1420    kernel WireGuard at its default MTU
#   wireguard 1280    at ARC's tunnel MTU
#
# Columns: TCP goodput (Mbit/s) up and down with 1 and 4 streams, then for
# the single-stream uplink run: CPU-seconds per GB moved (all cores, both
# tunnel ends, iperf3 included), context switches and inter-processor
# interrupts per MB of goodput, and bytes on the relay's client-facing link
# per byte of goodput (which checks that the tunnel carried the traffic).
# Everything is normalized by goodput, not by link packets: with GSO a veth
# counts a whole super-packet, and its headers, once, so per-packet and
# overhead figures from link counters would flatter ARC and plain routing.
# The wire/good column is therefore a lower bound on true per-packet
# overhead whenever GSO is in play. All counters are system-wide,
# so run nothing else alongside. Treat results as relative: both ends share
# one machine, and in a VM cross-CPU wakeups are unusually expensive.
#
# Usage: bench.sh BIN_DIR [SECONDS]
set -euo pipefail

BIN=$(cd "${1:?usage: bench.sh BIN_DIR [SECONDS]}" && pwd)
DURATION=${2:-10}
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
trap 'teardown_topology; rm -rf "$WORK"' EXIT
TARGET=192.168.20.2
HZ=$(getconf CLK_TCK)

setup_topology 10.77.0.0/16 10.88.0.0/24
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"

link_stat() { $R cat "/sys/class/net/r0/statistics/$1"; }
cpu_ticks() { awk '/^cpu / { print $2 + $3 + $4 + $7 + $8 }' /proc/stat; } # user nice system irq softirq
ctxt() { awk '/^ctxt/ { print $2 }' /proc/stat; }
ipis() { awk '/^ *IPI[0-9]+:/ { for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+$/) s += $i } END { print s + 0 }' /proc/interrupts; }

iperf() { # iperf ARGS...: prints receiver Mbit/s
  # shellcheck disable=SC2068
  $C iperf3 -c "$TARGET" -t "$DURATION" -f m $@ >"$WORK/run.log" 2>&1 || { cat "$WORK/run.log" >&2; return 1; }
  grep receiver "$WORK/run.log" | tail -1 | awk '{print $(NF-2)}'
}

ROWS=()
measure() { # measure NAME
  local name=$1 b0 p0 t0 c0 i0 up1 cost
  b0=$(link_stat rx_bytes) t0=$(cpu_ticks) c0=$(ctxt) i0=$(ipis)
  up1=$(iperf -P 1)
  cost=$(awk -v mb="$up1" -v d="$DURATION" -v hz="$HZ" \
    -v b=$(($(link_stat rx_bytes) - b0)) \
    -v t=$(($(cpu_ticks) - t0)) -v c=$(($(ctxt) - c0)) -v i=$(($(ipis) - i0)) 'BEGIN {
      good = mb * 1e6 / 8 * d
      printf "%9.2f %9.0f %9.0f %9.3f", t / hz / (good / 1e9), c / (good / 1e6), i / (good / 1e6), b / good
    }')
  ROWS+=("$(printf '%-20s %8s %8s %8s %8s %s' "$name" "$up1" "$(iperf -P 1 -R)" "$(iperf -P 4)" "$(iperf -P 4 -R)" "$cost")")
  echo "measured $name" >&2
}

# --- control: plain routing, no tunnel ---------------------------------------
$C ip route replace 192.168.20.0/24 via 192.168.10.2 dev c0 onlink
$I ip route replace 192.168.10.0/24 via 192.168.20.1
measure "plain routing"
$C ip route del 192.168.20.0/24
$I ip route del 192.168.10.0/24

# --- ARC -----------------------------------------------------------------
"$BIN/arc-relay" genkey >"$WORK/relay.key"
echo bench-token >"$WORK/tokens"
cp "$WORK/tokens" "$WORK/token"
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0
$C "$BIN/arc-client" run -relay 192.168.10.2:4433 \
  -relay-key "$("$BIN/arc-relay" pubkey <"$WORK/relay.key")" \
  -token-file "$WORK/token" -route 192.168.20.0/24 >"$WORK/client.log" 2>&1 &
PIDS+=($!)
wait_until 10 grep -q "session established" "$WORK/client.log" ||
  { cat "$WORK/client.log" "$WORK/relay.log"; exit 1; }
measure "arc"
for ns in arc-c arc-r; do
  ip netns exec "$ns" ethtool -K arc0 tso off gso off gro off tx off >/dev/null 2>&1
done
measure "arc, no offloads"
kill "${PIDS[@]}"; wait 2>/dev/null || true
PIDS=()
$C ip route del 192.168.20.0/24 2>/dev/null || true

# --- WireGuard -----------------------------------------------------------
# Ubuntu 26.04 confines wg with AppArmor to key files under /etc/wireguard,
# so the private keys reach it through a pipe instead of a path.
(umask 077; wg genkey >"$WORK/wg-relay.key"; wg genkey >"$WORK/wg-client.key")
ip -n arc-r link add wg0 type wireguard
$R wg set wg0 listen-port 51820 private-key <(cat "$WORK/wg-relay.key") \
  peer "$(wg pubkey <"$WORK/wg-client.key")" allowed-ips 10.88.0.2/32
ip -n arc-r addr add 10.88.0.1/24 dev wg0
ip -n arc-c link add wg0 type wireguard
$C wg set wg0 private-key <(cat "$WORK/wg-client.key") \
  peer "$(wg pubkey <"$WORK/wg-relay.key")" allowed-ips 0.0.0.0/0 endpoint 192.168.10.2:51820
ip -n arc-c addr add 10.88.0.2/24 dev wg0
for mtu in 1420 1280; do
  ip -n arc-r link set wg0 mtu "$mtu" up
  ip -n arc-c link set wg0 mtu "$mtu" up
  ip -n arc-c route replace 192.168.20.0/24 dev wg0
  wait_until 5 $C ping -c1 -W1 "$TARGET" || { echo "WireGuard tunnel did not come up"; exit 1; }
  measure "wireguard $mtu"
done

echo
echo "$DURATION s per run; $(nproc) CPUs; kernel $(uname -r); $($C iperf3 --version | head -1)"
printf '%-20s %8s %8s %8s %8s %9s %9s %9s %9s\n' "" "Mbit/s" "" "" "" "single-stream uplink:" "" "" ""
printf '%-20s %8s %8s %8s %8s %9s %9s %9s %9s\n' "" "up x1" "down x1" "up x4" "down x4" "cpu-s/GB" "ctx/MB" "ipi/MB" "wire/good"
printf '%s\n' "${ROWS[@]}"
echo "(wire/good counts GSO super-packet headers once, so it understates overhead when GSO is used)"
