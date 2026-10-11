#!/usr/bin/env bash
# Throughput comparison of ARC and kernel WireGuard over the lib.sh
# topology (run as root on Linux with the wireguard module and
# wireguard-tools). Each tunnel carries traffic from the client namespace
# to the "internet" namespace through the relay, which masquerades it;
# iperf3 measures TCP goodput both ways with 1 and 4 streams.
#
# WireGuard runs at its default MTU (1420) and at ARC's tunnel MTU (1280),
# so the comparison can separate per-packet cost from packet size.
#
# Usage: bench.sh BIN_DIR [SECONDS]
set -euo pipefail

BIN=$(cd "${1:?usage: bench.sh BIN_DIR [SECONDS]}" && pwd)
DURATION=${2:-10}
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
trap 'teardown_topology; rm -rf "$WORK"' EXIT
TARGET=192.168.20.2

setup_topology 10.77.0.0/16 10.88.0.0/24
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"

rx_bytes() { $R cat /sys/class/net/r0/statistics/rx_bytes; }

# measure NAME: runs iperf3 in four modes and appends a result row. The
# last column is bytes received on the relay's client-facing link per byte
# of uplink goodput: a check that the tunnel really carried the traffic,
# and a measure of its encapsulation overhead.
ROWS=()
measure() {
  local name=$1 row="" args before after mbps wire=""
  for args in "-P 1" "-P 4" "-P 1 -R" "-P 4 -R"; do
    before=$(rx_bytes)
    # shellcheck disable=SC2086
    $C iperf3 -c "$TARGET" -t "$DURATION" -f m $args >"$WORK/run.log" 2>&1 ||
      { cat "$WORK/run.log"; return 1; }
    after=$(rx_bytes)
    mbps=$(grep receiver "$WORK/run.log" | tail -1 | awk '{print $(NF-2)}')
    row+=$(printf ' %10s' "$mbps")
    if [[ -z $wire ]]; then
      wire=$(awk -v b=$((after - before)) -v m="$mbps" -v t="$DURATION" 'BEGIN { printf "%.3f", b * 8 / (m * 1e6 * t) }')
    fi
  done
  ROWS+=("$(printf '%-22s%s %10s' "$name" "$row" "$wire")")
  echo "measured $name"
}

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
ARC_CLIENT=$!
PIDS+=("$ARC_CLIENT")
wait_until 10 grep -q "session established" "$WORK/client.log" ||
  { cat "$WORK/client.log" "$WORK/relay.log"; exit 1; }
measure "arc (mtu 1280)"
kill "$ARC_CLIENT"; wait "$ARC_CLIENT" 2>/dev/null || true
$C ip route del 192.168.20.0/24 2>/dev/null || true

# --- WireGuard -----------------------------------------------------------
(umask 077; wg genkey >"$WORK/wg-relay.key"; wg genkey >"$WORK/wg-client.key")
ip -n arc-r link add wg0 type wireguard
$R wg set wg0 listen-port 51820 private-key "$WORK/wg-relay.key" \
  peer "$(wg pubkey <"$WORK/wg-client.key")" allowed-ips 10.88.0.2/32
ip -n arc-r addr add 10.88.0.1/24 dev wg0
ip -n arc-c link add wg0 type wireguard
$C wg set wg0 private-key "$WORK/wg-client.key" \
  peer "$(wg pubkey <"$WORK/wg-relay.key")" allowed-ips 0.0.0.0/0 endpoint 192.168.10.2:51820
ip -n arc-c addr add 10.88.0.2/24 dev wg0
for mtu in 1420 1280; do
  ip -n arc-r link set wg0 mtu "$mtu" up
  ip -n arc-c link set wg0 mtu "$mtu" up
  ip -n arc-c route replace 192.168.20.0/24 dev wg0
  wait_until 5 $C ping -c1 -W1 "$TARGET" || { echo "WireGuard tunnel did not come up"; exit 1; }
  measure "wireguard (mtu $mtu)"
done

echo
echo "TCP goodput, Mbit/s ($DURATION s per run; $(nproc) CPUs; kernel $(uname -r))"
printf '%-22s %10s %10s %10s %10s %10s\n' "" "up x1" "up x4" "down x1" "down x4" "wire/good"
printf '%s\n' "${ROWS[@]}"
