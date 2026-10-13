#!/usr/bin/env bash
# Forward error correction evaluation (spec §11.2) over one link of the
# lib.sh topology, at 40 ms RTT: TCP goodput up and down, ping RTT during
# the uplink transfer, and wire overhead, with FEC off, auto, and always,
# under uniform and bursty loss. Each cell is the median of REPS runs,
# since bursty loss varies a lot between runs. Nothing is asserted: this
# is for deciding FEC's default, not for CI.
#
# Usage: fec.sh BIN_DIR [SECONDS] [REPS]   (defaults 10 and 3)
set -euo pipefail

BIN=$(cd "${1:?usage: fec.sh BIN_DIR [SECONDS] [REPS]}" && pwd)
DURATION=${2:-10}
REPS=${3:-3}
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
TARGET=192.168.20.2
trap 'teardown_topology; rm -rf "$WORK"' EXIT

if ! netem_available; then
  echo "SKIP: this kernel has no netem (sch_netem)"
  exit 0
fi
setup_topology 10.77.0.0/16
$I ip route add 192.168.10.0/24 via 192.168.20.1
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"

"$BIN/arc-relay" genkey >"$WORK/relay.key"
echo fec-token >"$WORK/tokens"
cp "$WORK/tokens" "$WORK/token"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0

CLIENT=
start_client() { # start_client FEC_MODE
  if [[ -n $CLIENT ]]; then kill "$CLIENT"; wait "$CLIENT" 2>/dev/null || true; fi
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -fec "$1" >"$WORK/client.log" 2>&1 &
  CLIENT=$!
  PIDS+=("$CLIENT")
  wait_until 10 grep -q "session established" "$WORK/client.log" || { cat "$WORK/client.log"; exit 1; }
  sleep 1
}

tcp() { # tcp [IPERF_ARGS...]: prints goodput in Mbit/s, or 0
  local try
  for try in 1 2; do
    if $C timeout $((DURATION + 30)) iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m "$@" >"$WORK/iperf.log" 2>&1; then
      grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
      return
    fi
    sleep 1
  done
  echo 0
}

txbytes() { $C cat /sys/class/net/c0/statistics/tx_bytes; }
rxbytes() { $C cat /sys/class/net/c0/statistics/rx_bytes; }
median() { sort -g | awk '{v[NR] = $1} END {print (NR ? v[int((NR + 1) / 2)] : "-")}'; }

SCENARIOS=(
  "clean|delay 20ms"
  "loss 1%|delay 20ms loss 1%"
  "loss 5%|delay 20ms loss 5%"
  "bursty 1% (4)|delay 20ms loss gemodel 0.25% 25%"
  "bursty 5% (10)|delay 20ms loss gemodel 0.53% 10%"
)
ROWS=()
for sc in "${SCENARIOS[@]}"; do
  name=${sc%%|*} args=${sc#*|}
  for mode in off auto always; do
    ups=() downs=() pings=() over_up=() over_down=()
    for rep in $(seq "$REPS"); do
      start_client "$mode"
      # shellcheck disable=SC2086
      impair 0 $args
      sleep 2 # loss estimates form before the measured runs
      b=$(txbytes)
      $C timeout 60 ping -q -c 40 -i 0.25 -W 3 "$TARGET" >"$WORK/ping.log" 2>&1 &
      ping_pid=$!
      up=$(tcp)
      wait "$ping_pid" || true
      wire=$(($(txbytes) - b))
      ups+=("$up")
      over_up+=("$(awk -v w="$wire" -v g="$up" -v d="$DURATION" 'BEGIN { printf "%.3f", (g > 0 ? w * 8 / (g * 1e6 * (d + 2)) : 0) }')")
      pings+=("$(grep -oE 'rtt [^=]+= [0-9./]+' "$WORK/ping.log" | awk -F'= ' '{print $2}' | awk -F/ '{print $2}')")
      b=$(rxbytes)
      down=$(tcp -R)
      wire=$(($(rxbytes) - b))
      downs+=("$down")
      over_down+=("$(awk -v w="$wire" -v g="$down" -v d="$DURATION" 'BEGIN { printf "%.3f", (g > 0 ? w * 8 / (g * 1e6 * (d + 2)) : 0) }')")
      unimpair 0
    done
    ROWS+=("$(printf '%-16s %-7s %10s %10s %12s %10s %10s' "$name" "$mode" \
      "$(printf '%s\n' "${ups[@]}" | median)" "$(printf '%s\n' "${downs[@]}" | median)" \
      "$(printf '%s\n' "${pings[@]}" | median)" \
      "$(printf '%s\n' "${over_up[@]}" | median)" "$(printf '%s\n' "${over_down[@]}" | median)")")
    echo "measured: $name, fec $mode: up ${ups[*]}, down ${downs[*]}"
  done
done

echo
echo "FEC over one link at 40 ms RTT; medians of $REPS runs of $DURATION s; $(nproc) CPUs; kernel $(uname -r)"
echo "wire/good: bytes on the link per byte of TCP goodput (includes ARC, UDP, IP headers and FEC repairs)"
printf '%-16s %-7s %10s %10s %12s %10s %10s\n' "scenario" "fec" "up Mbit/s" "down Mbit/s" "ping ms (up)" "wire/good" "(down)"
printf '%s\n' "${ROWS[@]}"
