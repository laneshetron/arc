#!/usr/bin/env bash
# Split TCP evaluation (spec §11.3) over one link of the lib.sh topology, at
# 40 ms RTT: TCP goodput up and down through ARC with -split-tcp off and
# always, under uniform and bursty loss up to 90% each way. Each cell is
# the median of REPS runs. Nothing is asserted: this is for deciding when
# to split, not for CI.
#
# Usage: split.sh BIN_DIR [SECONDS] [REPS]   (defaults 10 and 3)
# Environment: ONLY, an extended regex, limits the scenarios to those whose
# names match; MODES (default "off always") the -split-tcp modes, and
# "plain" for plain routing as a control.
set -euo pipefail

BIN=$(cd "${1:?usage: split.sh BIN_DIR [SECONDS] [REPS]}" && pwd)
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
echo split-token >"$WORK/tokens"
cp "$WORK/tokens" "$WORK/token"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0

CLIENT=
start_client() { # start_client SPLIT_MODE, or plain for plain routing (no tunnel)
  if [[ -n $CLIENT ]]; then kill "$CLIENT"; wait "$CLIENT" 2>/dev/null || true; CLIENT=; fi
  $C ip route del 192.168.20.0/24 2>/dev/null || true
  if [[ $1 == plain ]]; then
    $C ip route add 192.168.20.0/24 via 192.168.10.2 dev c0 onlink
    return
  fi
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -split-tcp "$1" >"$WORK/client.log" 2>&1 &
  CLIENT=$!
  PIDS+=("$CLIENT")
  wait_until 10 grep -q "session established" "$WORK/client.log" || { cat "$WORK/client.log"; exit 1; }
  sleep 1
}

tcp() { # tcp [IPERF_ARGS...]: prints goodput in Mbit/s, or 0
  # iperf3's own timeouts are long at heavy loss; bound the run, and count a
  # run that cannot even set up its control connection as 0.
  if $C timeout $((DURATION + 30)) iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m --connect-timeout 10000 "$@" \
    >"$WORK/iperf.log" 2>&1; then
    grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
  else
    echo 0
  fi
}

median() { sort -g | awk '{v[NR] = $1} END {print (NR ? v[int((NR + 1) / 2)] : "-")}'; }

SCENARIOS=(
  "clean|delay 20ms"
  "loss 1%|delay 20ms loss 1%"
  "loss 5%|delay 20ms loss 5%"
  # Gilbert-Elliott bursts at the same average rates (mean burst 1/r):
  # p = loss * r / (1 - loss).
  "bursty 1% (4)|delay 20ms loss gemodel 0.25% 25%"
  "bursty 5% (10)|delay 20ms loss gemodel 0.53% 10%"
  "bursty 5% (30)|delay 20ms loss gemodel 0.175% 3.33%"
  "bursty 20% (10)|delay 20ms loss gemodel 2.5% 10%"
  "loss 20%|delay 20ms loss 20%"
  "loss 50%|delay 20ms loss 50%"
  "loss 90%|delay 20ms loss 90%"
)
ROWS=()
for sc in "${SCENARIOS[@]}"; do
  name=${sc%%|*} args=${sc#*|}
  [[ -z ${ONLY:-} || $name =~ $ONLY ]] || continue
  for mode in ${MODES:-off always}; do
    ups=() downs=()
    for rep in $(seq "$REPS"); do
      start_client "$mode"
      # shellcheck disable=SC2086
      impair 0 $args
      sleep 2 # loss estimates form before the measured runs
      ups+=("$(tcp)")
      downs+=("$(tcp -R)")
      unimpair 0
      # iperf3's server can stay busy with a stranded run at heavy loss.
      $I pkill -x iperf3 || true
      wait_until 5 sh -c "! pgrep -x iperf3 >/dev/null"
      $I iperf3 -s -D --logfile "$WORK/iperf-server.log"
    done
    ROWS+=("$(printf '%-16s %-7s %10s %10s' "$name" "$mode" \
      "$(printf '%s\n' "${ups[@]}" | median)" "$(printf '%s\n' "${downs[@]}" | median)")")
    echo "measured: $name, split $mode: up ${ups[*]}, down ${downs[*]}"
  done
done

echo
echo "Split TCP over one link at 40 ms RTT, loss in both directions; medians of $REPS runs of $DURATION s;"
echo "$(nproc) CPUs; kernel $(uname -r)"
printf '%-16s %-7s %10s %10s\n' "scenario" "split" "up Mbit/s" "down Mbit/s"
printf '%s\n' "${ROWS[@]}"
