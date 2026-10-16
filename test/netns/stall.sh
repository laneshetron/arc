#!/usr/bin/env bash
# Periodic link stalls, as a Mac's Wi-Fi shows while AWDL (AirDrop,
# Continuity) or a scan takes the radio off-channel: every PERIOD the link
# stops for STALL. The access point holds frames for the absent station,
# up to a fixed number of them, and drops the rest; the station queues its
# own sends until it is back. (On a real network, a 100 Hz ping saw these
# stalls only as delay, while 2000 packets/s lost ~110 of every ~180 sent
# in a stall: a frame count, not a byte budget.) Compares TCP download
# goodput through plain routing and through ARC over one link of the
# lib.sh topology at 40 ms RTT. Each cell is the median of REPS runs.
# Stall timing is approximate: each switch runs a few tc commands. Nothing
# is asserted.
#
# Usage: stall.sh BIN_DIR [SECONDS] [REPS]   (defaults 10 and 3)
# Environment: STALL (90ms), PERIOD (455ms), HOLD (frames the access point
# holds during a stall, 64), CCS (congestion controls to try, default
# "cubic bbr"), MODES (default "plain arc arc-fecoff").
set -euo pipefail

BIN=$(cd "${1:?usage: stall.sh BIN_DIR [SECONDS] [REPS]}" && pwd)
DURATION=${2:-10}
REPS=${3:-3}
STALL=${STALL:-90ms}
PERIOD=${PERIOD:-455ms}
HOLD=${HOLD:-64}
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
TARGET=192.168.20.2
STALLER=
trap '[[ -n $STALLER ]] && kill "$STALLER" 2>/dev/null; teardown_topology; rm -rf "$WORK"' EXIT

if ! netem_available; then
  echo "SKIP: this kernel has no netem (sch_netem)"
  exit 0
fi
setup_topology 10.77.0.0/16
$I ip route add 192.168.10.0/24 via 192.168.20.1
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"

"$BIN/arc-relay" genkey >"$WORK/relay.key"
echo stall-token >"$WORK/tokens"
cp "$WORK/tokens" "$WORK/token"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0

CLIENT=
start_client() { # start_client FEC_MODE
  stop_client
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -fec "$1" -status 1s >"$WORK/client.log" 2>&1 &
  CLIENT=$!
  PIDS+=("$CLIENT")
  wait_until 10 grep -q "session established" "$WORK/client.log" || { cat "$WORK/client.log"; exit 1; }
  sleep 1
}
stop_client() {
  if [[ -n $CLIENT ]]; then kill "$CLIENT"; wait "$CLIENT" 2>/dev/null || true; CLIENT=; fi
  $C ip route del 192.168.20.0/24 2>/dev/null || true
}
use_plain() { $C ip route replace 192.168.20.0/24 via 192.168.10.2 dev c0 onlink; }

# The "Internet" side (r1/i0) is the ISP: 20 ms each way, and a 400 Mbit/s
# downstream shaper with a deep queue. The client link (c0/r0) is the
# Wi-Fi: a token bucket at 800 Mbit/s that the staller switches between
# running and stopped. The bucket keeps its queue across changes (its
# limit never changes), so frames held during a stall go out when it ends.
# During a stall, the downlink (r0) bucket's queue shrinks to HOLD frames,
# so it keeps those and drops the rest; the uplink (c0) holds everything,
# as the station queues its own sends.
$I tc qdisc replace dev i0 root netem delay 20ms rate 400mbit limit 100000
$R tc qdisc replace dev r1 root netem delay 20ms limit 100000
RUN="rate 800mbit burst 200kb"
STOP="rate 8kbit burst 1600"
# A tbf change resets its fifo's limit to the tbf's own (here, in packets),
# so the stall shrinks the fifo after stopping the bucket.
$R tc qdisc replace dev r0 root handle 10: tbf $RUN limit 10000
$R tc qdisc replace dev r0 parent 10:1 handle 20: pfifo limit 10000
$C tc qdisc replace dev c0 root handle 10: tbf $RUN limit 10000000
wifi() { # wifi RUN|STOP
  ip netns exec arc-r tc qdisc change dev r0 root handle 10: tbf $1 limit 10000
  if [[ $1 == "$STOP" ]]; then
    ip netns exec arc-r tc qdisc change dev r0 parent 10:1 handle 20: pfifo limit "$HOLD"
  fi
  ip netns exec arc-c tc qdisc change dev c0 root handle 10: tbf $1 limit 10000000
}
start_stalls() {
  local stall=${STALL%ms} period=${PERIOD%ms}
  (
    while :; do
      wifi "$STOP"
      sleep "$(awk -v s="$stall" 'BEGIN { print s / 1000 }')"
      wifi "$RUN"
      sleep "$(awk -v s="$stall" -v p="$period" 'BEGIN { print (p - s) / 1000 }')"
    done
  ) &
  STALLER=$!
}
stop_stalls() {
  if [[ -n $STALLER ]]; then kill "$STALLER"; wait "$STALLER" 2>/dev/null || true; STALLER=; fi
  wifi "$RUN"
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
r0_drops() { $R tc -s qdisc show dev r0 | awk '/dropped/ { for (i = 1; i <= NF; i++) if ($i == "(dropped") { gsub(",", "", $(i + 1)); print $(i + 1); exit } }'; }
median() { sort -g | awk '{v[NR] = $1} END {print (NR ? v[int((NR + 1) / 2)] : "-")}'; }

available=$($I sysctl -n net.ipv4.tcp_available_congestion_control)
ROWS=()
for cc in ${CCS:-cubic bbr}; do
  if [[ " $available " != *" $cc "* ]]; then
    echo "skipping $cc: not available (have: $available)"
    continue
  fi
  for mode in ${MODES:-plain arc arc-fecoff}; do
    for stalls in off on; do
      downs=() drops=()
      for rep in $(seq "$REPS"); do
        case $mode in
          plain) stop_client; use_plain ;;
          arc) start_client auto ;;
          arc-fecoff) start_client off ;;
        esac
        [[ $stalls == on ]] && start_stalls
        d0=$(r0_drops)
        downs+=("$(tcp -R -C "$cc")")
        drops+=("$(($(r0_drops) - d0))")
        stop_stalls
      done
      ROWS+=("$(printf '%-6s %-11s %-7s %12s %10s' "$cc" "$mode" "$stalls" \
        "$(printf '%s\n' "${downs[@]}" | median)" "$(printf '%s\n' "${drops[@]}" | median)")")
      echo "measured: $cc $mode stalls $stalls: down ${downs[*]} (AP drops ${drops[*]})"
    done
  done
done
stop_client

echo
echo "Download at 40 ms RTT through a 400 Mbit/s ISP and 800 Mbit/s Wi-Fi, stalls of $STALL every $PERIOD with $HOLD frames held at the AP;"
echo "medians of $REPS runs of $DURATION s; $(nproc) CPUs; kernel $(uname -r)"
printf '%-6s %-11s %-7s %12s %10s\n' "cc" "path" "stalls" "down Mbit/s" "AP drops"
printf '%s\n' "${ROWS[@]}"
