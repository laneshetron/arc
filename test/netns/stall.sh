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
# holds during a stall, 64), LAST_HOP_RTT (round trip between the relay
# and the AP, taken out of the ISP's 40 ms, default 0ms), LAST_HOP_SLOT
# (netem slot arguments for each direction of the last hop, such as "0ms
# 20ms": packets go out in bursts at random intervals, delay varying as on
# Wi-Fi but without reordering; needs LAST_HOP_RTT), CCS (congestion
# controls to try, default
# "cubic bbr"), MODES (default "plain arc arc-fecoff"; arc-split runs the
# client with -split-tcp always), UDP (a rate, such
# as 20M: report the loss % of a constant-rate UDP download instead of TCP
# goodput), STALLS (which rows to run, default "off on"), SHOW_LOGS (print
# the last relay and client status lines).
# Each run also prints the sender's TCP counters: retransmitted segments,
# SACK recoveries, timeouts, DSACKs, and undos of window reductions.
set -euo pipefail

BIN=$(cd "${1:?usage: stall.sh BIN_DIR [SECONDS] [REPS]}" && pwd)
DURATION=${2:-10}
REPS=${3:-3}
STALL=${STALL:-90ms}
PERIOD=${PERIOD:-455ms}
HOLD=${HOLD:-64}
LAST_HOP_RTT=${LAST_HOP_RTT:-0ms}
LAST_HOP_SLOT=${LAST_HOP_SLOT:-}
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
RELAY= RELAY_ARGS=unset
start_relay() { # start_relay [ARC_RELAY_FLAGS...]: (re)starts the relay unless already running with these flags
  [[ $RELAY_ARGS == "$*" ]] && return
  stop_client
  if [[ -n $RELAY ]]; then
    kill "$RELAY"; wait "$RELAY" 2>/dev/null || true
    wait_until 5 sh -c "! ip netns exec arc-r ip link show arc0"
  fi
  $R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -network 10.77.0.1/16 -status 1s "$@" >"$WORK/relay.log" 2>&1 &
  RELAY=$!
  PIDS+=("$RELAY")
  RELAY_ARGS="$*"
  wait_until 10 $R ip addr show arc0
}

CLIENT=
start_client() { # start_client FEC_MODE [ARC_CLIENT_FLAGS...]
  stop_client
  local fec=$1; shift
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -fec "$fec" -status 1s "$@" >"$WORK/client.log" 2>&1 &
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

# The "Internet" side (r1/i0) is the ISP: 20 ms each way less half of
# LAST_HOP_RTT, and a 400 Mbit/s downstream shaper with a deep queue. The client link (c0/r0) is the
# Wi-Fi: a token bucket at 800 Mbit/s that the staller switches between
# running and stopped. The bucket keeps its queue across changes (its
# limit never changes), so frames held during a stall go out when it ends.
# During a stall, the downlink (r0) bucket's queue shrinks to HOLD frames,
# so it keeps those and drops the rest; the uplink (c0) holds everything,
# as the station queues its own sends.
#
# With LAST_HOP_RTT, a netem at the root of each client-link queue delays
# packets before they reach the bucket: the relay is that far from the AP.
# (On the uplink the delay then comes before the station's queue instead
# of after it, so sends queued during a stall skip it when the stall ends.)
last_hop=$(awk -v r="${LAST_HOP_RTT%ms}" 'BEGIN { printf "%g", r / 2 }')
isp=$(awk -v h="$last_hop" 'BEGIN { printf "%g", 20 - h }')
if awk -v h="$last_hop" 'BEGIN { exit !(h < 0 || h > 20) }'; then
  echo "LAST_HOP_RTT must be between 0 and 40 ms" >&2
  exit 2
fi
$I tc qdisc replace dev i0 root netem delay "${isp}ms" rate 400mbit limit 100000
$R tc qdisc replace dev r1 root netem delay "${isp}ms" limit 100000
RUN="rate 800mbit burst 200kb"
STOP="rate 8bit burst 1600" # 1 byte/s: nothing more gets through
WIFI="root"
if [[ $last_hop != 0 ]]; then
  slot=()
  [[ -n $LAST_HOP_SLOT ]] && read -ra slot <<<"slot $LAST_HOP_SLOT"
  $R tc qdisc replace dev r0 root handle 1: netem delay "${last_hop}ms" "${slot[@]}" limit 100000
  $C tc qdisc replace dev c0 root handle 1: netem delay "${last_hop}ms" "${slot[@]}" limit 100000
  WIFI="parent 1:1"
fi
# A tbf change resets its fifo's limit to the tbf's own (here, in packets),
# so the stall shrinks the fifo after stopping the bucket. Running again
# sets the fifo's limit back explicitly as well, rather than rely on that,
# and check_wifi confirms it after setup and after each run: a queue left
# at HOLD would skew every later cell.
FIFO=10000
$R tc qdisc replace dev r0 $WIFI handle 10: tbf $RUN limit 10000
$R tc qdisc replace dev r0 parent 10:1 handle 20: pfifo limit $FIFO
$C tc qdisc replace dev c0 $WIFI handle 10: tbf $RUN limit 10000000
wifi() { # wifi RUN|STOP
  ip netns exec arc-r tc qdisc change dev r0 $WIFI handle 10: tbf $1 limit 10000
  if [[ $1 == "$STOP" ]]; then
    ip netns exec arc-r tc qdisc change dev r0 parent 10:1 handle 20: pfifo limit "$HOLD"
  else
    ip netns exec arc-r tc qdisc change dev r0 parent 10:1 handle 20: pfifo limit $FIFO
  fi
  ip netns exec arc-c tc qdisc change dev c0 $WIFI handle 10: tbf $1 limit 10000000
}
check_wifi() { # the AP's queue and both buckets are as configured, running
  local fifo tbf
  fifo=$($R tc qdisc show dev r0 | awk '$2 == "pfifo" { print $NF }')
  tbf=$($R tc qdisc show dev r0 | awk '$2 == "tbf" { for (i = 1; i < NF; i++) if ($i == "rate") print $(i + 1) }')
  if [[ $fifo != "${FIFO}p" || $tbf != 800Mbit ]]; then
    echo "AP queue not restored: pfifo limit $fifo, tbf rate $tbf" >&2
    exit 1
  fi
}
check_wifi
# The staller stops at the end of a cycle, when asked through a file, so
# that no tc command of its own lands after stop_stalls restores the link
# (one did, leaving the AP's queue at HOLD frames for the next run).
start_stalls() {
  local stall=${STALL%ms} period=${PERIOD%ms}
  rm -f "$WORK/stop-stalls"
  (
    until [[ -e $WORK/stop-stalls ]]; do
      wifi "$STOP"
      sleep "$(awk -v s="$stall" 'BEGIN { print s / 1000 }')"
      wifi "$RUN"
      sleep "$(awk -v s="$stall" -v p="$period" 'BEGIN { print (p - s) / 1000 }')"
    done
  ) &
  STALLER=$!
}
stop_stalls() {
  if [[ -n $STALLER ]]; then
    touch "$WORK/stop-stalls"
    wait "$STALLER" 2>/dev/null || true
    STALLER=
  fi
  wifi "$RUN"
  check_wifi
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
udp_loss() { # udp_loss RATE: prints the loss % of a constant-rate UDP download
  $C timeout $((DURATION + 30)) iperf3 -c "$TARGET" -u -b "$1" -l 1200 -t "$DURATION" -R -f m >"$WORK/iperf.log" 2>&1 || { echo 100; return; }
  grep receiver "$WORK/iperf.log" | tail -1 | grep -oE '\(([0-9.e+-]+)%\)' | tr -d '(%)'
}
r0_drops() { $R tc -s qdisc show dev r0 | awk '/^qdisc tbf/ { tbf = 1 } tbf && /dropped/ { for (i = 1; i <= NF; i++) if ($i == "(dropped") { gsub(",", "", $(i + 1)); print $(i + 1); exit } }'; }
# The sender's TCP counters (the download's sender is iperf3 in arc-i), as
# absolute values: nstat's history file is shared across namespaces.
TCP_COUNTERS="TcpRetransSegs TcpExtTCPSackRecovery TcpExtTCPTimeouts TcpExtTCPDSACKRecv TcpExtTCPDSACKUndo TcpExtTCPLossUndo"
tcp_counters() { $I nstat -asz $TCP_COUNTERS | awk 'NR > 1 { v[$1] = $2 } END { n = split(ENVIRON["TCP_COUNTERS"], k, " "); for (i = 1; i <= n; i++) printf "%d ", v[k[i]]; print "" }'; }
export TCP_COUNTERS
median() { sort -g | awk '{v[NR] = $1} END {print (NR ? v[int((NR + 1) / 2)] : "-")}'; }

available=$($I sysctl -n net.ipv4.tcp_available_congestion_control)
ROWS=()
for cc in ${CCS:-cubic bbr}; do
  if [[ " $available " != *" $cc "* ]]; then
    if [[ -n ${CCS:-} ]]; then
      echo "FAIL: $cc requested but not available (have: $available; try modprobe tcp_$cc)" >&2
      exit 1
    fi
    echo "skipping $cc: not available (have: $available)"
    continue
  fi
  for mode in ${MODES:-plain arc arc-fecoff}; do
    for stalls in ${STALLS:-off on}; do
      downs=() drops=() retx=() undo=()
      for rep in $(seq "$REPS"); do
        case $mode in
          plain) stop_client; use_plain ;;
          arc) start_relay; start_client auto ;;
          arc-fecoff) start_relay; start_client off ;;
          arc-split) start_relay; start_client auto -split-tcp always ;;
        esac
        [[ $stalls == on ]] && start_stalls
        d0=$(r0_drops)
        read -ra t0 <<<"$(tcp_counters)"
        if [[ -n ${UDP:-} ]]; then
          downs+=("$(udp_loss "$UDP")")
        else
          downs+=("$(tcp -R -C "$cc")")
        fi
        drops+=("$(($(r0_drops) - d0))")
        read -ra t1 <<<"$(tcp_counters)"
        d=() # retransmitted segments, SACK recoveries, timeouts, DSACKs received, DSACK and loss undos
        for i in "${!t1[@]}"; do d+=("$((t1[i] - t0[i]))"); done
        retx+=("${d[0]}")
        undo+=("$((d[4] + d[5]))")
        echo "  run $rep: retransmits ${d[0]}, recoveries ${d[1]}, timeouts ${d[2]}, DSACKs ${d[3]}, undos $((d[4] + d[5]))"
        if [[ -n ${SHOW_LOGS:-} && $mode != plain ]]; then
          grep "msg=path" "$WORK/client.log" | tail -1 | sed 's/^/    client: /'
        fi
        stop_stalls
      done
      ROWS+=("$(printf '%-6s %-11s %-7s %12s %10s %10s %8s' "$cc" "$mode" "$stalls" \
        "$(printf '%s\n' "${downs[@]}" | median)" "$(printf '%s\n' "${drops[@]}" | median)" \
        "$(printf '%s\n' "${retx[@]}" | median)" "$(printf '%s\n' "${undo[@]}" | median)")")
      echo "measured: $cc $mode stalls $stalls: down ${downs[*]} (AP drops ${drops[*]})"
    done
  done
done
stop_client
if [[ -n ${SHOW_LOGS:-} ]]; then
  grep -E "resends|path" "$WORK/relay.log" | tail -20
  tail -20 "$WORK/client.log"
fi

echo
echo "Download at 40 ms RTT (last hop $LAST_HOP_RTT) through a 400 Mbit/s ISP and 800 Mbit/s Wi-Fi,"
echo "stalls of $STALL every $PERIOD with $HOLD frames held at the AP; medians of $REPS runs of $DURATION s;"
echo "$(nproc) CPUs; kernel $(uname -r). retx: the sender's retransmitted segments; undo: its DSACK and loss undos."
printf '%-6s %-11s %-7s %12s %10s %10s %8s\n' "cc" "path" "stalls" "down Mbit/s" "AP drops" "retx" "undo"
printf '%s\n' "${ROWS[@]}"
