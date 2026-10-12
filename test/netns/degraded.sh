#!/usr/bin/env bash
# Degraded-network tests and measurements over the lib.sh topology (run as
# root on Linux with netem, wireguard-tools, and iperf3).
#
# Part 1 runs plain routing (a control: what the impairment alone does to
# TCP), ARC, and kernel WireGuard over link 0 under a set of netem
# impairments, reporting TCP goodput, ping loss, and ping RTT.
#
# Part 2 runs ARC over both links and measures multipath behavior: failover
# time when the busy link is blackholed (clean and at 100 ms RTT), and
# whether traffic leaves the busy link when it becomes lossy but stays alive.
#
# Part 3 compares ARC's UDP and TLS/TCP carriers on one link, measuring TCP
# goodput and the ping RTT during the transfer (head-of-line blocking).
#
# Assertions are deliberately loose so they hold on shared CI runners:
#   - every tunnel carries traffic in every scenario
#   - on a 50 Mbit/s bottleneck ARC reaches >= 70% of plain routing
#   - failover from a blackholed link completes within 2 s
#   - traffic leaves a busy link with 5% or 30% loss when the other is clean
#   - 4 TCP flows over two 50 Mbit/s links get at least 1.4x one link's
#     goodput, uploading and downloading
#   - with both links at 5% loss (RTT ~0 and 40 ms), -redundancy auto at least halves ping loss
#     and at least doubles TCP goodput
#   - a session comes up within 15 s with both links at 70% loss
#   - TCP runs over the TLS/TCP carrier when UDP is blocked (Part 3)
#   - a session survives about 80 s of 90% loss on both links and carries
#     traffic again within 5 s of the loss clearing
#
# Usage: degraded.sh BIN_DIR [SECONDS]   (SECONDS per TCP run, default 10)
set -euo pipefail

BIN=$(cd "${1:?usage: degraded.sh BIN_DIR [SECONDS]}" && pwd)
DURATION=${2:-10}
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
TARGET=192.168.20.2
failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
trap 'teardown_topology; rm -rf "$WORK"' EXIT

if ! netem_available; then
  echo "SKIP: this kernel has no netem (sch_netem)"
  exit 0
fi
setup_topology 10.77.0.0/16 10.88.0.0/24
# UDP datagrams the kernel dropped because a socket's receive buffer was full.
rcvbuf_errors() { $1 awk '/^Udp:/ && ++n == 2 { print $6 }' /proc/net/snmp; }
$I ip route add 192.168.10.0/24 via 192.168.20.1 # return route for plain routing
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"

# --- tunnels, all up at once; a route switch picks which one carries traffic
"$BIN/arc-relay" genkey >"$WORK/relay.key"
echo degraded-token >"$WORK/tokens"
cp "$WORK/tokens" "$WORK/token"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
"$BIN/arc-relay" gencert -hosts 192.168.10.2 -cert "$WORK/relay.crt" -key "$WORK/relay.tls.key"
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -tls-listen 192.168.10.2:8443 -tls-cert "$WORK/relay.crt" -tls-key "$WORK/relay.tls.key" \
  -network 10.77.0.1/16 -status 1s >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0
$C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
  -token-file "$WORK/token" >"$WORK/client1.log" 2>&1 &
ARC1=$!
PIDS+=("$ARC1")
wait_until 10 grep -q "session established" "$WORK/client1.log" ||
  { cat "$WORK/client1.log"; exit 1; }

(umask 077; wg genkey >"$WORK/wg-relay.key"; wg genkey >"$WORK/wg-client.key")
ip -n arc-r link add wg0 type wireguard
$R wg set wg0 listen-port 51820 private-key "$WORK/wg-relay.key" \
  peer "$(wg pubkey <"$WORK/wg-client.key")" allowed-ips 10.88.0.2/32
ip -n arc-r addr add 10.88.0.1/24 dev wg0
ip -n arc-r link set wg0 up
ip -n arc-c link add wg0 type wireguard
$C wg set wg0 private-key "$WORK/wg-client.key" \
  peer "$(wg pubkey <"$WORK/wg-relay.key")" persistent-keepalive 10 \
  allowed-ips 0.0.0.0/0 endpoint 192.168.10.2:51820
ip -n arc-c addr add 10.88.0.2/24 dev wg0
ip -n arc-c link set wg0 up

use() { # use plain|arc|wireguard
  case $1 in
    plain) $C ip route replace 192.168.20.0/24 via 192.168.10.2 dev c0 onlink ;;
    arc) $C ip route replace 192.168.20.0/24 dev arc0 ;;
    wireguard) $C ip route replace 192.168.20.0/24 dev wg0 ;;
  esac
}

tcp_up() { # tcp_up [IPERF_ARGS...]: prints TCP goodput in Mbit/s (uplink unless -R), or 0 if the run failed
  # Omit the first 2 s: at 100 ms RTT slow start otherwise dominates and
  # single runs swing widely. Retry once, since the server can still be
  # finishing the previous run.
  local try
  for try in 1 2; do
    if $C iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m "$@" >"$WORK/iperf.log" 2>&1; then
      grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
      return
    fi
    sleep 1
  done
  sed 's/^/  iperf3: /' "$WORK/iperf.log" >&2
  echo 0
}

ping_stats() { # ping_stats [COUNT]: prints "LOSS% AVG_MS" for COUNT (50) pings 20 ms apart
  $C ping -q -c "${1:-50}" -i 0.02 -W 2 "$TARGET" >"$WORK/ping.log" 2>&1 || true
  local loss avg
  loss=$(grep -oE '[0-9.]+% packet loss' "$WORK/ping.log" | cut -d% -f1)
  avg=$(grep -oE 'rtt [^=]+= [0-9.]+/[0-9.]+' "$WORK/ping.log" | awk -F/ '{print $NF}')
  echo "${loss:-100} ${avg:--}"
}

# --- Part 1: single-link impairment matrix ------------------------------------
SCENARIOS=(
  "clean|"
  "rtt 100ms|delay 50ms"
  "loss 1%|loss 1%"
  "loss 5%|loss 5%"
  "rtt 100ms, jitter 20ms|delay 50ms 20ms distribution normal"
  "50 Mbit/s, rtt 40ms|rate 50mbit delay 20ms"
)
ROWS=()
declare -A GOODPUT
for s in "${SCENARIOS[@]}"; do
  name=${s%%|*} args=${s#*|}
  if [[ -n $args ]]; then
    # shellcheck disable=SC2086
    impair 0 $args
  else
    unimpair 0
  fi
  for tunnel in plain arc wireguard; do
    use "$tunnel"
    read -r loss avg <<<"$(ping_stats)"
    mbps=$(tcp_up)
    GOODPUT["$name/$tunnel"]=$mbps
    ROWS+=("$(printf '%-26s %-10s %10s %10s %10s' "$name" "$tunnel" "$mbps" "$loss" "$avg")")
    if [[ $mbps == 0 || $loss == 100 ]]; then
      fail "$tunnel carried no traffic under '$name'"
    fi
  done
  echo "measured: $name" >&2
done
unimpair 0

bottleneck="50 Mbit/s, rtt 40ms"
ratio=$(awk -v a="${GOODPUT["$bottleneck/arc"]}" -v p="${GOODPUT["$bottleneck/plain"]}" \
  'BEGIN { printf "%.2f", (p > 0 ? a / p : 0) }')
if awk -v r="$ratio" 'BEGIN { exit !(r >= 0.70) }'; then
  pass "ARC reaches ${ratio}x plain-routing goodput on the $bottleneck bottleneck"
else
  fail "ARC reaches only ${ratio}x plain-routing goodput on the $bottleneck bottleneck"
fi

# --- Part 2: multipath under impairment (ARC over both links) --------------
kill "$ARC1"; wait "$ARC1" 2>/dev/null || true
$C ip link del wg0
# Deleting wg0 can strand the last run's control connection, leaving the
# server waiting on it and refusing new tests as busy; start a fresh one.
restart_iperf_server() {
  $I pkill -x iperf3 || true
  wait_until 5 sh -c "! pgrep -x iperf3 >/dev/null"
  $I iperf3 -s -D --logfile "$WORK/iperf-server.log"
}
restart_iperf_server
MP_CLIENT=
start_multipath_client() { # start_multipath_client REDUNDANCY LOG
  if [[ -n $MP_CLIENT ]]; then kill "$MP_CLIENT"; wait "$MP_CLIENT" 2>/dev/null || true; fi
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -bind c1 -status 1s \
    -redundancy "$1" >"$WORK/$2" 2>&1 &
  MP_CLIENT=$!
  PIDS+=("$MP_CLIENT")
  wait_until 10 grep -q "path validated" "$WORK/$2" ||
    { cat "$WORK/$2"; exit 1; }
}
start_multipath_client off client2.log

tx() { $C cat "/sys/class/net/$1/statistics/tx_packets"; }
busy_link() { # prints 0 or 1: the link carrying tunnel traffic now
  local a b
  a=$(tx c0) b=$(tx c1)
  $C ping -q -c 20 -i 0.02 -W 1 "$TARGET" >/dev/null 2>&1 || true
  if (($(tx c0) - a >= $(tx c1) - b)); then echo 0; else echo 1; fi
}

# outage NETEM_ARGS...: applies NETEM_ARGS to the busy link 1 s into a 6 s
# ping stream (20 ms apart) and prints "LINK LOST_PINGS". Lost pings x 20 ms
# approximates the interruption.
outage() {
  local link
  link=$(busy_link)
  $C ping -q -c 300 -i 0.02 -W 1 "$TARGET" >"$WORK/outage.log" 2>&1 &
  local ping_pid=$!
  sleep 1
  impair "$link" "$@"
  wait "$ping_pid" || true
  local received
  received=$(grep -oE '[0-9]+ received' "$WORK/outage.log" | awk '{print $1}')
  echo "$link $((300 - ${received:-0}))"
}

MP_ROWS=()
measure_failover() { # measure_failover NAME BASE_NETEM_ARGS
  local name=$1 base=$2 link lost
  for l in 0 1; do
    # shellcheck disable=SC2086
    if [[ -n $base ]]; then impair "$l" $base; else unimpair "$l"; fi
  done
  sleep 2 # let RTT estimates settle
  # shellcheck disable=SC2086
  read -r link lost <<<"$(outage $base loss 100%)"
  MP_ROWS+=("$(printf '%-34s cut c%s: %4d ms without traffic' "$name" "$link" $((lost * 20)))")
  if ((lost * 20 <= 2000)); then
    pass "failover ($name) took about $((lost * 20)) ms"
  else
    fail "failover ($name) took about $((lost * 20)) ms"
  fi
  # Restore both links. The cut path was silent for less than the path
  # timeout, so it is never closed: it turns healthy again as soon as
  # packets flow, which the keepalives ensure within a few seconds.
  unimpair 0
  unimpair 1
  sleep 3
}
measure_failover "blackholed busy link, clean links" ""
measure_failover "blackholed busy link, rtt 100ms" "delay 50ms"

# A lossy but live busy link: loss-aware path selection (spec §15.2) should
# move traffic to the clean link within a couple of seconds, so TCP runs at
# clean-link speed rather than at the loss-limited speed of Part 1. The TCP
# run itself supplies the traffic the client measures loss on.
lossy_link() { # lossy_link LOSS
  local link after mbps
  link=$(busy_link)
  impair "$link" loss "$1"
  mbps=$(tcp_up)
  after=$(busy_link)
  MP_ROWS+=("$(printf '%-34s c%s at %s loss: traffic moved to c%s, TCP %s Mbit/s' "lossy busy link, other clean" "$link" "$1" "$after" "$mbps")")
  if [[ $after != "$link" ]]; then
    pass "traffic left c$link at $1 loss"
  else
    fail "traffic stayed on c$link at $1 loss"
  fi
  unimpair "$link"
  sleep 1
}
lossy_link 5%
lossy_link 30%

# Aggregation (spec §20 Stage B exit): independent flows spread across
# links, so 4 TCP flows over two 50 Mbit/s links beat one link, in both
# directions; a single flow stays on one link rather than being striped
# and reordered. The one-link reference blackholes link 1 for its runs.
aggregate() { # aggregate NAME IPERF_ARGS...: sets AGG_ONE and AGG_TWO
  local name=$1
  shift
  # A queue of about 100 ms at 50 Mbit/s, rather than impair's 100000
  # packets: TCP fills whatever queue there is, and seconds of standing
  # queue would make every path look congested.
  impair 0 rate 50mbit delay 10ms limit 500
  impair 1 loss 100%
  sleep 2
  AGG_ONE=$(tcp_up "$@")
  impair 1 rate 50mbit delay 10ms limit 500
  sleep 3 # link 1 answers its probes and turns healthy
  AGG_TWO=$(tcp_up "$@")
  unimpair 0
  unimpair 1
  MP_ROWS+=("$(printf '%-34s %s: one link %6s Mbit/s, two links %6s Mbit/s' "two 50 Mbit/s links" "$name" "$AGG_ONE" "$AGG_TWO")")
}
for dir in up down; do
  args=(-P 4)
  [[ $dir == down ]] && args+=(-R)
  aggregate "4 flows $dir" "${args[@]}"
  if awk -v two="$AGG_TWO" -v one="$AGG_ONE" 'BEGIN { exit !(two >= 1.4 * one) }'; then
    pass "4 flows $dir over two links: $AGG_TWO Mbit/s against $AGG_ONE on one"
  else
    fail "4 flows $dir over two links: $AGG_TWO Mbit/s, not 1.4x the $AGG_ONE of one link"
    echo "  path state (client, then relay), from -status:"
    grep 'msg=path ' "$WORK/client2.log" | tail -2 | sed 's/^/    /'
    grep 'msg=path ' "$WORK/relay.log" | tail -2 | sed 's/^/    /'
  fi
done
aggregate "1 flow up" # recorded: one flow stays on one link
sleep 1

# Both links lossy: there is no clean path to move to. Redundancy sends
# each packet on both links, so with independent 5% loss about 0.25% of
# packets are lost instead of 5% (spec §11.1). Ping loss counts both
# directions; 300 pings resolve it to about 0.3%.
both_lossy() { # both_lossy NAME REDUNDANCY NETEM_ARGS...: sets BL_MBPS and BL_LOSS
  local name=$1 mode=$2 avg
  shift 2
  start_multipath_client "$mode" "client-$mode.log"
  impair 0 "$@"
  impair 1 "$@"
  BL_MBPS=$(tcp_up)
  read -r BL_LOSS avg <<<"$(ping_stats 300)"
  unimpair 0
  unimpair 1
  MP_ROWS+=("$(printf '%-34s redundancy %-6s TCP %6s Mbit/s, ping loss %s%%' "$name" "$mode" "$BL_MBPS" "$BL_LOSS")")
}
compare_redundancy() { # compare_redundancy NAME NETEM_ARGS...
  local name=$1 off_mbps off_loss
  shift
  both_lossy "$name" off "$@"
  off_mbps=$BL_MBPS off_loss=$BL_LOSS
  both_lossy "$name" auto "$@"
  if awk -v a="$BL_LOSS" -v o="$off_loss" 'BEGIN { exit !(a < o / 2) }'; then
    pass "redundancy cut ping loss from $off_loss% to $BL_LOSS% ($name)"
  else
    fail "redundancy left ping loss at $BL_LOSS%, against $off_loss% without ($name)"
  fi
  if awk -v a="$BL_MBPS" -v o="$off_mbps" 'BEGIN { exit !(a > 2 * o) }'; then
    pass "redundancy raised TCP goodput from $off_mbps to $BL_MBPS Mbit/s ($name)"
  else
    fail "redundancy gave $BL_MBPS Mbit/s TCP goodput, against $off_mbps without ($name)"
  fi
}
compare_redundancy "both links at 5% loss" loss 5%
compare_redundancy "both at 5% loss, rtt 40ms" delay 20ms loss 5%

# Connecting through heavy loss (spec §9.2): the client repeats its
# handshake on both links and its AUTH every 100 ms, so a session comes up
# even when most packets are lost. It needs two round trips to get through,
# each with probability (1 - loss)^2 per attempt.
connect_under_loss() { # connect_under_loss LOSS LIMIT_SECONDS: sets CONNECT_S, "-" on timeout
  local log="$WORK/connect-$1.log" t0
  if [[ -n $MP_CLIENT ]]; then kill "$MP_CLIENT"; wait "$MP_CLIENT" 2>/dev/null || true; fi
  impair 0 loss "$1"
  impair 1 loss "$1"
  t0=$(date +%s.%N)
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -bind c1 >"$log" 2>&1 &
  MP_CLIENT=$!
  PIDS+=("$MP_CLIENT")
  if wait_until "$2" grep -q "session established" "$log"; then
    CONNECT_S=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
  else
    CONNECT_S=-
  fi
  unimpair 0
  unimpair 1
  MP_ROWS+=("$(printf '%-34s session established after %s s' "connect, both links at $1 loss" "$CONNECT_S")")
}
connect_under_loss 70% 30
if [[ $CONNECT_S != - ]] && awk -v s="$CONNECT_S" 'BEGIN { exit !(s <= 15) }'; then
  pass "connected through 70% loss on both links in $CONNECT_S s"
else
  fail "connecting through 70% loss on both links took $CONNECT_S s (limit 15)"
fi
connect_under_loss 90% 60 # recorded, not asserted: typically 10-40 s

# An established session through 90% loss on both links for about 80 s:
# what still gets through (pings; a 100 KB TCP transfer given 60 s), and
# whether the session survives and carries traffic again as soon as the
# loss clears. Objective: keep *a* connection, however slow. Only survival
# and recovery are asserted; the rest is the baseline for loss recovery
# inside the tunnel.
extreme_loss() { # extreme_loss REDUNDANCY
  local log="client-extreme-$1.log" received xfer t0 recover
  start_multipath_client "$1" "$log"
  sleep 1
  impair 0 loss 90%
  impair 1 loss 90%
  # ping fails when no reply arrives at all, which is a result here
  received=$({ $C ping -q -c 100 -i 0.2 -W 2 "$TARGET" 2>/dev/null || true; } | grep -oE '[0-9]+ received' | cut -d' ' -f1)
  t0=$(date +%s.%N)
  if $C timeout 60 iperf3 -c "$TARGET" -n 100K -f k >"$WORK/iperf-extreme.log" 2>&1; then
    xfer="$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f s", b - a }')"
  else
    xfer="not done in 60 s"
    restart_iperf_server # a killed client can leave the server stuck busy
  fi
  unimpair 0
  unimpair 1
  t0=$(date +%s.%N)
  if wait_until 10 $C ping -c 1 -W 1 "$TARGET"; then
    recover=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
  else
    recover=-
  fi
  MP_ROWS+=("$(printf '%-34s redundancy %-6s pings %3s/100, 100 KB TCP %s, traffic again %s s after' \
    "90% loss on both links" "$1" "${received:-0}" "$xfer" "$recover")")
  if grep -q "session ended" "$WORK/$log" || ! kill -0 "$MP_CLIENT" 2>/dev/null; then
    fail "session did not survive 90% loss on both links (redundancy $1): $(grep -m1 "session ended" "$WORK/$log")"
  elif [[ $recover == - ]] || ! awk -v r="$recover" 'BEGIN { exit !(r <= 5) }'; then
    fail "session survived 90% loss but carried no traffic within 5 s of it clearing (redundancy $1): $recover"
  else
    pass "session survived 90% loss on both links and recovered in $recover s (redundancy $1)"
  fi
}
extreme_loss off
extreme_loss auto

# --- Part 3: TLS/TCP carrier (spec §16.3) -----------------------------------
# One link, with UDP to the relay blocked for the TLS/TCP runs. TCP inside
# a TCP carrier suffers head-of-line blocking: a carrier retransmission
# holds up every packet behind it, so loss costs more and delay spikes.
# Ping RTT is measured during each transfer to show it. Only that TLS/TCP
# carries traffic is asserted.
if [[ -n $MP_CLIENT ]]; then kill "$MP_CLIENT"; wait "$MP_CLIENT" 2>/dev/null || true; fi
$C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
  -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 \
  -tls 192.168.10.2:8443 -tls-ca "$WORK/relay.crt" >"$WORK/client3.log" 2>&1 &
PIDS+=($!)
wait_until 10 grep -q "session established" "$WORK/client3.log" ||
  { cat "$WORK/client3.log"; exit 1; }
block_udp() { $C iptables -"$1" OUTPUT -p udp -d 192.168.10.2 --dport 4433 -j DROP; }
TLS_ROWS=()
carrier_row() { # carrier_row NAME NETEM_ARGS...
  local name=$1 carrier mbps rtt
  shift
  if [[ $# -gt 0 ]]; then impair 0 "$@"; else unimpair 0; fi
  for carrier in udp tls; do
    if [[ $carrier == tls ]]; then block_udp A; fi
    sleep 3 # the session moves to the working carrier
    $C ping -q -c 40 -i 0.25 -W 3 "$TARGET" >"$WORK/ping-during.log" 2>&1 &
    local ping_pid=$!
    mbps=$(tcp_up)
    wait "$ping_pid" || true
    rtt=$(grep -oE 'rtt [^=]+= [0-9./]+' "$WORK/ping-during.log" | awk -F'= ' '{print $2}' | awk -F/ '{printf "%s / %s", $2, $3}')
    TLS_ROWS+=("$(printf '%-26s %-10s %10s %20s' "$name" "arc-$carrier" "$mbps" "${rtt:--}")")
    if [[ $carrier == tls ]]; then
      block_udp D
      if [[ $mbps == 0 ]]; then fail "no TCP goodput over TLS/TCP ($name)"; fi
    fi
  done
  unimpair 0
}
carrier_row "clean"
carrier_row "loss 1%" loss 1%
carrier_row "rtt 40ms, loss 1%" delay 20ms loss 1%

echo
echo "Part 1: single link, $DURATION s TCP runs; $(nproc) CPUs; kernel $(uname -r)"
printf '%-26s %-10s %10s %10s %10s\n' "scenario" "tunnel" "TCP Mbit/s" "ping loss%" "ping ms"
printf '%s\n' "${ROWS[@]}"
echo
echo "Part 2: ARC over two links"
printf '%s\n' "${MP_ROWS[@]}"
echo
echo "Part 3: one link, UDP vs the TLS/TCP carrier (UDP blocked); ping during each transfer"
printf '%-26s %-10s %10s %20s\n' "scenario" "tunnel" "TCP Mbit/s" "ping avg / max ms"
printf '%s\n' "${TLS_ROWS[@]}"
echo
echo "UDP receive-buffer drops over the whole run: relay $(rcvbuf_errors "$R"), client $(rcvbuf_errors "$C")"
echo
if [[ $failures -eq 0 ]]; then echo "degraded: all checks passed"; else echo "degraded: $failures check(s) failed"; exit 1; fi
