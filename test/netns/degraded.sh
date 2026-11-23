#!/usr/bin/env bash
# Degraded-network tests and measurements over the lib.sh topology (run as
# root on Linux with netem, wireguard-tools, and iperf3).
#
# Part 1 runs plain routing (a control: what the impairment alone does to
# TCP), ARC, and kernel WireGuard over link 0 under a set of netem
# impairments, reporting TCP goodput, ping loss, and ping RTT. Loss comes
# uniform and in bursts (netem's Gilbert-Elliott model).
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
#   - with both links at 5% loss (RTT ~0 and 40 ms, uniform and in bursts),
#     -redundancy auto at least halves ping loss and at least doubles TCP
#     goodput, each pooled over 3 alternating runs per mode
#   - a session comes up within 15 s with both links at 70% loss
#   - TCP runs over the TLS/TCP carrier when UDP is blocked (Part 3)
#   - split TCP carries TCP at 50% loss, and at least doubles ARC's
#     TCP goodput at 20% loss (Part 4)
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
restart_iperf_server() {
  $I pkill -x iperf3 || true
  wait_until 5 sh -c "! pgrep -x iperf3 >/dev/null"
  $I iperf3 -s -D --logfile "$WORK/iperf-server.log"
}
restart_iperf_server

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

# Ubuntu 26.04 confines wg with AppArmor to key files under /etc/wireguard,
# so the private keys reach it through a pipe instead of a path.
(umask 077; wg genkey >"$WORK/wg-relay.key"; wg genkey >"$WORK/wg-client.key")
ip -n arc-r link add wg0 type wireguard
$R wg set wg0 listen-port 51820 private-key <(cat "$WORK/wg-relay.key") \
  peer "$(wg pubkey <"$WORK/wg-client.key")" allowed-ips 10.88.0.2/32
ip -n arc-r addr add 10.88.0.1/24 dev wg0
ip -n arc-r link set wg0 up
ip -n arc-c link add wg0 type wireguard
$C wg set wg0 private-key <(cat "$WORK/wg-client.key") \
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

# iperf_client LOG IPERF3_CMD...: runs an iperf3 client (perhaps under
# timeout) in arc-c with its output in LOG. The server takes one test at a
# time, and under loss it can spend seconds tearing down the last one,
# refusing new tests as busy meanwhile; wait that out, for up to about 15 s.
# A server still busy after that is stuck on a stranded run, so restart it
# and try once more. Any other failure returns at once.
iperf_client() {
  local log=$1 delay
  shift
  for delay in 0.25 0.5 1 2 2 3 3 3 restart; do
    if $C "$@" >"$log" 2>&1; then return 0; fi
    grep -q "server is busy" "$log" || return 1
    if [[ $delay == restart ]]; then
      echo "  iperf3: server still busy after 15 s; restarting it" >&2
      restart_iperf_server >&2
    else
      sleep "$delay"
    fi
  done
  $C "$@" >"$log" 2>&1
}

tcp_up() { # tcp_up [IPERF_ARGS...]: prints TCP goodput in Mbit/s (uplink unless -R), or 0 if the run failed
  # Omit the first 2 s: at 100 ms RTT slow start otherwise dominates and
  # single runs swing widely. Retry a failed run once.
  local try
  for try in 1 2; do
    if iperf_client "$WORK/iperf.log" iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m "$@"; then
      grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
      return
    fi
    sleep 1
  done
  sed 's/^/  iperf3: /' "$WORK/iperf.log" >&2
  echo 0
}

ping_stats() { # ping_stats [COUNT]: prints "LOSS% AVG_MS" for COUNT (50) pings 20 ms apart
  $C timeout 60 ping -q -c "${1:-50}" -i 0.02 -W 2 "$TARGET" >"$WORK/ping.log" 2>&1 || true
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
  # Loss in bursts (Gilbert-Elliott: p = good->bad, r = bad->good per
  # packet, every packet lost while bad), as on real wireless links, at the
  # same average rates as uniform loss. "bursty 1% (4)" averages 1% loss in
  # bursts of 4 packets; the mean burst length is 1/r.
  "rtt 40ms, loss 1%|delay 20ms loss 1%"
  "rtt 40ms, bursty 1% (4)|delay 20ms loss gemodel 0.25% 25%"
  "rtt 40ms, bursty 5% (10)|delay 20ms loss gemodel 0.53% 10%"
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
    if awk -v m="$mbps" -v l="$loss" 'BEGIN { exit !(m <= 0 || l >= 100) }'; then
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
  $C timeout 60 ping -q -c 20 -i 0.02 -W 1 "$TARGET" >/dev/null 2>&1 || true
  if (($(tx c0) - a >= $(tx c1) - b)); then echo 0; else echo 1; fi
}

# outage NETEM_ARGS...: applies NETEM_ARGS to the busy link 1 s into a 6 s
# ping stream (20 ms apart) and prints "LINK LOST_PINGS". Lost pings x 20 ms
# approximates the interruption.
outage() {
  local link
  link=$(busy_link)
  $C timeout 60 ping -q -c 300 -i 0.02 -W 1 "$TARGET" >"$WORK/outage.log" 2>&1 &
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

tcp_link() { # prints 0 or 1: the link that sent more packets over the next second
  local a b
  a=$(tx c0) b=$(tx c1)
  sleep 1
  if (($(tx c0) - a >= $(tx c1) - b)); then echo 0; else echo 1; fi
}

# A lossy but live busy link: loss-aware path selection (spec §15.2) should
# move a running TCP flow to the clean link within a few seconds (the loss
# estimate, then evictGrace). The link is judged by the TCP flow itself:
# flows are pinned per path, so a ping run beside it, as busy_link sends,
# can be on the other link and says nothing about where the TCP flow is.
# The flow also supplies the traffic the client measures loss on.
lossy_link() { # lossy_link LOSS
  local link after mbps iperf secs=$((DURATION < 8 ? 8 : DURATION))
  # A fresh session: loss estimates only refresh from traffic and are
  # otherwise kept for 30 s, so a link that an earlier scenario made lossy
  # would still look lossy, and staying put would then be right.
  start_multipath_client off "client-lossy-$1.log"
  sleep 1
  iperf_client "$WORK/iperf.log" iperf3 -c "$TARGET" -t $((secs + 4)) -f m &
  iperf=$!
  sleep 2
  link=$(tcp_link)
  local from
  from=$(wc -l <"$WORK/client-lossy-$1.log")
  impair "$link" loss "$1"
  sleep "$secs"
  after=$(tcp_link)
  wait "$iperf" || true
  mbps=$(grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}')
  if [[ -z $mbps ]]; then
    fail "TCP run failed at $1 loss"
    sed 's/^/  iperf3: /' "$WORK/iperf.log"
  fi
  MP_ROWS+=("$(printf '%-34s c%s at %s loss: TCP moved to c%s, %s Mbit/s overall' "lossy busy link, other clean" "$link" "$1" "$after" "${mbps:-0}")")
  if [[ $after != "$link" ]]; then
    pass "TCP left c$link at $1 loss"
  else
    fail "TCP stayed on c$link at $1 loss"
    echo "  client path state since the loss began, from -status:"
    tail -n +"$from" "$WORK/client-lossy-$1.log" | grep 'msg=path ' | sed 's/^/    /'
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
  AGG_CLIENT_LINE=$(wc -l <"$WORK/client-agg.log") AGG_RELAY_LINE=$(wc -l <"$WORK/relay.log")
  local c1tx c1rx
  c1tx=$($C cat /sys/class/net/c1/statistics/tx_bytes) c1rx=$($C cat /sys/class/net/c1/statistics/rx_bytes)
  impair 1 rate 50mbit delay 10ms limit 500
  sleep 3 # link 1 answers its probes and turns healthy
  AGG_RESTORE="link 1 while turning healthy: $(($($C cat /sys/class/net/c1/statistics/tx_bytes) - c1tx)) bytes out, $(($($C cat /sys/class/net/c1/statistics/rx_bytes) - c1rx)) in"
  AGG_TWO=$(tcp_up "$@")
  unimpair 0
  unimpair 1
  MP_ROWS+=("$(printf '%-34s %s: one link %6s Mbit/s, two links %6s Mbit/s' "two 50 Mbit/s links" "$name" "$AGG_ONE" "$AGG_TWO")")
}
start_multipath_client off client-agg.log
for dir in up down; do
  args=(-P 4)
  [[ $dir == down ]] && args+=(-R)
  aggregate "4 flows $dir" "${args[@]}"
  if awk -v two="$AGG_TWO" -v one="$AGG_ONE" 'BEGIN { exit !(two >= 1.4 * one) }'; then
    pass "4 flows $dir over two links: $AGG_TWO Mbit/s against $AGG_ONE on one"
  else
    fail "4 flows $dir over two links: $AGG_TWO Mbit/s, not 1.4x the $AGG_ONE of one link"
    echo "  $AGG_RESTORE"
    echo "  path state from link 1's restoration through the two-link run (client, then relay), from -status:"
    tail -n +"$AGG_CLIENT_LINE" "$WORK/client-agg.log" | grep 'msg=path ' | sed 's/^/    /'
    tail -n +"$AGG_RELAY_LINE" "$WORK/relay.log" | grep 'msg=path ' | sed 's/^/    /'
  fi
done
aggregate "1 flow up" # recorded: one flow stays on one link
sleep 1

# Both links lossy: there is no clean path to move to. Redundancy sends
# each packet on both links, so with independent 5% loss about 0.25% of
# packets are lost instead of 5% (spec §11.1). Ping loss counts both
# directions; 300 pings resolve it to about 0.3%. Bursty loss takes pings
# in runs of several, so 300 pings see only a few bursts either way, and
# one overlap of bursts on both links can cost redundancy its margin; those
# scenarios send 1000.
#
# A single 10 s TCP run under 5% loss at 40 ms RTT varies several-fold
# from run to run (a few retransmission timeouts more or less), more so
# under bursty loss: across 36 CI runs, goodput without redundancy ranged
# 1.2-11.7 Mbit/s (uniform) and 2-17.5 (bursty), and one run against one
# failed "at least doubles" in about 1 in 10 (uniform) and 1 in 35
# (bursty). So each mode gets ROUNDS runs, alternating off and on so that
# drift in the runner's speed hits both, and the check compares their
# pooled goodput (the mean of equal-length runs: the goodput of all of
# them end to end). Resampling those CI runs, three rounds bring the
# false-failure rate to about 1% (uniform, 40 ms) and 0.1% (bursty), while
# a redundancy that did nothing would still fail it over 90% of the time
# (and fail the ping check always). The pings are split across the rounds
# and pooled the same way.
ROUNDS=3
both_lossy() { # both_lossy REDUNDANCY PINGS NETEM_ARGS...: sets BL_MBPS and BL_LOSS
  local mode=$1 pings=$2 avg
  shift 2
  start_multipath_client "$mode" "client-$mode.log"
  impair 0 "$@"
  impair 1 "$@"
  BL_MBPS=$(tcp_up)
  read -r BL_LOSS avg <<<"$(ping_stats "$pings")"
  unimpair 0
  unimpair 1
}
num() { awk -v v="$1" 'BEGIN { printf(v >= 100 ? "%.0f" : "%.3g", v) }'; } # 3 significant digits, no exponent
mean() { num "$(awk 'BEGIN { for (i = 1; i < ARGC; i++) s += ARGV[i]; print s / (ARGC - 1) }' "$@")"; }
compare_redundancy() { # compare_redundancy NAME PINGS NETEM_ARGS...
  local name=$1 pings=$2 round mode off_mbps off_loss on_mbps on_loss
  local -A mbps=() loss=()
  shift 2
  for ((round = 1; round <= ROUNDS; round++)); do
    for mode in off auto; do
      both_lossy "$mode" $(((pings + ROUNDS - 1) / ROUNDS)) "$@"
      mbps[$mode]+=" $BL_MBPS" loss[$mode]+=" $(num "$BL_LOSS")"
    done
  done
  off_mbps=$(mean ${mbps[off]}) off_loss=$(mean ${loss[off]})
  on_mbps=$(mean ${mbps[auto]}) on_loss=$(mean ${loss[auto]})
  for mode in off auto; do
    MP_ROWS+=("$(printf '%-34s redundancy %-6s TCP %6s Mbit/s (runs%s), ping loss %s%% (runs%s)' \
      "$name" "$mode" "$(mean ${mbps[$mode]})" "${mbps[$mode]}" "$(mean ${loss[$mode]})" "${loss[$mode]}")")
  done
  if awk -v o="$off_loss" 'BEGIN { exit !(o < 2) }'; then
    # Bursty loss can miss a short ping run entirely; then there is nothing
    # to halve, and the goodput check below carries the comparison.
    echo "  ping loss without redundancy was only $off_loss%; not comparing ($name)"
  elif awk -v a="$on_loss" -v o="$off_loss" 'BEGIN { exit !(a < o / 2) }'; then
    pass "redundancy cut ping loss from $off_loss% to $on_loss% ($name; runs${loss[off]} against${loss[auto]})"
  else
    fail "redundancy left ping loss at $on_loss%, against $off_loss% without ($name; runs${loss[auto]} against${loss[off]})"
  fi
  if awk -v a="$on_mbps" -v o="$off_mbps" 'BEGIN { exit !(a > 2 * o) }'; then
    pass "redundancy raised TCP goodput from $off_mbps to $on_mbps Mbit/s, mean of $ROUNDS ($name; runs${mbps[off]} against${mbps[auto]})"
  else
    fail "redundancy gave $on_mbps Mbit/s TCP goodput, against $off_mbps without, mean of $ROUNDS ($name; runs${mbps[auto]} against${mbps[off]})"
  fi
}
compare_redundancy "both links at 5% loss" 300 loss 5%
compare_redundancy "both at 5% loss, rtt 40ms" 300 delay 20ms loss 5%
compare_redundancy "both bursty 5% (10), rtt 40ms" 1000 delay 20ms loss gemodel 0.53% 10%

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
  received=$({ $C timeout 60 ping -q -c 100 -i 0.2 -W 2 "$TARGET" 2>/dev/null || true; } | grep -oE '[0-9]+ received' | cut -d' ' -f1)
  t0=$(date +%s.%N)
  if iperf_client "$WORK/iperf-extreme.log" timeout 60 iperf3 -c "$TARGET" -n 100K -f k; then
    xfer="$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f s", b - a }')"
  else
    xfer="not done in 60 s"
    restart_iperf_server # a killed client can leave the server stuck busy
  fi
  unimpair 0
  unimpair 1
  t0=$(date +%s.%N)
  if wait_until 10 $C timeout 60 ping -c 1 -W 1 "$TARGET"; then
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
TLS_CLIENT=$!
PIDS+=("$TLS_CLIENT")
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
    $C timeout 60 ping -q -c 40 -i 0.25 -W 3 "$TARGET" >"$WORK/ping-during.log" 2>&1 &
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

# --- Part 4: split TCP (spec §11.3) -------------------------------------------
# One link at 40 ms RTT with heavy loss both ways, where TCP through any
# tunnel stalls: plain routing, ARC carrying IP packets, and ARC with
# -split-tcp always, which ends TCP at the client and carries its bytes as
# streams. Runs are bounded, since iperf3 can wait a long time at 90% loss.
kill "$TLS_CLIENT"; wait "$TLS_CLIENT" 2>/dev/null || true
SPLIT_CLIENT=
start_split_client() { # start_split_client MODE
  if [[ -n $SPLIT_CLIENT ]]; then kill "$SPLIT_CLIENT"; wait "$SPLIT_CLIENT" 2>/dev/null || true; fi
  unimpair 0
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -split-tcp "$1" >"$WORK/client4.log" 2>&1 &
  SPLIT_CLIENT=$!
  PIDS+=("$SPLIT_CLIENT")
  wait_until 10 grep -q "session established" "$WORK/client4.log" ||
    { cat "$WORK/client4.log"; exit 1; }
}
tcp_bounded() { # tcp_bounded [IPERF_ARGS...]: like tcp_up, but 0 after DURATION+30 s
  if iperf_client "$WORK/iperf.log" timeout $((DURATION + 30)) \
    iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m --connect-timeout 10000 "$@"; then
    grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
  else
    echo 0
  fi
  restart_iperf_server # a stranded run leaves the server busy
}
SPLIT_ROWS=()
declare -A SPLIT
for mode in plain off always; do
  if [[ $mode == plain ]]; then
    $C ip route replace 192.168.20.0/24 via 192.168.10.2 dev c0 onlink
  else
    start_split_client "$mode"
  fi
  for sc in "rtt 40ms, loss 5%|delay 20ms loss 5%" "rtt 40ms, loss 20%|delay 20ms loss 20%" \
    "rtt 40ms, loss 50%|delay 20ms loss 50%" "rtt 40ms, loss 90%|delay 20ms loss 90%"; do
    name=${sc%%|*} args=${sc#*|}
    # shellcheck disable=SC2086
    impair 0 $args
    sleep 2
    up=$(tcp_bounded)
    down=$(tcp_bounded -R)
    unimpair 0
    tunnel=arc-split-$mode
    [[ $mode == plain ]] && tunnel=plain
    SPLIT["$name/$mode"]=$down
    SPLIT_ROWS+=("$(printf '%-26s %-16s %10s %10s' "$name" "$tunnel" "$up" "$down")")
    echo "measured: $name, $tunnel" >&2
  done
  # The ARC client installs its own route when it connects.
  [[ $mode == plain ]] && $C ip route del 192.168.20.0/24
done
# 90% is recorded, not asserted: one 10 s iperf3 run there carries 0-2
# Mbit/s, and sometimes cannot finish setting up.
name="rtt 40ms, loss 50%"
on=${SPLIT["$name/always"]} off=${SPLIT["$name/off"]}
if awk -v on="$on" 'BEGIN { exit !(on > 0) }'; then
  pass "split TCP carried $on Mbit/s down at $name (IP packets: $off)"
else
  fail "split TCP carried no TCP at $name"
fi
on=${SPLIT["rtt 40ms, loss 20%/always"]} off=${SPLIT["rtt 40ms, loss 20%/off"]}
if awk -v on="$on" -v off="$off" 'BEGIN { exit !(on >= 2 * off && on > 0) }'; then
  pass "split TCP raised TCP goodput from $off to $on Mbit/s at 20% loss"
else
  fail "split TCP reached $on Mbit/s at 20% loss, against $off without; want at least twice"
fi

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
echo "Part 4: one link, split TCP; TCP goodput through the tunnel (or plain routing)"
printf '%-26s %-16s %10s %10s\n' "scenario" "tunnel" "up Mbit/s" "down Mbit/s"
printf '%s\n' "${SPLIT_ROWS[@]}"
echo
echo "UDP receive-buffer drops over the whole run: relay $(rcvbuf_errors "$R"), client $(rcvbuf_errors "$C")"
echo
if [[ $failures -eq 0 ]]; then echo "degraded: all checks passed"; else echo "degraded: $failures check(s) failed"; exit 1; fi
