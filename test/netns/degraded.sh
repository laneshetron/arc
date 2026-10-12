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
# Assertions are deliberately loose so they hold on shared CI runners:
#   - every tunnel carries traffic in every scenario
#   - on a 50 Mbit/s bottleneck ARC reaches >= 70% of plain routing
#   - failover from a blackholed link completes within 2 s
#   - traffic leaves a busy link with 5% or 30% loss when the other is clean
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
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
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

tcp_up() { # prints TCP uplink goodput in Mbit/s, or 0 if the run failed
  # Omit the first 2 s: at 100 ms RTT slow start otherwise dominates and
  # single runs swing widely. Retry once, since the server can still be
  # finishing the previous run.
  local try
  for try in 1 2; do
    if $C iperf3 -c "$TARGET" -t "$DURATION" -O 2 -f m >"$WORK/iperf.log" 2>&1; then
      grep receiver "$WORK/iperf.log" | tail -1 | awk '{print $(NF-2)}'
      return
    fi
    sleep 1
  done
  sed 's/^/  iperf3: /' "$WORK/iperf.log" >&2
  echo 0
}

ping_stats() { # prints "LOSS% AVG_MS" for 50 pings 20 ms apart
  $C ping -q -c 50 -i 0.02 -W 2 "$TARGET" >"$WORK/ping.log" 2>&1 || true
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
$I pkill -x iperf3 || true
wait_until 5 sh -c "! pgrep -x iperf3 >/dev/null"
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"
$C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
  -token-file "$WORK/token" -route 192.168.20.0/24 -bind c0 -bind c1 >"$WORK/client2.log" 2>&1 &
PIDS+=($!)
wait_until 10 grep -q "path validated" "$WORK/client2.log" ||
  { cat "$WORK/client2.log"; exit 1; }

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

echo
echo "Part 1: single link, $DURATION s TCP runs; $(nproc) CPUs; kernel $(uname -r)"
printf '%-26s %-10s %10s %10s %10s\n' "scenario" "tunnel" "TCP Mbit/s" "ping loss%" "ping ms"
printf '%s\n' "${ROWS[@]}"
echo
echo "Part 2: ARC over two links"
printf '%s\n' "${MP_ROWS[@]}"
echo
echo "UDP receive-buffer drops over the whole run: relay $(rcvbuf_errors "$R"), client $(rcvbuf_errors "$C")"
echo
if [[ $failures -eq 0 ]]; then echo "degraded: all checks passed"; else echo "degraded: $failures check(s) failed"; exit 1; fi
