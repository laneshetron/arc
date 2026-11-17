#!/usr/bin/env bash
# arc through mini-tspu (github.com/laneshetron/mini-tspu), a model of
# Russia's TSPU running as a transparent bridge in a censor namespace.
# The relay sits on a "foreign hosting" address, so the censor's freeze
# and UDP ban apply to it (spec/freeze-and-udp-ban.md). Run as root on
# Linux, or in Docker:
#
#   docker build -f test/netns/tspu.Dockerfile --build-context mini-tspu=../mini-tspu -t arc-tspu .
#   docker run --rm --privileged arc-tspu [SCENARIO...]
#
#   NS_C (client)         NS_T (censor)                  NS_S (relay)           NS_I
#   c0 10.0.0.1/24 --- t0 [mini-tspu bridge] t1 --- s0 10.0.0.4/24 hosting
#                                                    s1 192.168.20.1/24 ---- i0 192.168.20.2/24
#
# Usage: tspu.sh BIN_DIR [SCENARIO...]
#   BIN_DIR holds arc-client, arc-relay and mini-tspu.
#   Scenarios (default: all): freeze udp-ban
set -euo pipefail

BIN=$(cd "${1:?usage: tspu.sh BIN_DIR [SCENARIO...]}" && pwd)
shift
SCENARIOS=("$@")
((${#SCENARIOS[@]})) || SCENARIOS=(freeze udp-ban)
for b in arc-client arc-relay mini-tspu; do
  [[ -x $BIN/$b ]] || { echo "tspu.sh: $BIN/$b missing" >&2; exit 2; }
done

# Namespace names carry a per-run suffix (RUN_ID, default this shell's
# PID), and cleanup deletes only the namespaces this run created, so a
# concurrent run, or a leftover with the same name, is never torn down.
RUN_ID=${RUN_ID:-$$}
NS_C=tspu-c-$RUN_ID NS_T=tspu-t-$RUN_ID NS_S=tspu-s-$RUN_ID NS_I=tspu-i-$RUN_ID
CREATED_NS=()
C="ip netns exec $NS_C"
T="ip netns exec $NS_T"
S="ip netns exec $NS_S"
I="ip netns exec $NS_I"
HOSTING=10.0.0.4
SERVER=192.168.20.2
FREEZE_BYTES=16384
PIDS=()
WORK=$(mktemp -d)
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

wait_until() { # wait_until SECONDS COMMAND...
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
}

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for f in "$WORK"/iperf3.*.pid; do [[ -f $f ]] && kill "$(cat "$f")" 2>/dev/null || true; done
  for ns in "${CREATED_NS[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log "$WORK"/censor.json; do [[ -f $f ]] && { echo "--- $f"; tail -n 30 "$f"; }; done
  fi
  [[ -n ${OUT:-} ]] && cp -r "$WORK"/. "$OUT"/
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- topology ---------------------------------------------------------------
for ns in "$NS_C" "$NS_T" "$NS_S" "$NS_I"; do
  ip netns add "$ns" || { fail "create namespace $ns"; exit 1; }
  CREATED_NS+=("$ns")
  ip -n "$ns" link set lo up
done
ip link add c0 netns "$NS_C" type veth peer name t0 netns "$NS_T"
ip link add s0 netns "$NS_S" type veth peer name t1 netns "$NS_T"
ip link add s1 netns "$NS_S" type veth peer name i0 netns "$NS_I"
ip -n "$NS_C" addr add 10.0.0.1/24 dev c0
ip -n "$NS_S" addr add $HOSTING/24 dev s0
ip -n "$NS_S" addr add 192.168.20.1/24 dev s1
ip -n "$NS_I" addr add $SERVER/24 dev i0
# The bridge sees real packets: no segmentation offloads on its path.
for nsdev in "$NS_C:c0" "$NS_T:t0" "$NS_T:t1" "$NS_S:s0" "$NS_S:s1" "$NS_I:i0"; do
  ns=${nsdev%%:*} dev=${nsdev##*:}
  ip netns exec "$ns" ethtool -K "$dev" tx off tso off gso off gro off >/dev/null 2>&1 || true
  ip -n "$ns" link set "$dev" up
done
$S sysctl -qw net.ipv4.ip_forward=1
$S iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o s1 -j MASQUERADE

echo "$HOSTING/32" >"$WORK/hosting.txt"
$T "$BIN/mini-tspu" -inside t0 -outside t1 -hosting "$WORK/hosting.txt" \
  >"$WORK/censor.json" 2>"$WORK/censor.log" &
PIDS+=("$!")
wait_until 5 grep -q bridging "$WORK/censor.log" || { fail "censor up"; exit 1; }

# --- relay on the hosting address: UDP and the HTTPS front -------------------
"$BIN/arc-relay" genkey >"$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
echo tok >"$WORK/tokens"
echo tok >"$WORK/token"
"$BIN/arc-relay" gencert -hosts $HOSTING -cert "$WORK/relay.crt" -key "$WORK/relay.tls.key" 2>/dev/null
$S "$BIN/arc-relay" run -listen $HOSTING:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -front-listen $HOSTING:443 -tls-cert "$WORK/relay.crt" -tls-key "$WORK/relay.tls.key" \
  -network 10.77.0.1/16 >"$WORK/relay.log" 2>&1 &
PIDS+=("$!")
wait_until 10 $S ip addr show arc0 || { fail "relay up"; exit 1; }

for port in 5201 5202; do $I iperf3 -s -D -p $port -I "$WORK/iperf3.$port.pid"; done

CLIENT_PID=
# PCAP=1 captures the client's tunnel and link (for OUT=dir).
pcap() { # NAME
  [[ -n ${PCAP:-} ]] || return 0
  $C tcpdump -i arc-c0 -s 128 -w "$WORK/$1.tun.pcap" >/dev/null 2>&1 &
  PIDS+=("$!")
  $C tcpdump -i c0 -s 128 -w "$WORK/$1.link.pcap" >/dev/null 2>&1 &
  PIDS+=("$!")
}
start_client() { # NAME ARGS...
  local name=$1; shift
  $C "$BIN/arc-client" run -relay $HOSTING:4433 -relay-key "$RELAY_PUB" -token-file "$WORK/token" \
    -tun arc-c0 -route 192.168.20.0/24 -front $HOSTING:443 -tls-ca "$WORK/relay.crt" \
    -journal "$WORK/$name.journal" ${CLIENT_EXTRA:-} "$@" >"$WORK/$name.log" 2>&1 &
  CLIENT_PID=$!
  PIDS+=("$CLIENT_PID")
}
stop_client() { kill "$CLIENT_PID" 2>/dev/null || true; wait "$CLIENT_PID" 2>/dev/null || true; }

# download PORT SECONDS: bytes the client receives from the internet
# server through the tunnel in an iperf3 reverse-mode run; per-second
# intervals in $WORK/iperf.$PORT. Reads are 1 KB: iperf3 counts a read
# only once it fills its block (128 KB by default), which hides slow
# transfers entirely.
download() {
  $C timeout $(($2 + 15)) iperf3 -c $SERVER -p "$1" -R -l 1K -t "$2" -J --connect-timeout 5000 \
    >"$WORK/iperf.$1" 2>&1 || true
  python3 - "$WORK/iperf.$1" <<'EOF' 2>/dev/null || echo 0
import json, sys
r = json.load(open(sys.argv[1]))
if r.get("error"):
    print("iperf3: " + r["error"], file=sys.stderr)
print(int(r["end"]["sum_received"]["bytes"]))
EOF
}

# intervals PORT: per-second received kbit/s of the last download.
intervals() {
  python3 - "$WORK/iperf.$1" <<'EOF' 2>/dev/null || true
import json, sys
r = json.load(open(sys.argv[1]))
print(" ".join(str(int(i["sum"]["bits_per_second"] / 1000)) for i in r["intervals"]))
EOF
}

censor_events() { grep -o '"rule":"[a-z-]*"' "$WORK/censor.json" | sort | uniq -c | tr -s ' \n' ' '; }

# --- scenarios ---------------------------------------------------------------

# freeze: the front alone, to a hosting address. Each TCP connection
# delivers ~16 KB downstream before the censor silently drops the rest.
# The client must notice the stall and keep the downlink moving on new
# connections, well past one connection's budget.
scenario_freeze() {
  start_client freeze -no-udp
  if ! wait_until 15 grep -q "session established" "$WORK/freeze.log"; then
    fail "freeze: no session over the front"
    stop_client
    return
  fi
  pcap freeze
  local got
  got=$(download 5201 20)
  echo "freeze: received $got bytes in 20 s; kbit/s per second: $(intervals 5201)"
  echo "freeze: censor events: $(censor_events)"
  # The carrier redialed: more than one connection froze. A carrier
  # that stays on its first connection gets one frozen; one that learns
  # the cap, at least the two it learns from.
  local freezes
  freezes=$(grep -c '"rule":"freeze"' "$WORK/censor.json" || true)
  if ((freezes >= 2)); then
    pass "freeze: carrier redialed past the freeze ($freezes connections frozen)"
  else
    fail "freeze: carrier stayed on its frozen connection ($freezes frozen, want ≥ 2)"
  fi
  # Throughput, when FREEZE_FLOOR asks (in connections' worth). Stall and
  # redial alone isn't held to one: it moves ~55–100 KB in 20 s, but the
  # inner TCP connections back off through its 3 s stalls, and iperf3's
  # own setup can lose its control messages to them and never start.
  if ((${FREEZE_FLOOR:-0} > 0)); then
    local want=$((FREEZE_FLOOR * FREEZE_BYTES))
    if ((got > want)); then
      pass "freeze: downlink kept flowing past the freeze ($got bytes, > $want)"
    else
      fail "freeze: downlink stopped at the freeze ($got bytes, want > $want)"
    fi
  fi
  if grep -q 'timeout-at-N-bytes' "$WORK/freeze.journal"; then
    pass "freeze: stalls reported as timeout-at-N-bytes"
  else
    fail "freeze: no timeout-at-N-bytes stall reported"
  fi
  # Still alive after the transfer: a ping through the tunnel.
  if $C ping -c 3 -W 5 -i 0.5 $SERVER >/dev/null 2>&1 || $C ping -c 3 -W 5 -i 0.5 $SERVER >/dev/null 2>&1; then
    pass "freeze: tunnel still answers after the transfer"
  else
    fail "freeze: tunnel dead after the transfer"
  fi
  stop_client
}

# udp-ban: UDP and the front, as by default, but under the -censorship
# posture. UDP to a hosting address gets the relay's whole address
# banned, front included, so the client must not send any.
scenario_udp-ban() {
  # POSTURE= runs the default posture, for comparison: the ban fires.
  start_client udp-ban ${POSTURE--censorship}
  if wait_until 15 grep -q "session established" "$WORK/udp-ban.log"; then
    pass "udp-ban: session established"
  else
    fail "udp-ban: no session"
  fi
  # Traffic, so a UDP carrier (if any) carries well over the ban's
  # 25 datagrams; the ban fires as soon as it does.
  $C ping -c 60 -i 0.05 -W 1 $SERVER >/dev/null 2>&1 || true
  if grep -q '"rule":"udp-ban"' "$WORK/censor.json"; then
    fail "udp-ban: the censor banned the relay's address"
  else
    pass "udp-ban: no UDP ban"
  fi
  if $C ping -c 3 -W 5 -i 0.5 $SERVER >/dev/null 2>&1; then
    pass "udp-ban: tunnel answers over the front"
  else
    fail "udp-ban: tunnel dead"
  fi
  echo "udp-ban: censor events: $(censor_events)"
  stop_client
}

for s in "${SCENARIOS[@]}"; do
  echo "=== $s"
  "scenario_$s"
done

if ((failures)); then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
