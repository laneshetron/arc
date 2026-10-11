#!/usr/bin/env bash
# End-to-end tunnel test in three network namespaces (run as root on Linux):
#
#   arc-c (client)        arc-r (relay)                arc-i ("internet")
#   c0 192.168.10.1/32 -- r0 192.168.10.2/24
#                         r1 192.168.20.1/24  -------- i0 192.168.20.2/24
#
# The client's only route is a default route out of c0, so it cannot reach
# arc-i except through the tunnel, and in full-tunnel mode its carrier
# socket must use its fwmark to reach the relay without looping through the
# tunnel. The relay masquerades the tunnel network onto r1.
#
# Usage: e2e.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: e2e.sh BIN_DIR}" && pwd)
WORK=$(mktemp -d)
C="ip netns exec arc-c"
R="ip netns exec arc-r"
I="ip netns exec arc-i"
PIDS=()
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in arc-c arc-r arc-i; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local deadline=$((SECONDS + $1)) what=$2; shift 2
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then fail "$what (timed out)"; return 1; fi
    sleep 0.2
  done
}

# --- topology ------------------------------------------------------------
for ns in arc-c arc-r arc-i; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add c0 netns arc-c type veth peer name r0 netns arc-r
ip link add r1 netns arc-r type veth peer name i0 netns arc-i
ip -n arc-c addr add 192.168.10.1/32 dev c0
ip -n arc-c link set c0 up
ip -n arc-c route add 192.168.10.2 dev c0      # peer only, for the baseline check
ip -n arc-r addr add 192.168.10.2/24 dev r0
ip -n arc-r addr add 192.168.20.1/24 dev r1
ip -n arc-r link set r0 up
ip -n arc-r link set r1 up
ip -n arc-i addr add 192.168.20.2/24 dev i0
ip -n arc-i link set i0 up
$R sysctl -qw net.ipv4.ip_forward=1
$R iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o r1 -j MASQUERADE

if $C ping -c1 -W1 192.168.20.2 >/dev/null 2>&1; then
  fail "client reaches the internet namespace without the tunnel"
else
  pass "no route to the internet namespace before the tunnel"
fi
# From here on the client reaches everything through one default route.
ip -n arc-c route del 192.168.10.2 dev c0
ip -n arc-c route add default dev c0

# --- relay ---------------------------------------------------------------
"$BIN/arc-relay" genkey > "$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey < "$WORK/relay.key")
echo "e2e-token" > "$WORK/tokens"
echo "e2e-token" > "$WORK/token"
start_relay() {
  $R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=("$RELAY_PID")
}
start_relay
wait_for 10 "relay up" $R ip addr show arc0

# --- client --------------------------------------------------------------
$C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" \
  -token-file "$WORK/token" -full-tunnel >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")
wait_for 10 "client established" grep -q "session established" "$WORK/client.log" &&
  pass "session established"

# --- checks --------------------------------------------------------------
if $C ping -c5 -i0.2 -W2 192.168.20.2 >"$WORK/ping.log" 2>&1; then
  pass "ping through the tunnel ($(grep -o 'rtt.*' "$WORK/ping.log"))"
else
  fail "ping through the tunnel"
fi

if grep -q 'client=192.168.10.1:' "$WORK/relay.log"; then
  pass "carrier reached the relay directly, not through the tunnel"
else
  fail "relay did not see the client's real address"
fi

if $C ip -6 route get 2001:db8::1 2>&1 | grep -qiE 'unreachable|network is unreachable'; then
  pass "IPv6 is blocked while the full tunnel is up"
else
  fail "IPv6 is not blocked by the full tunnel"
fi

$I iperf3 -s -D --logfile "$WORK/iperf-server.log"
sleep 0.5
if $C iperf3 -c 192.168.20.2 -t 3 -f m >"$WORK/iperf-up.log" 2>&1; then
  pass "TCP uplink: $(grep -E 'receiver$' "$WORK/iperf-up.log" | awk '{print $(NF-2), $(NF-1)}')"
else
  fail "TCP uplink"
fi
if $C iperf3 -c 192.168.20.2 -t 3 -R -f m >"$WORK/iperf-down.log" 2>&1; then
  pass "TCP downlink: $(grep -E 'receiver$' "$WORK/iperf-down.log" | awk '{print $(NF-2), $(NF-1)}')"
else
  fail "TCP downlink"
fi
if grep -q '192.168.20.1' "$WORK/iperf-server.log"; then
  pass "relay masqueraded tunnel traffic"
else
  fail "internet namespace saw an unmasqueraded source"
fi

# Relay restart: the client learns of it through a stateless reset and
# reconnects with a new session.
kill "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
start_relay
$C ping -c1 -W1 192.168.20.2 >/dev/null 2>&1 || true   # triggers the reset
if wait_for 15 "reconnect after relay restart" bash -c "[ \$(grep -c 'session established' '$WORK/client.log') -ge 2 ]" &&
  $C ping -c3 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
  pass "client recovered after relay restart"
  grep -q 'relay reset the session' "$WORK/client.log" && pass "recovery used the stateless reset"
else
  fail "client did not recover after relay restart"
fi

# Shutdown removes the routing rules.
kill "$CLIENT_PID"; wait "$CLIENT_PID" 2>/dev/null || true
if $C ip rule | grep -q 5243; then
  fail "routing rules left behind after the client exited"
else
  pass "routing rules removed on exit"
fi

echo
if [[ $failures -eq 0 ]]; then echo "e2e: all checks passed"; else echo "e2e: $failures check(s) failed"; exit 1; fi
