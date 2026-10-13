#!/usr/bin/env bash
# End-to-end tunnel test in three network namespaces (run as root on Linux),
# using the topology in lib.sh.
#
# The client's only route is a default route out of c0, so it cannot reach
# arc-i except through the tunnel, and in full-tunnel mode its carrier
# socket must use its fwmark to reach the relay without looping through the
# tunnel. The relay masquerades the tunnel network onto r1.
#
# Usage: e2e.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: e2e.sh BIN_DIR}" && pwd)
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  teardown_topology
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local secs=$1 what=$2; shift 2
  wait_until "$secs" "$@" || { fail "$what (timed out)"; return 1; }
}

# --- topology ------------------------------------------------------------
setup_topology 10.77.0.0/16

if $C timeout 60 ping -c1 -W1 192.168.20.2 >/dev/null 2>&1; then
  fail "client reaches the internet namespace without the tunnel"
else
  pass "no route to the internet namespace before the tunnel"
fi
# From here on the client reaches everything through default routes, one
# per link; each carrier socket is bound to its link.
ip -n arc-c route del 192.168.10.2 dev c0
ip -n arc-c route del 192.168.10.2 dev c1
ip -n arc-c route add default dev c0
ip -n arc-c route add default dev c1 metric 100

# --- relay ---------------------------------------------------------------
"$BIN/arc-relay" genkey > "$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey < "$WORK/relay.key")
echo "e2e-token" > "$WORK/tokens"
echo "e2e-token" > "$WORK/token"
"$BIN/arc-relay" gencert -hosts 192.168.10.2 -cert "$WORK/relay.crt" -key "$WORK/relay.tls.key"
start_relay() {
  $R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -tls-listen 192.168.10.2:8443 -tls-cert "$WORK/relay.crt" -tls-key "$WORK/relay.tls.key" \
    -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=("$RELAY_PID")
}
start_relay
wait_for 10 "relay up" $R ip addr show arc0

# --- client --------------------------------------------------------------
# Each link also gets a TLS/TCP carrier, used only while UDP does not work.
CLIENT_ARGS=(-relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" -token-file "$WORK/token"
  -full-tunnel -bind c0 -bind c1 -tls 192.168.10.2:8443 -tls-ca "$WORK/relay.crt")
$C "$BIN/arc-client" run "${CLIENT_ARGS[@]}" >"$WORK/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")
wait_for 10 "client established" grep -q "session established" "$WORK/client.log" &&
  pass "session established"

# --- checks --------------------------------------------------------------
if $C timeout 60 ping -c5 -i0.2 -W2 192.168.20.2 >"$WORK/ping.log" 2>&1; then
  pass "ping through the tunnel ($(grep -o 'rtt.*' "$WORK/ping.log"))"
else
  fail "ping through the tunnel"
fi

if grep -qE 'client=192\.168\.1[01]\.1:' "$WORK/relay.log"; then
  pass "carrier reached the relay directly, not through the tunnel"
else
  fail "relay did not see the client's real address"
fi

# An unreachable default in the tunnel table makes IPv6 lookups fail with
# EHOSTUNREACH ("No route to host") instead of escaping around the tunnel.
if $C ip -6 route show table 5243 | grep -q '^unreachable default' &&
  ! $C ip -6 route get 2001:db8::1 >/dev/null 2>&1; then
  pass "IPv6 is blocked while the full tunnel is up"
else
  fail "IPv6 is not blocked by the full tunnel"
  $C ip -6 rule; $C ip -6 route show table 5243 || true
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

# Multipath failover: cut whichever link carries traffic in the middle of a
# ping stream; traffic must continue on the other link.
wait_for 10 "second link joined" grep -q "path validated" "$WORK/client.log" &&
  pass "second link joined the session"
tx() { $C cat "/sys/class/net/$1/statistics/tx_packets"; }
a0=$(tx c0) b0=$(tx c1)
$C timeout 60 ping -c20 -i0.05 -W1 192.168.20.2 >/dev/null 2>&1 || true
if (($(tx c0) - a0 >= $(tx c1) - b0)); then busy=c0; else busy=c1; fi
$C timeout 60 ping -c100 -i0.05 -W1 192.168.20.2 >"$WORK/failover.log" 2>&1 &
PING_PID=$!
sleep 1
ip -n arc-c link set "$busy" down
wait "$PING_PID" || true
received=$(grep -oE '[0-9]+ received' "$WORK/failover.log" | awk '{print $1}')
lost=$((100 - ${received:-0}))
# 100 pings at 50 ms intervals: losing at most 40 means recovery within 2 s.
if ((${received:-0} > 0 && lost <= 40)); then
  pass "failover from $busy lost $lost/100 pings (about $((lost * 50)) ms)"
else
  fail "failover from $busy lost $lost/100 pings"
fi
ip -n arc-c link set "$busy" up
if [[ $busy == c0 ]]; then
  ip -n arc-c route replace default dev c0
else
  ip -n arc-c route replace default dev c1 metric 100
fi

# Relay restart: the client learns of it through a stateless reset and
# reconnects with a new session.
kill "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
start_relay
$C timeout 60 ping -c1 -W1 192.168.20.2 >/dev/null 2>&1 || true   # triggers the reset
if wait_for 15 "reconnect after relay restart" bash -c "[ \$(grep -c 'session established' '$WORK/client.log') -ge 2 ]" &&
  $C timeout 60 ping -c3 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
  pass "client recovered after relay restart"
  grep -q 'relay reset the session' "$WORK/client.log" && pass "recovery used the stateless reset"
else
  fail "client did not recover after relay restart"
fi

# UDP blocked (spec §20 Stage C exit): the session's TLS/TCP paths take
# over without a new handshake, and UDP takes back over when it returns.
block_udp() { $C iptables -"$1" OUTPUT -p udp -d 192.168.10.2 --dport 4433 -j DROP; }
sessions=$(grep -c 'session established' "$WORK/client.log")
sleep 2 # the TLS carriers connect and join
$C timeout 60 ping -c100 -i0.05 -W1 192.168.20.2 >"$WORK/tls-failover.log" 2>&1 &
PING_PID=$!
sleep 1
block_udp A
wait "$PING_PID" || true
received=$(grep -oE '[0-9]+ received' "$WORK/tls-failover.log" | awk '{print $1}')
lost=$((100 - ${received:-0}))
if ((${received:-0} > 0 && lost <= 40)); then
  pass "UDP blocked: traffic moved to TLS/TCP, losing $lost/100 pings (about $((lost * 50)) ms)"
else
  fail "UDP blocked: traffic did not move to TLS/TCP ($lost/100 pings lost)"
fi
if $C iperf3 -c 192.168.20.2 -t 3 -f m >"$WORK/iperf-tls.log" 2>&1; then
  pass "TCP uplink over TLS/TCP: $(grep -E 'receiver$' "$WORK/iperf-tls.log" | awk '{print $(NF-2), $(NF-1)}')"
else
  fail "TCP uplink over TLS/TCP"
fi
if [[ $(grep -c 'session established' "$WORK/client.log") -eq $sessions ]]; then
  pass "UDP to TLS/TCP failover kept the session"
else
  fail "UDP to TLS/TCP failover started a new session"
fi
block_udp D
sleep 3 # UDP paths turn healthy again
if $C timeout 60 ping -c5 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
  pass "traffic continues after UDP returns"
else
  fail "traffic stopped after UDP returned"
fi

# Connecting with UDP blocked from the start: the handshake goes out on
# every carrier, so it completes over TLS/TCP.
kill "$CLIENT_PID"; wait "$CLIENT_PID" 2>/dev/null || true
block_udp A
$C "$BIN/arc-client" run "${CLIENT_ARGS[@]}" >"$WORK/client-tls.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")
if wait_for 15 "session over TLS/TCP" grep -q "session established" "$WORK/client-tls.log" &&
  $C timeout 60 ping -c3 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
  pass "connected with UDP blocked, over TLS/TCP"
else
  fail "could not connect with UDP blocked"
fi
block_udp D

# Shutdown removes the routing rules.
kill "$CLIENT_PID"; wait "$CLIENT_PID" 2>/dev/null || true
if $C ip rule | grep -q 5243; then
  fail "routing rules left behind after the client exited"
else
  pass "routing rules removed on exit"
fi

echo
if [[ $failures -eq 0 ]]; then echo "e2e: all checks passed"; else echo "e2e: $failures check(s) failed"; exit 1; fi
