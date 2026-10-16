#!/usr/bin/env bash
# End-to-end test of the relay's HTTPS front (-front-listen) in the
# lib.sh topology (run as root on Linux): the stream carrier rides an
# authenticated HTTP upgrade, while everyone else sees an ordinary site.
#
# The client uses split-tunnel routes, so the test needs no IPv6 (the full
# tunnel's routing is e2e.sh's concern) and runs wherever e2e.sh's
# namespaces do.
#
# Usage: front.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: front.sh BIN_DIR}" && pwd)
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

FRONT=192.168.10.2:8443
setup_topology 10.77.0.0/16

# --- relay: the front is its only stream carrier --------------------------
"$BIN/arc-relay" genkey > "$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey < "$WORK/relay.key")
echo "front-token" > "$WORK/tokens"
echo "front-token" > "$WORK/token"
"$BIN/arc-relay" gencert -hosts 192.168.10.2 -cert "$WORK/relay.crt" -key "$WORK/relay.tls.key"
mkdir "$WORK/site"
echo "<h1>Cover site</h1>" > "$WORK/site/index.html"
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -front-listen "$FRONT" -front-site "$WORK/site" -tls-handshake-timeout 2s \
  -tls-cert "$WORK/relay.crt" -tls-key "$WORK/relay.tls.key" \
  -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
PIDS+=("$!")
wait_for 10 "relay up" $R ip addr show arc0

# --- the persona: what a visitor or prober sees ---------------------------
curl_front() { $C curl -sS --max-time 10 --cacert "$WORK/relay.crt" -o "$WORK/body" -w '%{http_code}' "$@" "https://$FRONT/"; }
if [[ $(curl_front) == 200 ]] && grep -q 'Cover site' "$WORK/body"; then
  pass "visitor gets the cover site"
else
  fail "visitor did not get the cover site"
fi
if [[ $(curl_front --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: arc' -H 'Authorization: Bearer wrong-token') == 200 ]] &&
  grep -q 'Cover site' "$WORK/body"; then
  pass "upgrade with a wrong token gets the cover site, not 101"
else
  fail "upgrade with a wrong token was not answered with cover"
fi
# A connection that never starts TLS is closed at -tls-handshake-timeout.
start=$SECONDS
$C timeout 10 bash -c 'exec 3<>/dev/tcp/192.168.10.2/8443; cat <&3 >/dev/null' 2>/dev/null || true
elapsed=$((SECONDS - start))
if ((elapsed >= 1 && elapsed <= 5)); then
  pass "silent connection closed after the handshake timeout (${elapsed}s)"
else
  fail "silent connection closed after ${elapsed}s, want about 2s"
fi

# --- client: UDP blocked from the start, so the front carries the session --
block_udp() { $C iptables -"$1" OUTPUT -p udp -d 192.168.10.2 --dport 4433 -j DROP; }
block_udp A
CLIENT_ARGS=(-relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" -token-file "$WORK/token"
  -route 192.168.20.0/24 -bind c0 -bind c1 -front "$FRONT" -tls-ca "$WORK/relay.crt")
$C "$BIN/arc-client" run "${CLIENT_ARGS[@]}" >"$WORK/client.log" 2>&1 &
PIDS+=("$!")
if wait_for 20 "session over the front" grep -q "session established" "$WORK/client.log" &&
  $C timeout 60 ping -c3 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
  pass "connected with UDP blocked, through the front"
else
  fail "could not connect through the front with UDP blocked"
fi
$I iperf3 -s -D --logfile "$WORK/iperf-server.log"
sleep 0.5
if $C iperf3 -c 192.168.20.2 -t 3 -f m >"$WORK/iperf-front.log" 2>&1; then
  pass "TCP uplink through the front: $(grep -E 'receiver$' "$WORK/iperf-front.log" | awk '{print $(NF-2), $(NF-1)}')"
else
  fail "TCP uplink through the front"
fi
# The site stays up for visitors while carriers run on the same port.
if [[ $(curl_front) == 200 ]]; then
  pass "visitors still get the cover site while carriers run"
else
  fail "visitor refused while carriers run"
fi

# --- failover: UDP returns, then is blocked mid-session ---------------------
block_udp D
sleep 3 # UDP paths join and turn healthy
sessions=$(grep -c 'session established' "$WORK/client.log")
$C timeout 60 ping -c100 -i0.05 -W1 192.168.20.2 >"$WORK/front-failover.log" 2>&1 &
PING_PID=$!
sleep 1
block_udp A
wait "$PING_PID" || true
received=$(grep -oE '[0-9]+ received' "$WORK/front-failover.log" | awk '{print $1}')
lost=$((100 - ${received:-0}))
if ((${received:-0} > 0 && lost <= 40)); then
  pass "UDP blocked mid-session: traffic moved to the front, losing $lost/100 pings"
else
  fail "UDP blocked mid-session: traffic did not move to the front ($lost/100 pings lost)"
fi
if [[ $(grep -c 'session established' "$WORK/client.log") -eq $sessions ]]; then
  pass "failover to the front kept the session"
else
  fail "failover to the front started a new session"
fi
block_udp D

echo
if [[ $failures -eq 0 ]]; then echo "front: all checks passed"; else echo "front: $failures check(s) failed"; exit 1; fi
