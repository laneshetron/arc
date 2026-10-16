#!/usr/bin/env bash
# End-to-end test of the macOS client against a relay in Docker Desktop.
# Run as yourself from the repository root; it asks for sudo to run the
# client:
#
#   test/macos/e2e.sh
#
# The relay doesn't masquerade: Docker Desktop sends a container's
# Internet traffic out through the Mac, where the full tunnel would route
# it straight back into the tunnel. So the test reaches only addresses the
# relay's container owns: its tunnel address and 192.0.2.1, which stands
# in for the Internet. For the few seconds the full tunnel is up, nothing
# else on the Mac has Internet access.
set -euo pipefail

[[ $(uname) == Darwin ]] || { echo "macOS only; see test/netns for Linux" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
NAME=arc-macos-e2e
failures=0
client=

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  [[ -n $client ]] && sudo kill "$client" 2>/dev/null && sleep 2
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
    docker logs "$NAME" 2>&1 | tail -n 40 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_until() { # wait_until SECONDS COMMAND...
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 0.5
  done
}

routed_via() { # routed_via IFACE DEST: DEST's route leaves through IFACE
  route -n get "$2" 2>/dev/null | grep -q "interface: $1\$"
}

sudo -v
echo "building..."
(cd "$ROOT" && go build -o "$WORK/" ./cmd/arc-client ./cmd/arc-relay)
docker build -q -f "$ROOT/test/netns/Dockerfile" -t arc-e2e "$ROOT" >/dev/null

"$WORK/arc-relay" genkey > "$WORK/relay.key"
RELAY_PUB=$("$WORK/arc-relay" pubkey < "$WORK/relay.key")
echo "e2e-token" > "$WORK/tokens"
echo "e2e-token" > "$WORK/token"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged -p 4433:4433/udp -v "$WORK:/work" \
  --entrypoint sh arc-e2e -c '
    ip addr add 192.0.2.1/32 dev lo
    exec /arc/bin/arc-relay run -listen 0.0.0.0:4433 -key-file /work/relay.key \
      -reset-secret-file /work/reset.secret -tokens-file /work/tokens -network 10.77.0.1/16' >/dev/null

UNDERLAY=$(route -n get default | awk '/interface:/ {print $2}')
HOST_IP=$(ipconfig getifaddr "$UNDERLAY")
echo "underlay $UNDERLAY ($HOST_IP)"

start_client() { # start_client LOG ARGS...
  local log=$1; shift
  sudo "$WORK/arc-client" run -relay "$HOST_IP:4433" -relay-key "$RELAY_PUB" \
    -token-file "$WORK/token" "$@" >"$WORK/$log" 2>&1 &
  client=$!
  wait_until 10 grep -q 'tun=utun' "$WORK/$log" || { fail "client didn't start"; exit 1; }
  TUN=$(grep -o 'tun=utun[0-9]*' "$WORK/$log" | head -1 | cut -d= -f2)
}

stop_client() {
  sudo kill "$client"
  wait_until 10 sh -c "! kill -0 $client 2>/dev/null" || fail "client didn't exit"
  client=
}

# --- split tunnel ----------------------------------------------------------
start_client split.log -route 192.0.2.1/32
if wait_until 15 ping -c1 -t1 10.77.0.1; then
  pass "split: relay's tunnel address answers over $TUN"
else
  fail "split: no reply from 10.77.0.1"
fi
routed_via "$TUN" 192.0.2.1 && ping -c1 -t2 192.0.2.1 >/dev/null 2>&1 &&
  pass "split: -route prefix goes through the tunnel" || fail "split: -route prefix"
routed_via "$UNDERLAY" 198.51.100.1 && pass "split: other traffic stays off the tunnel" ||
  fail "split: other traffic routed into the tunnel"
stop_client
ifconfig "$TUN" >/dev/null 2>&1 && fail "split: $TUN outlived the client" || pass "split: $TUN removed on exit"

# --- full tunnel -----------------------------------------------------------
start_client full.log -full-tunnel -dns 10.77.0.1
if wait_until 15 ping -c1 -t1 192.0.2.1; then
  pass "full: Internet stand-in answers through the tunnel"
else
  fail "full: no reply from 192.0.2.1"
fi
grep -q "binding carrier to the default route's interface.*interface=$UNDERLAY" "$WORK/full.log" &&
  pass "full: carrier bound to $UNDERLAY" || fail "full: carrier not bound to $UNDERLAY"
routed_via "$TUN" 198.51.100.1 && pass "full: unrelated destinations go through $TUN" ||
  fail "full: 198.51.100.1 not routed through $TUN"
route -n get -inet6 2001:db8::1 2>&1 | grep -q REJECT && pass "full: IPv6 rejected" ||
  fail "full: IPv6 not rejected"
scutil --dns | awk '/^resolver #1/,/^$/' | grep -q 'nameserver\[0\] : 10.77.0.1' &&
  pass "full: default resolver is the tunnel's" || fail "full: default resolver not set"
stop_client
if routed_via "$UNDERLAY" 198.51.100.1 && ! route -n get -inet6 2001:db8::1 2>&1 | grep -q REJECT; then
  pass "full: routes restored on exit"
else
  fail "full: routes left behind"
fi
scutil --dns | grep -q 'nameserver\[[0-9]*\] : 10.77.0.1' && fail "full: tunnel resolver left behind" ||
  pass "full: DNS restored on exit"
echo "show State:/Network/Service/arc/IPv4" | scutil | grep -q 'No such key' &&
  pass "full: configd service removed" || fail "full: configd service left behind"

echo
if [[ $failures -eq 0 ]]; then echo "all passed"; else echo "$failures failed"; exit 1; fi
