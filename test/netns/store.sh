#!/usr/bin/env bash
# The relay's accounts store end to end (run as root on Linux): a relay
# with -accounts-store, seeded from a tokens file, changed while it runs
# through `arc-relay accounts` on its control socket, and while it is
# stopped by the same command acting as the writer. Covers what the
# in-process tests cannot: the real binaries, the socket, the writer
# lock, and the lease handed over across a restart and a crash.
#
# Usage: store.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: store.sh BIN_DIR}" && pwd)
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  teardown_topology
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
    echo "--- accounts store"; cat "$WORK/accounts" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local secs=$1 what=$2; shift 2
  wait_until "$secs" "$@" || { fail "$what (timed out)"; return 1; }
}

setup_topology 10.77.0.0/16

"$BIN/arc-relay" genkey >"$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
echo "lane legacy-token relay" >"$WORK/tokens"
echo "legacy-token" >"$WORK/legacy-token"
STORE="file:$WORK/accounts"
CTL="$WORK/control"
ACCOUNTS=("$BIN/arc-relay" accounts -control "$CTL" -store "$STORE")

start_relay() {
  $R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -accounts-store "$STORE" -accounts-control "$CTL" -accounts-holder relay-1 \
    -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=("$RELAY_PID")
}

# client NAME TOKEN_FILE TUN: runs a client, recording its PID in NAME_PID.
client() {
  $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" -token-file "$2" \
    -route 10.77.0.0/16 -bind c0 -tun "$3" >"$WORK/client-$1.log" 2>&1 &
  printf -v "${1}_PID" %s $!
  PIDS+=($!)
}

start_relay
wait_for 10 "relay holds the lease" grep -q "accounts lease acquired" "$WORK/relay.log" &&
  pass "relay seeded the empty store from the tokens file and took the lease"
grep -q "^# arc-accounts 2" "$WORK/accounts" && ! grep -q legacy-token "$WORK/accounts" &&
  pass "store is in the version-2 format, with no plaintext token" ||
  fail "store not migrated: $(head -c 300 "$WORK/accounts")"

client legacy "$WORK/legacy-token" arc0
wait_for 10 "legacy token connects" grep -q "session established" "$WORK/client-legacy.log" &&
  pass "a migrated token still connects"

# Changes through the control socket, while the relay runs.
"${ACCOUNTS[@]}" add alexei >/dev/null &&
  "${ACCOUNTS[@]}" add-token alexei laptop | tail -n1 >"$WORK/alexei-token" &&
  [[ -s "$WORK/alexei-token" ]] && pass "account and device added through the control socket" ||
  fail "control socket commands failed"
client alexei "$WORK/alexei-token" arc9
wait_for 10 "new device connects" grep -q "session established" "$WORK/client-alexei.log" &&
  pass "a device added while the relay runs connects without a restart"
grep -q 'msg="session established".*account=alexei.*device=laptop' "$WORK/relay.log" &&
  pass "relay names the account and device" || fail "session line lacks account or device"

"${ACCOUNTS[@]}" revoke alexei/laptop >/dev/null
wait_for 10 "revoked client stops" bash -c "! kill -0 $alexei_PID 2>/dev/null" &&
  pass "revoking a device closes its session and its client stops"
grep -q 'msg="session revoked".*device=laptop' "$WORK/relay.log" &&
  pass "relay logged the revocation" || fail "no revocation line"
kill -0 "$legacy_PID" 2>/dev/null && pass "other devices keep their sessions" ||
  fail "revoking one device ended another's client"

# While the relay is stopped, the command is the writer itself; a clean
# shutdown released the lease, so it need not wait.
kill "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
if "${ACCOUNTS[@]}" add offline >"$WORK/offline.log" 2>&1; then
  pass "offline command committed to the store after a clean shutdown"
else
  fail "offline command: $(cat "$WORK/offline.log")"
fi
start_relay
wait_for 10 "relay retakes the lease" bash -c "[ \$(grep -c 'accounts lease acquired' '$WORK/relay.log') -ge 2 ]" &&
  "${ACCOUNTS[@]}" list >"$WORK/list.log" && grep -q '^offline' "$WORK/list.log" && grep -q '^alexei' "$WORK/list.log" &&
  ! grep -q laptop "$WORK/list.log" && pass "restarted relay serves the store's latest state" ||
  fail "after restart: $(cat "$WORK/list.log" 2>/dev/null)"
wait_for 20 "legacy client reconnects" bash -c "[ \$(grep -c 'session established' '$WORK/client-legacy.log') -ge 2 ]" &&
  pass "legacy client reconnected to the restarted relay"

# After a crash, the relay retakes its own live lease at once: the token
# it kept in its control directory proves the lease is its own.
kill -9 "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
start_relay
wait_for 10 "crashed relay retakes its lease" bash -c "[ \$(grep -c 'accounts lease acquired' '$WORK/relay.log') -ge 3 ]" &&
  pass "a relay restarted after a crash retakes its own lease at once"

# Another relay with the same holder name but its own control directory
# is a different instance: it waits for the lease instead of taking it.
$R "$BIN/arc-relay" run -listen 192.168.10.2:4435 -key-file "$WORK/relay.key" -reset-secret-file "$WORK/reset.secret" \
  -accounts-store "$STORE" -accounts-control "$WORK/control-twin" -accounts-holder relay-1 \
  -tun arc2 -network 10.79.0.1/16 >"$WORK/twin.log" 2>&1 &
TWIN_PID=$!
PIDS+=("$TWIN_PID")
wait_for 10 "same-named relay waits" grep -q "waiting for the accounts lease" "$WORK/twin.log" &&
  ! grep -q "accounts lease acquired" "$WORK/twin.log" && pass "a relay with the same holder name does not take a live lease" ||
  fail "same-named relay: $(cat "$WORK/twin.log")"

# The operator, asserting the holder is gone, has the waiting relay take
# over through its control socket; the old holder loses the lease at its
# next renewal and closes its sessions.
if "$BIN/arc-relay" accounts -control "$WORK/control-twin" takeover >"$WORK/takeover.log" 2>&1; then
  grep -q "accounts lease acquired" "$WORK/twin.log" && pass "takeover through a waiting relay's control socket" ||
    fail "takeover: the waiting relay did not log the lease"
else
  fail "takeover: $(cat "$WORK/takeover.log")"
fi
wait_for 90 "old holder loses the lease" grep -q "accounts lease lost" "$WORK/relay.log" &&
  pass "the old holder lost the lease after the takeover"
kill "$TWIN_PID"; wait "$TWIN_PID" 2>/dev/null || true

# A second relay process on the host is refused by the writer lock.
if $R "$BIN/arc-relay" run -listen 192.168.10.2:4434 -key-file "$WORK/relay.key" -reset-secret-file "$WORK/reset.secret" \
  -accounts-store "$STORE" -accounts-control "$CTL" -tun arc1 -network 10.78.0.1/16 >"$WORK/second.log" 2>&1; then
  fail "a second relay ran against the same control directory"
else
  grep -q "another writer on this host" "$WORK/second.log" && pass "a second writer on the host is refused" ||
    fail "second relay failed otherwise: $(cat "$WORK/second.log")"
fi

echo
if [[ $failures -eq 0 ]]; then echo "store: all checks passed"; else echo "store: $failures check(s) failed"; exit 1; fi
