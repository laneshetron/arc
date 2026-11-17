#!/usr/bin/env bash
# Devices managing devices end to end (run as root on Linux): a device
# lists its account's devices and revokes another over ARC
# (`arc-client devices` and `revoke`, self-service-accounts.md §3.8).
# Covers the device tree, a device younger than 24 hours refused, a
# connected device revoked with its descendants from another (its client
# stops), the relay's warning, the operator's restore, a device revoking
# itself, and a legacy device refused.
#
# Usage: devices.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: devices.sh BIN_DIR}" && pwd)
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
: >"$WORK/tokens"
CTL="$WORK/control"
ACCOUNTS=("$BIN/arc-relay" accounts -control "$CTL")
start_relay() {
  $R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -accounts-store "file:$WORK/accounts" -accounts-control "$CTL" -invite-key-file "$WORK/invite.key" \
    -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
  RELAY_PID=$!
  PIDS+=("$RELAY_PID")
}
start_relay
wait_for 10 "relay holds the lease" grep -q "accounts lease acquired" "$WORK/relay.log"

"${ACCOUNTS[@]}" add alexei >/dev/null
invite() { "${ACCOUNTS[@]}" invite -address 192.168.10.2 alexei | tail -n 1; }

# client CMD NAME ARGS...: runs arc-client CMD in the client namespace,
# logging to CMD-NAME.log (and its stdout to CMD-NAME.out).
client() {
  local cmd=$1 name=$2; shift 2
  $C "$BIN/arc-client" "$cmd" -bind c0 -timeout 60s "$@" >"$WORK/$cmd-$name.out" 2>"$WORK/$cmd-$name.log"
}
devices() { "${ACCOUNTS[@]}" list; }

# The laptop and desktop enroll by operator invites; the phone by one the
# laptop minted.
client enroll laptop -profile "$WORK/laptop" -device laptop "$(invite)" || fail "laptop enroll: $(tail -n 3 "$WORK/enroll-laptop.log")"
client enroll desktop -profile "$WORK/desktop" -device desktop "$(invite)" || fail "desktop enroll: $(tail -n 3 "$WORK/enroll-desktop.log")"
client invite laptop -profile "$WORK/laptop" && client enroll phone -profile "$WORK/phone" -device phone "$(tail -n 1 "$WORK/invite-laptop.out")" ||
  fail "phone: $(tail -n 3 "$WORK/invite-laptop.log" "$WORK/enroll-phone.log")"

if client devices desktop1 -profile "$WORK/desktop"; then
  out="$WORK/devices-desktop1.out"
  grep -q "^desktop (this device)" "$out" && grep -q "^laptop " "$out" && grep -q "^  phone " "$out" &&
    pass "a device lists its account's devices as a tree, marking itself" || fail "devices: $(cat "$out")"
else
  fail "devices: $(tail -n 3 "$WORK/devices-desktop1.log")"
fi

# A device younger than 24 hours may not revoke another.
if client revoke young -profile "$WORK/desktop" laptop; then
  fail "a device younger than 24 hours revoked another"
else
  grep -q "only once enrolled for 24 hours" "$WORK/revoke-young.log" && devices | grep -q "^  laptop " &&
    pass "a device younger than 24 hours is refused" || fail "young: $(tail -n 3 "$WORK/revoke-young.log")"
fi

# Age the desktop past the cooling-off: stop the relay (releasing the
# lease), backdate its record in the store, and start the relay again.
kill "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
sed -i -E '/^device [0-9a-f]+ [0-9a-f]+ desktop /s/created=[^ ]+/created=2020-01-01T00:00:00Z/' "$WORK/accounts"
start_relay
wait_for 10 "relay retakes the lease" bash -c "[ \$(grep -c 'accounts lease acquired' '$WORK/relay.log') -ge 2 ]"

# The desktop revokes the connected laptop, and the phone it invited.
$C "$BIN/arc-client" run -profile "$WORK/laptop" -route 10.77.0.0/16 -bind c0 -tun arc0 >"$WORK/run-laptop.log" 2>&1 &
LAPTOP=$!
PIDS+=("$LAPTOP")
wait_for 10 "laptop connects" grep -q "session established" "$WORK/run-laptop.log"
if client revoke desktop -profile "$WORK/desktop" -descendants laptop; then
  devices >"$WORK/list.log"
  ! grep -qE "^ +(laptop|phone) " "$WORK/list.log" && grep -q "^  desktop " "$WORK/list.log" &&
    pass "a device revoked another, and its descendants" || fail "revoke: $(cat "$WORK/list.log")"
else
  fail "revoke: $(tail -n 5 "$WORK/revoke-desktop.log")"
fi
wait_for 10 "the revoked laptop's client stops" bash -c "! kill -0 $LAPTOP 2>/dev/null" &&
  grep -q "revoked" "$WORK/run-laptop.log" && pass "the revoked laptop's session closed with REVOKED and its client stopped" ||
  fail "laptop client: $(tail -n 3 "$WORK/run-laptop.log")"
# Its token is now refused REVOKED, so the device learns why even without
# the CLOSE.
if client devices revoked -profile "$WORK/laptop"; then
  fail "a revoked device listed devices"
else
  grep -q "this device has been revoked" "$WORK/devices-revoked.log" && pass "a revoked device is told so when it connects again" ||
    fail "revoked device: $(tail -n 3 "$WORK/devices-revoked.log")"
fi
grep -q 'level=WARN msg="device revoked by a device" account=alexei by=desktop device=laptop' "$WORK/relay.log" &&
  pass "the relay warned of the revocation, naming both devices" || fail "no warning in the relay's log"

# The operator sees it, and restores the laptop: it connects again.
devices >"$WORK/list.log"
grep -q "revoked laptop .*by desktop; restore until" "$WORK/list.log" || fail "list omits the revocation: $(cat "$WORK/list.log")"
if "${ACCOUNTS[@]}" restore alexei/laptop >"$WORK/restore.log" 2>&1 && "${ACCOUNTS[@]}" restore alexei/phone >>"$WORK/restore.log" 2>&1; then
  $C "$BIN/arc-client" run -profile "$WORK/laptop" -route 10.77.0.0/16 -bind c0 -tun arc0 >"$WORK/run-laptop2.log" 2>&1 &
  LAPTOP=$!
  PIDS+=("$LAPTOP")
  wait_for 10 "the restored laptop connects" grep -q "session established" "$WORK/run-laptop2.log" &&
    pass "the operator restored the revoked devices, and the laptop connects again"
  kill "$LAPTOP" 2>/dev/null || true
else
  fail "restore: $(cat "$WORK/restore.log")"
fi
if "${ACCOUNTS[@]}" revoke alexei/phone >/dev/null && ! "${ACCOUNTS[@]}" restore alexei/phone >/dev/null 2>&1; then
  pass "an operator revocation cannot be restored"
else
  fail "restored an operator revocation"
fi

# A device may always revoke itself, young or not.
if client revoke self -profile "$WORK/laptop" laptop; then
  ! devices | grep -q "^  laptop " && pass "a device revoked itself" || fail "self revoke left the laptop"
else
  fail "self revoke: $(tail -n 3 "$WORK/revoke-self.log")"
fi

# A legacy device, a token bound to no key, may not list or revoke.
LEGACY_TOKEN=$("${ACCOUNTS[@]}" add-token alexei legacy | tail -n 1)
mkdir -p "$WORK/legacy"
echo "$LEGACY_TOKEN" >"$WORK/legacy/token"
"$BIN/arc-relay" genkey >"$WORK/legacy/key"
printf 'relay=192.168.10.2:4433\nrelay-key=%s\n' "$("$BIN/arc-relay" pubkey <"$WORK/relay.key")" >"$WORK/legacy/profile"
if client devices legacy -profile "$WORK/legacy"; then
  fail "a legacy device listed devices"
else
  grep -q "does not let this device manage" "$WORK/devices-legacy.log" && pass "a legacy device is refused" ||
    fail "legacy: $(tail -n 3 "$WORK/devices-legacy.log")"
fi

echo
if [[ $failures -eq 0 ]]; then echo "devices: all checks passed"; else echo "devices: $failures check(s) failed"; exit 1; fi
