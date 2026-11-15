#!/usr/bin/env bash
# Enrollment end to end (run as root on Linux): an operator invite from
# `arc-relay accounts invite`, redeemed over ARC itself by
# `arc-client enroll` (self-service-accounts.md §3.4), then the profile it
# wrote used by `arc-client run -profile`. Covers enrolling under heavy
# loss, a lost answer retried past the invite's expiry, a second
# redemption refused, and a copied token refused from another key.
#
# Usage: enroll.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: enroll.sh BIN_DIR}" && pwd)
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
$R "$BIN/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -accounts-store "file:$WORK/accounts" -accounts-control "$CTL" \
  -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_for 10 "relay holds the lease" grep -q "accounts lease acquired" "$WORK/relay.log"

"${ACCOUNTS[@]}" add -max-devices 3 alexei >/dev/null
invite() { # invite [FLAGS]: prints a new invite to alexei
  "${ACCOUNTS[@]}" invite -address 192.168.10.2 "$@" alexei | tail -n 1
}
INVITE=$(invite)
[[ $INVITE == arc1:* ]] && pass "operator invite printed (${#INVITE} characters)" || fail "invite: $INVITE"

# enroll NAME PROFILE INVITE [FLAGS]: runs arc-client enroll in the client
# namespace, logging to enroll-NAME.log.
enroll() {
  local name=$1 dir=$2 inv=$3; shift 3
  $C "$BIN/arc-client" enroll -profile "$dir" -bind c0 -timeout 60s "$@" "$inv" >"$WORK/enroll-$name.log" 2>&1
}

# Enrolling under heavy loss: the handshake and the AUTH that redeems the
# invite are repeated until they get through, as the tunnel's are.
lossy=
if netem_available; then
  impair 0 loss 50%
  lossy=" under 50% loss each way"
fi
if enroll laptop "$WORK/laptop" "$INVITE" -device laptop; then
  pass "enrolled$lossy"
else
  fail "enroll: $(tail -n 5 "$WORK/enroll-laptop.log")"
fi
[[ -n $lossy ]] && unimpair 0
grep -q "device enrolled.*account=alexei device=laptop" "$WORK/relay.log" &&
  pass "relay logged the enrollment" || fail "no enrollment in the relay's log"
grep -q "^device=laptop" "$WORK/laptop/profile" && ! grep -q "^invite=" "$WORK/laptop/profile" &&
  pass "profile records the device and drops the redeemed invite" || fail "profile: $(cat "$WORK/laptop/profile")"

$C "$BIN/arc-client" run -profile "$WORK/laptop" -route 10.77.0.0/16 -bind c0 -tun arc0 >"$WORK/run-laptop.log" 2>&1 &
LAPTOP_PID=$!
PIDS+=("$LAPTOP_PID")
wait_for 10 "profile connects" grep -q "session established" "$WORK/run-laptop.log" &&
  wait_for 10 "relay names the device" grep -q "session established.*device=laptop" "$WORK/relay.log" &&
  pass "arc-client run -profile connects as the enrolled device"

if enroll again "$WORK/laptop" "$INVITE"; then
  fail "enrolled twice into one profile"
else
  grep -q "already holds an enrolled device" "$WORK/enroll-again.log" && pass "an enrolled profile is not enrolled again" ||
    fail "re-enroll: $(tail -n 3 "$WORK/enroll-again.log")"
fi

# Another device with the same invite is told it was used, and the relay
# warns: someone else redeemed it first.
if enroll phone "$WORK/phone" "$INVITE"; then
  fail "a second device redeemed the same invite"
else
  grep -q "already used by another device" "$WORK/enroll-phone.log" &&
    grep -q "invite already used by another device" "$WORK/relay.log" &&
    pass "a second redemption is refused INVITE_USED, and the relay warns" ||
    fail "second redemption: $(tail -n 3 "$WORK/enroll-phone.log")"
fi

# A copied token is useless from another key.
"$BIN/arc-relay" genkey >"$WORK/other.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
if timeout 20 $C "$BIN/arc-client" run -relay 192.168.10.2:4433 -relay-key "$RELAY_PUB" -token-file "$WORK/laptop/token" \
  -key-file "$WORK/other.key" -bind c0 -tun arc1 >"$WORK/copied.log" 2>&1; then
  fail "a copied token connected from another key"
else
  grep -q "token bound to another device key" "$WORK/relay.log" &&
    pass "a copied token is refused from another key" || fail "copied token: $(tail -n 3 "$WORK/copied.log")"
fi

# A lost answer: the relay enrolled the device, but the client never heard
# (here, its profile is put back as it was before the answer). Retried
# after the invite expired, the redemption is still recognized as made.
SHORT=$(invite -ttl 5s)
mkdir -p "$WORK/tablet"
# Write the profile and stop before connecting: a relay that is not
# reachable yet (the client's link down).
ip -n arc-c link set c0 down
enroll tablet-prep "$WORK/tablet" "$SHORT" -device tablet -timeout 2s || true
ip -n arc-c link set c0 up
cp -a "$WORK/tablet" "$WORK/tablet.before"
if enroll tablet "$WORK/tablet" "$SHORT" -device tablet; then
  rm -rf "$WORK/tablet" && mv "$WORK/tablet.before" "$WORK/tablet" # the answer, lost
  sleep 6
  if enroll tablet-retry "$WORK/tablet" "$SHORT" -device tablet; then
    grep -q "^device=tablet" "$WORK/tablet/profile" && [[ $(grep -c "device enrolled.*device=tablet" "$WORK/relay.log") -ge 2 ]] &&
      pass "a redemption whose answer was lost is recognized past the invite's expiry" ||
      fail "retry: $(cat "$WORK/tablet/profile")"
  else
    fail "retry after expiry: $(tail -n 5 "$WORK/enroll-tablet-retry.log")"
  fi
else
  fail "tablet enroll: $(tail -n 5 "$WORK/enroll-tablet.log")"
fi
"${ACCOUNTS[@]}" list >"$WORK/list.log"
[[ $(grep -c "^  tablet" "$WORK/list.log") -eq 1 ]] && pass "the retry made no second device" ||
  fail "devices after the retry: $(cat "$WORK/list.log")"

echo
if [[ $failures -eq 0 ]]; then echo "enroll: all checks passed"; else echo "enroll: $failures check(s) failed"; exit 1; fi
