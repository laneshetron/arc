#!/usr/bin/env bash
# Device-minted invites end to end (run as root on Linux): an enrolled
# device asks the relay for an invite to its account over ARC
# (`arc-client invite`, self-service-accounts.md §3.6) and a new device
# enrolls with it, under the minter. Covers minting under heavy loss, an
# interrupted request resumed, a chain of minters, the outstanding cap, a
# legacy device refused, revoke -descendants closing a descendant's live
# session, and rotate.
#
# Usage: invites.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: invites.sh BIN_DIR}" && pwd)
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
  -accounts-store "file:$WORK/accounts" -accounts-control "$CTL" -invite-key-file "$WORK/invite.key" \
  -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_for 10 "relay holds the lease" grep -q "accounts lease acquired" "$WORK/relay.log"

"${ACCOUNTS[@]}" add -max-devices 5 alexei >/dev/null
OPERATOR=$("${ACCOUNTS[@]}" invite -address 192.168.10.2 alexei | tail -n 1)

# client CMD NAME ARGS...: runs arc-client CMD in the client namespace,
# logging to CMD-NAME.log (and its stdout to CMD-NAME.out).
client() {
  local cmd=$1 name=$2; shift 2
  $C "$BIN/arc-client" "$cmd" -bind c0 -timeout 60s "$@" >"$WORK/$cmd-$name.out" 2>"$WORK/$cmd-$name.log"
}
devices() { "${ACCOUNTS[@]}" list; }

client enroll laptop -profile "$WORK/laptop" -device laptop "$OPERATOR" ||
  fail "laptop enroll: $(tail -n 3 "$WORK/enroll-laptop.log")"

# Minting under heavy loss: the request and its answer get through as
# AUTH does.
lossy=
if netem_available; then
  impair 0 loss 50%
  lossy=" under 50% loss each way"
fi
if client invite laptop1 -profile "$WORK/laptop"; then
  MINTED=$(tail -n 1 "$WORK/invite-laptop1.out")
  [[ $MINTED == arc1:* ]] && pass "an enrolled device minted an invite$lossy" || fail "invite: $MINTED"
else
  fail "invite: $(tail -n 5 "$WORK/invite-laptop1.log")"
fi
[[ -n $lossy ]] && unimpair 0
grep -q "invite minted.*account=alexei device=laptop" "$WORK/relay.log" &&
  pass "the relay logged the minted invite" || fail "no minted invite in the relay's log"
[[ ! -e "$WORK/laptop/invite-request" ]] && pass "the answered request is forgotten" || fail "request file left behind"

# A new device enrolls with it, under the minter.
if client enroll phone -profile "$WORK/phone" -device phone "$MINTED"; then
  devices >"$WORK/list.log"
  grep -q "^    phone" "$WORK/list.log" && pass "the minted invite enrolled a device under its minter" ||
    fail "phone not under laptop: $(cat "$WORK/list.log")"
else
  fail "phone enroll: $(tail -n 5 "$WORK/enroll-phone.log")"
fi

# An interrupted request is kept, and resumed by the next run.
ip -n arc-c link set c0 down
client invite laptop2 -profile "$WORK/laptop" -timeout 3s || true
ip -n arc-c link set c0 up
REQ=$(cat "$WORK/laptop/invite-request" 2>/dev/null || true)
if [[ -n $REQ ]] && client invite laptop3 -profile "$WORK/laptop"; then
  pass "an interrupted request is kept and resumed"
else
  fail "resume: request '$REQ', $(tail -n 3 "$WORK/invite-laptop3.log")"
fi

# A minted device mints in turn: its child is two below the root.
if client invite phone1 -profile "$WORK/phone" && client enroll tablet -profile "$WORK/tablet" -device tablet "$(tail -n 1 "$WORK/invite-phone1.out")"; then
  devices >"$WORK/list.log"
  grep -q "^      tablet" "$WORK/list.log" && pass "a chain of minters: tablet enrolled under phone" ||
    fail "tablet: $(cat "$WORK/list.log")"
else
  fail "chain: $(tail -n 3 "$WORK/invite-phone1.log" "$WORK/enroll-tablet.log")"
fi

# laptop3's invite is still outstanding; one more fills the cap of 2, and
# the next is refused.
client invite laptop4 -profile "$WORK/laptop" || fail "second outstanding: $(tail -n 3 "$WORK/invite-laptop4.log")"
if client invite laptop5 -profile "$WORK/laptop"; then
  fail "a third outstanding invite was minted"
else
  grep -q "invites outstanding" "$WORK/invite-laptop5.log" && pass "a third outstanding invite is refused" ||
    fail "third: $(tail -n 3 "$WORK/invite-laptop5.log")"
fi

# A legacy device, a token bound to no key, may not mint.
LEGACY_TOKEN=$("${ACCOUNTS[@]}" add-token alexei legacy | tail -n 1)
mkdir -p "$WORK/legacy"
echo "$LEGACY_TOKEN" >"$WORK/legacy/token"
"$BIN/arc-relay" genkey >"$WORK/legacy/key"
printf 'relay=192.168.10.2:4433\nrelay-key=%s\n' "$("$BIN/arc-relay" pubkey <"$WORK/relay.key")" >"$WORK/legacy/profile"
if client invite legacy -profile "$WORK/legacy"; then
  fail "a legacy device minted an invite"
else
  grep -q "does not let this device mint" "$WORK/invite-legacy.log" && pass "a legacy device is refused" ||
    fail "legacy: $(tail -n 3 "$WORK/invite-legacy.log")"
fi

# revoke -descendants: the laptop, and the phone and tablet it led to;
# the tablet's live session closes.
$C "$BIN/arc-client" run -profile "$WORK/tablet" -route 10.77.0.0/16 -bind c0 -tun arc0 >"$WORK/run-tablet.log" 2>&1 &
TABLET=$!
PIDS+=("$TABLET")
wait_for 10 "tablet connects" grep -q "session established" "$WORK/run-tablet.log"
"${ACCOUNTS[@]}" revoke -descendants alexei/laptop >"$WORK/revoke.log"
devices >"$WORK/list.log"
if grep -q "alexei/tablet" "$WORK/revoke.log" && ! grep -qE "^ +(laptop|phone|tablet) " "$WORK/list.log" && grep -q "^  legacy" "$WORK/list.log"; then
  pass "revoke -descendants revoked the laptop and every device under it, and no other"
else
  fail "revoke -descendants: $(cat "$WORK/revoke.log" "$WORK/list.log")"
fi
wait_for 10 "the tablet's session closed" grep -q "session closed.*device=tablet" "$WORK/relay.log" &&
  pass "a descendant's live session is closed"

# rotate: every device and invite goes, the policy stays, and a fresh
# operator invite is printed.
"${ACCOUNTS[@]}" rotate -address 192.168.10.2 alexei >"$WORK/rotate.log"
devices >"$WORK/list.log"
if tail -n 1 "$WORK/rotate.log" | grep -q "^arc1:" && ! grep -q "^  legacy" "$WORK/list.log" &&
  grep -q "^alexei.*max_devices=5" "$WORK/list.log" && [[ $(grep -c "^  invite" "$WORK/list.log") -eq 1 ]]; then
  pass "rotate revoked every device and invite, kept the policy, and printed a fresh invite"
else
  fail "rotate: $(cat "$WORK/rotate.log" "$WORK/list.log")"
fi

echo
if [[ $failures -eq 0 ]]; then echo "invites: all checks passed"; else echo "invites: $failures check(s) failed"; exit 1; fi
