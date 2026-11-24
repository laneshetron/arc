#!/usr/bin/env bash
# Cross-version compatibility (run as root on Linux): a relay from one
# build with a client from another, both ways round, so a change that
# breaks devices already in the field, or clients meeting a relay not yet
# upgraded, fails here rather than after a deploy.
#
# Each round (old relay with new client, then new relay with old client)
# checks what a deployed device does: a plain-token device connects; an
# operator invite (made by the relay's build, decoded by the client's)
# enrolls; the enrolled profile connects over UDP and carries bulk traffic
# both ways; the device lists its account's devices and mints an invite
# that enrolls another; and a TLS-only invite enrolls and carries traffic
# over the stream carrier alone.
#
# The script uses only flags both builds have. CI runs it against the
# pull request's base and against the oldest build still supported
# (.github/workflows/ci.yml, COMPAT_FLOOR).
#
# Usage: compat.sh NEW_BIN_DIR OLD_BIN_DIR
#   (each holds arc-client and arc-relay; see the Dockerfile for Docker)
set -euo pipefail

NEW=$(cd "${1:?usage: compat.sh NEW_BIN_DIR OLD_BIN_DIR}" && pwd)
OLD=$(cd "${2:?usage: compat.sh NEW_BIN_DIR OLD_BIN_DIR}" && pwd)
source "$(dirname "$0")/lib.sh"
failures=0
ROUND=

pass() { echo "PASS: [$ROUND] $*"; }
fail() { echo "FAIL: [$ROUND] $*"; failures=$((failures + 1)); }

WORK=
dump_logs() {
  [[ -n $WORK && -d $WORK ]] || return 0
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- [$ROUND] $f"; tail -n 30 "$f"; done
  fi
}
cleanup() {
  teardown_topology
  dump_logs
  if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local secs=$1 what=$2; shift 2
  wait_until "$secs" "$@" || { fail "$what (timed out)"; return 1; }
}

# round LABEL RELAY_BIN CLIENT_BIN
round() {
  ROUND=$1
  local rbin=$2 cbin=$3 before=$failures
  WORK=$(mktemp -d)
  PIDS=()
  setup_topology 10.77.0.0/16
  $I iperf3 -s -D -I "$WORK/iperf.pid" --logfile "$WORK/iperf-server.log"
  wait_until 5 test -s "$WORK/iperf.pid" && PIDS+=("$(cat "$WORK/iperf.pid")")

  "$rbin/arc-relay" genkey >"$WORK/relay.key"
  "$rbin/arc-relay" gencert -hosts 192.168.10.2 -cert "$WORK/relay.crt" -key "$WORK/relay.tls.key"
  : >"$WORK/tokens"
  local ctl="$WORK/control"
  accounts() { "$rbin/arc-relay" accounts -control "$ctl" "$@"; }
  $R "$rbin/arc-relay" run -listen 192.168.10.2:4433 -key-file "$WORK/relay.key" \
    -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
    -accounts-store "file:$WORK/accounts" -accounts-control "$ctl" -invite-key-file "$WORK/invite.key" \
    -tls-listen 192.168.10.2:8443 -tls-cert "$WORK/relay.crt" -tls-key "$WORK/relay.tls.key" -tls-camouflage \
    -network 10.77.0.1/16 >>"$WORK/relay.log" 2>&1 &
  PIDS+=($!)
  wait_for 10 "relay holds the lease" grep -q "accounts lease acquired" "$WORK/relay.log" || { finish_round "$before"; return; }
  accounts add alexei >/dev/null

  # client CMD NAME ARGS...: a one-shot arc-client command, logging to
  # CMD-NAME.log and its stdout to CMD-NAME.out.
  client() {
    local cmd=$1 name=$2; shift 2
    $C "$cbin/arc-client" "$cmd" -bind c0 -timeout 60s "$@" >"$WORK/$cmd-$name.out" 2>"$WORK/$cmd-$name.log"
  }
  # tunnel NAME ARGS...: runs arc-client run until it is established,
  # checks traffic through it, then stops it. With -down, only the
  # download is measured.
  tunnel() {
    local name=$1; shift
    $C "$cbin/arc-client" run -route 192.168.20.0/24 -bind c0 -tun "arc-$name" "$@" >"$WORK/run-$name.log" 2>&1 &
    local pid=$!
    if wait_for 15 "$name connects" grep -q "session established" "$WORK/run-$name.log"; then
      if $C timeout 30 ping -c3 -i0.2 -W2 192.168.20.2 >/dev/null 2>&1; then
        pass "$name connects and reaches the internet through the relay"
      else
        fail "$name: no ping through the tunnel"
      fi
      local dir
      for dir in up down; do
        local rev=()
        [[ $dir == down ]] && rev=(-R)
        if $C timeout 30 iperf3 -c 192.168.20.2 -t 2 -f m "${rev[@]}" >"$WORK/iperf-$name-$dir.log" 2>&1; then
          pass "$name carries bulk traffic $dir ($(awk '/receiver/ {print $7, $8}' "$WORK/iperf-$name-$dir.log"))"
        else
          fail "$name: iperf3 $dir failed"
        fi
      done
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  }

  # A plain-token device, as from before invites.
  local token
  token=$(accounts add-token alexei legacy | tail -n 1)
  echo "$token" >"$WORK/legacy.token"
  tunnel legacy -relay 192.168.10.2:4433 -relay-key "$("$rbin/arc-relay" pubkey <"$WORK/relay.key")" \
    -token-file "$WORK/legacy.token"

  # An operator invite, made by the relay's build.
  local inv
  inv=$(accounts invite -address 192.168.10.2 alexei | tail -n 1)
  if client enroll laptop -profile "$WORK/laptop" -device laptop "$inv"; then
    pass "an operator invite enrolls"
    tunnel laptop -profile "$WORK/laptop"
  else
    fail "enroll: $(tail -n 3 "$WORK/enroll-laptop.log")"
  fi

  # The device's own requests: list devices, mint an invite.
  if client devices laptop -profile "$WORK/laptop" && grep -q "^laptop (this device)" "$WORK/devices-laptop.out" &&
    grep -q "^legacy " "$WORK/devices-laptop.out"; then
    pass "the device lists its account's devices"
  else
    fail "devices: $(cat "$WORK/devices-laptop.out"; tail -n 3 "$WORK/devices-laptop.log")"
  fi
  if client invite laptop -profile "$WORK/laptop" &&
    client enroll phone -profile "$WORK/phone" -device phone "$(tail -n 1 "$WORK/invite-laptop.out")"; then
    pass "the device mints an invite that enrolls another"
  else
    fail "minted invite: $(tail -n 3 "$WORK/invite-laptop.log" "$WORK/enroll-phone.log" 2>/dev/null)"
  fi

  # A TLS-only invite: enrollment and traffic over the stream carrier.
  inv=$(accounts invite -address 192.168.10.2 -udp-port 0 -tls-port 8443 -tls-cover www.example.com alexei | tail -n 1)
  if client enroll tls -profile "$WORK/tls" -device tls "$inv"; then
    pass "a TLS-only invite enrolls"
    tunnel tls -profile "$WORK/tls"
  else
    fail "TLS-only enroll: $(tail -n 3 "$WORK/enroll-tls.log")"
  fi

  finish_round "$before"
}

finish_round() { # finish_round FAILURES_BEFORE
  local before=$1
  [[ $failures -eq $before ]] && echo "[$ROUND] all checks passed"
  teardown_topology
  dump_logs
  rm -rf "$WORK"
  WORK=
  echo
}

round "old relay, new client" "$OLD" "$NEW"
round "new relay, old client" "$NEW" "$OLD"

# Exit explicitly: otherwise the EXIT trap's last command sets the status.
if [[ $failures -eq 0 ]]; then echo "compat: all checks passed"; exit 0; fi
echo "compat: $failures check(s) failed"
exit 1
