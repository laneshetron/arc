#!/usr/bin/env bash
# Tests for portal-probe.sh.
#
# The script is run on a network the reader cannot debug, so its bugs show up
# as wrong conclusions rather than as errors. The cases below are the ones
# that produced a wrong conclusion in the field:
#
#   - curl prints "000" and exits nonzero on a failed transfer, so
#     `curl -w '%{http_code}' || echo fail` appends and yields "000fail",
#     which matches no intended case and fell through to "reachable".
#   - a missing nc made every port read "blocked", reporting a firewall that
#     may not exist.
#   - a probe that timed out read as "cleartext is redirected".
#
# Each test sources the script with its probes stubbed, so nothing here
# touches the network.
#
# Usage: ./portal-probe-test.sh   (needs bash, and nothing else)

set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/portal-probe.sh"
failures=0

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; failures=$((failures + 1)); }

# The script runs its whole report on source, which is inconvenient for unit
# tests. Everything up to the "collect" marker is definitions; take that.
defs() {
  sed -n '1,/^# ---------------------------------------------------------------- collect/p' "$SCRIPT"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- http_head
# The real function, with curl replaced. This is the regression exactly: curl
# prints "000" and exits nonzero on a failed transfer, so a `|| echo fail`
# appends to it.
test_http_head_real_function() {
  local out
  out=$(cd "$WORK" && { defs; cat <<'EOF'
have() { [ "$1" = curl ]; }
curl() { printf '%s' "$STUB_HTTP"; return "${STUB_RC:-0}"; }
v=$(http_head http://x/); printf '%s\n' "$v"
EOF
} >t.sh; STUB_HTTP='000|' STUB_RC=28 bash t.sh)
  case $out in
    "fail|") pass "http_head: curl printing 000 on failure yields fail" ;;
    *)       fail "http_head: got '$out' for a failed transfer, want 'fail|'" ;;
  esac

  out=$({ defs; cat <<'EOF'
have() { [ "$1" = curl ]; }
curl() { printf '%s' "$0" >/dev/null; printf '200|'; return 0; }
v=$(http_head http://x/); printf '%s\n' "$v"
EOF
} >"$WORK/t2.sh"; bash "$WORK/t2.sh")
  case $out in
    "200|") pass "http_head: a successful transfer keeps its status" ;;
    *)      fail "http_head: got '$out' for a successful transfer, want '200|'" ;;
  esac
}

# ---------------------------------------------------------------- tcp_verdict
# A missing nc must not read as a closed port.
test_tcp_verdict_without_nc() {
  local out
  out=$({ defs; cat <<'EOF'
NC_CONN=""
r=$(tcp_verdict 1.1.1.1 443); printf '%s\n' "$r"
EOF
} >"$WORK/t3.sh"; bash "$WORK/t3.sh")
  case $out in
    cannot-test*) pass "tcp_verdict: no nc reports cannot-test, not blocked" ;;
    blocked)      fail "tcp_verdict: no nc reported 'blocked', inventing a firewall" ;;
    *)            fail "tcp_verdict: got '$out' without nc" ;;
  esac
}

test_tcp_verdict_states() {
  local got
  for want in open blocked; do
    got=$({ defs; cat <<EOF
NC_CONN="-z -w"
nc() { return $([ "$want" = open ] && echo 0 || echo 1); }
printf '%s\n' "\$(tcp_verdict 1.1.1.1 443)"
EOF
} >"$WORK/t4.sh"; bash "$WORK/t4.sh")
    if [ "$got" = "$want" ]; then
      pass "tcp_verdict: reports $want"
    else
      fail "tcp_verdict: got '$got', want '$want'"
    fi
  done
}

# ---------------------------------------------------------------- section 0
# The verdict must distinguish three cases. Run the real section 0 against
# stubbed probes and read the line it prints.
portal_verdict_for() { # portal_verdict_for GSTREAM AAPPLE
  local g=$1 a=$2
  { defs; cat <<EOF
http_head() {
  case "\$1" in
    *gstatic*) printf '%s\n' "$g" ;;
    *apple*)   printf '%s\n' "$a" ;;
  esac
}
have() { return 0; }
resolve() { printf '\n'; }
$(sed -n '/^# Connectivity: is there a portal/,/^# Resolve the Apple push host/p' "$SCRIPT")
EOF
} >"$WORK/t5.sh"
  bash "$WORK/t5.sh" 2>&1 | grep -E '^  portal ' | sed 's/^  portal *//'
}

test_section0_healthy() {
  local got
  got=$(portal_verdict_for '204|' '200|')
  case $got in
    "no cleartext redirect seen"*) pass "section 0: two clean answers read as clean" ;;
    *) fail "section 0: got '$got' for two clean answers" ;;
  esac
}

test_section0_redirect() {
  local got
  got=$(portal_verdict_for '302|http://portal.example/login' '200|')
  case $got in
    YES*) pass "section 0: a redirect reads as a portal" ;;
    *)    fail "section 0: got '$got' for a redirect" ;;
  esac
}

test_section0_rewritten() {
  local got
  got=$(portal_verdict_for '200|' '200|')
  case $got in
    YES*) pass "section 0: a rewritten 200 reads as a portal" ;;
    *)    fail "section 0: got '$got' for a rewritten body" ;;
  esac
}

# The regression that matters: no answer must not be announced as a portal.
test_section0_no_answer() {
  local got
  got=$(portal_verdict_for 'fail|' 'fail|')
  case $got in
    YES*)        fail "section 0: an unreachable network was reported as redirecting cleartext" ;;
    undetermined*) pass "section 0: no answer reads as undetermined" ;;
    *)           fail "section 0: got '$got' when nothing answered" ;;
  esac
}

# One endpoint failing while the other answers cleanly is not a portal either:
# the answer we did get is the evidence, and it says the network is open.
test_section0_one_failure() {
  local got
  got=$(portal_verdict_for 'fail|' '200|')
  case $got in
    YES*) fail "section 0: a single failed probe was announced as a portal" ;;
    *)    pass "section 0: a failed gstatic with a clean apple is not a portal" ;;
  esac
}

# ---------------------------------------------------------------- sections
# Builds a script: the definitions, then stubs, then one extracted section —
# appended with sed rather than written inside a quoted heredoc, so the section
# is expanded at build time as intended.
section_harness() { # section_harness STUBS START_RE END_RE
  local stubs=$1 start=$2 end=$3
  { defs; printf '%s\n' "$stubs"; sed -n "/^# -* ${start}/,/^# -* ${end}/p" "$SCRIPT"; } >"$WORK/section.sh"
}

# Section 4 must appear even when -r is absent, so the numbering does not
# silently skip and the reader can tell "not tested" from "lost".
test_section4_always_present() {
  section_harness 'have() { return 1; }
nc_init() { :; }
resolve() { printf "\n"; }
tcp_verdict() { echo blocked; }
tls_probe() { echo timeout; }
RELAY=""' '3\. destination' '5\. private'
  local out
  out=$(bash "$WORK/section.sh" 2>&1)
  case $out in
    *"4. Your relay"*) pass "section 4 is printed when no relay is given" ;;
    *) fail "section 4 vanished without -r, so the report looks truncated" ;;
  esac
  case $out in
    *"not tested"*) pass "section 4 says it was not tested" ;;
    *) fail "section 4 does not say why it is empty" ;;
  esac
}

# The canary flag must do something: it was parsed and never used.
test_canary_is_used() {
  section_harness 'have() { return 0; }
nc_init() { :; }
resolve() { echo 203.0.113.9; }
tcp_verdict() { echo open; }
tls_probe() { echo ok; }
CANARY="wifi.example.net"' '2\. name vs address' '3\. destination'
  local out
  out=$(bash "$WORK/section.sh" 2>&1)
  case $out in
    *"203.0.113.9:443 SNI=wifi.example.net"*) pass "-c CANARY is actually probed" ;;
    *) fail "-c was accepted and never used: the canary was not probed" ;;
  esac
}

# The reading must not claim SNI filtering when nothing opened.
test_sni_reading_when_nothing_opens() {
  section_harness 'have() { return 0; }
nc_init() { :; }
resolve() { printf "\n"; }
tcp_verdict() { echo blocked; }
tls_probe() { echo timeout; }
CANARY=""' '2\. name vs address' '3\. destination'
  local out
  out=$(bash "$WORK/section.sh" 2>&1)
  case $out in
    *"SNI is being filtered"*) fail "SNI filtering claimed for an unreachable address" ;;
    *"says nothing about SNI"*) pass "an unreachable address is not read as SNI filtering" ;;
    *) fail "no reading printed for two failed probes" ;;
  esac
}

# ---------------------------------------------------------------- run
for t in $(declare -F | awk '{print $3}' | grep '^test_'); do
  "$t"
done

if [ "$failures" -ne 0 ]; then
  printf '\n%d check(s) failed\n' "$failures"
  exit 1
fi
printf '\nall checks passed\n'
