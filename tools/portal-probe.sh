#!/usr/bin/env bash
# portal-probe: characterise what a captive network actually permits.
#
# Run this ON the device, while connected to the network in question, from a
# shell that is NOT going through the tunnel. Its job is to answer four
# questions that decide whether ARC can work there at all:
#
#   1. Is it the *port* or the *destination* that the network permits?
#   2. Is it the *name* (SNI) or the *address* that gates access?
#   3. Does the permitted policy reach a destination we could host a relay on?
#   4. What exactly breaks on the paths that fail?
#
# It changes nothing and stores nothing. Every probe is an ordinary
# connection a browser would make; nothing here tunnels, spoofs or evades.
#
# Usage:
#   ./portal-probe.sh                       # default host set
#   ./portal-probe.sh -r relay.example.net  # also test your own relay
#   ./portal-probe.sh -j out.json           # machine-readable result
#
# Exit status is 0 if the report was produced, regardless of findings.

set -u

TIMEOUT=5
RELAY=""
JSON=""
CANARY=""          # a name the network is known to permit, if you know one

# Addresses used as "somewhere else, deliberately" controls. Chosen for being
# widely reachable and stable; they are controls, never targets.
CTRL_IP=1.1.1.1          # Cloudflare DNS, anycast
CTRL_IP2=8.8.8.8         # Google DNS
APPLE_IP=""              # resolved at run time from courier.push.apple.com

usage() {
  cat >&2 <<'EOF'
portal-probe [-r RELAY_HOST[:PORT]] [-j JSON_FILE] [-c CANARY_DOMAIN] [-t SECONDS]

  -r  a relay hostname to test explicitly (e.g. your -tls or -front endpoint)
  -j  write the results as JSON to this file as well as printing them
  -c  a domain the network is known to permit, to test name-vs-address gating
  -t  per-probe timeout in seconds (default 5)
EOF
  exit 2
}

while getopts ":r:j:c:t:h" opt; do
  case $opt in
    r) RELAY=$OPTARG ;;
    j) JSON=$OPTARG ;;
    c) CANARY=$OPTARG ;;
    t) TIMEOUT=$OPTARG ;;
    *) usage ;;
  esac
done

# ---------------------------------------------------------------- utilities

have() { command -v "$1" >/dev/null 2>&1; }

# Results are collected as they are produced so the report and any JSON agree.
# Flat "id<TAB>value" lists, because bash 3.2 (stock macOS) has no associative
# arrays, and because a key containing '=' (a TLS SNI probe does) would break
# any '='-splitting scheme. Deduplicated on emit, so a repeated probe cannot
# produce duplicate JSON keys.
TCP_RESULTS=""
TLS_RESULTS=""
TCP_add() { TCP_RESULTS="${TCP_RESULTS}${1}	${2}"$'\n'; }
TLS_add() { TLS_RESULTS="${TLS_RESULTS}${1}	${2}"$'\n'; }

# A portable "did this TCP connection open" with a timeout. nc's timeout flag
# differs between dialects (BSD/macOS -G, GNU/OpenBSD -w), so probe for it.
NC_CONN=""
nc_init() {
  if ! have nc; then return; fi
  # macOS/BSD: -G is connect timeout. GNU/OpenBSD: -w is. Try -G first on
  # Darwin, -w elsewhere.
  case $(uname -s) in
    Darwin) NC_CONN="-z -G" ;;
    *)      NC_CONN="-z -w" ;;
  esac
}

tcp() { # tcp HOST PORT -> 0 open, 1 refused/filtered, 2 cannot test
  local host=$1 port=$2
  [ -n "$NC_CONN" ] || return 2
  # shellcheck disable=SC2086
  nc $NC_CONN "$TIMEOUT" "$host" "$port" >/dev/null 2>&1
}

# tcp_verdict HOST PORT -> open, blocked, or cannot-test. The distinction
# matters: without nc every port reads as "blocked", which is a missing tool
# reported as a network policy, and the report then describes a firewall that
# may not exist.
tcp_verdict() {
  tcp "$1" "$2"
  case $? in
    0) echo open ;;
    1) echo blocked ;;
    *) echo "cannot-test (no nc)" ;;
  esac
}

resolve() { # resolve NAME -> newline-separated A records
  local n=$1
  if have dig; then
    dig +short +time=3 +tries=1 "$n" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
  elif have host; then
    host -W 3 -t A "$n" 2>/dev/null | awk '/has address/{print $NF}'
  fi
}

# tls_probe HOST PORT [SERVERNAME] -> prints "ok", "reset", "timeout", "refused",
# or "verify:<err>". Deliberately distinguishes these: a reset after
# ClientHello, a clean TLS failure and a timeout are different enforcement
# layers (network-profiling.md §4 P3).
tls_probe() {
  local host=$1 port=$2 sni=${3:-$1} out rc
  have openssl || { echo "no-openssl"; return; }
  out=$(printf '' | openssl s_client -connect "$host:$port" -servername "$sni" \
        -brief -no_ign_eof 2>&1)
  rc=$?
  case $out in
    *"Verification error"*|*"verify error"*) echo "verify:$(printf '%s' "$out" | sed -n 's/.*[Vv]erif[a-z]* error: *//p' | head -1)" ;;
    *"CONNECTION ESTABLISHED"*) echo "ok" ;;
    *)
      if [ $rc -eq 0 ]; then echo "closed"
      elif printf '%s' "$out" | grep -qi 'timed out\|timeout'; then echo "timeout"
      elif printf '%s' "$out" | grep -qi 'refused'; then echo "refused"
      elif printf '%s' "$out" | grep -qi 'reset by peer'; then echo "reset"
      else echo "failed"; fi
      ;;
  esac
}

# http_probe URL [MAXBYTES] -> "status|redirect|body"
#
# The body is needed because two of the three endpoints declare one: a portal
# that injects its own page into a 200 is not passing the check
# (captive-portals.md §4.1), and comparing only the status would let it
# through. Bounded, because a portal page can be large and a hostile one
# unbounded.
#
# One request, not two: the body goes to a file and -w reports the status, so
# the two cannot disagree about what was fetched.
http_probe() {
  local url=$1 max=${2:-4096} bodyfile out rc body status redir
  have curl || { printf 'no-curl||\n'; return; }
  bodyfile=$(mktemp "${TMPDIR:-/tmp}/portal-probe.XXXXXX")
  out=$(curl -sS --max-time "$TIMEOUT" --max-filesize "$max" \
        -o "$bodyfile" -w '%{http_code}|%{redirect_url}' "$url" 2>/dev/null)
  rc=$?
  if [ $rc -ne 0 ] || [ -z "$out" ]; then
    rm -f "$bodyfile"
    printf 'fail||\n'
    return
  fi
  status=${out%%|*}
  redir=${out#*|}
  body=""
  if [ -s "$bodyfile" ]; then
    # Command substitution strips trailing newlines, and these endpoints are
    # served with one: captive.apple.com sends its 68-character page as 69
    # bytes. The declared body in §4.1 is the page, so the newline must not
    # count, or every healthy network reports a body mismatch. CR is stripped
    # for the same reason on any server that uses CRLF.
    body=$(tr -d '\r' <"$bodyfile")
    # An interior newline would break the single-line report, so a body that
    # genuinely spans lines is reported by size instead.
    case $body in
      *$'\n'*) body="<$(wc -c <"$bodyfile" | tr -d ' ') bytes, multi-line>" ;;
    esac
  fi
  rm -f "$bodyfile"
  printf '%s|%s|%s\n' "$status" "$redir" "$body"
}

# http_head URL -> "status|redirect_url", with status "fail" when no HTTP
# answer arrived.
#
# The status is captured into a variable first and only then tested. Writing
# `curl ... -w '%{http_code}' || echo fail` is wrong: curl still prints "000"
# when the transfer fails, so the echo *appends* and the result is "000fail" —
# a value no case statement anticipates, and one that silently reads as an
# answer rather than a failure.
http_head() {
  local url=$1 out rc
  have curl || { echo "no-curl|"; return; }
  out=$(curl -sS -o /dev/null --max-time "$TIMEOUT" \
        -w '%{http_code}|%{redirect_url}' "$url" 2>/dev/null)
  rc=$?
  if [ $rc -ne 0 ] || [ -z "$out" ]; then
    echo "fail|"
    return
  fi
  echo "$out"
}

verdict() { # verdict LABEL VALUE
  printf '  %-38s %s\n' "$1" "$2"
}

rule() { printf '\n%s\n%s\n' "$1" "$(printf '%.0s-' $(seq 1 ${#1}))"; }

# ---------------------------------------------------------------- collect

nc_init

# Connectivity: is there a portal at all, and does it intercept plaintext?
rule "0. Network state"
EP_HTTP="http://connectivitycheck.gstatic.com/generate_204"
EP_APPLE="http://captive.apple.com/hotspot-detect.html"
# The declared healthy body for the Apple endpoint, byte for byte
# (captive-portals.md §4.1). Comparing only the status would pass a portal
# that answers 200 with its own page, which is the commonest pre-auth shape.
APPLE_BODY='<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'

h_full=$(http_probe "$EP_HTTP")
a_full=$(http_probe "$EP_APPLE")
IFS='|' read -r h h_redir h_body <<<"$h_full"
IFS='|' read -r a_status a_redir a_body <<<"$a_full"

# Four outcomes per endpoint, because they mean different things
# (captive-portals.md §4.3.2): the declared answer, an answer whose body is
# not the declared one, a redirect, and no answer at all. A failure is never a
# portal verdict.
endpoint_note() { # endpoint_note STATUS REDIR BODY WANT [WANT_BODY]
  local status=$1 redir=$2 body=$3 want=$4 want_body=${5:-}
  if [ "$status" = fail ] || [ "$status" = no-curl ]; then
    echo "no answer — unreachable, not a portal verdict"
  elif [ -n "$redir" ]; then
    echo "redirect to $redir — positive portal evidence"
  elif [ "$status" != "$want" ]; then
    echo "answered $status, not $want — cleartext is being rewritten"
  elif [ -n "$want_body" ] && [ "$body" != "$want_body" ]; then
    # The status matched but the page did not: §4.1's exact-body rule.
    echo "answered $want with the wrong body (${#body} bytes) — a page is being injected"
  else
    echo "as expected, no redirect"
  fi
}
verdict "gstatic /generate_204" "$h  $(endpoint_note "$h" "$h_redir" "$h_body" 204)"
verdict "apple /hotspot-detect" "$a_status  $(endpoint_note "$a_status" "$a_redir" "$a_body" 200 "$APPLE_BODY")"

# Portal evidence is a redirect, a wrong status, or a wrong body. A failure is
# none of them: it is reported as unreachable and leaves the question open,
# which is what the client's unknown state is for.
portal=no
answered=0
for st in "$h" "$a_status"; do
  [ "$st" = fail ] || [ "$st" = no-curl ] || answered=1
done
if [ -n "$h_redir" ] || [ -n "$a_redir" ]; then
  portal=yes
elif [ "$h" != fail ] && [ "$h" != no-curl ] && [ "$h" != 204 ]; then
  portal=yes
elif [ "$a_status" != fail ] && [ "$a_status" != no-curl ] &&
     { [ "$a_status" != 200 ] || [ "$a_body" != "$APPLE_BODY" ]; }; then
  portal=yes
fi

if [ "$portal" = yes ]; then
  verdict "portal" "YES — cleartext is redirected or rewritten"
elif [ "$answered" = 0 ]; then
  verdict "portal" "undetermined — no endpoint answered; this says nothing about a portal"
else
  verdict "portal" "no cleartext redirect seen (a TLS-intercepting portal would not show here)"
fi

# Resolve the Apple push host; it is the 5223 target and an interesting
# control because it is what free-messaging tiers typically permit.
APPLE_IP=$(resolve courier.push.apple.com | head -1)

# ---------------------------------------------------------------- 1. port vs destination
rule "1. Is it the port or the destination?"
# The discriminating experiment: same port, two destinations.
for tgt in "$CTRL_IP:5223" "$CTRL_IP2:5223" "${APPLE_IP:-none}:5223" "$CTRL_IP:443" "$CTRL_IP:53"; do
  host=${tgt%:*}; port=${tgt##*:}
  [ "$host" = none ] && continue
  r=$(tcp_verdict "$host" "$port")
  TCP_add "tcp $host:$port" "$r"
  verdict "tcp $host:$port" "$r"
done

# ---------------------------------------------------------------- 2. name vs address
rule "2. Is it the name or the address?"
# The experiment needs an address that *does* serve TLS for the name under
# test, otherwise both SNI values fail for a reason that has nothing to do
# with network policy. Two shapes:
#
#   - One address, two SNI values. If both open, gating is by address; if only
#     the permitted name opens, it is SNI-based, which -tls-cover can satisfy.
#
#   - The permitted name against the address it really resolves to. This is
#     the one that matters for "can ARC pose as this host": the network's
#     allowlist may name a host whose real address serves a real certificate.
#
# An earlier version probed Apple's *push* address on 443, where Apple does
# not serve TLS at all, so "refused" there was the server's answer and not the
# network's — a false positive for censorship.
NAME_VS_ADDR_TESTED=0
if [ -n "$CANARY" ]; then
  # The operator named a host this network is known to permit. Resolve it and
  # test the real pairing first.
  for ip in $(resolve "$CANARY" | head -2); do
    r=$(tls_probe "$ip" 443 "$CANARY")
    TLS_add "canary:$ip:443 SNI=$CANARY" "$r"
    verdict "tls $ip:443 SNI=$CANARY" "$r"
    NAME_VS_ADDR_TESTED=1
  done
  if [ "$NAME_VS_ADDR_TESTED" = 0 ]; then
    verdict "resolve $CANARY" "no answer — the canary is not usable as a control"
  fi
fi

# The control pairing: an address that certainly serves TLS on 443, tried with
# a name that certainly is not the one it serves. Both results are needed —
# a refused second probe only means SNI gating if the first one opened.
CTRL_SNI="cloudflare-dns.com"
r_ok=$(tls_probe "$CTRL_IP" 443 "$CTRL_SNI")
r_alt=$(tls_probe "$CTRL_IP" 443 example.com)
TLS_add "control:$CTRL_IP:443 SNI=$CTRL_SNI" "$r_ok"
TLS_add "control:$CTRL_IP:443 SNI=example.com" "$r_alt"
verdict "tls $CTRL_IP:443 SNI=$CTRL_SNI" "$r_ok"
verdict "tls $CTRL_IP:443 SNI=example.com" "$r_alt"
case "$r_ok:$r_alt" in
  ok:ok)      verdict "  reading" "both names open the same address — gating is by address, -tls-cover buys nothing" ;;
  ok:*)       verdict "  reading" "only the expected name opened — SNI is being filtered; -tls-cover with a permitted name is the answer" ;;
  *:ok)       verdict "  reading" "only the unexpected name opened — SNI filtering in reverse; investigate before trusting -tls-cover" ;;
  *)          verdict "  reading" "neither name opened — this address is unreachable, so it says nothing about SNI" ;;
esac

# Apple's push address is the most interesting 443 target on a messaging-tier
# network: it serves a real certificate for courier.push.apple.com on 443 (I
# checked: CN=courier.push.apple.com, issued by Apple Public Server ECC CA 12),
# and it is exactly the endpoint a free-messaging allowlist has to permit. So
# the pairing worth testing is that name against that address — permitted name
# first, then an arbitrary one, to separate SNI gating from address gating.
if [ -n "$APPLE_IP" ]; then
  r1=$(tls_probe "$APPLE_IP" 443 courier.push.apple.com)
  r2=$(tls_probe "$APPLE_IP" 443 example.com)
  TLS_add "apple:$APPLE_IP:443 SNI=courier.push.apple.com" "$r1"
  TLS_add "apple:$APPLE_IP:443 SNI=example.com" "$r2"
  verdict "tls $APPLE_IP:443 SNI=courier.push.apple.com" "$r1"
  verdict "tls $APPLE_IP:443 SNI=example.com"           "$r2"
  case "$r1:$r2" in
    ok:ok) verdict "  reading" "both names open Apple's push address — gating is by address" ;;
    ok:*)  verdict "  reading" "only Apple's name opened — SNI is filtered; -tls-cover with a permitted name is the answer" ;;
    *)     verdict "  reading" "Apple's own name did not open — see the tcp result above before reading this as SNI filtering" ;;
  esac
fi

# ---------------------------------------------------------------- 3. destination reachability
rule "3. Which destinations does the policy reach?"
for host in "$CTRL_IP" "$CTRL_IP2" "${APPLE_IP:-none}"; do
  [ "$host" = none ] && continue
  r=$(tcp_verdict "$host" 443)
  TCP_add "tcp $host:443" "$r"
  verdict "tcp $host:443" "$r"
done

# ---------------------------------------------------------------- 4. relay
if [ -n "$RELAY" ]; then
  rule "4. Your relay: $RELAY"
  rhost=${RELAY%%:*}
  rport=${RELAY##*:}
  [ "$rport" = "$RELAY" ] && rport=443
  ips=$(resolve "$rhost")
  if [ -z "$ips" ]; then
    verdict "resolve $rhost" "FAILED — DNS does not answer for it"
  else
    verdict "resolve $rhost" "$(echo "$ips" | tr '\n' ' ')"
    for ip in $ips; do
      verdict "tcp $ip:$rport" "$(tcp_verdict "$ip" "$rport")"
      verdict "tls $ip:$rport (SNI $rhost)" "$(tls_probe "$ip" "$rport" "$rhost")"
      verdict "tls $ip:$rport (SNI example.com)" "$(tls_probe "$ip" "$rport" example.com)"
    done
  fi
  # UDP is a separate question and usually answered by silence.
  verdict "udp $rhost:$rport" "$(have nc && (nc -u -z -w "$TIMEOUT" "$rhost" "$rport" >/dev/null 2>&1 && echo open || echo no-response) || echo no-nc)"
else
  # Said explicitly rather than omitted: a section that silently disappears
  # leaves the report looking truncated, and the reader cannot tell a skipped
  # test from a lost one.
  rule "4. Your relay"
  verdict "not tested" "no -r given; rerun with -r RELAY_HOST[:PORT] to test your own endpoint"
fi

# ---------------------------------------------------------------- 5. private relay
rule "5. iCloud Private Relay"
for prh in mask.icloud.com mask-h2.icloud.com; do
  ips=$(resolve "$prh")
  if [ -z "$ips" ]; then
    verdict "$prh" "no answer"
    continue
  fi
  ip=$(echo "$ips" | head -1)
  r443=$(tcp_verdict "$ip" 443)
  r5223=$(tcp_verdict "$ip" 5223)
  verdict "$prh" "$ip  tcp443=$r443  tcp5223=$r5223"
done
if have curl; then
  # This endpoint answers 400 without query parameters, which is fine: any
  # answer at all, including an error from Apple's own server, proves the
  # network permits the host. Only a transport failure counts against it.
  #
  # Captured before it is tested, for the reason http_head documents: curl
  # prints 000 on a failed transfer, so a `|| echo fail` would append and
  # produce "000fail", which reads as an answer.
  pr=$(curl -sS -o /dev/null --max-time "$TIMEOUT" -w '%{http_code}' \
       https://mask-api.icloud.com/egress-ip-ranges 2>/dev/null)
  pr_rc=$?
  if [ $pr_rc -ne 0 ] || [ -z "$pr" ] || [ "$pr" = 000 ]; then
    verdict "mask-api" "unreachable — Private Relay ingress is filtered"
  else
    verdict "mask-api" "HTTP $pr — reachable (any answer from Apple's server counts)"
  fi
fi

# ---------------------------------------------------------------- summary
rule "How to read this"
cat <<'EOF'
  1. Port vs destination: if 5223 is open to 1.1.1.1 as well as Apple, the
     network permits the PORT and ARC can run on it today with -tls on 5223.
     If only Apple's address opens, the policy is a destination allowlist and
     the relay would have to live inside it.

  2. Name vs address: if both SNI values open the same address, gating is by
     address and -tls-cover buys nothing. If only the "permitted" name opens,
     it is SNI-based and -tls-cover with that name is the whole answer. Pass
     -c with a host this network is known to permit to test the pairing that
     actually matters. "Neither name opened" is not SNI filtering: it means
     the address is unreachable on this network.

  3. Reach: if whole provider ranges (1.1.1.1, 8.8.8.8) are reachable on 443,
     host the relay anywhere and the messaging-tier question disappears.

  4. Relay: "blocked" on tcp but "ok" on nothing else means the address is
     filtered; "verify:" means TLS is intercepted (likely a portal); "reset"
     right after the handshake means active interference.

  5. Private Relay: if mask-api answers, the network permits Apple's relay
     ingress. That does not carry ARC (see portal-escape.md), but it does mean
     Apple's ranges are usable for hosting if you can get an address in them.

  "No answer" and "cleartext rewritten" are different findings. A probe that
  timed out says nothing about a portal; a probe that answered with the wrong
  status is evidence of a rewriting middlebox. captive-portals.md §4.3.2
  keeps them apart for the same reason: only the second is a verdict.
EOF

# ---------------------------------------------------------------- json
# Emitted from the collected lists, so the JSON and the report cannot
# disagree. Hand-rolled because the script must run on a stock macOS box
# where python3 may not be present; python3 is used only to verify.
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

json_pairs() { # json_pairs "flat list" INDENT
  # The list is "key<TAB>value" lines. A JSON object cannot repeat a key and a
  # probe may be repeated (a relay host with two addresses, say), so keep the
  # last value per key. Done in awk because bash 3.2 has no associative arrays
  # and this must run on the device.
  local ind=$2
  printf '%s' "$1" | awk -F'\t' -v ind="$ind" '
    $1 == "" { next }
    { v[$1] = $2; order[++n] = $1 }
    END {
      first = 1
      for (i = 1; i <= n; i++) {
        k = order[i]
        if (seen[k]++) continue
        gsub(/\\/, "\\\\", k); gsub(/"/, "\\\"", k)
        s = v[k]; gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s)
        if (first) { printf "%s\"%s\": \"%s\"", ind, k, s; first = 0 }
        else       { printf ",\n%s\"%s\": \"%s\"", ind, k, s }
      }
    }'
}

if [ -n "$JSON" ]; then
  {
    printf '{\n'
    printf '  "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "portal_cleartext": "%s",\n' "$portal"
    printf '  "gstatic_status": "%s",\n' "$(json_escape "$h")"
    printf '  "apple_status": "%s",\n' "$(json_escape "$a_status")"
    printf '  "apple_redirect": "%s",\n' "$(json_escape "$a_redir")"
    printf '  "apple_push_ip": "%s",\n' "${APPLE_IP:-}"
    printf '  "tcp": {\n';   json_pairs "$TCP_RESULTS" '    '; printf '\n  },\n'
    printf '  "tls": {\n';   json_pairs "$TLS_RESULTS" '    '; printf '\n  }\n'
    printf '}\n'
  } >"$JSON"
  if have python3; then
    if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$JSON" 2>/dev/null; then
      printf '\nJSON written to %s (valid)\n' "$JSON"
    else
      printf '\nWARNING: %s is not valid JSON; please report this\n' "$JSON" >&2
    fi
  else
    printf '\nJSON written to %s\n' "$JSON"
  fi
fi
