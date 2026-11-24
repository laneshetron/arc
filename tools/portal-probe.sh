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

tcp() { # tcp HOST PORT -> 0 open, 1 refused/filtered
  local host=$1 port=$2
  [ -n "$NC_CONN" ] || return 2
  # shellcheck disable=SC2086
  nc $NC_CONN "$TIMEOUT" "$host" "$port" >/dev/null 2>&1
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

# http_head URL -> "status|redirect_url"
http_head() {
  local url=$1
  have curl || { echo "no-curl|"; return; }
  curl -sS -o /dev/null --max-time "$TIMEOUT" \
       -w '%{http_code}|%{redirect_url}' "$url" 2>/dev/null \
    || echo "fail|"
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
# http_head returns "status redirect_url"; keep the two parts separately so
# the report and the JSON say the same thing and the portal test is explicit.
h_full=$(http_head "$EP_HTTP")
a_full=$(http_head "$EP_APPLE")
h=${h_full%%|*}
h_redir=${h_full#*|}
a_status=${a_full%%|*}
a_redir=${a_full#*|}
verdict "gstatic /generate_204"   "$h  redirect=${h_redir:-none}   (want 204, no redirect)"
verdict "apple /hotspot-detect"   "$a_status  redirect=${a_redir:-none}   (want 200)"
portal=no
[ "$h" = 204 ] || portal=yes
[ -n "$a_redir" ] && portal=yes
[ -n "$h_redir" ] && portal=yes
if [ "$portal" = yes ]; then
  verdict "portal" "YES — cleartext is redirected or rewritten"
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
  if tcp "$host" "$port"; then r=open; else r=blocked; fi
  TCP_add "tcp $host:$port" "$r"
  verdict "tcp $host:$port" "$r"
done

# ---------------------------------------------------------------- 2. name vs address
rule "2. Is it the name or the address?"
# Same address, two names: one the tier is likely to permit, one arbitrary.
# If both open, gating is by address. If only the permitted name works, it is
# SNI-based, which ARC's -tls-cover can satisfy.
if [ -n "$APPLE_IP" ]; then
  r1=$(tls_probe "$APPLE_IP" 443 courier.push.apple.com)
  r2=$(tls_probe "$APPLE_IP" 443 example.com)
  TLS_add "apple:$APPLE_IP:443 SNI=permitted" "$r1"
  TLS_add "apple:$APPLE_IP:443 SNI=other"     "$r2"
  verdict "tls $APPLE_IP:443 SNI=courier.push.apple.com" "$r1"
  verdict "tls $APPLE_IP:443 SNI=example.com"           "$r2"
fi
r3=$(tls_probe "$CTRL_IP" 443 cloudflare-dns.com)
TLS_add "control:$CTRL_IP:443" "$r3"
verdict "tls $CTRL_IP:443 SNI=cloudflare-dns.com"       "$r3"

# ---------------------------------------------------------------- 3. destination reachability
rule "3. Which destinations does the policy reach?"
for host in "$CTRL_IP" "$CTRL_IP2" "${APPLE_IP:-none}"; do
  [ "$host" = none ] && continue
  if tcp "$host" 443; then r=open; else r=blocked; fi
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
      verdict "tcp $ip:$rport" "$(tcp "$ip" "$rport" && echo open || echo blocked)"
      verdict "tls $ip:$rport (SNI $rhost)" "$(tls_probe "$ip" "$rport" "$rhost")"
      verdict "tls $ip:$rport (SNI example.com)" "$(tls_probe "$ip" "$rport" example.com)"
    done
  fi
  # UDP is a separate question and usually answered by silence.
  verdict "udp $rhost:$rport" "$(have nc && (nc -u -z -w "$TIMEOUT" "$rhost" "$rport" >/dev/null 2>&1 && echo open || echo no-response) || echo no-nc)"
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
  if tcp "$ip" 443; then r443=open; else r443=blocked; fi
  if tcp "$ip" 5223; then r5223=open; else r5223=blocked; fi
  verdict "$prh" "$ip  tcp443=$r443  tcp5223=$r5223"
done
if have curl; then
  # This endpoint answers 400 without query parameters, which is fine: any
  # answer at all, including an error from Apple's own server, proves the
  # network permits the host. Only a transport failure counts against it.
  pr=$(curl -sS -o /dev/null --max-time "$TIMEOUT" -w '%{http_code}' \
       https://mask-api.icloud.com/egress-ip-ranges 2>/dev/null || echo fail)
  case $pr in
    fail) verdict "mask-api" "unreachable — Private Relay ingress is filtered" ;;
    000)  verdict "mask-api" "unreachable — Private Relay ingress is filtered" ;;
    *)    verdict "mask-api" "HTTP $pr — reachable (any answer from Apple's server counts)" ;;
  esac
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
     it is SNI-based and -tls-cover with that name is the whole answer.

  3. Reach: if whole provider ranges (1.1.1.1, 8.8.8.8) are reachable on 443,
     host the relay anywhere and the messaging-tier question disappears.

  4. Relay: "blocked" on tcp but "ok" on nothing else means the address is
     filtered; "verify:" means TLS is intercepted (likely a portal); "reset"
     right after the handshake means active interference.

  5. Private Relay: if mask-api answers, the network permits Apple's relay
     ingress. That does not carry ARC (see portal-escape.md), but it does mean
     Apple's ranges are usable for hosting if you can get an address in them.
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
