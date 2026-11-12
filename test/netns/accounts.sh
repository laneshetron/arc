#!/usr/bin/env bash
# Account isolation end to end (run as root on Linux): two clients of
# different accounts, with split TCP on, against a relay host that has an
# address outside the tunnel network and sits in a "VPC" it denies.
#
#   arc-c (account lane, relay access) -- c0/r0 --+
#                                                 arc-r -- r1/i0 -- arc-i
#   arc-d (account friend)             -- d0/r3 --+
#
# arc-r also holds 172.31.5.9 (a dummy interface: the relay host's VPC
# address), with an iperf3 server on it, and routes 172.31.7.1 (another
# VPC host, in arc-i) out of r1. The relay runs -deny 172.31.0.0/16. The
# in-memory engine tests cannot show this: the host's own addresses are
# delivered locally by the kernel, and split TCP dials from the host.
#
# Usage: accounts.sh BIN_DIR   (BIN_DIR holds arc-client and arc-relay)
set -euo pipefail

BIN=$(cd "${1:?usage: accounts.sh BIN_DIR}" && pwd)
source "$(dirname "$0")/lib.sh"
WORK=$(mktemp -d)
D="ip netns exec arc-d"
HOST=172.31.5.9 VPC_PEER=172.31.7.1 INTERNET=192.168.20.2
failures=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  teardown_topology
  ip netns del arc-d 2>/dev/null || true
  if [[ $failures -ne 0 || -n "${KEEP_LOGS:-}" ]]; then
    for f in "$WORK"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- topology ------------------------------------------------------------
setup_topology 10.77.0.0/16
ip netns add arc-d
ip -n arc-d link set lo up
ip link add d0 netns arc-d type veth peer name r3 netns arc-r
ip -n arc-d addr add 192.168.12.1/32 dev d0
ip -n arc-d link set d0 up
ip -n arc-d route add 192.168.12.2 dev d0
ip -n arc-r addr add 192.168.12.2/24 dev r3
ip -n arc-r link set r3 up
ip -n arc-r link add vpc0 type dummy
ip -n arc-r addr add "$HOST/32" dev vpc0
ip -n arc-r link set vpc0 up
ip -n arc-r route add "$VPC_PEER" dev r1
ip -n arc-i addr add "$VPC_PEER/32" dev i0

$R iperf3 -s -D -B "$HOST" --logfile "$WORK/iperf-host.log"
$I iperf3 -s -D --logfile "$WORK/iperf-internet.log"

# --- relay ---------------------------------------------------------------
"$BIN/arc-relay" genkey >"$WORK/relay.key"
RELAY_PUB=$("$BIN/arc-relay" pubkey <"$WORK/relay.key")
printf 'lane lane-token relay\nfriend friend-token\n' >"$WORK/tokens"
echo lane-token >"$WORK/lane.token"
echo friend-token >"$WORK/friend.token"
$R "$BIN/arc-relay" run -listen 0.0.0.0:4433 -key-file "$WORK/relay.key" \
  -reset-secret-file "$WORK/reset.secret" -tokens-file "$WORK/tokens" \
  -network 10.77.0.1/16 -deny 172.31.0.0/16 >"$WORK/relay.log" 2>&1 &
PIDS+=($!)
wait_until 10 $R ip addr show arc0 || { fail "relay up"; exit 1; }

# --- clients -------------------------------------------------------------
start_client() { # start_client NS RELAY NAME
  local ns=$1 relay=$2 name=$3
  ip netns exec "$ns" "$BIN/arc-client" run -relay "$relay:4433" -relay-key "$RELAY_PUB" \
    -token-file "$WORK/$name.token" -route 172.31.0.0/16 -route 192.168.20.0/24 \
    -split-tcp always >"$WORK/$name.log" 2>&1 &
  PIDS+=($!)
  wait_until 10 grep -q "session established" "$WORK/$name.log" || { fail "$name established"; exit 1; }
}
start_client arc-c 192.168.10.2 lane
start_client arc-d 192.168.12.2 friend
lease() { grep -m1 -oE 'address=10\.77\.[0-9]+\.[0-9]+' "$WORK/$1.log" | cut -d= -f2; }
LANE=$(lease lane) FRIEND=$(lease friend)
sleep 1
if grep -q "account=lane" "$WORK/relay.log" && grep -q "account=friend" "$WORK/relay.log"; then
  pass "relay logged both sessions' accounts"
else
  fail "relay did not log the sessions' accounts"
fi

# --- checks --------------------------------------------------------------
reaches() { timeout 10 ip netns exec "$1" ping -c2 -i0.2 -W2 "$2" >/dev/null 2>&1; }
check_ip() { # check_ip NS DST WANT DESCRIPTION
  if reaches "$1" "$2"; then got=yes; else got=no; fi
  if [[ $got == "$3" ]]; then pass "IP: $4"; else fail "IP: $4 (reached: $got)"; fi
}
check_ip arc-c "$INTERNET" yes "lane reaches the internet"
check_ip arc-d "$INTERNET" yes "friend reaches the internet"
check_ip arc-c 10.77.0.1 yes "lane (relay access) reaches the relay's tunnel address"
check_ip arc-d 10.77.0.1 no "friend cannot reach the relay's tunnel address"
check_ip arc-c "$HOST" yes "lane (relay access) reaches the relay host's VPC address"
check_ip arc-d "$HOST" no "friend cannot reach the relay host's VPC address"
check_ip arc-c "$VPC_PEER" no "lane cannot reach the denied VPC"
check_ip arc-d "$VPC_PEER" no "friend cannot reach the denied VPC"
check_ip arc-c "$FRIEND" no "lane cannot reach friend's client"
check_ip arc-d "$LANE" no "friend cannot reach lane's client"

# Split TCP: the client ends each TCP connection itself and the relay
# dials the destination, so these exercise AllowDial, not IP forwarding.
connects() { timeout 20 ip netns exec "$1" iperf3 -c "$2" -t 1 --connect-timeout 3000 >/dev/null 2>&1; }
check_tcp() { # check_tcp NS DST WANT DESCRIPTION
  if connects "$1" "$2"; then got=yes; else got=no; fi
  if [[ $got == "$3" ]]; then pass "split TCP: $4"; else fail "split TCP: $4 (connected: $got)"; fi
}
check_tcp arc-c "$INTERNET" yes "lane reaches the internet"
check_tcp arc-d "$INTERNET" yes "friend reaches the internet"
check_tcp arc-c "$HOST" yes "lane (relay access) reaches a service on the relay host's VPC address"
check_tcp arc-d "$HOST" no "friend cannot reach a service on the relay host's VPC address"
check_tcp arc-c "$VPC_PEER" no "lane cannot reach the denied VPC"
check_tcp arc-d "$VPC_PEER" no "friend cannot reach the denied VPC"
# The host's service saw the relay itself as the peer: the stream was
# dialed from the relay host, past any rule on forwarded packets.
if grep -q "connected to $HOST\|from $HOST" "$WORK/iperf-host.log"; then
  pass "split TCP dialed the host's service from the relay host"
else
  fail "the host's service did not see a connection from the relay host"
fi

echo
if [[ $failures -eq 0 ]]; then echo "accounts: all checks passed"; else echo "accounts: $failures check(s) failed"; exit 1; fi
