# Shared by e2e.sh and bench.sh: the three-namespace topology.
#
#   arc-c (client)        arc-r (relay)                arc-i ("internet")
#   c0 192.168.10.1/32 -- r0 192.168.10.2/24
#   c1 192.168.11.1/32 -- r2 192.168.11.2/24
#                         r1 192.168.20.1/24  -------- i0 192.168.20.2/24
#
# c0 and c1 are two independent client links (think Wi-Fi and cellular),
# both reaching the relay's address 192.168.10.2. The client starts with
# only host routes to the relay, preferring c0. The relay forwards and
# masquerades the given tunnel networks onto r1.

C="ip netns exec arc-c"
R="ip netns exec arc-r"
I="ip netns exec arc-i"
PIDS=()

# setup_topology TUNNEL_NETWORK...
setup_topology() {
  for ns in arc-c arc-r arc-i; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  ip link add c0 netns arc-c type veth peer name r0 netns arc-r
  ip link add c1 netns arc-c type veth peer name r2 netns arc-r
  ip link add r1 netns arc-r type veth peer name i0 netns arc-i
  ip -n arc-c addr add 192.168.10.1/32 dev c0
  ip -n arc-c addr add 192.168.11.1/32 dev c1
  ip -n arc-c link set c0 up
  ip -n arc-c link set c1 up
  ip -n arc-c route add 192.168.10.2 dev c0
  ip -n arc-c route add 192.168.10.2 dev c1 metric 100
  ip -n arc-r addr add 192.168.10.2/24 dev r0
  ip -n arc-r addr add 192.168.11.2/24 dev r2
  ip -n arc-r addr add 192.168.20.1/24 dev r1
  ip -n arc-r link set r0 up
  ip -n arc-r link set r2 up
  ip -n arc-r link set r1 up
  ip -n arc-i addr add 192.168.20.2/24 dev i0
  ip -n arc-i link set i0 up
  $R sysctl -qw net.ipv4.ip_forward=1
  for net in "$@"; do
    $R iptables -t nat -A POSTROUTING -s "$net" -o r1 -j MASQUERADE
  done
}

teardown_topology() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in arc-c arc-r arc-i; do ip netns del "$ns" 2>/dev/null || true; done
}

# impair LINK NETEM_ARGS...: emulate an impaired link in both directions with
# netem, e.g. `impair 0 delay 50ms loss 1%`. LINK 0 is c0/r0, 1 is c1/r2.
# Each direction gets the arguments independently, so `delay 50ms` makes a
# 100 ms round trip.
impair() {
  local link=$1; shift
  local cdev=c$link rdev=r0
  [[ $link == 1 ]] && rdev=r2
  ip netns exec arc-c tc qdisc replace dev "$cdev" root netem limit 100000 "$@"
  ip netns exec arc-r tc qdisc replace dev "$rdev" root netem limit 100000 "$@"
}

# unimpair LINK: remove impairment from a link.
unimpair() {
  local link=$1 rdev=r0
  [[ $link == 1 ]] && rdev=r2
  ip netns exec arc-c tc qdisc del dev "c$link" root 2>/dev/null || true
  ip netns exec arc-r tc qdisc del dev "$rdev" root 2>/dev/null || true
}

# netem_available: whether the kernel supports netem (sch_netem).
netem_available() {
  ip netns add arc-probe 2>/dev/null || return 1
  ip -n arc-probe link add d0 type dummy
  local ok=0
  ip netns exec arc-probe tc qdisc add dev d0 root netem delay 1ms 2>/dev/null || ok=1
  ip netns del arc-probe
  return $ok
}

# wait_until SECONDS COMMAND...: poll until COMMAND succeeds.
wait_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
}
