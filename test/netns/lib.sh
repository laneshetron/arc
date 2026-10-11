# Shared by e2e.sh and bench.sh: the three-namespace topology.
#
#   arc-c (client)        arc-r (relay)                arc-i ("internet")
#   c0 192.168.10.1/32 -- r0 192.168.10.2/24
#                         r1 192.168.20.1/24  -------- i0 192.168.20.2/24
#
# The client starts with only a host route to the relay. The relay forwards
# and masquerades the given tunnel networks onto r1.

C="ip netns exec arc-c"
R="ip netns exec arc-r"
I="ip netns exec arc-i"
PIDS=()

# setup_topology TUNNEL_NETWORK...
setup_topology() {
  for ns in arc-c arc-r arc-i; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  ip link add c0 netns arc-c type veth peer name r0 netns arc-r
  ip link add r1 netns arc-r type veth peer name i0 netns arc-i
  ip -n arc-c addr add 192.168.10.1/32 dev c0
  ip -n arc-c link set c0 up
  ip -n arc-c route add 192.168.10.2 dev c0
  ip -n arc-r addr add 192.168.10.2/24 dev r0
  ip -n arc-r addr add 192.168.20.1/24 dev r1
  ip -n arc-r link set r0 up
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

# wait_until SECONDS COMMAND...: poll until COMMAND succeeds.
wait_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 0.2
  done
}
