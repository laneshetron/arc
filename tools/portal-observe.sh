#!/usr/bin/env bash
# What portal-escape.md §2.4.1 says to do: one bounded passive capture on the
# associated interface, link-layer headers only, no payload decoding.
#
# This is the fallback path. Where monitor mode is available, §2.4.4's shape
# scoring is strictly better; macOS has had no supported monitor mode since
# the airport utility was removed in 14.4, so on a Mac this is all there is.
#
# It answers "are there candidate addresses at all", never "which of them is
# admitted". §2.4.1 is explicit that admission is discovered by trying (§2.5),
# not by inspection, and §2.4.4.1 that observed shape cannot settle it.
#
# Usage: sudo ./portal-observe.sh [-c FRAMES]
set -uo pipefail

FRAMES=500
WINDOW=60   # seconds; a bounded capture must also be bounded in time
while getopts ":c:t:h" opt; do
  case $opt in
    c) FRAMES=$OPTARG ;;
    t) WINDOW=$OPTARG ;;
    *) echo "usage: portal-observe.sh [-c FRAMES] [-t SECONDS]" >&2; exit 2 ;;
  esac
done

IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
if [ -z "$IFACE" ]; then
  echo "no default route: connect to the network first" >&2
  exit 1
fi
GW_IP=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
OURS=$(ifconfig "$IFACE" 2>/dev/null | awk '/ether/{print $2}')

# The hardware address, when it differs, means the OS is using a private
# (randomized) address — portal-escape.md §2.3, and the caller needs to know
# because the OS may roll it back mid-attempt.
HW=$(networksetup -listallhardwareports 2>/dev/null \
     | awk -v d="$IFACE" '$1=="Device:" && $2==d {getline; print $NF}')

# The gateway's link-layer address, from the ARP table rather than guessed.
GW_MAC=$(arp -an 2>/dev/null | awk -v ip="$GW_IP" '$0 ~ "\\("ip"\\)" {print $4}' | head -1)

# The SSID and whether the link is encrypted. On an open SSID §2.4.4's payload
# route would be conclusive *if* monitor mode existed; the security line also
# tells the reader which row of §2.4.4's table applies.
SUMMARY=$(ipconfig getsummary "$IFACE" 2>/dev/null)
SSID=$(printf '%s\n' "$SUMMARY" | awk -F' : ' '/SSID/{print $2; exit}')
SEC=$(printf '%s\n' "$SUMMARY" | awk -F' : ' '/Security/{print $2; exit}')

echo "interface       $IFACE"
echo "ssid            ${SSID:-<unknown>}"
echo "security        ${SEC:-<unknown>}"
echo "gateway         $GW_IP  ${GW_MAC:-<not in arp>}"
echo "our address    $OURS${HW:+  (hardware $HW${HW:+ — randomized, see §2.3})}"
[ -n "$HW" ] && [ "$HW" != "$OURS" ] && \
  echo "                NOTE: the OS is using a private address; it may roll it back (portal-escape.md §2.3)"
echo

# Does unicast to a peer get through? This is the test that distinguishes
# isolation, and the earlier version of this script got it wrong: every
# protocol in its filter is broadcast or multicast, which is flooded to every
# station on an isolated segment too, so a station's broadcasts said nothing
# about whether unicast reaches it.
PEER=$(arp -an 2>/dev/null | awk -v gw="$GW_IP" -v me="$OURS" '
  $4 != "" && $4 != "at" && $0 !~ "\\("gw"\\)" && $4 != me {print $2; exit}' | tr -d '()')
if [ -n "$PEER" ]; then
  echo "--- isolation: one ICMP echo to a peer ($PEER), not a scan"
  if ping -c 2 -W 1000 "$PEER" >/dev/null 2>&1; then
    echo "    peer answered — unicast reaches other stations, so client"
    echo "    isolation is OFF and §2.4.1's premise holds fully."
  else
    echo "    no answer — unicast to a peer is dropped: client isolation is ON."
    echo "    §2.4.1 still yields candidates from broadcast traffic, but no"
    echo "    more than that, and §2.4.4's payload route is unavailable."
  fi
  echo
fi

echo "--- addresses seen in one bounded capture, most frames first"
# Broadcast and multicast only, deliberately: with isolation on these are the
# only frames another station's address appears in. That is enough to leak an
# address and not enough to say anything about admission.
#
# Bounded in time as well as in frames. `tcpdump -c 500` waits for 500
# matching frames, and on a quiet network that is forever — a capture that
# hangs is not a bounded capture, and the earlier version of this script could
# block indefinitely after the user authenticated and the link went quiet.
CAP=$(sudo tcpdump -i "$IFACE" -e -c "$FRAMES" -nn -q -U \
      'arp or udp port 67 or udp port 68 or icmp6 or udp port 5353' 2>/dev/null &
      tcpdump_pid=$!
      ( sleep "$WINDOW"; kill "$tcpdump_pid" 2>/dev/null ) &
      watcher=$!
      wait "$tcpdump_pid" 2>/dev/null
      kill "$watcher" 2>/dev/null
      wait 2>/dev/null)

if [ -z "$CAP" ]; then
  echo "  (no frames captured in ${WINDOW}s — the link may be idle, or sudo"
  echo "   was not granted; try a longer window with -t)"
  exit 0
fi

# Apply §2.4.1's candidate filter. The capture is summarised first, because the
# address appears many times per line — once as the transmitter and often again
# as the destination — and a count of raw matches is not a count of frames.
printf '  %-19s %6s  %s\n' address frames verdict
printf '%s\n' "$CAP" \
  | awk '{ if (match($0, /^[0-9:.]+ ([0-9a-f]{2}:){5}[0-9a-f]{2}/)) {
             split(substr($0, RSTART, RLENGTH), f, " ")
             print tolower(f[2])
           } }' \
  | sort | uniq -c | sort -rn \
  | while read -r n mac; do
      first=$((16#${mac%%:*}))
      # The OUI is the first three octets; `%:*:*` strips only two, so it has
      # to be cut explicitly. Getting this wrong makes the gateway-OUI test
      # silently never fire, which is worse than not having it.
      oui=$(printf '%s' "$mac" | cut -d: -f1-3)
      gw_oui=""
      [ -n "$GW_MAC" ] && gw_oui=$(printf '%s' "$GW_MAC" | cut -d: -f1-3)
      why=""
      if (( first & 1 )); then why="multicast"
      elif [ "$mac" = "$OURS" ]; then why="ours"
      elif [ -n "$GW_MAC" ] && [ "$mac" = "$GW_MAC" ]; then why="gateway"
      elif [ -n "$gw_oui" ] && [ "$oui" = "$gw_oui" ]; then
        # Same OUI as the gateway: an appliance with several addresses (a
        # controller plus its data interface) is common, and equality with the
        # gateway's one address would not catch it. §5.1 records why.
        why="same OUI as the gateway — likely the AP or its data interface"
      elif [ "$n" -lt 2 ]; then why="seen once — device may have left"
      elif (( (first & 2) == 0 )); then why="vendor address — likely AP or fixed appliance"
      else why="CANDIDATE"
      fi
      printf '  %-19s %6s  %s\n' "$mac" "$n" "$why"
    done

# Two link-layer addresses for one IP means the station rotated its private
# address, or the AP proxies ARP. Either way §2.4.1's "seen in at least two
# frames" test passes it and the assumption behind that test — one address,
# one device — does not hold. §5.1 records the case that exposed this.
echo
echo "--- one IP with more than one link-layer address (rotated, or proxied ARP)"
arp -an 2>/dev/null | awk '
  $4 ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ {
    ip = $2; gsub(/[()]/,"",ip); c[ip]++; m[ip] = m[ip] " " $4
  }
  END { for (i in c) if (c[i] > 1) printf "  %-16s%s\n", i, m[i] }' | sort
