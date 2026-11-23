# ARC — Portal escape: MAC rotation and permitted-service carriers

**Status:** draft design. Specifies the two capabilities `captive-portals.md`
§11 defers: **MAC rotation**, for portals that key a grant to the device's
hardware address alone, and **permitted-service carriers**, for networks that
allow only a named service after authentication. Both consume that
document's state model and neither is implemented.

## 1. Scope and posture

Both capabilities are for the case where the portal has *already classified
`unauthenticated`* and the user has no credential, no voucher, or no
intention of supplying one. They are not detection, they are not
authentication, and they do not make a network carry traffic it refuses to
carry — they change *which device the network believes it is talking to*
(MAC rotation) or *which service the traffic appears to be* (permitted
service).

They are opt-in, and the posture flags follow the existing pattern
(`-censorship`, `-allowlist`): nothing here runs unless asked for, and each
has its own flag so an operator can take one without the other.

**What the software does and the user chooses are different things.**
These capabilities exist because ARC's purpose is reachability on networks
that are not obliged to cooperate, and a hostile-network assumption is the
design premise (`network-profiling.md` §5). Whether a given use is
appropriate — a paid tier, a corporate device, a network whose operator
counts sessions — is the user's judgement, not the client's. What the client
owes the user is accurate information about what it did and what traces it
left (§5.6), which is what most of this document is.

## 2. MAC rotation

### 2.1 What it defeats, precisely

A portal that keys a grant to the device's hardware address and nothing else
will pass any previously-unseen address without a credential. That is a
narrower class than it sounds:

| portal keys the grant on | rotation helps? |
|---|---|
| MAC alone (hotel captive portals, some airline tiers) | **yes** |
| MAC + room number / voucher / surname | no — the credential is checked |
| MAC + a per-session cookie and an IP binding | no — the IP changes with the MAC and the grant is voided |
| 802.1X / EAP credentials | no — the identity is the credential, and EAP binds it to the association |
| a portal that rate-limits or fingerprints new devices | partially, and visibly (§2.6) |

So rotation is a *device-identity* trick for a *device-identity* control. It
cannot manufacture a credential, and the client must not pretend otherwise:
if rotation three times in a row leaves the portal asking for a login, this
portal is not MAC-keyed, and §2.5 stops.

### 2.2 Platform mechanics

Setting the address is a privileged operation that **takes the interface
down**, so every connection on it dies — carrier sockets included.

| platform | mechanism | privilege | notes |
|---|---|---|---|
| Linux | `netlink.LinkSetHardwareAddr` (`ip link set DEV address MAC`) | `CAP_NET_ADMIN` — ARC already holds it for the TUN | needs the link down on most drivers; re-association follows |
| macOS | `ifconfig DEV ether MAC` | root | **conflicts with the OS's own private address (§2.3)** |
| iOS, Android | — | — | no API exists; an app cannot change the hardware address |

**Rotation is therefore desktop-only, and the client says so** rather than
offering a flag that silently does nothing on a phone. On mobile the
platform has its own per-network private address (§2.3) and that is the
whole of what is available.

### 2.3 macOS already rotates, and ARC would be fighting it

On a current macOS, Wi-Fi *already* presents a per-SSID private address and
keeps it stable for that network. This is observable: on the machine this
was written on, `networksetup -getMACAddress en0` reports the hardware
address `70:8c:f2:…` while `ifconfig en0` reports `26:9a:4a:…` — a
locally-administered address, which is the private one in use.

Two consequences, both of which the spec has to face:

- **The OS has already done the useful half.** A portal that keys on MAC
  sees a stable per-network address; the device is already
  indistinguishable from any other device the portal has not seen *if the
  user has not joined that network before*. Rotating again only helps when
  the portal has *already* granted that private address and the grant has
  expired.
- **`ifconfig en0 ether` is not durable.** The Wi-Fi daemon owns the
  interface's address on modern macOS and may restore it on the next
  association or roam. So a rotation that appears to succeed can silently
  revert, and the client would report a rotation that did not happen.

The client therefore **verifies** (§2.4) rather than trusting the command's
exit status, and treats a reverted address as a failed rotation rather than
retrying forever. Where private Wi-Fi is **disabled** for the network, ARC
may rotate and the address is durable; `-portal-mac-rotate` reports which
case it found.

### 2.4 Choosing an address

A rotated address MUST be **locally administered and unicast**, which is
exactly two bits of the first octet: bit 0 (I/G) clear, bit 1 (U/L) set — so
the first octet is one of `x2`, `x6`, `xA`, `xE`. That also means the
address cannot collide with a real vendor's OUI, since a vendor-assigned
address has the U/L bit clear.

The remaining 46 bits come from the OS CSPRNG, with two constraints:

- **Not the current address, and not one used on this attachment before**
  (the client keeps the last few), since reusing one invites a portal that
  remembers it to refuse.
- **A multicast or all-zero address is malformed** and a driver may reject
  it; both are precluded by the bits above.

**Collision is checked, not assumed.** Before association the client reads
the link's ARP/neighbour table for a conflicting entry and picks again if it
finds one. That is a best-effort check — a device on a segment this host has
never talked to is invisible — and the cost of a collision is a duplicated
address on the link, which is why the client does not rotate into an address
it has recently seen traffic from.

**The original address is recorded before the first rotation**, persisted
with the attachment's profile, and restored on exit and at the next start
(§2.7).

### 2.5 When to rotate, and when to stop

Rotation is driven by the state model, and the trigger is narrow:

```text
state == unauthenticated
  AND portal_seen                     (a portal was positively identified)
  AND the portal has asked for a credential
  AND -portal-mac-rotate is on
```

Then:

1. **Rotate once**, restore the link, and re-run probe A on the portal
   cadence.
2. **If the portal now passes**, the rotation worked; the state reaches
   `authenticated` through the ordinary path (`captive-portals.md` §4.3) and
   nothing else happens.
3. **If the portal still demands a credential**, this is not a MAC-keyed
   portal. Rotate once more — some portals key on *freshness within a
   window* rather than uniqueness — and if that also fails, **stop and say
   so**: `-portal-mac-rotate` reports that the portal is credential-bound
   and leaves the device on its original address.

**Two attempts, then a stop**, because each attempt costs a reassociation, a
new DHCP lease and a visible change to the Wi-Fi infrastructure. An earlier
draft of this idea would have retried until something changed, which is how
a client exhausts a hotel's DHCP pool and gets the *user's* laptop flagged.

**Rotation never runs while `authenticated`.** There is nothing to escape,
and dropping a working interface to look for a better identity would be the
self-inflicted outage §14.6 exists to avoid.

### 2.6 Budget, and what rotation leaves behind

Caps, all enforced client-side and all reported:

| cap | default | why |
|---|---|---|
| rotations per attachment per hour | 4 | each is a reassociation and a DHCP lease |
| rotations per attachment, total | 8 | beyond that the client is scanning, not escaping |
| rotations per day, all attachments | 16 | a device that rotates everywhere is a pattern |

**The traces are real and worth stating plainly**, because the user is the
one who bears them:

- **The access point sees every address.** Rotation is a sequence of new
  associations from one radio in one place; infrastructure that logs
  association events sees exactly that, and it is a stronger signal than the
  one the portal was enforcing.
- **DHCP sees a new client each time**, with a new lease. Repeated new
  leases from one radio is likewise visible, and a small pool can be
  exhausted.
- **The portal's own accounting sees N grants** where it expected one.
  Where a grant is sold (a day pass, a device count), this is the operator's
  revenue control being defeated, and the operator's remedy is account
  termination or worse, applied to the user.
- **Nothing here hides that traffic is a tunnel.** Rotation changes who the
  network thinks is connected, not what the connection carries.

The client therefore **journals every rotation** with the old and new
address — the addresses are not secrets, and a user who cannot see what
their client did to their device's identity has been badly served. This is
the one place the journal records something the operator did not ask for,
and it is recorded for the user, not for the operator.

### 2.7 Restoring, and never being left spoofed

A device left on a rotated address is a real problem: corporate NAC and
asset inventory key on hardware addresses, and a laptop whose address silently
changed may fail to authenticate next week.

- The original address is restored **on clean exit**, on `SIGINT`/`SIGTERM`,
  and **at the next client start** if the previous run died with a rotation
  outstanding — the persisted record of §2.4 is what makes that possible.
- Restoration is **verified** by reading the address back, not by trusting
  the command, for the same reason the rotation is (§2.3).
- If restoration fails — the interface is gone, the daemon has taken the
  address, the user is on another network — the client **says so loudly** and
  prints the exact command to restore it, rather than exiting quietly and
  leaving the device spoofed.

## 3. Permitted-service carriers

### 3.1 The shape of the problem

A "free" portal tier commonly permits the operator's own services — the
airline's app, a messaging service, a captive entertainment portal — and
nothing else. Where the tier permits an arbitrary destination after
authentication, this is an `allowlist` regime and the `-allowlist` posture
already covers it. What is left is the case where the
**only** thing that passes is a named service, and that is what this section
addresses.

`network-profiling.md` §10 already names the shape: an "application-layer
lifeline" adapter contract, below DNS and ICMP in the D6 ordering, for
rendezvous and small payloads rather than throughput.

### 3.2 The carrier contract

A permitted-service carrier is any transport that can, on demand:

1. **send** a small payload to a destination the network permits, and
2. **receive** a small payload back, addressed to this client,

with the same properties a constrained carrier already has: it is
request/response or slow, its payloads are tiny and metered, and the
destination side is infrastructure the *operator* controls — not the
service the network permits.

**What it carries is cells, unchanged.** A permitted-service carrier is a
framing adapter over `CELL` (`ARC-v1-…-Handoff.md` §12.1), exactly as the DNS
adapter is, so nothing about the session is new: the same `assoc_id`, the
same reassembly, and **one cell per ARC packet** — because a
request/response carrier cannot complete a multi-cell packet inside ARC's
retransmission timer. `dns-lifeline.md` §2.4 derives that from
`rtt.pto()` = 691 ms against a poll interval of seconds; the derivation is
identical here and the rule is not optional for the same reason.

That also fixes this carrier's maximum packet size at its own cell minus 18,
which for a 300-byte service payload is about 282 B of ARC packet and 245 B
of inner IP, before fragmentation.

**The envelope is the permitted service's protocol.** That is the whole
difference from DNS: the DNS adapter encodes cells in query names and
answers, and this one encodes them in whatever the permitted service will
carry to the operator's own infrastructure. The contract is therefore:

| the adapter must | the adapter must not |
|---|---|
| encode one cell per request, decodable unambiguously | assume the service preserves arbitrary bytes |
| carry a fresh client-chosen nonce per request, for replay safety | rely on service-side echo semantics |
| report a structured failure (`refused`, `truncated`, `rewritten`, `rate_limited`, `timeout`) | collapse failures into "unreachable" (`network-profiling.md` §8) |
| bound its own rate and payload | retry past a service's own limit |

### 3.3 The limit is the service's rate, not ours

Three caps, and the tightest is not the one ARC sets:

- **The service's own limits** — message rate, per-account quota, payload
  size — which the adapter must discover and stay well inside, because
  exceeding them gets the *user's* account restricted or closed.
- **The operator's per-client budget** in the manner ARC already uses for
  constrained carriers: a stated hourly allowance, control traffic first,
  enforced where the frames are still visible rather than at the adapter.
- **The path's own pacing**, which follows from both.

Expected throughput is **lower than the DNS lifeline**, which is already
0.04–2 KiB/s by rate dial. A messaging service with a 1/second send limit
and a 300-byte payload is about 600 B/s of downlink at best, and typically a
fraction of it once the receive path requires polling. That is enough for
rendezvous — learning a relay address, reporting state, keeping a session's
control plane alive — and not enough for anything a user would call
connectivity. `network-profiling.md` §10's "rendezvous-only role, never data
plane" is the right description and this document keeps it.

### 3.4 No provider is specified here, deliberately

This document specifies the **contract** and the **policy**. It specifies no
particular service, and that is a considered position rather than an
omission:

- **Each provider is separate protocol work.** A real adapter needs that
  service's client protocol, its authentication, its versioning and its
  anti-automation behaviour. None of that generalises, and a paragraph in
  this document claiming otherwise would be fiction.
- **Each provider is a separate decision.** Using a service to carry traffic
  it was not intended to carry is a terms question specific to that service,
  and the operator choosing an adapter is choosing that.
- **The state model is what generalises.** `captive-portals.md`'s
  `unauthenticated`/`authenticated` distinction, the posture that selects
  this carrier, and the `allowlist` regime row are all provider-independent,
  and they are specified.

So a provider adapter is a later document, one per provider, implementing
§3.2's contract and constrained by §3.3's budget. What exists here is the
socket it plugs into.

### 3.5 What the client tells the user

A permitted-service carrier is the least honest-looking thing ARC does, in
the sense that the network is deliberately shown something other than ARC.
Two rules follow:

- **The user is told which carrier is in use and what it will cost them.**
  The status line names the service and the account, if the adapter uses
  one, because a user whose messaging account is at risk of restriction
  should know before it happens, not after.
- **The operator is not told anything extra.** Nothing about this carrier
  changes what reaches the journal beyond its name and its failure modes;
  §5 of `captive-portals.md` on redaction applies unchanged.

## 4. Interaction with the state machine

Both capabilities consume `captive-portals.md`'s states and neither adds a
state:

| capability | when it runs | effect on state |
|---|---|---|
| MAC rotation | `unauthenticated`, `portal_seen`, credential demanded | none directly — it succeeds or fails, and the state machine observes the result through probe A |
| permitted-service carrier | `authenticated` (the tier passes some traffic) or `unknown` | none — it is a carrier, so it participates as a path (§14.4 validates it) |

**Neither runs under `unknown` as an escape.** A MAC rotation triggered by
an unconfirmed guess about the network is a device-identity change with no
evidence it will help, and the state model exists precisely to avoid acting
on guesses.

**Rotation and the tunnel release are independent**, and the ordering
matters: rotation takes the interface down, which kills the carrier sockets;
`captive-portals.md` §7.1's release is about the *host's* routes. A rotation
while the tunnel is up therefore needs §7.1's release to have happened first
or the route to be reinstalled afterwards, and the client sequences them
explicitly rather than relying on which timer fires first.

## 5. Testing

`test/netns/portal-escape.sh`, alongside `portal.sh`, with a portal that can
be told to key its grant on MAC alone, on MAC plus a voucher, or on nothing.

| scenario | assertion |
|---|---|
| **MAC-keyed portal, grant spent** | one rotation passes the portal; state reaches `authenticated`; the address is LAA and unicast |
| **Credential-keyed portal** | two rotations fail, the client **stops** and reports `credential_bound`; **the original address is restored** |
| **Address chosen** | first octet has U/I set and LAA bit set; never the previous address; never one in the neighbour table |
| **Rotation with the tunnel up** | §7.1's release happens first, or the route is reinstalled after; the interface comes back with a working route either way |
| **Clean exit after a rotation** | the original address is restored and verified |
| **`SIGKILL` after a rotation** | the next start restores it from the persisted record and says it did |
| **Restore fails** | the client prints the exact restore command and exits non-zero, rather than leaving the device spoofed |
| **Rate caps** | the 5th rotation in an hour is refused; nothing rotates while `authenticated` |
| **Journal** | every rotation logged with both addresses; no credential, voucher or portal URL path |
| **Permitted-service carrier** | a cell round-trips through a stub service adapter; one cell per request; a `rate_limited` failure is reported as such and not retried past the limit |
| **Service adapter on a one-cell budget** | a packet larger than one cell is refused before emission, since a request/response carrier cannot finish a multi-cell packet inside ARC's PTO (§3.2) |

The rows that matter most are the two that leave the device in a bad state:
**restore after a crash**, and **restore failure being loud**. Those are the
ones a happy-path implementation gets wrong, and they are the reason §2.7 is
as long as it is.

## 6. Deferred

- **Per-provider service adapters.** §3.4 explains why: each is its own
  protocol, decision and document.
- **Rotating the *radio* rather than the address.** A USB Wi-Fi adapter with
  its own address is a second device with its own identity, which is
  cleaner than spoofing the first and does not defeat the OS's private
  address. It needs hardware, so it is a user instruction rather than a
  feature.
- **Detecting that a portal keys on MAC without rotating.** An information
  element in a probe could ask the portal to describe its own policy; no
  portal does, and the two-attempt probe of §2.5 is cheaper than a protocol.
- **A permitted-service carrier over a *paid* tier's included services.**
  Same contract, different budget accounting; nothing structural is missing.
- **Restoring a *vendor* address deliberately** (presenting as a known device
  class). Out of scope: it is a different capability with a different risk
  profile, and nothing in ARC needs it.
