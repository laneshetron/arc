# ARC — Portal escape: MAC rotation and permitted-service carriers

**Status:** draft design. Specifies the two capabilities `captive-portals.md`
§11 defers: **MAC rotation**, for portals that key a grant to the device's
hardware address alone, and **permitted-service carriers**, for networks that
allow only a named service after authentication. Both consume that
document's state model and neither is implemented.

## 1. Scope and posture

Both capabilities exist for the case where the **portal will not be passed on
the user's terms** — the grant is spent, there is no credential to give, or
the tier admits only certain services. They are not detection, they are not
authentication, and they do not make a network carry traffic it refuses to
carry: MAC rotation changes *which device the network believes it is talking
to*, and a permitted-service carrier changes *what the traffic looks like*.

They apply at **different states**, and my earlier revision wrongly put both
under `unauthenticated`:

| capability | state it runs in | why |
|---|---|---|
| MAC rotation | `unauthenticated` | the portal is blocking everything; a new identity is the only lever |
| permitted-service carrier | `authenticated` or `unknown` | the tier *is* passing the permitted service, so a path exists; under `unauthenticated` nothing passes, so there is no carrier to build |

That is the §1/§4 conflict the review found. A permitted-service carrier
under `unauthenticated` would be a carrier over a service the portal is
refusing — which is just a worse version of the tunnel the portal already
blocked. The tier case is `authenticated`: the network lets some traffic
through, and this carrier uses only that.

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
left (§2.6, §3.5), which is what much of this document is.

## 2. MAC rotation

### 2.1 What it defeats, precisely

My earlier revision claimed a MAC-keyed portal "will pass any
previously-unseen address", and the review is right that this conflates two
things: a network can **identify** a device by its hardware address and
still **require every new device to pay or authenticate**. Tracking a grant
by MAC is not the same as granting access to new MACs.

The thing rotation actually defeats is narrower and worth naming exactly:
a portal that gives **every previously-unseen device an automatic grant** —
a free window, a trial, an introductory session — and tracks that grant by
hardware address so it does not have to give it twice. That is a real and
common configuration on hotel and venue captive portals, and it is the only
one where a new address buys anything.

| portal's admission policy | identifies by MAC? | rotation helps? |
|---|---|---|
| **automatic per-new-device grant** (free window/trial) | yes | **yes** — a new address is a new grant |
| per-device purchase, one grant | yes | no — the new address still has to pay |
| per-device authentication, one session | yes | no — the credential is checked |
| MAC + voucher / room number / surname | yes | no |
| MAC + session cookie + IP binding | yes | no — the IP changes with the MAC and the grant is voided |
| 802.1X / EAP credentials | n/a | no — the identity *is* the credential |
| rate-limits or fingerprints new devices | yes | partially, and visibly (§2.6) |

So rotation is a *device-identity* trick for a *device-identity* control
that happens to be paired with a free grant. It cannot manufacture a
credential, and it cannot conjure a grant the operator never gives. The
client must not pretend otherwise, and §2.5's stopping rule exists because
it usually cannot tell which row it is in.

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
3. **If the portal still demands a credential**, rotate once more — some
   portals key on *freshness within a window* rather than uniqueness — and
   if that also fails, **stop**.

**The stop reports what was observed, not a diagnosis.** My earlier revision
said the client would report `credential_bound`, and the review is right
that two failed rotations do not establish that: a MAC-only portal with no
free grant, an exhausted shared quota, a MAC+IP binding, a failed DHCP lease,
a failed reassociation, or the OS rolling the address back (§2.3) all
produce the same observation. So the client reports
**`rotation_ineffective`** and the evidence behind it:

| field | meaning |
|---|---|
| `reason` | `rotation_ineffective` — never a verdict about the portal |
| `attempts` | how many rotations were tried |
| `address_applied` | whether the address actually took, verified (§2.3) |
| `link_recovered` | whether the interface came back with a lease, route and DNS (§2.7.1) |
| `probe_verdict` | what probe A said after the last attempt |

A maintainer reading that can tell "the portal wants a credential" from
"DHCP never gave us a lease", which the single word `credential_bound`
could not. If the link never recovered, the client says so and stops
rotating entirely — a rotation that breaks the interface is not evidence
about the portal at all.

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

**The rotation audit is local-only, and this contradicts the rule I already
wrote.** My earlier revision said the journal records both addresses because
"they are not secrets" and it is "for the user, not for the operator" — but
`-share-diagnostics` uploads the journal to the relay operator, so a
persistent local-network identifier would reach a third party that nobody
asked to share it with. That is exactly the mistake
`captive-portals.md` §4.7 exists to prevent, and I applied the rule there
and forgot it here.

So there are two records with different audiences:

| record | where | contents |
|---|---|---|
| **rotation audit** | local only, beside the profile, never uploaded | the attachment, both addresses, the timestamps, the outcome |
| **journal line** | the shared journal | `mac rotated` / `mac rotation failed`, with the *count* and the outcome, and **no address** |

The user sees the full audit (`arc-client portal audit`); an operator
receiving a shared journal learns that a rotation happened and whether it
worked, not what any address was. Both are what their audience needs, and
neither leaks.

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

#### 2.7.1 The record is crash-safe and attachment-scoped

"Restore at next start" only works if the record is durable *before* the
mutation, and the review is right that I left both halves unspecified.

**Write order.** The record is written, `fsync`ed and renamed into place
**before** the address is changed. A crash at any point in the mutation
therefore leaves a record that says "this attachment's original address is
X, a rotation to Y was in progress" — the worst case is a redundant restore
of an address that was never changed, which is harmless. A crash *after* the
address change but before a record would be the unrecoverable case, and the
write order precludes it.

**Identity.** The record is keyed on `(interface name, network identity)`,
where the network identity is the SSID on Wi-Fi and the gateway MAC plus
subnet on wired — the same key `network-profiling.md` §3.1 uses for the
local profile cache. That is what stops a restore from applying another
network's address, or from overwriting an address the OS chose for a network
this run has never seen:

- **Same interface, same network** → restore, verify, clear the record.
- **Same interface, different network** → the OS may have set a private
  address for *that* network, so the record does not apply; the client
  clears it and journals that it declined to restore.
- **Interface absent** (a USB adapter unplugged) → keep the record, wait for
  the interface to return, and never write another interface's address.

**A record that is unreadable or malformed never causes a write.** The
client reports it and asks the user, because a corrupt record is exactly the
case where guessing could set a wrong address.

#### 2.7.2 Bringing the network back

"Restore the link and re-run probe A" was what my earlier revision said, and
the review is right that it is nowhere near enough: changing the address
takes the interface down and can change the DHCP lease, the address, the
gateway, the DNS servers, and every carrier socket's binding — and on Linux
it can move the interface index out from under a route.

The client runs one **sequenced lifecycle** for a rotation, and only then
resumes:

1. **Pause.** Stop the reconnect attempts, mark every path `DRAINING`, and
   keep the session alive on the relay side (`captive-portals.md` §5.1's
   "expiry does not kill sessions" applies for the same reason).
2. **Mutate.** Write the record (§2.7.1), bring the link down, set the
   address, bring it up, and **verify the address took** — a silent rollback
   (§2.3) ends the lifecycle here.
3. **Reassociate and acquire.** Wait for association, then for DHCP or RA,
   then for a default route, then for resolvable DNS — each with its own
   timeout, and each failure reported distinctly. A link that comes up with
   no lease is not a recovered link.
4. **Invalidate what the address owned.** The attachment's cached local
   profile and any per-attachment probe results keyed on the old identity
   are discarded (`network-profiling.md` §3.1). The upstream profile is
   *not* invalidated, because the upstream did not change.
5. **Rebind the carriers.** Every carrier socket is recreated on the new
   interface address and re-bound (§17.1's marks and `-bind`), because the
   old ones are bound to an address that no longer exists.
6. **Re-probe, then revalidate.** Probe A and B run once (§4 of
   `captive-portals.md`); if the portal now passes, paths rejoin by the
   ordinary §14.6 rules and may re-handshake, which is expected since the
   client's source address changed.

**Every step reports, and the lifecycle is journalled as a sequence**, so a
`rotation_ineffective` (§2.5) can be told apart from "the address changed
and DHCP never answered". The end-to-end test is that ARC carries traffic
after the rotation, not that the link came back.

## 3. Permitted-service carriers

### 3.1 The shape of the problem

A "free" portal tier commonly permits the operator's own services — the
airline's app, a messaging service, a captive entertainment portal — and
nothing else. Where the tier permits an arbitrary destination after
authentication, this is an `allowlist` regime and `dns-lifeline.md` or the
`-allowlist` posture already covers it. What is left is the case where the
**only** thing that passes is a named service, and that is what this section
addresses.

`network-profiling.md` §10 already names the shape: an "application-layer
lifeline" adapter contract, below DNS and ICMP in the D6 ordering, for
rendezvous and small payloads rather than throughput.

### 3.2 The carrier contract

My earlier revision defined a permitted-service carrier as anything that can
"send a small payload to a destination the network permits and receive one
back", and said the destination would be operator-controlled infrastructure.
The review is right that this **assumes the hard part away**: a network
permitting a named service means the *service* is reachable, not that
arbitrary payloads can be delivered through it to infrastructure the
operator controls and returned to this client. A generic framing contract
cannot manufacture a return path the service does not expose.

So the return path is a **precondition of the adapter, established per
provider**, and an adapter that has not established it is not a carrier:

| precondition | what must be true, per provider |
|---|---|
| **an operator-controlled endpoint** | there is a concrete destination in that service that the operator owns or controls — an account, a bot, a channel, a mailbox, a hosted app — and it is named in the adapter's configuration, not inferred |
| **authenticated addressing** | the adapter can address *this client's* traffic distinctly, through that endpoint, on that service's own authentication |
| **a delivery path** | the service will carry a payload from the client to that endpoint, with a size and rate the adapter has measured rather than assumed |
| **a return path** | the service will expose the endpoint's response to the client — by push, by a subscription the client can hold, or by polling an API the client is authorised to call |
| **a correlation** | the client can tell *its* response from anyone else's, which is the nonce requirement below |

A service that fails any row is not usable as a carrier, whatever its
payload limits. **That is the common case**, and the document says so
instead of implying otherwise: most "free tiers" permit a service's own
clients to talk to the service's own servers, and expose neither an
operator-controlled endpoint nor a client-addressable return path.

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
carry to the operator's endpoint — and the permitted service is the one that
decides what that payload can look like. The contract is therefore:

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
- **The operator's per-client budget**, as `dns-lifeline.md` §5.3 sets for
  the DNS lifeline: a stated hourly allowance, control traffic first,
  enforced where the frames are still visible rather than at the adapter.
- **The path's own pacing**, which follows from both.

Expected throughput is **lower than the DNS lifeline**, which is already
0.04–2 KiB/s by rate dial. A messaging service with a 1-per-second send
limit and a 300-byte payload carries **at most 300 B/s in that direction** —
600 B/s only as the aggregate of both directions, and only before the
service's own envelope, the adapter's encoding, and the polling overhead
the receive path imposes. In practice it is a fraction of that, and the
receive path usually sets the figure rather than the send path.

That is enough for rendezvous — learning a relay address, reporting state,
keeping a session's control plane alive — and not enough for anything a
user would call connectivity. `network-profiling.md` §10's "rendezvous-only
role, never data plane" is the right description and this document keeps
it.

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
| permitted-service carrier | `authenticated` (the tier passes the service) or `unknown`; **never `unauthenticated`**, where nothing passes | none — it is a carrier, so it participates as a path (§14.4 validates it) |

**Neither runs under `unknown` as an escape.** A MAC rotation triggered by
an unconfirmed guess about the network is a device-identity change with no
evidence it will help, and the state model exists precisely to avoid acting
on guesses.

**Rotation never authorizes a tunnel release.** My earlier revision said a
rotation "needs `captive-portals.md` §7.1's release to have happened first
*or* the route to be reinstalled afterwards", without saying who may trigger
the release — and that would have made enabling `-portal-mac-rotate` an
implicit permission to drop VPN protection, which is precisely what §7.1's
`ask` default exists to prevent.

The rule is therefore:

- **A rotation does not itself release anything.** It takes the interface
  down, which kills the carrier sockets, but the host's routes stay as they
  are — so the machine keeps whatever protection it had, and traffic does
  not start flowing outside the tunnel because a device changed its address.
- **If a release is needed** for the user to reach the portal, it happens
  through §7.1's own path: `ask` requires the user to run
  `arc-client portal login`, `off` forbids it entirely, and `auto` releases
  only on the portal state machine's own evidence. Rotation is not evidence.
- **With `-portal-release-tunnel off`**, rotation still runs — the two
  capabilities are orthogonal — but the route stays installed throughout, so
  the user reaches the portal however they otherwise would.
- **Reinstall is unconditional.** If a release happened at any point, the
  route is reinstalled when the state returns to `authenticated` or the
  rotation lifecycle completes, whichever comes first, and the reinstall is
  verified rather than assumed.

**Sequencing with `ask`.** A rotation under the default is a user-initiated
action already (`-portal-mac-rotate` is opt-in), so the natural order is:
user sees the portal message, runs `arc-client portal login`, and the client
then rotates if `-portal-mac-rotate` allows it — release first, rotation
second, and the route stays released only as long as `ask` would have left
it. Under `off`, the rotation proceeds with the route intact.

## 5. Testing

`test/netns/portal-escape.sh`, alongside `portal.sh`, with a portal that can
be told to key its grant on MAC alone, on MAC plus a voucher, or on nothing.

| scenario | assertion |
|---|---|
| **MAC-keyed *with a free per-device grant*, grant spent** | one rotation passes the portal; state reaches `authenticated`; the address is LAA and unicast |
| **MAC-keyed but per-device purchase** | two rotations fail and the ledger is unchanged: no free grant is invented (§2.1) |
| **Credential-keyed portal** | two rotations fail; the client stops and reports **`rotation_ineffective` with its evidence**, never `credential_bound`; **the original address is restored** |
| **Rotation where DHCP never answers** | reported as `link_recovered=false`, distinguished from a portal refusal (§2.5) |
| **Address chosen** | first octet has I/G clear and U/L set; never the previous address; never one in the neighbour table |
| **The OS rolls the address back** | the rotation counts as failed and the lifecycle stops, rather than reporting a success that did not happen (§2.3) |
| **End-to-end recovery after a rotation** | not just "the link is up": association, DHCP, default route, DNS, carrier rebind, and ARC **carrying traffic** (§2.7.2) |
| **Local profile cache** | the attachment's local profile is invalidated by a rotation; the **upstream** profile is not (§2.7.2) |
| **Clean exit after a rotation** | the original address is restored and verified |
| **`SIGKILL` at each mutation boundary** | the record is durable before the address changes, so the next start restores correctly from every crash point (§2.7.1) |
| **A rotation record for a different SSID** | the client declines to restore and journals why, rather than writing another network's address (§2.7.1) |
| **A corrupt rotation record** | reported and queried with the user; **no address is written** (§2.7.1) |
| **Restore fails** | the client prints the exact restore command and exits non-zero, rather than leaving the device spoofed |
| **`-portal-release-tunnel off` + rotation** | the rotation runs and **the full-tunnel route stays installed throughout** — a rotation cannot downgrade protection (§4) |
| **`ask` + rotation** | the release happens only through `arc-client portal login`, as it would without rotation, and the route is reinstalled when the state returns to `authenticated` |
| **Rate caps** | the 5th rotation in an hour is refused; nothing rotates while `authenticated` |
| **Journal vs audit** | the shared journal records the count and outcome with **no address**; the local audit has both addresses and is never uploaded (§2.6) |
| **Permitted-service carrier round-trip** | a cell goes to an operator-controlled endpoint through a stub service adapter and comes back; one cell per request; a `rate_limited` failure is reported as such and not retried past the limit |
| **A service with no return path** | rejected as a carrier at configuration time, not attempted and failed at runtime (§3.2) |
| **A service carrier in `unauthenticated`** | refused: the portal is not passing the service, so there is nothing to build (§1, §4) |
| **Service adapter on a one-cell budget** | a packet larger than one cell is refused before emission, since a request/response carrier cannot finish a multi-cell packet inside ARC's PTO (§3.2) |

The rows that matter most are the ones that leave the device or the user in a
bad state: **restore after a crash at each boundary**, **restore failure
being loud**, **a rotation that cannot downgrade the tunnel**, and **no
address in the shared journal**. Those are what a happy-path implementation
gets wrong, and they are why §2.6–§2.7 are as long as they are.

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
