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
| MAC rotation, policy A (fresh address) | `unauthenticated` | the portal is blocking everything; a new identity is the lever |
| MAC rotation, policy B (observed address) | `unauthenticated` | the portal is blocking us but has admitted another device; its address is the lever |
| permitted-service carrier | `authenticated` or `unknown` | the tier *is* passing the permitted service, so a path exists; under `unauthenticated` nothing passes, so there is no carrier to build |

That is the §1/§4 conflict the review found. A permitted-service carrier
under `unauthenticated` would be a carrier over a service the portal is
refusing — which is just a worse version of the tunnel the portal already
blocked. The tier case is `authenticated`: the network lets some traffic
through, and this carrier uses only that.

They are opt-in, and the posture flags follow the existing pattern
(`-censorship`, `-allowlist`): nothing here runs unless asked for, and each
has its own flag so an operator can take one without the other.

**When and where to use them is a deployment decision, not a client one.**
ARC's premise is reachability on networks that are not obliged to cooperate
(`network-profiling.md` §5), and these are two more instruments for that.
What the client owes in exchange is an accurate record of what it did and
what traces it left (§2.6, §3.5), which is what much of this document is
about.

## 2. MAC rotation

### 2.1 The two admission policies rotation defeats

Two distinct configurations let a changed address buy access, and they need
different inputs:

**A. Automatic per-new-device grant.** The portal gives every previously
unseen device a free window, trial or introductory session, and tracks the
grant by hardware address so it does not give it twice. A new address is a
new grant. This needs no input beyond a fresh address.

**B. An allowlisted identity keyed on MAC.** The portal admits a device's
traffic once that device has passed, and remembers the admission against its
hardware address rather than against a session cookie, an IP binding or a
credential. Presenting an **already-admitted** address therefore inherits
that admission — its allowlist entry, its firewall rule, its session — for
as long as the portal keeps the entry. This needs the address of a device
that has already passed, which the client observes (§2.4.1).

B is the stronger technique where it works, and the two fail differently:

| portal's admission policy | input needed | rotation helps? |
|---|---|---|
| **automatic per-new-device grant** | any fresh address | **yes** — a new address is a new grant |
| **admission keyed on MAC across sessions** | an admitted address | **yes** — the admission is inherited (§2.4.1) |
| per-device purchase, one grant | — | no — the new address still has to pay |
| per-device authentication, one session | — | no — the credential is checked |
| MAC + voucher / room number / surname | — | no |
| MAC + session cookie + IP binding | — | no — the IP changes with the MAC and the grant is voided |
| 802.1X / EAP credentials | — | no — the identity *is* the credential |
| rate-limits or fingerprints new devices | — | partially, and visibly (§2.6) |

The distinction that matters operationally is **what the portal stores the
admission against**. If a device that has passed can leave and return hours
later with no credential and be admitted on its address alone, the portal is
case B and an observed address works. If returning requires the portal page
again, it is not, and §2.5's attempt sequence ends there.

So rotation is a *device-identity* trick for a *device-identity* control. It
cannot manufacture a credential and cannot conjure an admission the operator
never made; §2.5's stopping rule exists because the client cannot always tell
which row it is in.

### 2.2 Platform mechanics

Setting the address is a privileged operation that **takes the interface
down**, so every connection on it dies — carrier sockets included.

| platform | mechanism | privilege | notes |
|---|---|---|---|
| Linux | `netlink.LinkSetHardwareAddr` (`ip link set DEV address MAC`) | `CAP_NET_ADMIN` — ARC already holds it for the TUN | needs the link down on most drivers; re-association follows |
| Linux, candidate scoring | `iw dev DEV interface add mon0 type monitor` | `CAP_NET_ADMIN` | concurrent monitor and managed works on many chipsets; `iw list` reports which, and some drop the association — §2.4.4 |
| macOS | **no supported mechanism** — see below | — | `ifconfig DEV ether MAC` fails with `SIOCAIFADDR: Can't assign requested address`; the Wi-Fi daemon owns the address |
| iOS, Android | — | — | no API exists; an app cannot change the hardware address |

**Correction: `ifconfig DEV ether MAC` does not work on current macOS.**
Earlier revisions of this document claimed it did, and it does not. Verified
on macOS 26.5.2:

```
$ sudo ifconfig en0 ether 02:00:00:00:00:01
ifconfig: ioctl (SIOCAIFADDR): Can't assign requested address
```

The interface's address is owned by the Wi-Fi daemon rather than by
`ifconfig`, so the ioctl is refused outright — this is not a durability
problem as §2.3 previously suggested, but a refusal. Tools that wrap the
same ioctl (`spoof-mac` and its equivalents) fail identically, which reads
as a broken tool and is not one.

What remains on macOS is the OS's own per-network private address (§2.3),
which is not attacker-chosen and not scriptable. **So policy B's observed
path — presenting someone else's address — is not implementable on macOS at
all**, and the client must report it as unavailable rather than attempting a
rotation that cannot take. `-portal-mac-rotate` on macOS is the case §2.3
describes: the OS already rotates, and ARC has nothing to add.

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
- **`ifconfig en0 ether` is not merely non-durable — it is refused.** The
  Wi-Fi daemon owns the interface's address on modern macOS, so the ioctl
  fails outright (`Can't assign requested address`, verified on 26.5.2)
  rather than succeeding and later reverting. An earlier revision said the
  address could be set and might be restored on the next association; that
  was wrong, and it is why `spoof-mac` looks broken on current macOS.

The client therefore cannot set the address at all on macOS, and there is
nothing to verify there: §2.4's verification still applies on Linux, where
the address does change, and treats a reverted address as a failed rotation
rather than retrying forever. `-portal-mac-rotate` on macOS reports that
the OS's private address is what is in use and that ARC cannot add to it,
rather than offering a rotation that cannot take.

### 2.4 Choosing an address

There are two address sources, corresponding to §2.1's two policies.

#### 2.4.1 Observing an admitted address

For policy B the client must present an address the portal has already
admitted, which means reading other clients' addresses off the link.

**What leaks an address.** The 802.11 headers carry the transmitter and
receiver addresses in the clear on every frame — management, control and
data alike — so any associated station receives the addresses of frames
addressed to it or broadcast. On a segment without client isolation this is
most of the traffic; with isolation it is still the DHCP, ARP and mDNS
broadcasts, plus any frame the AP floods. A passive capture on the
associated interface is enough:

```sh
# while associated and idle; no monitor mode, no privilege beyond capture
tcpdump -i en0 -e -c 200 -nn 'arp or udp port 67 or 68' 2>/dev/null \
  | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | sort | uniq -c | sort -rn
```

`tcpdump -e` prints the link-layer header, so this yields the transmitter
address of every frame captured. The count column is the ranking: the AP's
own address, the gateway's and the busiest stations sort to the top.

**Candidate filtering.** An address is a candidate only if:

| test | why |
|---|---|
| **locally administered** (first octet `x2`/`x6`/`xA`/`xE`) | a randomized client address; a vendor address is as likely to be the AP or a fixed device |
| **not the AP's address, not the gateway's** | read from the association and the default route, not guessed |
| **not our own address** | and not one used on this attachment before |
| **seen in at least two separate frames** | one frame is one device that may since have left |
| **seen within the last `-portal-mac-observe-window` (default 5 min)** | an address whose device has gone cannot be displaced, and the portal may have expired its entry |

**Ordering.** Candidates are tried most-recently-active first, because an
address whose device is still present has an admission the portal is still
refreshing. The list is capped at `-portal-mac-candidates` (default 4) so a
crowded segment does not become an unbounded scan.

**What the client does not do.** It does not attempt to *identify* which
stations are admitted versus unadmitted — that would need a successful
rotation to distinguish, so it is discovered by trying (§2.5), not by
inspection. And it does not decode payloads: only link-layer headers, which
is what `tcpdump -e` gives, are read.

**Capture is passive and bounded.** `-portal-mac-observe` allows at most one
capture of `-portal-mac-observe-count` frames (default 500) per rotation
attempt, and the capture is closed before the interface goes down. Nothing is
stored beyond the candidate list, which is discarded once the attempt ends.

#### 2.4.2 A synthetic address

For policy A the address is generated: **locally administered and unicast**
(first octet `x2`/`x6`/`xA`/`xE`), the remaining 46 bits from the OS CSPRNG,
never the current address, never one used on this attachment before, never
one in the neighbour table.

An address that is multicast or all-zero is malformed and a driver may
reject it; both are precluded by the bits above.

**Collision is checked, not assumed.** Before association the client reads
the link's ARP/neighbour table for a conflicting entry and picks again if it
finds one. That is a best-effort check — a device on a segment this host has
never talked to is invisible — and the cost of a collision is a duplicated
address on the link.

#### 2.4.3 Recorded before it is used

Either way, **the original address is recorded before the first rotation**,
persisted with the attachment's profile, and restored on exit and at the next
start (§2.7).

#### 2.4.4 Scoring candidates by whether they are past the portal

Activity alone is a poor proxy for *admitted* (§2.4.1): a pre-auth station
reloading the portal looks busy, while an admitted one holding a quiet TCP
connection looks dead. Where a monitor-mode interface is available, the
client can read every frame's shape and rank candidates on evidence rather
than volume.

**What is observable, and why it settles the question.** In monitor mode the
client sees all frames on the channel, including frames not addressed to it.
What can be read from them depends on the link-layer security:

| network | readable | admitted-vs-not is |
|---|---|---|
| open SSID | payloads in the clear | **conclusive**: DNS to a resolver other than the portal's, TLS SNI to non-portal hosts |
| WPA2-PSK | headers; unicast encrypted | **conclusive if decrypted** — the PMK derives from the passphrase the client already holds, and a captured four-way handshake yields each station's PTK. No cracking needed. |
| WPA3-SAE, 802.1X | headers only | **inferred from shape** (§2.4.4.1) |
| any | radiotap + 802.11 headers, EAPOL | association state, retry counts, RSSI |

**The client uses shape, not decryption.** Reading payloads would settle it
exactly, but that is interception of another passenger's communications
rather than link-layer metadata, and it is a different class of act from
what this capability is. Shape is enough to rank:

| signal | admission implies | pre-auth implies |
|---|---|---|
| **per-station byte rate**, 10 s window | often kbit/s and up | bytes per second |
| **frame size distribution** | a data-frame tail near the MTU | small control-plane frames |
| **temporal pattern** | sustained | periodic retry bursts |
| **RSSI** | tiebreak only — whose session it is, by proximity |

A station moving more than `-portal-mac-busy-bytes` (default 10 KB in the
window) is scored **admitted**; one below `-portal-mac-idle-bytes` (default
512 B) is scored **unadmitted**; between the two it is **uncertain** and
ranked after both, because a wrong guess costs an attempt from §2.6's
budget.

**Ranking is admitted-first, then RSSI.** A busy station is highly likely to
be admitted, which is what saves attempts; the cost is that the disruption to
that device is immediate and visible to it (§2.6.1). Ranking by idleness
would be gentler and frequently wrong, since a quiet station may simply have
expired — and a failed attempt spends a fourth of the hourly budget.

**Requirements and fallback.** Scoring needs a monitor interface on the same
channel:

```sh
iw dev wlan0 interface add mon0 type monitor
ip link set mon0 up
# ... capture with radiotap headers, then:
iw dev mon0 del
```

Concurrent monitor and managed operation works on many chipsets and drops the
association on others — `iw list` reports support under "valid interface
combinations". So:

- **Where it works**, scoring runs before the observed attempts and orders
  the candidate list.
- **Where it does not**, the client falls back to the activity ranking of
  §2.4.1 and journals that scoring was unavailable. That is the current
  behaviour, not a failure. (On macOS this distinction is moot: there is no
  monitor mode since the `airport` utility was removed in 14.4, *and* no way
  to set the address at all (§2.2), so the observed path does not run there
  regardless of scoring.)
- **`-portal-mac-score`** selects `auto` (default: try monitor, fall back),
  `off` (never monitor), or `require` (fail the observed path rather than
  fall back, for an operator who wants no unranked attempts).

**The capture is bounded and temporary.** One monitor interface, created for
the scoring window (`-portal-mac-score-window`, default 10 s), removed
afterwards, capturing headers only. The station table is scored, the
candidates retained, and everything else discarded — no per-frame record
survives the window.

#### 2.4.4.1 What shape cannot tell you

Two stations can look identical in shape and differ in admission: a
pre-auth station streaming a captive-portal video is busy and *not* admitted,
and an admitted station polling for mail every minute is quiet and *is*. The
scoring reduces the number of wrong attempts; it does not eliminate them, and
the attempt budget of §2.6 is what bounds the cost of being wrong.

Ranking by *admitted status* rather than by *observed shape* would need a
position on the path with more state than a client has — seeing which side
of the portal's enforcement point a station's traffic lands on. That is
deferred (§6) rather than approximated.

### 2.5 When to rotate, and when to stop

Rotation is driven by the state model, and the trigger is narrow:

```text
state == unauthenticated
  AND portal_seen                     (a portal was positively identified)
  AND the portal has asked for a credential
  AND -portal-mac-rotate is on
```

**The attempt sequence tries both policies before stopping**, because the
client cannot tell from outside which one the portal implements (§2.1):

1. **Synthetic first** (§2.4.2), one attempt. If the portal passes, it is
   policy A and the rotation worked; the state reaches `authenticated`
   through the ordinary path (`captive-portals.md` §4.3).
2. **Observed second** (§2.4.1), only if a candidate exists and only when
   `-portal-mac-observe` is on. Candidates are **scored and ordered first**
   where §2.4.4 can run, so admitted-looking stations are tried before
   uncertain ones and both before unadmitted ones. One attempt per candidate
   up to the cap. If one passes, the portal is policy B and the admission is
   inherited.
3. **Stop** when the synthetic attempt and every candidate have failed.

Synthetic goes first because it is self-contained: no capture, no
interference with another station, and it settles policy A without touching
anyone's address. Observed runs only after it fails, which is also what keeps
the common case free of the complications in §2.6. Scoring orders the
observed attempts; it does not create candidates and does not change when the
observed path runs.

**The stop reports what was observed, not a diagnosis.** My earlier revision
said the client would report `credential_bound`, and the review is right
that failed rotations do not establish that: a portal with no free grant, an
exhausted shared quota, a MAC+IP binding, a failed DHCP lease, a failed
reassociation, or the OS rolling the address back (§2.3) all produce the
same observation. So the client reports **`rotation_ineffective`** and the
evidence behind it:

| field | meaning |
|---|---|
| `reason` | `rotation_ineffective` — never a verdict about the portal |
| `attempts` | how many rotations were tried, and from which source |
| `address_applied` | whether each address actually took, verified (§2.3) |
| `link_recovered` | whether the interface came back with a lease, route and DNS (§2.7.2) |
| `probe_verdict` | what probe A said after the last attempt |
| `candidates_tried` | how many observed addresses were attempted |

A maintainer reading that can tell "the portal wants a credential" from
"DHCP never gave us a lease", which the single word `credential_bound`
could not. If the link never recovered, the client says so and stops
rotating entirely — a rotation that breaks the interface is not evidence
about the portal at all.

**The budget of §2.6 counts both sources together**, so a failed synthetic
attempt spends one of the four in the hour. That matters more for the
observed case, where each attempt also costs a capture and an association on
someone else's address.

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
  association events sees exactly that, which is a stronger signal than the
  one the portal was enforcing.
- **DHCP sees a new client each time**, with a new lease. Repeated new
  leases from one radio is likewise visible, and a small pool can be
  exhausted.
- **The portal's own accounting sees N admissions** where it expected one.
  Where access is sold (a day pass, a device count), this is the operator's
  accounting being defeated, and the operator's remedy is applied to the
  user.
- **Nothing here hides that traffic is a tunnel.** Rotation changes who the
  network thinks is connected, not what the connection carries.

#### 2.6.1 Sharing an address with the device that owns it

An observed address (§2.4.1) is in use by another station, so the rotation
creates a **duplicate address on the link**. What follows is mechanical and
worth the client handling rather than discovering:

| what happens | consequence |
|---|---|
| **DHCP sees the address already leased** | the server renews or reassigns, so the second device and the first can end up with the *same* IP, or the first is pushed to a new one. Either way one of them loses its routing. |
| **The AP's forwarding table has two ports claiming one address** | frames addressed *to* that address are delivered to whichever the AP learned last, so the two devices alternate traffic rather than sharing it. The observed device sees its connection break and reconnect. |
| **A portal with a device limit** | the new association displaces the earlier one, which is the mechanism that makes policy B work; that device's session ends and it must pass the portal again to return. |
| **A controller that detects duplicate addresses** | some quarantine both ports. If the client's link drops after an observed rotation, the attempt is over: it restores and stops. |

**The client therefore:** restores the original address as soon as the
attempt fails (§2.7), does not retry the same candidate twice, and treats a
link that drops immediately after an observed rotation as a duplicate-address
rejection rather than a portal refusal — recorded as `address_conflict`
rather than `rotation_ineffective`, because the two call for different next
steps.

The captured candidates are also **not retried beyond the attempt**: a
candidate that failed is dropped from the list rather than tried again on the
next rotation, so that repeated attempts across an hour do not converge on
one station.

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

**Identity.** The record is keyed on `(physical device identity, network
identity)`, where the physical identity is the adapter's permanent address
(reported by the driver, not the current one, so it survives a rotation) and
the network identity is the SSID on Wi-Fi and the gateway MAC plus subnet on
wired — the same key `network-profiling.md` §3.1 uses for the local profile
cache.

**A record for another network is retained, never discarded.** My earlier
revision said the client "clears it and journals that it declined", and the
review is right that this loses the only durable copy of the pre-rotation
address. The failure is concrete: rotate `wlan0` on SSID A, crash, associate
with SSID B before restart — B's startup discards A's record, and on return
to A there is nothing left to restore, while on Linux the spoofed address
has been sitting on the interface the whole time because the address is a
property of the interface and not of the network.

So the rules are:

- **Same device, same network** → restore, verify, clear the record.
- **Same device, different network** → **keep the record**, do not apply it,
  and restore it the next time that network is seen. The interface is left
  as it is, because the OS may have set a private address for the current
  network and that is the correct state for it.
- **Device absent** (a USB adapter unplugged) → keep the record and restore
  when the device returns.
- **Startup while unassociated, or before the SSID is readable** → do not
  guess. The client treats it as "network identity not yet known", leaves
  records alone, and evaluates them once association completes. A rotation
  record is acted on only when both halves of the key are known.

Records are retained until they are applied or the user discards them
(`arc-client portal restore --discard`), and their presence is reported at
startup so a device is never left quietly spoofed because a restore was
pending and unnoticed.

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

1. **Pause the transport, without draining paths.** Stop the reconnect
   attempts and suspend carrier I/O, but **do not mark paths `DRAINING`**:
   `ARC-v1-…-Handoff.md` §14.1 makes `DRAINING` a one-way state whose only
   successor is `DEAD`, and §14.3 forbids reusing a retired path ID. Draining
   every path would therefore retire the whole session during an
   association or DHCP delay, with no way back.

   The pause is instead a **transport suspend** that keeps each path's
   identity — path ID, CIDs, reset token, nonce space — while its socket is
   gone, exactly as §9.4's suspend grace already allows a session to outlive
   its paths for up to 120 s. Paths stay `VALIDATED` but not usable, and the
   keepalive clock for each path restarts when its socket is rebound, so the
   rotation interval is not charged as loss (the same exemption §14.4 gives
   an MTU probe). If the rotation exceeds the suspend grace, the session ends
   and re-handshakes on the new address, which is the correct outcome and is
   reported as `session_reestablished` rather than as a rotation failure.
2. **Mutate.** Write the record (§2.7.1), bring the link down, set the
   address, bring it up, and **verify the address took** — a silent rollback
   (§2.3) ends the lifecycle here.
3. **Reassociate and acquire.** Wait for association, then for DHCP or RA,
   then for a default route, then for resolvable DNS — each with its own
   timeout, and each failure reported distinctly. A link that comes up with
   no lease is not a recovered link.
4. **Verify the address again, after association** (§2.3): the Wi-Fi daemon
   can restore the OS's own address during association or a subsequent roam,
   so the effective address is read back here and compared with the intended
   one. A mismatch is an **OS rollback**, reported as a rotation failure
   *before* any portal result is attributed to the new identity — otherwise
   the client would credit a portal pass it did not earn.
5. **Invalidate what the address owned.** The attachment's cached local
   profile and any per-attachment probe results keyed on the old identity
   are discarded (`network-profiling.md` §3.1). The upstream profile is
   *not* invalidated, because the upstream did not change.
6. **Rebind the carriers.** Every carrier socket is recreated on the new
   interface address and re-bound (§17.1's marks and `-bind`), because the
   old ones are bound to an address that no longer exists.
7. **Re-probe, then revalidate.** Probe A and B run once (§4 of
   `captive-portals.md`); if the portal now passes, each suspended path
   resumes with its identity intact and is re-validated by `PATH_CHALLENGE`
   on its new address (§14.5, an address change on an existing path), not by
   joining a new path.

**Every step reports, and the lifecycle is journalled as a sequence**, so a
`rotation_ineffective` (§2.5) can be told apart from "the address changed
and DHCP never answered", and both from an OS rollback. The end-to-end test
is that ARC carries traffic after the rotation on the *same* path IDs, not
that the link came back.

### 2.8 Configuration

| flag | default | meaning |
|---|---|---|
| `-portal-mac-rotate` | `off` | enables rotation at all; `off` means neither policy runs |
| `-portal-mac-observe` | `on` | allows policy B's passive capture and observed addresses (§2.4.1). With it off, only the synthetic attempt runs |
| `-portal-mac-observe-count` | `500` | frames captured per attempt; the capture closes when reached or when the interface goes down |
| `-portal-mac-observe-window` | `5m` | how recent an observed address must be to count as a candidate |
| `-portal-mac-candidates` | `4` | most observed addresses tried per attempt, most-recently-active first |
| `-portal-mac-score` | `auto` | candidate scoring (§2.4.4): `auto` tries a monitor interface and falls back, `off` never monitors, `require` fails the observed path rather than falling back |
| `-portal-mac-score-window` | `10s` | how long the monitor interface exists before it is removed |
| `-portal-mac-busy-bytes` | `10000` | bytes in the scoring window above which a station is scored admitted |
| `-portal-mac-idle-bytes` | `512` | bytes below which a station is scored unadmitted; between the two is uncertain |
| `-portal-mac-restore` | `on` | restore the original address on exit and at the next start (§2.7). `off` exists only for a device whose address is managed by something else, and the client says so at startup |

**`-portal-mac-observe` is on by default, given `-portal-mac-rotate` is
already opt-in.** An operator who has enabled device-identity rotation on a
captive network has asked for the capability, and gating policy B behind a
second flag would mean the common portal — one that admits by address across
sessions — silently fails while the client reports `rotation_ineffective`.
The flag exists so it can be turned off where capture is unwanted (§2.4.1's
bounded, header-only capture), not because the capability is separate.

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

#### 3.2.1 It joins an established session; it does not bootstrap one

One cell per packet puts a hard ceiling on what this carrier can carry, and
the review is right that I claimed a capability the arithmetic does not
support. The handshake is the problem:

| packet | size | fits a 282 B budget? | fits a 114 B budget? |
|---|---|---|---|
| `HANDSHAKE_INIT` | 122 B | yes | **no** |
| `AUTH`, 43-byte token | 80 B | yes | yes |
| `AUTH`, 256-byte token | 293 B | **no** | **no** |
| `AUTH`, `MaxCredentialLen` 4,096 | 4,133 B | **no** | **no** |

And those are bare frame sizes: the 282 B figure is the packet budget *before*
the service's own envelope and the adapter's encoding, so the real ceiling is
lower in every case. A device holding a long token — or enrolled with the
112-byte enrollment credential — **cannot establish a session over this
carrier at all**, and on a small-payload service even `HANDSHAKE_INIT` does
not fit.

**Rule: a permitted-service carrier joins an already-established ARC
session. It never bootstraps one.** That means:

- The session is established on another carrier — any UDP, TLS or front path
  — and this carrier's path is added with `PATH_JOIN` (§14.4), which is 45 B
  and fits.
- If no session exists, the client does not offer this carrier and says so.
  Offering it would produce a handshake that fails at the first packet with
  no diagnostic a user could act on.
- Where a service's payload budget is at least 300 B **after** envelope and
  encoding, a deployment *may* additionally allow it to carry the handshake;
  that is a per-provider property measured by the adapter, not a default, and
  §3.2.2's sizing rule below is what makes it decidable.

**This also bounds what the carrier is for.** `network-profiling.md` §10
describes its role as rendezvous and small payloads; joining an established
session is consistent with that, and bootstrapping a session over a chat
service was never plausible. The correction is to say so rather than let the
generic contract imply otherwise.

#### 3.2.2 Sizing is measured, and the adapter reports it

The maximum ARC packet this carrier can carry is
`service_payload − envelope − encoding − 18`, not `cell − 18` — the cell is
this adapter's own framing, and there may be several layers of it. The
adapter therefore **reports the resulting `max_packet` to the session** as a
constrained carrier does (`dns-lifeline.md` §4.1), and the session applies
its one-cell rule against that value. An adapter that cannot state its
payload budget is not usable, because nothing downstream can size a packet
against a guess.

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
| **Policy A: free per-device grant, spent** | the synthetic address passes; state reaches `authenticated`; the address is LAA and unicast; no capture was taken |
| **Policy B: admission keyed on MAC across sessions** | the synthetic address fails, an observed candidate passes, state reaches `authenticated` |
| **Policy B with client isolation on** | candidates still come from broadcast DHCP/ARP; the attempt proceeds |
| **Candidate filtering** | the AP and gateway addresses are excluded; our own and previously-used addresses excluded; a single-frame station excluded; a candidate older than the window excluded |
| **Candidate cap** | at most `-portal-mac-candidates` observed addresses are tried, most-recent first |
| **Candidates not retried across attempts** | a failed candidate is dropped, not retried on the next rotation in the same hour |
| **Duplicate address: the link drops after an observed rotation** | reported as `address_conflict`, not `rotation_ineffective`; the original address is restored and no further candidates are tried |
| **Capture is bounded** | at most one capture of `-portal-mac-observe-count` frames per attempt, closed before the interface goes down; nothing stored beyond the candidate list |
| **`-portal-mac-observe off`** | only the synthetic attempt runs; an observed-capable portal reports `rotation_ineffective` rather than silently capturing |
| **Per-device purchase** | the synthetic attempt fails and the ledger is unchanged: no admission is invented (§2.1) |
| **Credential-keyed portal** | every attempt fails; the client stops and reports **`rotation_ineffective` with its evidence**, never `credential_bound`; **the original address is restored** |
| **Rotation where DHCP never answers** | reported as `link_recovered=false`, distinguished from a portal refusal (§2.5) |
| **Address chosen** | first octet has I/G clear and U/L set; never the previous address; never one in the neighbour table |
| **The OS rolls the address back** | the rotation counts as failed and the lifecycle stops, rather than reporting a success that did not happen (§2.3) |
| **End-to-end recovery after a rotation** | not just "the link is up": association, DHCP, default route, DNS, carrier rebind, and ARC **carrying traffic on the same path IDs** (§2.7.2) |
| **A rotation longer than the suspend grace** | the session ends and re-handshakes; reported as `session_reestablished`, not as a rotation failure (§2.7.2) |
| **A rotation in which the OS restores its address during association** | read back **after** association, reported as an OS rollback **before** any portal result is attributed to the new identity (§2.7.2 step 4) |
| **Local profile cache** | the attachment's local profile is invalidated by a rotation; the **upstream** profile is not (§2.7.2) |
| **Clean exit after a rotation** | the original address is restored and verified |
| **`SIGKILL` at each mutation boundary** | the record is durable before the address changes, so the next start restores correctly from every crash point (§2.7.1) |
| **Rotate on SSID A, crash, start on SSID B, then return to A** | B retains A's record without applying it; on return to A the address is restored. **The record is never discarded for being the wrong network** (§2.7.1) |
| **Startup while unassociated, SSID unreadable** | no record is applied or discarded; evaluation waits for association (§2.7.1) |
| **A corrupt rotation record** | reported and queried with the user; **no address is written** (§2.7.1) |
| **Restore fails** | the client prints the exact restore command and exits non-zero, rather than leaving the device spoofed |
| **Scoring ranks a busy station above an idle one** | in a seeded capture, a station at 50 KB/10 s scores admitted and is tried first; a 100 B/10 s station scores unadmitted and last (§2.4.4) |
| **Scoring unavailable (no monitor interface, or macOS)** | falls back to activity ranking and journals that scoring was unavailable. On Linux the observed path still runs; **on macOS it stops here** — §2.2 has no mechanism to set the address, so the client reports the observed path unavailable rather than attempting it (§2.2) |
| **`-portal-mac-score require` without monitor support** | the observed path fails with a stated reason rather than attempting unranked candidates |
| **Monitor interface cleanup** | the interface exists only for the scoring window and is removed; the association survives, or is re-established if the chipset dropped it |
| **Scoring reads no payloads** | on a WPA2 network the capture yields headers only; no decryption is attempted and no PTK is derived (§2.4.4) |
| **`-portal-release-tunnel off` + rotation** | the rotation runs and **the full-tunnel route stays installed throughout** — a rotation cannot downgrade protection (§4) |
| **`ask` + rotation** | the release happens only through `arc-client portal login`, as it would without rotation, and the route is reinstalled when the state returns to `authenticated` |
| **Rate caps** | the 5th rotation in an hour is refused; nothing rotates while `authenticated` |
| **Journal vs audit** | the shared journal records the count and outcome with **no address**; the local audit has both addresses and is never uploaded (§2.6) |
| **Permitted-service carrier round-trip** | a cell goes to an operator-controlled endpoint through a stub service adapter and comes back; one cell per request; a `rate_limited` failure is reported as such and not retried past the limit |
| **A service with no return path** | rejected as a carrier at configuration time, not attempted and failed at runtime (§3.2) |
| **A service carrier in `unauthenticated`** | refused: the portal is not passing the service, so there is nothing to build (§1, §4) |
| **`HANDSHAKE_INIT` over a small-payload service** | never attempted: a carrier that cannot carry the handshake joins an established session only, so the client does not offer it without one (§3.2.1) |
| **A 256-byte-token `AUTH` (293 B) on a 282 B carrier** | not attempted for establishment; the session is established elsewhere and the carrier joins by `PATH_JOIN` (§3.2.1) |
| **An adapter that cannot state its payload budget** | refused as unusable, since nothing downstream can size a packet against a guess (§3.2.2) |
| **Service adapter on a one-cell budget** | a packet larger than `max_packet` is refused before emission, and `max_packet` is the *measured* budget after envelope and encoding, not the cell minus 18 (§3.2.2) |

The rows that matter most are the ones that leave the device or the user in a
bad state: **restore after a crash at each boundary**, **restore failure
being loud**, **a rotation that cannot downgrade the tunnel**, and **no
address in the shared journal**. Those are what a happy-path implementation
gets wrong, and they are why §2.6–§2.7 are as long as they are.

### 5.1 An observed case, recorded because it contradicts an assumption

One real network — a US domestic airline's in-flight Wi-Fi, measured from
macOS on an open SSID, before authentication — is worth writing down because
three things happened that a reader of §2.4 would not predict.

**Broadcasts leak addresses on an isolated segment; that is all they leak.**
The capture in §2.4.1 yielded ten candidate addresses. A first reading of
that is "client isolation is off", which is wrong: every protocol the filter
selects (ARP, DHCP, ICMPv6, mDNS) is broadcast or multicast, and broadcast is
flooded to every station on an isolated segment too. The discriminating test
is unicast to a peer, and here it failed — `ping` to another station's
address got nothing while the gateway answered normally. **Isolation was
on.** §2.4.1's premise therefore holds only in its broadcast half: enough to
enumerate addresses, not enough to see who is passing traffic.

This is worth a caution in the implementation: *a capture full of other
stations' addresses is not evidence that isolation is off*, and the client
must not draw that conclusion, because §2.4.4's scoring depends on the
answer. Where scoring is available it should test unicast explicitly rather
than infer from frame counts.

**Two addresses appeared for one IP.** `arp -an` showed a single neighbour
address owned by two different link-layer addresses within one capture — a
station that rotated its own private address, or an AP proxying ARP. Either
way §2.4.1's "seen in at least two frames" test passes it and the assumption
behind that test — one address, one device — does not hold. The capture
tooling now reports addresses that share an IP, so this is visible rather
than silently ranked.

**A gateway-adjacent address nearly passed the filter.** The default gateway
was `74:24:9f:64:17:39`, and a second address from the same OUI,
`74:24:9f:63:ff:5c`, appeared in the capture but not in the neighbour table.
§2.4.1's exclusion is by exact address, so this variant was excluded only by
the vendor-address rule — a fragile accident rather than a decision. On
networks where the AP and gateway are the same appliance with several
addresses, the safer test is a /24 OUI match against the gateway, not
equality.

None of this changes §2.4's design; the candidate path worked, and it worked
on a network whose isolation would have defeated a naive implementation. It
tightens three details, and it is the first evidence we have that §2.4.1's
fallback is worth having where monitor mode is unavailable.

It also demonstrated why §2.2 matters more than it looks: the capture and
the candidate list were obtained on a Mac, and **no address in that list
could then have been applied**. `ifconfig en0 ether` is refused on current
macOS (§2.2), so the observation path terminates at the observation and the
client has to say so. A tool that offered to "use" a candidate on that
platform would be offering something it cannot do — and the failure would
surface as a broken rotation rather than as an unavailable capability,
which is the worse of the two.

**One thing the case did not establish, and could not.** Which candidate was
admitted. Activity ranking put one station far ahead of the rest — 217
captured frames against a next-highest 93 — and that is exactly the
ambiguity §2.4.4.1 warns about: a pre-auth passenger streaming video looks
identical. §2.5's answer is to try, and the cost of trying is that
passenger's session.

## 6. Deferred

- **Per-provider service adapters.** §3.4 explains why: each is its own
  protocol, decision and document.
- **Rotating the *radio* rather than the address.** A USB Wi-Fi adapter with
  its own address is a second device with its own identity, which is
  cleaner than spoofing the first and does not defeat the OS's private
  address. It needs hardware, so it is a user instruction rather than a
  feature.
- **Detecting which policy a portal implements without rotating.** An
  information element in a probe could ask the portal to describe its own
  policy; no portal does, and §2.5's synthetic-then-observed attempt order is
  cheaper than a protocol.
- **Selecting candidates by *admitted* status rather than by inferred shape.**
  §2.4.4 ranks on traffic shape, which reduces wrong attempts but cannot
  eliminate them: a pre-auth station streaming portal video looks busy, and an
  admitted station polling mail looks quiet. Observing which side of the
  portal's enforcement point a station's traffic lands on would settle it,
  which needs a position on the path with more state than a client has.
- **Decrypting WPA2 unicast to read a candidate's payloads.** Possible — the
  PMK comes from the passphrase the client already holds, and a captured
  four-way handshake yields each station's PTK, so no cracking is involved.
  Deliberately not used: it is interception of another station's
  communications rather than link-layer metadata, and shape is enough to rank
  (§2.4.4). WPA3-SAE and 802.1X defeat it anyway.
- **A permitted-service carrier over a *paid* tier's included services.**
  Same contract, different budget accounting; nothing structural is missing.
- **Restoring a *vendor* address deliberately** (presenting as a known device
  class). Out of scope: it is a different capability with a different risk
  profile, and nothing in ARC needs it.
