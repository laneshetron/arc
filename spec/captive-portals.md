# ARC — Captive portals and pre-authentication networks

**Status:** draft design. Extends `network-profiling.md` §5.1 (Stage 0,
which this document specifies in full) and fills the "pre-auth restricted
local network" case that document names as its second running example
(§1). Nothing here is implemented.

## 1. What this is for

A captive portal is the local layer's own admission system: an airline, a
hotel, a café, a corporate guest network. It is not hostile in the sense
`network-profiling.md` §3 uses that word — it is not trying to detect ARC —
but it does two things that break ARC completely, and it does them before
any carrier exists:

1. **It lies about the network.** Until the user authenticates, DNS may
   resolve everything to the portal, HTTP may be redirected, and TLS may be
   intercepted. Every carrier's first packet is answered by something that
   is not the relay.
2. **It has states, and the transition between them is invisible to ARC.**
   A session that worked five minutes ago starts failing because the
   portal's one-hour grant expired. Without a state model that looks exactly
   like the network dying.

The result today, on `main`, is a client that retries forever and tells the
user nothing. This document specifies the state model, the detection that
populates it, and what ARC does in each state. It deliberately does **not**
specify the escape techniques — those are §6, and they are separate work.

## 2. Design principles

**C1 — Classify before connecting.** Portal detection runs before the first
carrier opens, not after the first failure. A client that begins a Noise
handshake through a portal has already spent a handshake attempt on a
network that cannot complete one, and on a metered airplane link that is
real money.

**C2 — No probe is more revealing than a browser.** Detection uses the OS
connectivity endpoints and an ordinary HTTPS GET. It must not look like
ARC, and it must not repeat on a loop. The portal operator is a legitimate
third party whose network this is, so which probes are acceptable is
governed by `network-profiling.md` §3.3's probe-risk rule: the local
context decides which probes run.

**C3 — Report, do not guess.** Four states, and `unknown` is one of them.
A portal that intercepts TLS cannot be classified from outside it, and
pretending otherwise produces a client that confidently sends the user to
the wrong remedy.

**C4 — The state is observable.** Every transition is logged to the journal
with its evidence, because "it didn't work on the plane" is otherwise
undebuggable, and because the portal case is the one users are most likely
to report.

**C5 — One probe, three consumers.** The portal state feeds the user
message, the carrier selection (do not open UDP through a portal), and the
DNS lifeline's resolver discovery (`dns-lifeline.md` §5.2), which must know
whether the resolver it found is the portal's or the real one.

## 3. The state model

```text
                    ┌──────────┐
   start ──────────►│ unknown  │◄─────────── detection fails/inconclusive
                    └────┬─────┘
                         │ 204, empty body
                         ▼
   ┌──────────┐      ┌────────┐    redirect / 200-with-HTML / DNS hijack
   │  none    │◄─────┤ probe  ├──────────────────────┐
   └──────────┘      └────────┘                      ▼
        ▲                                    ┌────────────────┐
        │  keepalive ok                      │ unauthenticated│
        │                                    └───────┬────────┘
        │                                            │ keepalive starts
        │                                            │ answering 204
        │                                            ▼
        │                                    ┌────────────────┐
        └────────────────────────────────────┤ authenticated  │
                                             └───────┬────────┘
                                                     │ keepalive reverts
                                                     ▼
                                             unauthenticated
```

| state | meaning | ARC does |
|---|---|---|
| `none` | no portal; the network is open | proceed normally |
| `unauthenticated` | a portal exists and the user has not passed it | **do not start carriers**; tell the user the portal URL and wait |
| `authenticated` | a portal exists and the user has passed it | proceed; run the expiry keepalive (§5) |
| `unknown` | detection could not conclude | proceed **with a warning**; the first carrier failure explains itself later |

`unknown` is the important one and the one my earlier drafts of this idea
left out. A portal that intercepts TLS, or a network that drops the
connectivity endpoints, cannot be classified from the outside — and a
client that treats "I cannot tell" as "it is open" will blame the relay for
the portal's behaviour.

## 4. Detection (Stage 0)

### 4.1 The probes, and what each establishes

All probes go from a socket **bound to the physical interface**, outside
the TUN — the rule `network-profiling.md` §3.2 states for every probe,
because canary traffic routed through the TUN profiles the relay's egress
instead of the network's. Before the tunnel exists this is automatic;
after it, it is the same rule the lifeline uses (`dns-lifeline.md` §5.2).

| probe | target | establishes |
|---|---|---|
| **A. Connectivity endpoint** | the OS's own check (`connectivitycheck.gstatic.com/generate_204`, `captive.apple.com/hotspot-detect.html`, or `-portal-probe URL`) | whether the network redirects or rewrites — the primary signal |
| **B. DNS honesty** | resolve one canary name through the system resolver, compare with a pinned-IP expectation | portal DNS hijack, which outlives a passing A |
| **C. Portal presence** | the URL A redirected to, fetched **without** following further redirects | that a portal page is actually served there |
| **D. TLS reachability** | a TLS handshake to the relay's own endpoint (`-tls`/`-front` host) | whether the portal permits the relay host at all |

Probes A and B are the classification; C confirms the portal is real rather
than a broken network; D is what makes the *later* failure attributable.
D is not a probe of the relay in `network-profiling.md` §4 P1's sense — it
is a TLS handshake to the relay's own front, which is exactly what a browser
visit to that host would do, and it establishes nothing about the session.

### 4.2 The classification table

The outcome of A drives the state, with B and C resolving ambiguity:

| A's result | B: DNS | C: portal page | state |
|---|---|---|---|
| 204, empty body | honest | — | `none` |
| 204, **non-empty** body | either | — | `unknown` — a rewriting proxy, not a portal |
| 3xx **to another host** | either | 200 with HTML | `unauthenticated` |
| 3xx **to the same host** | either | 200 with HTML | `unauthenticated` (login on the same host) |
| 200 where 204 was expected | either | — | `unauthenticated` |
| any 2xx with HTML | either | — | `unauthenticated` |
| 204, empty | **hijacked** | — | `unauthenticated` — the DNS lie outlives A |
| timeout / refusal | — | — | `unknown` |
| TLS failure to A's endpoint | — | — | `unknown` |

**"Empty body" is the discriminator for `none`, and it must be checked
literally.** Many portals answer 204 with an HTML body, or 200 with a login
page; both are portals. A client that only checks the status code
misclassifies the single most common airline case.

**DNS honesty outranks A for the purpose of `none`.** A portal can pass A
(a cached 204, or a whitelisted connectivity host) while still hijacking
DNS. If B says hijacked, the state is `unauthenticated` whatever A said,
because the lifeline and every name-based carrier would be fed the portal's
answers.

### 4.3 The portal URL

When a probe redirects, the redirect target is the portal URL the user must
visit. Two rules:

- **It is fetched once, without following redirects**, to confirm it serves
  a page. A portal that redirects to a dead host is a broken portal, and
  the state is `unknown` — sending a user to a 404 wastes their time.
- **It is reported verbatim** in the message (§7), because portals often
  need a specific path (`/login?ref=...`), and the user navigating to the
  bare host can land somewhere that does not work.

## 5. The expiry keepalive

A portal grant expires — commonly after an hour, sometimes on a traffic
quota, sometimes when the aircraft changes coverage. ARC must distinguish
that from the network dying, and the only way is to keep asking.

**Rule.** While the state is `authenticated`, re-run probes A and B every
`-portal-keepalive` (default 60 s), from a socket outside the TUN, on the
**physical interface only** — one request a minute is what a logged-in
browser does when a tab is open, and it is well below any portal's
tolerance.

| keepalive result | transition | what the user sees |
|---|---|---|
| 204 empty, DNS honest | stays `authenticated` | nothing |
| redirect / portal page | → `unauthenticated` | "Your portal session expired; visit URL" |
| timeout, 3 in a row | → `unknown` | "Network unreachable" |
| 204 but DNS hijacked | → `unauthenticated` | as above |

**Three timeouts, not one.** A single lost request is an aircraft handover
or a congested AP; `network-profiling.md` §4 P2's paired-control principle
applies at this scale too, and the client should not tell a user their
portal expired because one packet was lost.

**On `authenticated` → `unauthenticated`, live sessions continue.** A
portal has not necessarily stopped forwarding established flows when it
stops admitting new ones, and killing a working session because a probe
failed would be the same self-inflicted outage §14.6 avoids. The client
reports the state, stops *new* dials, and lets the session die on its own
evidence — which, if the portal really has closed, it will within one
keepalive interval.

## 6. What happens in each state

### 6.1 `unauthenticated`

**The client does not open carriers.** The connection cannot succeed, so
opening one spends a handshake attempt, logs a misleading failure at the
relay, and on a metered link costs the user money. Instead:

- It prints the portal URL and the instruction to authenticate (§7).
- It keeps the keepalive running, so it notices when the user does.
- It starts the moment the state reaches `authenticated` — no restart.

That last point matters: a user who reads "log in, then reconnect" and
reconnects by hand is doing something the client could have done for them.

### 6.2 `authenticated`

Carriers open normally. **Carrier selection changes in one way:** under a
portal, the client does not open a UDP carrier to the relay unless probe D
showed UDP is permitted. No portal admits arbitrary UDP, but some admit
DNS and some admit nothing but 443, so a UDP carrier that fails every
handshake is a poll and a handshake budget spent for nothing.

This is the same shape as `network-profiling.md` §6.2's "QUIC
throttled/blocked → demote UDP carriers" row, but derived from **local**
evidence rather than from a classified upstream regime — which is why it
belongs here and not in the profiler's mapping table.

### 6.3 `unknown`

Carriers open normally, with a warning in the log and the status line. The
first carrier failure then either confirms the portal hypothesis (a TLS
failure right after the handshake begins) or refutes it, and the journal
records which. This is the case where ARC cannot know, and the honest
behaviour is to try and to say so.

## 7. What the user sees

One line, in the status output, with the URL when there is one:

```text
arc-client: captive portal at https://portal.example.net/login?ref=UA123
            log in with a browser, then ARC will connect automatically
```

and on expiry:

```text
arc-client: the portal session expired
            visit https://portal.example.net/login?ref=UA123 to reconnect
```

Both are also journal lines with the evidence (`status`, `body_bytes`,
`sni`, `resolver`), so a report from a user contains what a maintainer
needs. `-portal-message off` suppresses the status line for scripted use,
but never suppresses the journal.

## 8. Configuration

| flag | default | meaning |
|---|---|---|
| `-portal-check` | `auto` | `auto`, `off`, or `force` (run detection even when `-full-tunnel` is not set) |
| `-portal-probe URL` | the OS endpoint | the connectivity-check URL, for networks that block the standard ones |
| `-portal-keepalive` | `60s` | how often to re-check while `authenticated`; `0` disables |
| `-portal-wait` | `0` | `0` waits indefinitely for the user; a duration exits if no portal login happens |

**`-portal-check off` exists** because a network that blocks the
connectivity endpoints would otherwise be classified `unknown` on every
start, and an operator who knows their network should not pay for a probe
they do not need. It is not the default because the failure it prevents is
silent.

## 9. Interaction with the rest of ARC

- **The DNS lifeline** (`dns-lifeline.md` §5.2) discovers the physical
  link's upstream resolver. Under a portal the system resolver may be the
  portal's own, and the `dns_integrity` classification that decides
  whether to trust it (`network-profiling.md` §5.1, §6.1) is exactly probe
  B of this document. They must read the same probe, not run two.
- **The profiler** (`network-profiling.md` §5.1) lists portal detection as
  Stage 0 and this document is that stage; when the full profiler is built,
  its `portal_state` feature is this state machine's output.
- **The cache** (§3.1 there) keys the local profile on the network
  attachment. The portal state is part of that profile and shares its
  expiry — but a portal state change must *not* invalidate the upstream
  profile, because the upstream did not change.
- **`freeze-and-udp-ban.md` §4** holds UDP back from a hosting address.
  This document holds it back under a portal for a different reason (it will
  not pass), and the two rules compose: either one suppresses the carrier.

## 10. Testing

`test/netns/portal.sh` (Linux, like its neighbours) builds a portal that
implements each row of §4.2 and asserts the state. The portal is a small
Go binary that serves the connectivity endpoint and a login page, with
per-MAC grant state and an expiry it can be told to trigger.

| scenario | assertion |
|---|---|
| Open network: 204, empty, DNS honest | `none`, carriers open immediately |
| Portal: 3xx to a login host | `unauthenticated`, **no carrier opened**, URL in the message |
| Portal: 200 with HTML where 204 was expected | `unauthenticated` — the common airline case |
| Portal: 204 with a non-empty body | `unknown`, carriers open with a warning |
| Portal: 204 but DNS hijacked | `unauthenticated`, because the DNS lie outranks the status code |
| Portal: redirects to a dead host | `unknown`, not `unauthenticated` — do not send the user to a 404 |
| Login completed | state reaches `authenticated` without a restart, and carriers open |
| Grant expires mid-session | state returns to `unauthenticated`, the message names the URL, **and the live session is not killed** |
| Three keepalive timeouts | `unknown`, reported as unreachable rather than as expiry |
| TLS intercepted, probes fail | `unknown`; carriers open and the journal records the evidence |
| `-portal-check off` | no probes sent; state is `none` by configuration, and the journal says so |
| `-portal-wait 30s` with no login | the client exits with the URL rather than waiting forever |

The last three rows are the ones that fail on a naive implementation:
`unknown` versus `unauthenticated` is a distinction a status-code check
cannot make, and the "do not kill the session" row is the one that would
otherwise produce a support ticket about ARC dropping connections.

## 11. Deferred

- **The escape techniques.** MAC rotation (for portals that key the grant
  to the device's hardware address with no per-device credential), and
  riding a "free tier" that permits only the provider's own services.
  Both are capabilities rather than detections: they belong here, behind
  explicit posture flags in the manner of `-censorship` and `-allowlist`,
  but they need the state model above to know when they apply. Specified
  separately.
- **Portal page rendering.** ARC does not embed a browser; it reports the
  URL and lets the OS handle it. A mini-browser is a large surface for a
  problem the platform already solves.
- **Authenticating on the user's behalf.** Portals commonly use forms with
  per-provider quirks (seat number, frequent-flyer code, payment). Filling
  them is a per-airline integration and an obvious place to mishandle
  credentials, so it is out of scope until someone needs it enough to
  specify the credential handling.
- **Detecting a portal *through* an established tunnel**, i.e. a portal
  that appears when the aircraft changes coverage. The keepalive covers the
  observable part; distinguishing "portal" from "no network" when every
  socket fails is the profiler's job, not this document's.
