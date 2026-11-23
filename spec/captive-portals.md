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
message, the carrier selection, and the resolver-integrity classification,
which must know whether the resolver it found is the portal's or the real
one.

## 3. The state model

```text
                       ┌──────────┐
   start ─────────────►│ unknown  │◄────────── 3 timeouts / TLS intercept
                       └────┬─────┘
                            │ endpoint's success criterion met, DNS honest
                            ▼
   ┌──────────┐      ┌─────────────┐   redirect / wrong body / DNS hijack
   │  none    │◄─────┤  classified ├──────────────────────┐
   └──────────┘      └─────────────┘                      ▼
        ▲                                          ┌────────────────┐
        │  passing check, sticky was none          │ unauthenticated│
        │                                          └───────┬────────┘
        │                                                  │ login poll sees
        │                                                  │ a passing check
        │                                                  ▼
        │                                          ┌────────────────┐
        └──────────────────────────────────────────┤ authenticated  │
              (only if sticky was none; else stays) └───────┬────────┘
                                                           │ keepalive reverts
                                                           ▼
                                                   unauthenticated
```

The state cannot be derived from one probe: `none` and `authenticated` are
**observationally identical** — both show a passing check and honest DNS —
so which one it is depends on whether a portal was seen on this attachment
before (§4.3).

| state | meaning | ARC does |
|---|---|---|
| `none` | no portal has been seen; the network is open | proceed normally |
| `unauthenticated` | a portal exists and the user has not passed it | **do not start carriers**; show the URL and poll for the login |
| `authenticated` | a portal exists and the user has passed it | proceed; run the expiry keepalive (§5) |
| `unknown` | detection could not conclude | proceed **with a warning**; the first carrier failure explains itself later |

`unknown` is the important one and the one my early drafts left out. A
portal that intercepts TLS, or a network that drops the connectivity
endpoints, cannot be classified from outside — and a client that treats "I
cannot tell" as "it is open" blames the relay for the portal's behaviour.

Each state carries the three fields of §4.3 (`sticky`, `portal_host`,
`dns_honest`), and `sticky` is what survives a restart on the same network
attachment.

## 4. Detection (Stage 0)

### 4.1 The probes, and what each establishes

All probes go from a socket **bound to the physical interface**, outside
the TUN — the rule `network-profiling.md` §3.2 states for every probe,
because canary traffic routed through the TUN would measure the relay's
egress instead of the network's.

| probe | target | establishes |
|---|---|---|
| **A. Connectivity endpoint** | a named endpoint with a **known-good response** (§4.2), or `-portal-probe URL` with a required status/body | whether the network redirects, rewrites or intercepts — the primary signal |
| **B. DNS honesty** | a canary name through the **physical link's** resolver (§4.4) | portal DNS hijack, which outlives a passing A |
| **C. Portal presence** | the redirect target, fetched **without** following further redirects | that a portal page is actually served there |
| **D. Reachability of the relay's endpoint** | a TLS handshake to the relay's own `-tls`/`-front` host | whether the portal permits the relay host at all |

A and B are the classification; C separates "portal" from "broken network";
D is what makes a later carrier failure attributable. D is **not** a UDP
check and makes no claim about UDP — see §6.2, which was wrong about this.

**Probe A's success criterion is per endpoint, not "204".** This is the
correction that matters most: `captive.apple.com/hotspot-detect.html`
returns **200 with a 69-byte `Success` page** on a healthy network, and
`connectivitycheck.gstatic.com/generate_204` returns 204 with no body. A
client that expects 204 everywhere classifies every healthy Mac as
`unauthenticated` and never starts. So each endpoint carries its own
expected response:

| endpoint | healthy response |
|---|---|
| `connectivitycheck.gstatic.com/generate_204` | `204`, no body |
| `captive.apple.com/hotspot-detect.html` | `200`, body exactly `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>` |
| `www.msftconnecttest.com/connecttest.txt` | `200`, body exactly `Microsoft Connect Test` |
| `-portal-probe URL` | whatever `-portal-probe-expect STATUS[:SUBSTRING]` says; the flag is **required** with a custom URL, because there is no other way to know |

Comparison is on the **body's exact bytes** for the body-bearing endpoints
(not a substring match, not "contains Success"), because a portal that
injects its own page into a 200 is not passing the check. A `-portal-probe`
whose expectation is omitted is a configuration error and the client says
so rather than guessing.

### 4.2 Detection does not read a 204 body

My earlier revision made "an empty 204 body" the discriminator for `none`,
and claimed portals routinely answer 204 *with* a body. **That is
unimplementable in Go and unsound in principle:**

- **Go discards it.** `net/http` treats a 204 as bodiless, reads zero bytes,
  and logs any trailing octets as an "unsolicited response on idle channel".
  I verified this: a server sending `204` + `Content-Length: 11` +
  `HELLOWORLD` yields `body_bytes_read=0` from `http.Get`. A probe written
  against `net/http` literally cannot see the body being tested for.
- **RFC 9110 forbids it.** A 204 has no body, so anything claiming to be one
  is a protocol violation — evidence of interception, not a portal, and not
  something to build a routine on.
- **It is not needed.** Portals that intercept HTTP produce a **redirect** or
  a **200 with HTML**, not a malformed 204. The discriminator exists only if
  you insist on testing the one response shape that cannot carry it.

So detection classifies on the **endpoint's declared success criterion**
(§4.1), on **redirects**, and on **DNS honesty** — never on a 204 body. A
malformed 204 is recorded in the journal as evidence of a rewriting
middlebox and contributes to `unknown` at most; it never decides the state.

### 4.3 Classification is history-aware, not a lookup

The review's strongest structural point: `none` and `authenticated` are
**observationally identical** — both show a passing check and honest DNS —
so a stateless table can never reach `authenticated`, loses the expiry
monitor, and reports an already-logged-in hotel network as `none`.

The classifier therefore keeps three pieces of state across probes:

| field | what it holds |
|---|---|
| `sticky` | the most restrictive state ever observed on this attachment (`none` < `authenticated` < `unauthenticated` < `unknown`, per §3's ordering of *restrictiveness*, not of severity) |
| `portal_host` | the host of the last portal page seen, so a later passing check can be attributed to *that* portal rather than a generic "open" |
| `dns_honest` | whether the physical resolver answered honestly the last time it was asked |

and the transition rules are:

| observation | `sticky` before | new state |
|---|---|---|
| passing check, honest DNS | `none` | `none` |
| **passing check, honest DNS** | **`unauthenticated`** | **`authenticated`** — the portal was passed |
| passing check, honest DNS | `authenticated` | `authenticated` — stays, and the expiry monitor runs |
| passing check, honest DNS | `unknown` | `authenticated` if `portal_host` is set, else `none` |
| redirect / wrong body | any | `unauthenticated` |
| DNS hijacked | any | `unauthenticated` |
| three timeouts | any | `unknown` (retaining `sticky`) |

**`sticky` persists per network attachment** (§3.1 of the profiler's cache
model) and survives a tunnel restart within the same attachment. It is what
makes "an already-logged-in hotel network" show as `authenticated` with an
expiry monitor, instead of as `none` with none.

**A previously-open network is re-evaluated, not trusted.** `sticky ==
none` does not skip probing: the keepalive of §5 runs on every attachment
while a session is up, so a portal appearing mid-session is caught. What
`none` skips is the *portal URL* search, which has nothing to find.

### 4.4 Probe B must ask the physical link's resolver

Probe B says "the system resolver", and the review is right that this is
wrong once a tunnel is up: ARC's managed DNS replaces the system resolver
with the tunnel's (`tun.dnsState.configure` sets `~.` with
`default-route yes`), so a resolver query made after AUTH measures
*relay-side* DNS and will always look honest.

Probe B therefore resolves through the **physical link's upstream** — not
the system resolver, and not through the TUN. On Linux that is
`resolvectl dns <ifindex>`, which reports the link's configured upstreams
rather than systemd-resolved's `127.0.0.53` stub; on macOS it is the
`State:/Network/Service/*/DNS` entries for the link's service, read with
`scutil --dns`. Loopback and link-local answers are rejected, and the query
goes from a socket bound to the interface. Where no such upstream is discoverable — a stub-only
host, or a DoH-only network — probe B reports `unmeasurable` and the state
falls back to A alone, which is why `dns_honest` is tri-state rather than a
boolean.

**Comparison tolerates CDN variance.** Comparing one answer against one
pinned IP is wrong for any name behind a CDN: the honest answer legitimately
varies by geography and by resolver. `dns_honest` is therefore `hijacked`
only when the answer is *categorically* implausible — a private, loopback,
link-local or reserved address for a public name, or an answer identical to
the portal host's own address — and `clean` otherwise. A different public
address in the same AS is not evidence of anything.

### 4.5 The portal URL is evidence, separate from the state

The review is right that I conflated two things. A portal's *existence* and
a *usable login URL* are independent:

| interception | login URL usable? | state | URL |
|---|---|---|---|
| redirect to a live login host | yes | `unauthenticated` | the redirect target |
| `200` login page served by the connectivity host itself | yes | `unauthenticated` | the probe URL's host |
| redirect to a dead or 404 host | no | **`unauthenticated`** | none — see below |
| TLS interception, no HTTP-level signal | unknown | `unknown` | none |

So a redirect to a dead host is `unauthenticated`, **not** `unknown` as my
earlier revision had it — the interception is proven even though the URL is
useless, and `unknown` would open carriers into a portal. What changes is
the *instruction*: with no usable URL the client says so and names the
endpoint it probed, so the user can find the portal by other means:

```text
arc-client: this network requires a login ARC cannot locate
            open a browser and it will show the portal page
```

**Where the platform offers a standard discovery mechanism, prefer it.**
macOS exposes captive-portal state through `CaptiveNetwork`/the
`CaptivePortal` API and Windows through NCSI; where those are available they
give the URL without probing, and are strictly better evidence than an HTTP
check. They are not a substitute for A and B (a platform that thinks it is
online may still be behind a transparent portal), so they refine the URL,
not the state.

### 4.6 Plaintext HTTP and HTTPS answer different questions

The review's cross-cutting note, and it changes what the check can see.
Both standard endpoints serve the same path over both schemes — I verified
`captive.apple.com/hotspot-detect.html` returns `200` and the same 69-byte
`Success` page over **HTTPS**, with a valid certificate, and
`connectivitycheck.gstatic.com/generate_204` likewise — so the *choice of
scheme* decides which failure modes are observable:

| check | what interception looks like | what it establishes |
|---|---|---|
| **plaintext HTTP** | `3xx` to a login host, or a `200` with the portal's HTML | a portal that redirects or rewrites cleartext |
| **HTTPS, certificate verified** | a **TLS failure**, not an HTTP status — so the classification lands in `unknown` | a portal that intercepts TLS, or a network that breaks TLS |
| **HTTPS to the endpoint with verification skipped** | the portal's `200`, indistinguishable from the real page by status alone | nothing on its own; it is how you *render* a portal, not how you detect one |

**So a passing plaintext check does not prove the tunnel will work**, and a
failing HTTPS check does not prove a portal — a network with a broken
middlebox looks the same. The state model handles this by ordering:

1. **Plaintext A runs first.** It is the only check that yields an HTTP-level
   redirect, which is what produces a login URL (§4.5).
2. **If plaintext A passes, an HTTPS check to the same endpoint runs.** Its
   job is to catch a portal that leaves cleartext alone but intercepts TLS —
   a real airline configuration. A TLS failure there is **not** a portal
   verdict: the state stays at whatever plaintext A justified, and the
   journal records `tls_intercepted=true` so a later carrier failure is
   attributable.
3. **A TLS failure with plaintext A also failing** is `unknown`, because
   there is no HTTP-level evidence either way.

A portal that intercepts *everything* therefore lands in `unknown`, not
`unauthenticated`, and §6.3 opens carriers with a warning — which is
correct: the client cannot prove a portal exists, and refusing to start on
"probably a portal" would strand users on ordinary networks with broken
middleboxes.

**Never disable certificate verification to classify.** Following a TLS
failure with a second, unverified request is how a portal page is fetched
*for display* — and this document does not display pages (§11) — but it must
not feed the classifier, or a real MITM would be indistinguishable from a
portal and the state would be decided by whoever is intercepting.

### 4.7 Portal URLs are redacted in anything persisted

Portal login URLs commonly carry per-device or per-session tokens in the
query string (`?ref=UA123&sid=...`). Showing the exact URL **on screen** is
right — the user needs it. Writing it to the journal is not, because the
journal is exactly what `-share-diagnostics` uploads to the relay operator
(`ARC-v1-…-Handoff.md` §11.4).

**Rule.** The status line shows the URL verbatim. Everything persisted keeps
`scheme://host` and drops the path and query, and drops the query of any
URL it records for any reason. The journal records the *classification
evidence* — status codes, body lengths, the endpoint used, whether a
redirect was followed — which is what a maintainer needs, and none of which
is a credential.

```text
journal:  portal state=unauthenticated endpoint=gstatic status=302
          location_host=portal.example.net body_bytes=0 dns=clean
screen:   captive portal at https://portal.example.net/login?ref=UA123
```

This is a deliberate asymmetry between what the user sees and what the
operator receives, and it is the same rule ARC already applies to traffic
and credentials: the journal never carries secrets.

## 5. The keepalive, in both directions

A portal grant expires — commonly after an hour, sometimes on a traffic
quota, sometimes when the aircraft changes coverage. ARC must distinguish
that from the network dying. And in the other direction, a client sitting
in `unauthenticated` must notice a login it did not perform.

**Both need the same loop**, and my earlier revision ran it only while
`authenticated`, which meant an `unauthenticated` client waited forever for
a login nobody would see. One loop, two roles:

| state | cadence | purpose |
|---|---|---|
| `authenticated` | `-portal-keepalive` (default 60 s) | detect expiry |
| `unauthenticated` | `-portal-poll` (default 10 s), backing off to 60 s after a minute | detect a completed login |
| `none` | `-portal-keepalive` while a session is up, else none | detect a portal appearing mid-session |
| `unknown` | `-portal-keepalive` | resolve the uncertainty |

**Unauthenticated polling is faster and backed off.** Ten seconds is how
long a user expects their login to take effect; a minute is how long they
will tolerate being told to wait. So the loop starts at 10 s and doubles to
60 s after the first minute unchanged, resetting whenever the state changes.
It is still one ordinary GET to the connectivity endpoint — the same
request a browser tab would make — so it stays within C2.

**`-portal-keepalive 0` disables only the `authenticated` and `none`
cadences**, not the `unauthenticated` poll: a client that cannot notice a
login is broken, and an operator who wants no background traffic at all
should use `-portal-check off`, which disables detection entirely and says
so in the journal.

**`-portal-wait` bounds the `unauthenticated` loop, not the process.** With
the default `0` the client waits indefinitely, which is right for an
interactive user watching the message. With a duration it exits after that
long without a login, printing the URL, so a script cannot hang behind a
portal forever. It does not affect any other state.

### 5.1 Transitions the keepalive drives

| observation | from | to | what the user sees |
|---|---|---|---|
| the endpoint's declared success criterion, DNS honest | `authenticated` | `authenticated` | nothing |
| passing check, DNS honest, `sticky` was `unauthenticated` | `unauthenticated` | `authenticated` | "portal passed, connecting" |
| redirect / wrong body | `authenticated` | `unauthenticated` | "portal session expired; visit URL" |
| three consecutive timeouts | any | `unknown` | "network unreachable" |
| passing check, DNS hijacked | `authenticated` | `unauthenticated` | as above |
| passing check, DNS honest | `unknown` | `authenticated` or `none` | nothing, per §4.3 |

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
- It runs the login poll (§5) at `-portal-poll`, so it notices when the
  user finishes.
- It starts the moment the state reaches `authenticated` — no restart.

That last point matters: a user who reads "log in, then reconnect" and
reconnects by hand is doing something the client could have done for them.

### 6.2 `authenticated`

Carriers open normally, with **one gate: the client does not open a UDP
carrier unless something measured that UDP passes.** My earlier revision
claimed probe D established this, and the review is right that it cannot —
D is a TLS handshake, which says nothing about UDP.

There are only two honest sources for that signal, and the client uses them
in this order:

1. **The profiler's `udp_general` / `udp_443`** from
   `network-profiling.md` §6.1, where the profiler has run. That is the
   designed source and it is unimplemented today.
2. **The client's own attempt history** on this attachment: a UDP carrier
   that completed a handshake here within the last hour is evidence; one
   that failed is evidence the other way.

**With neither, the client opens UDP and lets it fail.** That is a
deliberate reversal of my earlier revision, which gated unconditionally on
a probe that measured nothing. The cost of trying is one handshake on a
path that will not validate, which the session already handles; the cost of
a wrong gate is a client that refuses to use UDP on a network where it
works, and has no way to learn otherwise. `-no-udp` remains the operator's
explicit choice.

A portal does not usually block UDP outright at layer 4 — it blocks it by
not NATing it, which looks identical from the client. That is precisely why
the signal has to come from measurement rather than from the portal's
classification, and why this belongs to the profiler's evidence rather than
to this document's state model.

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

Both are also journal lines with the evidence — but **not the URL**, which
is redacted (§4.7). The screen and the journal deliberately differ: the user
needs the link, the operator needs the classification.
`sni`, `resolver`), so a report from a user contains what a maintainer
needs. `-portal-message off` suppresses the status line for scripted use,
but never suppresses the journal.

## 8. Configuration

| flag | default | meaning |
|---|---|---|
| `-portal-check` | `auto` | `auto`, `off`, or `force` (run detection even when `-full-tunnel` is not set) |
| `-portal-probe URL` | the OS endpoint | the connectivity-check URL, for networks that block the standard ones. **Requires** `-portal-probe-expect` |
| `-portal-probe-expect STATUS[:SUBSTRING]` | — | the success criterion for a custom probe, e.g. `204` or `200:Microsoft Connect Test`. Mandatory with `-portal-probe`, since nothing else knows what a healthy answer looks like |
| `-portal-keepalive` | `60s` | cadence while `authenticated`, `none` and `unknown`; `0` disables those, never the login poll |
| `-portal-poll` | `10s` | cadence while `unauthenticated`, backing off to 60 s; this is how a completed login is noticed |
| `-portal-wait` | `0` | `0` waits indefinitely for the login; a duration exits after it, printing the URL |

**`-portal-check off` exists** because a network that blocks the
connectivity endpoints would otherwise be classified `unknown` on every
start, and an operator who knows their network should not pay for a probe
they do not need. It is not the default because the failure it prevents is
silent.

**`-portal-probe` without `-portal-probe-expect` is refused at startup**,
not defaulted to 204. A custom URL with a guessed success criterion is the
exact bug the review found in the built-in endpoints, and guessing again
would repeat it.

## 9. Interaction with the rest of ARC

- **Any adapter that trusts a resolver.** Under a portal the system
  resolver may be the portal's own, and the `dns_integrity` classification
  that decides whether to trust it (`network-profiling.md` §5.1, §6.1) is
  exactly probe B of this document. They must read the same probe, not run
  two.
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
| Open network, gstatic endpoint: `204`, no body, DNS honest | `none`, carriers open immediately |
| **Open network, Apple endpoint: `200` + `Success` page** | `none` — a 204-only check would wrongly say `unauthenticated` and never start |
| **Apple endpoint returning the Success page over HTTPS** | `none`; the HTTPS check confirms rather than reclassifies (§4.6) |
| Portal: `3xx` to a login host | `unauthenticated`, **no carrier opened**, URL in the message |
| Portal: `200` with the portal's HTML where the Success page was expected | `unauthenticated` — the common airline case |
| Portal: `204` with trailing octets after the header | recorded as evidence of rewriting; state is `unknown` at most, never decided by it (§4.2) |
| Portal: passing check but DNS hijacked | `unauthenticated`, because the DNS lie outranks the check |
| **Portal: redirect to a dead host** | `unauthenticated` still — the interception is proven — but no URL, and the message tells the user to open a browser (§4.5) |
| **Portal: `200` login page served by the connectivity host itself** | `unauthenticated` with the probe host as the URL — no redirect needed |
| **Already-logged-in hotel network, cold start** | `authenticated`, and the expiry monitor runs — not `none` (§4.3) |
| **Login completed while `unauthenticated`** | the 10 s login poll notices it, state reaches `authenticated`, carriers open, no restart |
| Grant expires mid-session | state returns to `unauthenticated`, the message names the URL, **and the live session is not killed** |
| Three keepalive timeouts | `unknown`, reported as unreachable rather than as expiry |
| TLS intercepted, plaintext check also failing | `unknown`; carriers open and the journal records `tls_intercepted=true` |
| **TLS intercepted, plaintext check passing** | state stays where plaintext put it; the journal records the interception and a later carrier failure is attributable (§4.6) |
| **Portal DNS hijack behind a stub-only resolver** | probe B reports `unmeasurable`, state falls back to probe A alone, and the journal says why (§4.4) |
| **CDN canary answering from a different public IP** | DNS still `clean` — variance is not hijack (§4.4) |
| **UDP untested: no profiler, no history** | the client opens UDP anyway and lets it fail; no gate on absent evidence (§6.2) |
| **`-portal-check off`** | no probes sent; state is `none` by configuration, and the journal says so |
| **`-portal-probe` without `-portal-probe-expect`** | refused at startup, not defaulted |
| **`-portal-keepalive 0`** | `authenticated` re-checks stop; the login poll continues, because a client that cannot notice a login is broken (§5) |
| `-portal-wait 30s` with no login | the client exits with the URL rather than waiting forever |
| **Journal after any portal event** | contains `scheme://host` at most — never a path or query, so no session token reaches `-share-diagnostics` (§4.7) |

The rows that fail a naive implementation are the ones the review found:
the Apple endpoint alone would break every Mac, `unknown` versus
`unauthenticated` is a distinction a status-code check cannot make, an
already-logged-in portal is invisible to a stateless table, and the
redaction row is invisible until someone reads an uploaded journal.

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
