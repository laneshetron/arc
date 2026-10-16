# ARC — Network Profiling and Carrier Selection

**Status:** draft design, feeds spec 0.3. Companion to the ARC/1 handoff
(`ARC-v1-Protocol-and-Implementation-Handoff.md`); section references (§N)
point there.

## 1. Purpose and scope

ARC's premise is that a session survives on any permitted subset of carriers.
Choosing that subset requires knowing what the network actually does to
traffic: what is blocked, what is throttled, what is inspected, and by which
layer of the path. This document specifies the **network profiler**: the
component that characterizes the environment and produces the profile the
path manager consumes when ranking carriers.

The design driver is the censored national network (Russia's TSPU apparatus
is the running example), with post-auth restricted local networks (hotel,
airplane, corporate egress) as the second case. This document changes nothing
about the scope limits in §2: the profiler *characterizes* networks; carrier
policy decides what to do with the characterization. A camouflage carrier is
only ever used when the user has explicitly opted into a censorship profile.

## 2. Definitions

- **Probe:** a single measurement transaction against a network target,
  with a recorded failure mode.
- **Canary:** a probe target whose expected behavior is known in advance.
  Canaries are third parties (neutral or known-blocked destinations) or
  sacrificial infrastructure operated by the ARC deployment. Canaries are
  never relays (§4, P1).
- **Local layer:** the first administrative domain on the path — Wi-Fi AP,
  captive portal, corporate egress, home router, mobile operator's access
  edge. Keyed by network attachment (SSID/gateway identity).
- **Upstream layer:** everything past the local gateway, treated as one
  black box — access ISP, mobile core, national DPI (TSPU), international
  gateway, and destination-side filtering. Keyed by *observed egress
  identity* (apparent IP/ASN/country), not assumed geography.
- **Profile:** a feature vector (§6.1) describing one layer's observed
  behavior, plus per-feature attribution.
- **Regime:** the classified enforcement posture of a layer (open,
  blocklist, allowlist, shutdown).

## 3. Model: two batteries, one composed vector

```
client ──[local layer]──[ISP / mobile core]──[national DPI / IX]── relay
         local battery    ┌──────── upstream battery ────────┐
         → local profile  →         upstream profile
                    \              /
                     compose()  →  effective profile → carrier ranking
```

The carrier cascade consumes **one effective feature vector**, but the
profiler MUST keep two separately cached profiles and compose them:

- **Local profile.** Cheap battery (§5.1), cached per network attachment,
  refreshed event-driven (interface change, portal state change), expires
  in hours.
- **Upstream profile.** Expensive battery (§5.2–5.4), cached per observed
  egress ASN/country, refreshed on anomaly and slow decay (days).
- **Composition** is most-restrictive-wins per feature, with the
  contributing layer recorded per feature for attribution.

### 3.1 Why not a single opaque vector

1. **Probe amortization.** Probing is observable traffic and takes time.
   Factoring means a hotel→cellular handoff re-runs only the cheap local
   battery and re-composes against a cached upstream profile.
2. **Cache hygiene.** Layer interactions corrupt a merged cache:
   - *False positive:* a pre-auth portal that hijacks all DNS is
     indistinguishable from national DNS poisoning. The local battery runs
     first; upstream results gathered through a portal-contaminated path
     are tagged contaminated and MUST NOT enter the upstream cache.
   - *False negative:* a permissive local layer masks the upstream one
     (corporate egress tunneled to another country, iCloud Private Relay,
     the user's own upstream VPN). Blocked canaries pass; "Russia: open"
     gets cached. Hence the egress-identity rule (§3.2).
3. **Attribution.** New failure on a known-good network ⇒ likely upstream
   regime change; failure only on a new network ⇒ likely local. This
   drives refresh decisions and user messaging.

### 3.2 The egress-identity rule

The upstream cache is keyed by **observed egress identity** (apparent
IP/ASN/country as reported by a canary), never by assumed geography.
Corollaries:

- An egress-identity check is part of every local-battery run: if the
  egress ASN changed without a country change, the upstream cache still
  applies; if the jurisdiction changed, select or build the matching
  upstream profile.
- **Probes MUST be pinned outside the tunnel.** Once ARC is up, canary
  traffic routed through the TUN profiles the relay's egress and concludes
  the regime is permanently benign. Probe sockets follow the same rule as
  carrier sockets (§16: adapters keep sockets outside the TUN routing
  loop).
- Russia-specific: enforcement differs between fixed-line and mobile
  operators, and shutdown/whitelist events have been mobile-specific.
   Wi-Fi↔cellular handoff can change the *upstream* profile; the
  egress-identity check detects this cheaply.

### 3.3 Attribution limits

Past the local gateway, layers are a black box: a killed QUIC handshake is
byte-identical whether the AP or TSPU killed it. v1 accepts
`feature = value (layer: unattributed)` where the carrier choice is
unaffected. Hop-level localization (TTL-limited probes carrying a
blocked-SNI ClientHello) is deferred (§10).

Attribution still changes behavior in two places even when mechanics don't:

1. **Probe risk modulation.** Which canaries are safe to probe depends on
   local context (employer-monitored egress vs. home). The local profile
   gates which probes run, not just which carriers are selected.
2. **Posture.** The user's contractual relationship is with the local
   layer (paid portal, employer); the upstream layer is the one a
   censorship profile addresses. Carrier policy is expressed per layer.

## 4. Design principles

- **P1 — Never burn the relay to learn the environment.** Characterize
  against third-party canaries and sacrificial probe infrastructure. First
  contact with a relay is a real, fully-camouflaged session attempt, never
  a probe (§7).
- **P2 — Every interesting probe gets a paired control.** "Blocked" means
  the interesting probe fails *while* a neutral control in the same
  protocol and time window succeeds. This separates enforcement from link
  flakiness.
- **P3 — Record failure modes, not failures.** RST-after-ClientHello,
  silent timeout, kill-after-ServerHello, throttle-after-N-bytes are
  different enforcement layers with different carrier implications.
  Classification MUST NOT collapse them into "unreachable."
- **P4 — Profiles decay.** Enforcement changes on days-to-weeks and is
  sometimes probabilistic (deliberate throttling, intermittent shutdowns).
  One-shot classification is wrong; every profile carries confidence and
  expiry, and classification uses agreement thresholds with hysteresis
  (§8), mirroring the FEC auto precedent (§11.2).

## 5. Probe battery

Stages run in order; each stage is skippable when a valid cached profile
covers it. All active probes use a parroted TLS fingerprint (the
camouflage TLS profile), never the Go-native `crypto/tls` fingerprint —
the probe client's fingerprint is itself a measured variable (§5.2).

### 5.1 Stage 0 — passive and local (zero or near-zero signature)

- Captive portal detection via the OS connectivity endpoints; an
  unexpected redirect or content mismatch identifies the portal state.
- HTTP probe to a canary: detects transparent proxies (injected
  `Via`/similar headers) and portal redirects.
- Egress identity: apparent IP/ASN/country from a canary (§3.2).
- Local resolver behavior: resolve the canary set through the system
  resolver; compare against DoH answers (bootstrapped from pinned resolver
  IPs) and known-good addresses. Classifies DNS as clean, poisoned,
  sinkholed, or portal-hijacked.
- Output: local profile (portal state, proxy presence, DNS honesty, UDP
  permission), plus the routing decision for the upstream battery.

### 5.2 Stage 1 — TLS reachability matrix (upstream, core)

Each probe records exactly where the connection dies. Canary classes:

| Canary class | Diagnoses |
|---|---|
| Neutral global sites (high-reputation CDN-hosted) | Baseline TCP/443 reachability; RTT/loss reference; controls for all other rows |
| Known-blocked SNI (jurisdiction-specific list) | TCP OK + TLS killed after ClientHello ⇒ SNI blocklist; TCP connect itself fails ⇒ IP block |
| Same CDN edge IP, two SNIs (allowed vs. blocked) | Isolates SNI filtering from IP filtering |
| ECH extension present | ECH intolerance (Russia blocks ECH outright; an ECH ClientHello is a flag, not a cloak, there) |
| Same target, Go fingerprint vs. parroted browser fingerprint | TLS fingerprinting active — and self-validates the parrot before any relay contact |
| Sustained download, 10–30 s | Bulk-flow throttling; per-flow byte caps |

### 5.3 Stage 2 — UDP and protocol matrix

- QUIC handshake to a neutral HTTP/3 endpoint: passes, or dies after N
  bytes/seconds (QUIC throttling), or unreachable (UDP/443 blocked).
- Non-standard TCP ports to a canary: detects port-based allowlisting.
- ICMP echo to canaries (lifeline carrier feasibility, §16.6).
- **Protocol-shape probes:** WireGuard-shaped and ARC-shaped UDP flights
  sent to *sacrificial probe servers* operated for this purpose — never to
  relays. This is a standing infrastructure requirement: the probe pool is
  burnable, the relay pool is not.

### 5.4 Stage 3 — classification

Combine results into the feature vector (§6.1). Every classification
requires agreement (P2, P4): e.g. SNI-blocklist requires ≥3 of 4
known-blocked canaries failing with controls passing, within a bounded
window. Regimes: `open`, `blocklist`, `allowlist`, `shutdown`, each with
confidence.

### 5.5 Stage 4 — carrier pre-flight

Before the selected camouflage carrier touches a relay: verify the
parroted fingerprint passes the fingerprint canary, verify ECH policy,
and check the relay persona canary (§7).

## 6. Profile schema and carrier mapping

### 6.1 Feature vector (per layer, with attribution and confidence)

| Feature | Values |
|---|---|
| `portal_state` | none / unauthenticated / authenticated / expiring |
| `http_proxy` | none / transparent / explicit-required |
| `dns_integrity` | clean / poisoned / sinkholed / portal-hijacked |
| `tcp_443` | open / sni-blocklist / sni+ip-blocklist / allowlist-only |
| `tls_fingerprinting` | none / go-fingerprint-blocked / unknown-parrot-tolerance |
| `ech` | tolerated / intolerant |
| `udp_443` | open / quic-throttled / blocked |
| `udp_general` | open / throttled / blocked |
| `bulk_throttle` | none / after-N-bytes / probabilistic |
| `stability` | stable / oscillating |
| `egress` | ASN, country, observed-via canary |

### 6.2 Regime → carrier profile mapping

| Effective regime | Carrier selection |
|---|---|
| open | Normal ARC behavior: UDP primary, TLS/TCP fallback |
| blocklist, fingerprint-tolerant | Borrowed-handshake TLS profile (REALITY-style) or parroted TLS; UDP with obfuscation profile |
| fingerprint-sensitive | Parrot verified by §5.2 self-check before relay contact |
| QUIC throttled/blocked | Demote UDP carriers; TLS/TCP primary; FEC/split-TCP per link quality (except under a censorship profile: see below) |
| ECH-intolerant | Never send ECH (it flags) |
| allowlist | Only carriers reachable through allowed shared infrastructure, plus DNS/ICMP lifelines (§16.5–16.6); inform user full tunnel is unavailable |
| shutdown | Lifelines keep probing at low rate; session resumes on regime lift (path death ≠ session death, §14.6) |

**Split TCP under a censorship profile.** Split TCP (§11.3) carries the bytes of real inner connections — most often TLS records themselves — inside the carrier. On a TLS-borne camouflage carrier those bytes present a genuine TLS-in-TLS shape to a passive classifier, whatever the ClientHello cover says. Split-TCP streams are therefore scheduled per link quality only in profiles without a censorship posture; under a censorship profile they are never placed on TLS-borne carriers (they remain free on every other carrier). Record-layer padding is optional hardening for the same shape problem, not a prerequisite for this rule.

## 7. Relay admission discipline

- First relay contact is always a real session attempt through the
  selected profile. There is no "relay probe" packet shape.
- The relay's decoy persona (borrowed-handshake profile) doubles as its
  own reachability canary: an ordinary HTTPS GET to the persona checks
  whether the relay's IP/SNI got blocked, without revealing anything.
- Relay domain resolution uses pinned IPs with borrowed SNI when local
  DNS is untrusted.
- Backoff with jitter on failed attempts; no retry storms (correlation
  risk, and matches carrier reconnection policy).

## 8. Reliability mechanics

- **Agreement and hysteresis.** N-of-M canary agreement before
  classifying; hysteresis before switching regimes or carrier profiles
  (FEC auto thresholds at §11.2 are the in-codebase precedent).
- **Carrier error taxonomy.** Carriers MUST report structured failure
  outcomes up to the profiler, not opaque errors. Minimum set:
  `tcp-rst-after-clienthello`, `tcp-timeout-after-clienthello`,
  `tls-killed-after-serverhello`, `reset-at-N-bytes`, `http-redirected`,
  `dns-mismatch`, `quic-initial-dead`, `quic-dead-at-N-bytes`. (The
  stream carrier's current `OnState func(err error)` hook is the
  integration point; the sans-IO design keeps this unit-testable.)
- **Refresh triggers.** Interface change (path manager already fires);
  repeated death of a VALIDATED path (possible regime change — but guard
  the feedback loop where a dying *relay* masquerades as a regime
  change); slow periodic sweep.
- **Caches.** Local: per attachment, hours. Upstream: per egress
  ASN/country, days. Both store confidence and provenance.
- **Canary list maintenance.** Stale canaries silently degrade
  classification (unblocked "blocked" sites, dead neutral hosts). Lists
  are signed, versioned, and updatable over the rendezvous channel;
  clients MUST handle list update failure by widening uncertainty, not by
  trusting stale data harder. Until rendezvous exists (§10), the update
  channel cannot either: v1 clients ship a compiled-in baseline list, take
  an operator config override, and treat the lack of updates as
  uncertainty, never as confirmation.

## 9. Testing: the mini-TSPU harness

`test/netns` already simulates loss, jitter, and bandwidth with netem.
Extend it with an inline namespace implementing each enforcement layer,
then assert the profiler's classification and the client's carrier choice,
deterministically and in CI:

| Harness behavior | Expected classification |
|---|---|
| SNI-based RST injection | `tcp_443 = sni-blocklist` |
| IP blackhole of canary range | `tcp_443 = sni+ip-blocklist` (or IP-block attribution) |
| DNS poison / sinkhole of canary names | `dns_integrity = poisoned / sinkholed` |
| Portal redirect + DNS hijack pre-"auth" | local `portal_state = unauthenticated`; upstream battery withheld |
| UDP/443 drop; QUIC throttled after N bytes | `udp_443 = blocked / quic-throttled` |
| Throughput cliff after N bytes on TLS | `bulk_throttle = after-N-bytes` |
| ECH ClientHello killed | `ech = intolerant` |
| Go-fingerprint TLS killed, parrot passes | `tls_fingerprinting = go-fingerprint-blocked` |
| Everything blocked except an allowlisted pair | `regime = allowlist`; lifelines only |

The harness doubles as the regression suite for every future
fingerprint-hygiene change: a parrot regression or a giveaway ALPN
reappearing flips a classification and fails CI.

## 10. Deferred

- **Hop-level enforcement localization** (TTL-limited blocked-SNI probes)
  for cases where ISP-vs-national attribution changes the response.
- **Allowed-infrastructure carriers** for the allowlist regime (the
  "application-layer lifeline" adapter contract below DNS/ICMP in the D6
  sense); rendezvous-only role, never data plane.
- **Rendezvous and relay rotation** proper: private-relay distribution,
  fronted low-bandwidth broker, migration story. Profiling assumes these
  exist; it does not specify them.
- **Probe budgeting.** Adaptive caps on probe rate/volume per network to
  bound the profiler's own observability; needs measurement first.
- **Per-jurisdiction safety policy** for canary selection (§3.3), with
  user-facing controls.
