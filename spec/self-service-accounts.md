# ARC — Self-Service Accounts: Invites and Devices

**Status:** draft design, feeds spec 0.3. Companion to the ARC/1 handoff
(`ARC-v1-Protocol-and-Implementation-Handoff.md`); section references (§N)
point there. Nothing here is implemented yet.

## 1. Problem

Today an operator adds a person by generating a token, writing it to the
relay's tokens file, restarting the relay (which drops every session), and
sending the person a folder of files: the token, the relay's public key,
its certificate and its address. The person then types a long
`arc-client run` command built from them. Each of their further devices
needs the operator again, or a copy of the same token.

That has three problems:

- **The token travels outside ARC.** Whatever channel carries the folder
  carries a long-lived credential. Signal, the obvious choice, is itself
  blocked in Russia.
- **Every device is the operator's work.** A person cannot add a laptop
  without asking, so in practice devices share one token. The relay's logs
  then cannot tell them apart, and a lost device means rotating the token
  on all of them.
- **Adding anyone restarts the relay.** The relay reads its tokens file
  once, at start.

The goal: the operator approves a person once, with one short string sent
over any channel, and that person adds and names their own devices.

## 2. Alternatives considered

**Sign-in with an identity provider (OAuth), as void-server does.** The
person signs in at a web page and is issued a token. Rejected for ARC:

- The sign-in page and the identity provider must be reachable from the
  person's network. Reaching things from that network is the problem ARC
  exists to solve, and a web page on a Lambda URL or `*.authkit.app` gets
  none of ARC's camouflage. Russia has blocked AWS address ranges before.
- It does not remove the operator's step. A relay's exit address is the
  operator's, so sign-up cannot be open; someone still approves each
  person.
- A sign-in that fails leaves the operator nothing: no attempt reaches the
  relay, so none of its attempt logs record it.

**Copying one token to every device.** Works today: the relay accepts a
token on several sessions at once. Rejected as the model because devices
become indistinguishable and unrevocable one at a time.

**Enrollment over a separate HTTPS endpoint on the relay.** Same
reachability problem as OAuth, and a second service to camouflage.

## 3. Design

An **invite** is a short string holding everything a client needs to
reach the relay, plus a single-use secret. The client redeems it **over
ARC itself**, in the session's ordinary `AUTH` (§9.2), and in the same
step registers a token it generated for that device. Enrollment therefore
takes exactly the path, carriers and camouflage the tunnel will, and an
enrollment that fails is logged by the relay like any other attempt.

An enrolled device can ask the relay for an invite to its own account,
and redeem it on a new device. The operator is involved only in creating
the account.

### 3.1 Accounts and devices

An account keeps its present meaning (gateway isolation, `relay` access).
Each of its tokens now belongs to a named **device**:

```text
alexei TOKEN device=laptop
alexei TOKEN device=desktop
lane   TOKEN relay device=mac
```

- Device names are letters, digits, `.`, `_` and `-`, at most 32 bytes,
  unique within the account. The client proposes one (its hostname, by
  default); the relay appends `-2`, `-3`, … on a clash and returns the
  name it chose.
- Lines without `device=` stay valid (device named by line number), so
  existing files need no migration.
- Each account has a **device cap**, `max_devices=N` on any of its lines,
  default 5. Redemptions past the cap fail (§3.4), so a stolen device
  cannot mint unlimited tokens.
- Relay log lines and diagnostics uploads name the device as well as the
  account.

### 3.2 The relay owns the accounts file

Redemption adds tokens while the relay runs, so the relay becomes the
file's only writer:

- The relay reloads the gateway in place when it adds or removes a token;
  existing sessions are untouched. Adding a person no longer restarts it.
- Every change rewrites the file atomically (write, sync, rename, sync the
  directory) before the relay answers. An `AUTH_RESULT(success)` for a
  redemption is sent only once the new token is durable.
- Operator changes go through the relay binary on the host, not by
  editing the file: `arc-relay accounts add NAME [relay]`,
  `invite NAME [-ttl D]`, `revoke NAME[/DEVICE]`, `list`. Each takes a
  lock on the file and signals the running relay to reload. Revoking a
  device closes its live sessions (`CLOSE(AUTH_FAILED)`).
- Deployment backs the file up wherever it keeps secrets. In the
  reference infra, the host copies it to SSM `/arc/tokens` after each
  change, and `add-account.sh` becomes an SSM command that runs
  `arc-relay accounts add` and `invite` on the host and prints the invite.
  `secrets.sh` stops writing `/arc/tokens` once it exists.

Invites are kept in the same file, so they survive restarts and instance
replacement:

```text
invite ID HASH ACCOUNT EXPIRES [by=DEVICE] [redeemed=TOKEN_HASH]
```

`HASH` is SHA-256 of the invite secret; the secret itself is never stored.
A redeemed invite stays until it expires, for idempotent retries (§3.4),
then is deleted.

### 3.3 Invite string

```text
arc1:<base64url, no padding>
```

| Field | Size | Notes |
|---|---|---|
| version | 1 | 1 |
| relay UDP address | 6 or 18 | IPv4 or IPv6, port |
| TLS port | 2 | 0 if none |
| relay static public key | 32 | the pin (§9.1) |
| invite ID | 8 | random |
| invite secret | 16 | random |
| fingerprint | 1 | `-tls-fingerprint` choice, 0 for none |
| cover host | 1 + n | `-tls-cover`, length-prefixed, n ≤ 253 |
| CRC-16 | 2 | catches transcription errors only |

With a 16-byte cover host this is about 87 bytes, 116 characters: short
enough to paste into any messenger or show as a QR code. No certificate is
carried: with a cover host the client skips certificate verification and
ARC's Noise handshake authenticates the relay (§D2), and the pinned key in
the invite is what the handshake checks. An invite with a TLS port
therefore always has a cover host.

The invite is as sensitive as its secret for its lifetime, and reveals the
relay's address for good. That is no worse than today's folder of files,
whose token never expires.

### 3.4 Redemption

`arc-client enroll [-device NAME] <invite>`:

1. Generates the device's static key and a 32-byte random token, and
   writes both, with the relay settings from the invite, to its profile
   directory **before** connecting. A redemption that is interrupted is
   retried with the same token, never a new one.
2. Connects as `arc-client run` would, on every carrier the invite allows,
   and sends `AUTH` with an **enrollment credential** in place of a token:

   ```text
   "\x00ARC-ENROLL1" || invite_id[8] || secret[16] ||
   u8 len || token || u8 len || device_name
   ```

   The leading zero byte cannot begin a token from a tokens file, which
   are text, so the relay tells the two apart without a new frame type.
3. The relay, in its Authorizer:
   - looks the invite up by ID and compares the secret's hash in constant
     time; an unknown ID or wrong secret is `AUTH_FAILED`, the same as a
     wrong token, and is logged as an attempt (`handshake rejected:
     unknown invite`);
   - if the invite is expired: `INVITE_EXPIRED`;
   - if it was redeemed with **this** token: success again (idempotent);
     if with another: `INVITE_USED`, logged as a warning naming the
     account, since it means someone else redeemed it first;
   - if the account is at its device cap: `CAPACITY`;
   - otherwise adds `ACCOUNT TOKEN device=NAME`, marks the invite
     redeemed, syncs the file, and continues as for a token: the session
     gets its lease and `AUTH_RESULT(success)`.
4. `AUTH_RESULT` gains the device name the relay chose, as an optional
   trailing `u8 len || name` (the value grows from 28 bytes to 29 + n).
   The client records it, and from then on authenticates with its token.

Because redemption is an ordinary `AUTH`, all of §9.2's loss recovery
applies: the client repeats `AUTH` until it hears `AUTH_RESULT`, the relay
answers duplicates idempotently, and a session lost mid-redemption is
retried from scratch with the same token, which step 3 accepts. This
matters on the networks ARC targets: a redemption must survive the same
90% loss the tunnel does.

An interception race is visible rather than silent: whoever redeems first
gets the device, and the other side gets `INVITE_USED`. The operator
revokes the impostor's device and sends a new invite.

### 3.5 Devices inviting devices

A session's `AUTH_RESULT` advertises features bit 4, `INVITES`, when its
account may mint invites (every account, by default; `invites=no` on an
account's line turns it off). With it, the client may send:

| Type | Name | Value | |
|---|---|---|---|
| `0x18` | `INVITE_REQUEST` | `request_id:u32` | client → relay |
| `0x19` | `INVITE` | `request_id:u32; status:u8; invite_id[8]; secret[16]; expires:u32` | relay → client |

- `INVITE_REQUEST` is retransmitted until answered; the relay answers a
  repeated `request_id` with the same invite.
- The relay creates an invite for the session's own account, recorded
  `by=DEVICE`, never for another account, and never with more than the
  account's access (it carries no `relay` option of its own).
- Status is 0, or `CAPACITY` when the account is at its device cap or has
  2 unredeemed invites outstanding. Device-minted invites expire after 24
  hours; operator invites after 48 by default.
- The relay logs each minted invite, naming account and device.
- The client builds the invite string from the relay settings it already
  has: `arc-client invite` prints it, and the QR code with `-qr`.

### 3.6 Front carrier

The front admits a carrier upgrade by its bearer token (§16.3) before any
ARC session exists. An enrolling client has no token yet, so the front
also admits a bearer of the form `invite_id || secret` (hex) for an
unexpired invite, and the session then authenticates with the enrollment
credential as above. The front's admission list is reloaded with the
gateway. The front is not deployed today; this lands with it.

## 4. Threats

- **Intercepted invite:** usable once, until it expires; a race is visible
  (§3.4). Short operator TTLs bound the window.
- **Guessing:** 128-bit secrets, checked only after a Noise handshake, so
  guesses cost the attacker the relay's handshake rate limits.
- **Stolen device:** can mint invites until revoked, bounded by the device
  cap and 2 outstanding invites, and every mint is logged. Revoking the
  device revokes nothing else.
- **Relay compromise:** unchanged; tokens are already in the relay's file.
  Storing token hashes instead is possible (the relay compares hashes) and
  is listed below.
- **The invite leaks the relay's address:** as today's files do.

## 5. Spec changes

- §9.2: `AUTH` carries either a token or an enrollment credential (§3.4
  here); enrollment is otherwise an ordinary authentication.
- §10.1: frames `0x18 INVITE_REQUEST`, `0x19 INVITE`; `AUTH_RESULT`
  feature bit 4 `INVITES` and an optional trailing device name.
- Close codes: `11 INVITE_USED`, `12 INVITE_EXPIRED`.
- wire-registry.md and the wire fixtures, accordingly.

## 6. Implementation plan (one reviewed PR each)

1. **Relay-owned accounts file:** device labels and caps in the parser,
   hot reload without restart, atomic rewrites, `arc-relay accounts`
   subcommands, revocation closing live sessions.
2. **Invites and redemption:** invite store, enrollment credential in the
   gateway Authorizer, `INVITE_USED`/`INVITE_EXPIRED`, `arc-client enroll`
   and client profiles (`arc-client run -profile DIR` in place of the long
   flag list). netns test: enroll under heavy loss, with the reply to the
   first `AUTH` dropped, and a second redemption of the same invite
   refused.
3. **Device-minted invites:** `INVITES` feature, the two frames,
   `arc-client invite`, caps and logging.
4. **Infra:** host syncs the file to SSM; `add-account.sh` prints an
   invite; `secrets.sh` stops owning `/arc/tokens`; README.
5. **Front admission of invites,** with the front.

## 7. Open questions

- Should a device be able to list and revoke its account's other devices
  (a lost laptop revoked from the desktop), or is that the operator's
  job in v1?
- Store token hashes rather than tokens in the accounts file?
- Notify the operator out of band when a device mints an invite, or is
  the log enough?
- Device cap and TTL defaults.
