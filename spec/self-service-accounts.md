# ARC — Self-Service Accounts: Invites and Devices

**Status:** draft design, revision 3, feeds spec 0.3. Companion to the
ARC/1 handoff (`ARC-v1-Protocol-and-Implementation-Handoff.md`); section
references (§N) point there. Nothing here is implemented yet.

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
step registers a token it generated for that device, bound to the
device's Noise static key. Enrollment therefore takes exactly the path,
carriers and camouflage the tunnel will, and an enrollment that fails is
logged by the relay like any other attempt.

An enrolled device can ask the relay for an invite to its own account,
and redeem it on a new device. The operator is involved only in creating
the account and in incident recovery.

**Invariant:** nothing sent before the Noise handshake completes can
redeem an invite or authenticate a device. Invite secrets and tokens
travel only inside `DATA` encryption (§9.2).

### 3.1 Records

The accounts file holds three kinds of record, one per line, after a
format header. Accounts and devices have **immutable random IDs** (8
bytes, hex), never derived from names or line numbers, so rewrites and
renames cannot change them.

```text
# arc-accounts 2
account  ID NAME [relay] [max_devices=5] [invites=yes|no] [manage=yes|no]
device   ID ACCOUNT_ID NAME token=SHA256 [key=CLIENT_STATIC] [via=INVITE_ID] [created=T]
invite   ID ACCOUNT_ID HASH expires=T [by=DEVICE_ID req=REQUEST_ID] [redeemed=DEVICE_ID]
revoked  ID until=T [by=DEVICE_ID] [record=...]
```

- **`account`** exists independently of devices, so an account can be
  created, with its policy, before anyone enrolls. Policy (`relay`,
  `max_devices`, `invites`, `manage`) lives once per account.
  `max_devices` is at most 16, so an account's device list fits in one
  packet (§3.8). The gateway accepts
  accounts with no devices.
- **`device`** stores the SHA-256 of its token, not the token: tokens are
  32 random bytes, so a plain hash suffices, and a copy of the file no
  longer authenticates anyone. `key` is the Noise static public key the
  device enrolled with; when present, the token authenticates only a
  handshake from that key (§3.4). `via` records the invite it was
  enrolled with, which gives every device its provenance (§3.7).
- **`invite`** stores the SHA-256 of its secret. `by`/`req` identify an
  invite a device minted, for idempotency (§3.6).
- **`revoked`** keeps a revoked device's ID until its records could no
  longer be restored from a backup (§3.2), so a restore cannot revive it.
  A revocation made by a device (§3.8) also keeps `by=` that device and
  the revoked device's whole record, for 7 days, so the operator can
  undo it.
- Device names are letters, digits, `.`, `_` and `-`, at most 32 bytes,
  unique within the account. The client proposes one (its hostname by
  default); the relay appends `-2`, `-3`, … on a clash.
- **Migration.** A file without the header is today's format
  (`NAME TOKEN [relay]`, or a bare `TOKEN`). The relay reads it, and on
  its first write converts it: one `account` per name, one `device` per
  token (named `legacy-1`, `legacy-2`, …, with no `key`), tokens hashed.
  Legacy devices stay unbound to a key.

### 3.2 One writer: the running relay

Redemption changes the file while the relay runs, so **the running relay
is its only writer** and serializes every mutation:

- The relay holds the records in memory and applies each mutation (add
  account, add device, mint or redeem invite, revoke) as a transaction:
  apply to a copy, write the file (write, `fsync`, rename, `fsync` the
  directory), then publish the new state. An `AUTH_RESULT(success)` for a
  redemption is sent only after its transaction is durable.
- Operator commands (`arc-relay accounts add|invite|revoke|rotate|list`)
  are clients of a control socket the relay listens on
  (`/run/arc-relay/control.sock`, mode 0600, root only). They do not open
  the file. With the relay stopped, the same commands edit the file
  directly under an exclusive `flock` on a separate, never-renamed lock
  file (`accounts.lock`), which the relay also takes at start, so the two
  never write concurrently.
- **Gateway identity across changes.** The gateway keeps one `*Account`
  per account ID for the relay's lifetime and updates it in place under
  its lock; mutations never re-parse the file into new objects. Leases,
  refreshes and isolation keep comparing `*Account`, and they stay
  correct because the pointer for an ID never changes. The token index
  (token hash → device → account) is replaced atomically per
  transaction. Removing an account or device closes its live sessions
  (`CLOSE(AUTH_FAILED)`) and releases their leases.
- **Backups and their failure.** Deployment may back the file up (the
  reference infra copies it to SSM `/arc/tokens`) through a hook the
  relay runs after each transaction, with the transaction's generation
  number. The file carries that generation; a restore never replaces a
  local file of a higher generation.
  - Enrollments and mints do not wait for the backup. If an instance is
    replaced before a backup catches up, a device enrolled since is lost
    from the relay, but its client still holds its token and its invite
    shows unredeemed in the restored file, so the client's retry (§3.4)
    re-redeems it with the same token, if the invite has not expired.
  - **Revocations wait.** A `revoke` or `rotate` reports success only once
    the hook has confirmed a backup at or after its generation; until
    then it reports the revocation as local only and exits nonzero. That
    way, instance replacement cannot restore a revoked device. The
    `revoked` record covers the same case for backups taken earlier.

### 3.3 Invite string

```text
arc1:<base64url, no padding>
```

| Field | Size | Notes |
|---|---|---|
| version | 1 | 1 |
| carriers | 1 | bitmask: 0 UDP, 1 TLS (raw ARC after TLS), 2 front (HTTP/1.1 upgrade first, §16.3) |
| relay address | 4 or 16 | with a family byte before it; the address for every carrier |
| UDP port | 2 | present if bit 0 |
| TLS port | 2 | present if bit 1 |
| front port | 2 | present if bit 2 |
| relay static public key | 32 | the pin (§9.1) |
| invite ID | 8 | random |
| invite secret | 16 | random |
| fingerprint | 1 | `-tls-fingerprint` choice, 0 for none |
| server name | 1 + n | length-prefixed, n ≤ 253: the cover host for TLS, the front's own domain for the front |
| CRC-16 | 2 | catches transcription errors only |

Validation, on both sides: at least one carrier bit; TLS and front are
mutually exclusive (a relay runs one stream carrier); TLS or front
requires a server name. With TLS, the name is a cover host and the
client skips certificate verification, since ARC's Noise handshake
authenticates the relay (§D2) against the pinned key above. With the
front, the client verifies the front's certificate against the system
roots for that name, as `-front` does today.

With UDP, raw TLS and a 16-byte cover host this is about 90 bytes, 120
characters: short enough to paste into any messenger or show as a QR
code.

The invite is as sensitive as its secret until it is redeemed or expires,
and reveals the relay's address for good. That is no worse than today's
folder of files, whose token never expires.

### 3.4 Redemption

`arc-client enroll [-device NAME] <invite>`:

1. Generates the device's static key and a 32-byte random token, and
   writes both, with the relay settings from the invite, to its profile
   directory **before** connecting. An interrupted redemption is retried
   with the same key and token, never new ones.
2. Connects as `arc-client run` would, on every carrier the invite allows,
   and sends `AUTH` with an **enrollment credential** in place of a token:

   ```text
   "\x00ARC-ENROLL1" || invite_id[8] || secret[16] ||
   u8 len || token || u8 len || device_name
   ```

   The leading zero byte cannot begin a token, which is text, so the
   relay tells the two apart without a new frame type.
3. The relay, in its Authorizer, which already receives the client's
   static key (§9.1):
   - looks the invite up by ID and compares the secret's hash in constant
     time; an unknown ID or wrong secret is `AUTH_FAILED`, the same as a
     wrong token, and is logged as an attempt (`handshake rejected:
     unknown invite`);
   - if it was redeemed by a device with **this** token and **this**
     static key: success again (idempotent), **whether or not the invite
     has since expired**; a redeemed invite's record is kept for 7 days
     past its expiry for this;
   - if redeemed by another device: `INVITE_USED`, logged as a warning
     naming the account, since someone else redeemed it first;
   - if expired: `INVITE_EXPIRED`;
   - if the account is at its device cap: `CAPACITY`;
   - otherwise, in one transaction (§3.2), adds the `device` record with
     the token's hash, the static key and `via=` the invite, and marks the
     invite `redeemed=` it; then continues as for a token: the session
     gets its lease and `AUTH_RESULT(success)`.
4. With that `AUTH_RESULT`, and only in answer to an enrollment
   credential, the relay sends `ENROLLED` (§3.6) with the device's ID and
   the name it chose. `AUTH_RESULT` itself stays exactly 28 bytes, so
   clients that authenticate with tokens see no change. The client records
   both, and from then on authenticates with its token.

**Fallback.** If a redemption that may have committed (the client sent
its `AUTH` and lost the session before an answer) is later answered
`INVITE_EXPIRED`, `INVITE_USED` or `AUTH_FAILED`, the client tries once
more authenticating with its persisted token. Success means the device
was enrolled and only the answer was lost.

**Key binding.** A token on a `device` with a `key` authenticates only a
session whose Noise static key is that key: the Authorizer compares
before it leases. A copied token is useless on another machine, and log
lines naming a device mean that device's key. The client's profile keeps
its static key for good; replacing it means enrolling again.

Because redemption is an ordinary `AUTH`, all of §9.2's loss recovery
applies: the client repeats `AUTH` until it hears `AUTH_RESULT`, the relay
answers duplicates idempotently, and a session lost mid-redemption is
retried from scratch with the same key and token, which step 3 accepts.
This matters on the networks ARC targets: a redemption must survive the
same 90% loss the tunnel does.

### 3.5 Front carrier

The front admits a carrier upgrade by a bearer value in an HTTP header,
**before** Noise (§16.3), and a camouflaged TLS client may not verify the
certificate it is talking to. Anything in that header must be assumed
captured by an active man in the middle. So:

- An enrolling client presents
  `front_admission = SHA-256("ARC/1 front admission" || secret)[0:16]`
  as its bearer, never the secret. The relay stores it with the invite.
  It admits one carrier upgrade, nothing more; it cannot redeem the
  invite, since redemption needs the secret, which travels only inside
  Noise.
- Enrolled devices likewise present
  `SHA-256("ARC/1 front admission" || token)[0:16]` rather than the token
  itself, which the relay can check against a stored value per device.
  (Today's front sends the token itself; legacy devices keep doing so
  until they re-enroll.)
- Admissions by an invite's value share a small budget (a few
  concurrent upgrades per invite) and lapse when it is redeemed or
  expires.

The front is not deployed today; this lands with it.

### 3.6 Frames

`AUTH_RESULT` advertises features bit 4, `INVITES`, when the session's
account may mint invites (`invites=yes`, the default).

| Type | Name | Value | Direction |
|---|---|---|---|
| `0x18` | `ENROLLED` | `device_id[8]; u8 len; name` | relay → client, only after an enrollment credential |
| `0x19` | `INVITE_REQUEST` | `request_id[8]` | client → relay, with bit 4 |
| `0x1A` | `INVITE` | `request_id[8]; status:u8; invite_id[8]; secret[16]; expires:u32` | relay → client |

`ENROLLED` is retransmitted until acknowledged; it is sent only to
clients that enrolled, which implement it, so older clients never see a
frame type they would reject.

**Minting, and its idempotency.** The client picks a random `request_id`
and **persists it before sending**, retransmitting `INVITE_REQUEST`
until answered, across sessions and restarts. The relay records the
minted invite with `by=` the device and `req=` the request ID, and
answers any later request with the same (device, request ID) with the
same invite, across sessions and relay restarts, for as long as the
invite record is kept. A lost answer therefore never mints a second
invite or consumes a second slot of the cap.

- The invite is for the session's own account, and carries no access
  beyond the account's policy.
- Status is 0, or `CAPACITY` when the account is at its device cap or has
  2 unredeemed invites outstanding. Device-minted invites expire after 24
  hours; operator invites after 48 by default.
- The relay logs each minted invite, naming account and device.
- The client builds the invite string from the relay settings it already
  has: `arc-client invite` prints it, and the QR code with `-qr`.

### 3.7 Revocation and incident recovery

Every device records the invite it came from (`via`), and every minted
invite the device that minted it (`by`), so the relay knows each device's
**descendants**: devices enrolled through invites it minted, and theirs in
turn. Operator invites have no `by`; their devices are roots.

- `revoke ACCOUNT/DEVICE` revokes one device: its record goes, its live
  sessions close, and its unredeemed invites are cancelled.
- `revoke -descendants ACCOUNT/DEVICE` also revokes every descendant, for
  a device known to be compromised: an attacker holding it could have
  enrolled devices of their own, each with its own token.
- `rotate ACCOUNT` revokes every device and invite of the account, keeps
  the account and its policy, and prints a fresh operator invite, for
  when it is unclear which device was compromised.
- `list` shows each account's devices as a tree by provenance, with each
  device's key fingerprint, creation time and last session.
- `restore ACCOUNT/DEVICE` reinstates a device that **another device**
  revoked, within 7 days, with its original ID, token hash and key (§3.8).
  Operator revocations are final.

A revoked device's sessions close with `CLOSE(REVOKED)`. Its client
reports that the device was revoked, and stops reconnecting, instead of
retrying as for a network failure.

### 3.8 Devices managing devices

A person who loses a laptop should be able to cut it off from their
desktop at once, without reaching the operator. With features bit 5,
`DEVICES` (account policy `manage=yes`, the default), a device may list
its account's devices and revoke them.

| Type | Name | Value | Direction |
|---|---|---|---|
| `0x1B` | `DEVICES_REQUEST` | `request_id[8]` | client → relay, with bit 5 |
| `0x1C` | `DEVICES` | `request_id[8]; status:u8; n:u8;` n × `device_id[8]; parent[8]; created:u32; last_seen:u32; key[8]; u8 len; name` | relay → client |
| `0x1D` | `REVOKE_REQUEST` | `request_id[8]; device_id[8]; flags:u8` (bit 0: descendants) | client → relay, with bit 5 |
| `0x1E` | `REVOKE_RESULT` | `request_id[8]; status:u8` | relay → client |

- `parent` is the device that minted the invite a device came from, zero
  for one enrolled by an operator invite; `key` is the first 8 bytes of
  its static key, for comparing with what the device itself shows. At 16
  devices with 32-byte names, `DEVICES` is about 1,050 bytes.
- `arc-client devices` lists them, marking this device and showing the
  tree. `arc-client revoke NAME [-descendants]` revokes one; a device may
  revoke itself (for instance before being given away).
- Requests are retransmitted until answered. Revoking is idempotent: a
  device already revoked answers status 0. Like an operator revocation,
  the answer waits until the change is durable and the backup has
  confirmed it (§3.2). If the backup hook fails, the revocation still
  takes effect at once and the status is `NOT_BACKED_UP`; the relay keeps
  retrying the backup.

**A thief holds a device too.** Whoever has the stolen laptop can use
these same frames against the owner's other devices. The design does not
try to decide who is the owner; it bounds the damage and keeps recovery
with the operator:

- **Cooling-off.** A device may revoke other devices only once it has
  been enrolled for 24 hours (its own revocation is always allowed). A
  device an attacker enrolls through a stolen device's invites cannot
  purge the account before the owner notices, and descendants revoke
  with their ancestor anyway.
- **Undoable.** Revocations by devices are soft: the operator can
  `restore` the owner's devices for 7 days, then `revoke -descendants`
  the thief's. Operator revocations are not undoable by devices.
- **Logged.** Every revocation by a device is a warning line naming the
  account, the revoking device and the revoked one, so the operator sees
  it without being told.
- **No escalation.** Revoking grants nothing: a device cannot raise the
  device cap, change the account's policy, or touch another account.

In the common case, the owner acts first: they revoke the lost device
(with `-descendants`) from another, and the thief's device is closed out
before it can do anything. If the thief acts first, the owner is locked
out of nothing the operator cannot restore.

## 4. Threats

- **Intercepted invite:** usable once, until it expires; a race is visible
  (`INVITE_USED`, §3.4). Short operator TTLs bound the window.
- **Active MITM before Noise:** sees at most a front admission value
  (§3.5), which admits one upgrade and redeems nothing. Invite secrets and
  tokens cross only inside Noise, to the pinned relay key.
- **Guessing:** 128-bit secrets, checked only after a Noise handshake, so
  guesses cost the attacker the relay's handshake rate limits.
- **Copied token:** useless without the device's static key, for devices
  enrolled under this design (§3.4).
- **Stolen device:** can mint invites until revoked, bounded by the device
  cap and 2 outstanding invites, and every mint is logged. Its
  descendants are revoked with it (§3.7). It can also revoke the owner's
  other devices, once it is 24 hours old; the operator can undo that for
  7 days (§3.8).
- **Stolen accounts file or backup:** holds token and secret hashes only.
- **Restore after revocation:** prevented by revocations waiting for the
  backup, and by `revoked` records (§3.2).
- **The invite leaks the relay's address:** as today's files do.

## 5. Spec changes

- §9.2: `AUTH` carries either a token or an enrollment credential (§3.4
  here). A device's token may be bound to its Noise static key.
- §10.1: frames `0x18 ENROLLED`, `0x19 INVITE_REQUEST`, `0x1A INVITE`,
  `0x1B DEVICES_REQUEST`, `0x1C DEVICES`, `0x1D REVOKE_REQUEST`,
  `0x1E REVOKE_RESULT`; `AUTH_RESULT` feature bits 4 `INVITES` and 5
  `DEVICES`. `AUTH_RESULT` is unchanged.
- §16.3 (front): the admission bearer is a value derived from the
  credential, never the credential.
- Close codes: `11 INVITE_USED`, `12 INVITE_EXPIRED`, `13 REVOKED`,
  `14 NOT_BACKED_UP`.
- wire-registry.md and the wire fixtures, accordingly.

## 6. Implementation plan (one reviewed PR each)

1. **Records and the single writer:** the version-2 file with stable IDs,
   migration from today's format, token hashes, in-place gateway updates
   keeping `*Account` identity, transactions with `fsync`, the control
   socket and offline `flock`, `arc-relay accounts` commands, revocation
   closing live sessions, the backup hook and generations.
2. **Invites and redemption:** invite records, the enrollment credential,
   key binding, `ENROLLED`, `INVITE_USED`/`INVITE_EXPIRED`, the fallback,
   `arc-client enroll` and client profiles (`arc-client run -profile
   DIR`). netns tests: enroll under heavy loss; with the answer to the
   first `AUTH` dropped; with the answer lost past the invite's expiry; a
   second redemption refused; a copied token refused from another key.
3. **Device-minted invites:** `INVITES`, the request frames with
   persisted request IDs, caps, logging, `revoke -descendants` and
   `rotate`.
4. **Devices managing devices:** `DEVICES`, the list and revoke frames,
   cooling-off, soft revocation and `restore`, `CLOSE(REVOKED)`,
   `arc-client devices` and `revoke`. netns tests: revoke a device from
   another while it is connected; a device younger than 24 hours refused;
   restore after a device revocation.
5. **Infra:** the SSM backup hook with revocations waiting for it;
   `add-account.sh` prints an invite; `secrets.sh` stops owning
   `/arc/tokens`; README.
6. **Front admission** by derived values, with the front.

## 7. Open questions

- Notify the operator out of band when a device mints an invite, or is
  the log enough?
- Device cap, invite TTLs and the 7-day retention of redeemed invites.
- Is 24 hours the right cooling-off? It also stops an owner's brand-new
  device from revoking a lost one on its first day; the owner's older
  devices, or the operator, still can.
