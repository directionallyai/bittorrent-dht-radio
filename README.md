# bittorrent-dht-radio

`radio` is a small cross-platform CLI that lets a few people (a **circle**) broadcast short,
**SSH-signed** status messages over the public **BitTorrent mainline DHT** and listen to each other,
with no server, account or open port.

* Each member publishes to their own [BEP 44](https://www.bittorrent.org/beps/bep_0044.html)
  mutable item, signed with a dedicated Ed25519 *DHT publisher key*.
* Inside the item, the message carries an OpenSSH **SSHSIG** (`ssh-keygen -Y sign` format) made with
  the member's *SSH key*, in the namespace `bittorrent-dht-radio@directionally.com`.
* Listeners verify everything against a **locally pinned** circle (name → SSH key → DHT key). Nothing
  learned from the DHT is trusted.

v1 scope: **small announcements**: public broadcasts, plus short [direct messages](#direct-messages)
encrypted to one member's SSH key. No GUI, chat history or large payloads
(see [Threat model and limits](#threat-model-and-limits)).

* [5-minute two-person setup](#5-minute-two-person-setup)
* [Offline trust bootstrap](#offline-trust-bootstrap)
* [Commands](#commands) · [Running unattended](#running-unattended) · [Exit codes](#exit-codes)
* [Protocol](#protocol) · [Config directory](#config-directory) · [SSH keys](#ssh-keys-agents-and-fido2)
* [Build, test, release](#build-test-release) · [Threat model and limits](#threat-model-and-limits)

## 5-minute two-person setup

Alice and Bob each do steps 1–3 on their own machine; then they swap cards (step 4).

**1. Get `radio`.** Download the binary for your OS from the GitHub release (and check it against
`SHA256SUMS`), or build it: `cargo install --path .` (see [Build](#build-test-release)).

**2. Make a dedicated SSH key** (any existing Ed25519 key works too, but a dedicated one is tidy):

```sh
# Linux / macOS Terminal
ssh-keygen -t ed25519 -N "" -C "alice radio" -f ~/.ssh/id_radio
```
```powershell
# Windows PowerShell (OpenSSH client is built into Windows 10+)
ssh-keygen -t ed25519 -N '""' -C "alice radio" -f "$env:USERPROFILE\.ssh\id_radio"
```

**3. Initialise.** You choose the SSH key explicitly; `radio` never scans `~/.ssh`. This creates the
config dir and a *separate* DHT publisher key, and prints your shareable **circle card**:

```sh
radio init --name alice --ssh-key ~/.ssh/id_radio --card-out alice.card
```
```powershell
radio init --name alice --ssh-key "$env:USERPROFILE\.ssh\id_radio" --card-out alice.card
```

(`--card-out` writes the card as UTF-8. Without it the card is printed to stdout and the chatter to
stderr; in Windows PowerShell 5.1 prefer `--card-out`, because `>` writes UTF-16, which `radio circle
add` also tolerates. `radio card [--out FILE]` shows it again at any time. To sign through an
ssh-agent instead of a key file use `--ssh-agent ~/.ssh/id_radio.pub`, see
[SSH keys](#ssh-keys-agents-and-fido2).)

**4. Swap cards and pin each other.** Send `alice.card` to Bob and get `bob.card` back (chat, email,
USB stick: the card is public data, but see the next section for *verifying* it). Then:

```sh
radio circle add --card bob.card        # shows fingerprints, asks you to confirm
```

**5. Broadcast and listen.**

```sh
# Alice
radio publish --message "Alice is online"

# Bob (one-shot: prints new verified messages; exit code 0 = got one, 10 = nothing new)
radio listen
radio listen --follow            # keep polling every 60s
radio listen --json              # JSON lines for scripts

# Alice, to Bob only (encrypted to his SSH key; Alice's broadcast is unchanged)
radio publish --publish-to bob --message "the spare key is under the mat"
```

Check on things any time with `radio status` (saved state, no network) and `radio doctor` (live
checks: bootstrap, routing table, your own record, every member).

No internet handy? `radio selftest` runs a two-client publish/listen on a private loopback DHT.

## Offline trust bootstrap

The security of the whole circle rests on you pinning the *right* keys. Do this out of band, once per
member:

1. **Exchange cards** (`radio card` / `radio circle export [NAME] [--out FILE]`). A card holds the name, the SSH
   public key, the DHT publisher public key and the optional salt.
2. **Compare fingerprints over a different channel** than the one that carried the card: in person, or
   a voice/video call. `radio circle add --card FILE` prints, for the card in front of you:
   * `SSH fingerprint: SHA256:…` — the same string `ssh-keygen -lf id_radio.pub` shows on the owner's
     machine;
   * `DHT fingerprint: SHA256:…` and the full `DHT key` (64 hex characters);
   * a short `card code` (e.g. `7a83-0cba-18e1-9910-175a-96ac`) covering name, both keys and salt:
     reading this one aloud is enough to confirm the whole card.
3. **Only then confirm** the pin (`--yes` skips the prompt for scripts; use it only after step 2).
4. **Pinning is final until you remove it.** `radio circle add` refuses to replace a name with
   different keys; use `radio circle remove NAME` first (after re-verifying) if someone rotates a key.
   Their accepted-seq history is kept so a removed-and-re-added feed cannot be rolled back.

Without a card file you can pin explicit keys:

```sh
radio circle add --name bob --ssh-key-file bob_id.pub --dht-key <64 hex> [--salt NAME] --yes
```

`radio circle list` shows every pinned member with the same fingerprints for later re-checks.

## Commands

| Command | What it does |
| --- | --- |
| `radio init --name N (--ssh-key FILE \| --ssh-agent ID) [--salt S] [--bootstrap IP:PORT]…` | Create the config dir, a dedicated BEP 44 Ed25519 publisher key, and `config.toml`; print your card. |
| `radio card [--out FILE]` | Print your circle card again. |
| `radio circle add\|list\|remove\|export` | Manage the pinned circle; import/export card files. |
| `radio publish --message "…"` / `--file f.txt` (`-` = stdin) | Sign and put a message now. `--ttl 24h` sets how long it stays valid; `--no-prev` omits the previous-message hash. |
| `radio publish --publish-to NAME --message "…"` (alias `--to`) | Send a [direct message](#direct-messages) to one pinned member, encrypted to their SSH key. |
| `radio republish` | Re-put the **last already-signed item unchanged** (see below). |
| `radio listen [--follow] [--interval 60s] [--jitter 10%] [--json]` | Poll every member's feed (and their direct slot for you); print verified new messages and state changes. |
| `radio run --status-file F --publish-every 15m --listen-every 60s [--jitter 10%] [--republish-every 1h]` | Publish and listen at the same time on independent intervals, unattended. |
| `radio status` | Saved state, no network: last put/get results, republish times, per-member staleness. |
| `radio doctor` | Live diagnostics: signer, bootstrap resolution, routing table, own record, members. |
| `radio selftest` | Two-client loopback publish/listen check; needs no internet or configuration. |

Global options: `--config-dir DIR` (or `RADIO_CONFIG_DIR`), `--json`.

### Republish is not a heartbeat

* `radio publish` (and each `run` cycle) **re-signs**: new `seq`, new issued-at, new expiry. A
  listener learns *the sender was alive at that time*.
* `radio republish` (and `run --republish-every`) re-puts the **same signed bytes**. It keeps the DHT
  record from aging out (storage nodes forget items after roughly two hours) but it does **not**
  advance the signed timestamp and it does **not** prove the sender is online. Once the signed
  expiry passes, listeners reject the item as expired, and `radio republish` refuses to re-send an
  expired item (exit 5).

### What listeners see

For every member, every poll ends in one of these states (JSON field `status`):

| status | meaning | `listen` exit |
| --- | --- | --- |
| `ok` | a verified, unexpired record is on the DHT (new ones are printed once) | 0 if new, else 10 |
| `not-found` | the DHT answered but holds no record: publisher offline, or the record aged out | 10 + warning |
| `expired` | the newest record's signed lifetime has passed: publisher likely offline | 10 + warning |
| `unreachable` | no DHT node answered: **freshness could not be verified** | 11 |
| `rejected` | a record was found but failed verification (reason in the `rejected` event) | 12 |

"No new message" (10) and "I could not check" (11) are deliberately different. Warnings include
how long ago a message from that member was last verified. In `--follow`/`run` mode state *changes*
are announced once (and recoveries too), and nothing is repeated after a restart.

## Running unattended

```sh
echo "alice: backups OK" > ~/status.txt
radio run --status-file ~/status.txt --publish-every 15m --listen-every 60s --jitter 10% --republish-every 1h
```

* Publishing and listening run on independent threads and timers. `--jitter` adds a random extra
  delay (a duration like `30s` or a percentage like `10%`) to every interval.
* The status file is re-read each cycle, so any script can update it. Each heartbeat is re-signed;
  `--ttl` defaults to `max(3 × publish-every, 1h)`.
* DHT outages do not stop it: failures are reported as `error`/status events, and the client
  re-bootstraps. Ctrl-C (or SIGTERM from a service manager) stops cleanly.
* Unattended signing needs a key that signs without interaction: an unencrypted key file, an
  encrypted file with `RADIO_SSH_KEY_PASSPHRASE` set, or an ssh-agent that has the key loaded.

Typical service setups: a systemd *user* unit (`ExecStart=%h/bin/radio run --status-file …`), a
launchd agent, or a Windows Scheduled Task at logon (`radio.exe run …`). Installation needs no
privileges: it is one binary and a per-user config directory.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK (for `listen`: at least one new verified message) |
| 1 | Unexpected error |
| 2 | Command-line usage error |
| 3 | Not initialised, or configuration/circle problem |
| 4 | Message invalid: empty, control characters, or too large (bencoded `v` > 1000 bytes) |
| 5 | `republish`: nothing to republish, or the stored signed item has expired |
| 6 | Signing failed: SSH key unreadable, ssh-agent unavailable/identity missing, FIDO2 key |
| 10 | `listen`: no new message (everything reachable and verified) |
| 11 | DHT unavailable (bootstrap failed, UDP timeouts): freshness could not be verified / put failed |
| 12 | Verification failure (bad signature, tampered payload, signer mismatch, rollback, clock skew…) |

`listen` precedence when several members differ: **12** (any verification failure) > **0** (any new
message) > **11** (some member unverifiable) > **10**. `status`, `doctor` and `run` return 0 unless
something is wrong with the setup (`doctor` uses 3, 6, 11 or 12 for the first hard problem).

## Protocol

**BEP 44 item.** Every member has their *own* feed key (never a shared circle key): the dedicated
Ed25519 publisher key in `publisher.key`, plus an optional salt. `seq` is monotonic: the next `seq` is
`max(last + 1, current Unix time)`, so it stays increasing even if local state is lost. The put uses
BEP 44 CAS against the last known `seq` and re-reads/retries on a conflict. The BEP 44 key and the SSH
key are different keys and are never conflated.

**Size limit.** BEP 44 caps the *bencoded* `v` at 1000 bytes. `v` is a bencoded byte string, so its
size is `len(raw) + digits(len(raw)) + 1`, i.e. at most 996 raw bytes. `radio` checks this **before
signing** and fails with exit 4 and a clear message (exactly 1000 is accepted, 1001 is rejected; both
boundaries are tested). The SSH signature takes about 203 bytes and the header about 70, leaving
roughly 700 bytes for the message text.

**`v` layout.** `u16 payload_len ‖ payload ‖ SSHSIG blob` (the binary SSHSIG, i.e. the PEM body without
the armor), where the payload is canonical UTF-8 text, and decoding rejects any non-canonical form:

```text
radio/1
from: alice
seq: 1761142000
iat: 1761142000
exp: 1761145600
prev: 0123456789abcdef        (optional: first 8 bytes of the previous payload's SHA-256)

free-form message text
```

**SSHSIG.** Namespace `bittorrent-dht-radio@directionally.com`, hash SHA-512, Ed25519 keys. The
signature interoperates with OpenSSH, see [Verify a signature with ssh-keygen](#verify-a-signature-with-ssh-keygen).

**Verification** uses only local state. A fetched item is accepted only if all of these hold, and each
failure has its own diagnostic (the `reason` of the `rejected` event):

| reason | check |
| --- | --- |
| `unknown-publisher` | the DHT key is a pinned member's key |
| `salt-mismatch` | the item's salt is the pinned salt |
| `malformed-value` / `malformed-payload` | framing and canonical payload parse |
| `bad-signature` | the SSHSIG is parseable, Ed25519, supported hash |
| `wrong-namespace` | namespace is exactly ours |
| `signer-mismatch` | the SSHSIG was made by *the pinned SSH key of that feed's owner* (feed-owner ↔ SSH-signer) |
| `tampered-payload` | the signature actually covers this payload |
| `sender-mismatch` / `seq-mismatch` | payload `from` is the pinned name; payload `seq` equals the BEP 44 `seq` |
| `recipient-mismatch` | a broadcast has no `to:`; a [direct message](#direct-messages) is addressed to your SSH fingerprint |
| `decrypt-failed` | a direct message decrypts with your SSH key (checked after the signature) |
| `clock-skew` | `iat` is not further in the future than `clock_skew_secs` (default 120 s) |
| `replay-rollback` / `seq-reuse` | `seq` is not below the highest accepted; the same `seq` never carries different content |
| `expired` | `exp` has not passed (reported as a stale warning, not a failure) |

**Persistence.** `state.json` keeps, per signer, the highest accepted `seq`, the last verified message
and its hash, member status, and your last signed item. A restart therefore prints no duplicates and
cannot be rolled back.

**Bootstrap.** `bootstrap = ["IP:port", …]` in `config.toml` (or `--bootstrap` at `init`). Literal
`IP:port` needs no DNS; `host:port` is optional and resolved with a timeout. Unresolvable hosts are
reported and skipped while the IP entries keep working. If the list is empty the mainline defaults
(`router.bittorrent.com`, `dht.transmissionbt.com`, `dht.libtorrent.org`, `relay.pkarr.org`) are
used. The routing table is saved to `cache/routing.txt` and reused as extra bootstrap peers on the
next run; bootstrap retries with exponential backoff.

### Direct messages

`radio publish --publish-to bob` sends one message to one member whose card you have pinned.
Bob receives it with his normal `radio listen` / `radio run`, as a `direct-message` event (human
output: `… alice -> you: text (direct, …)`). Nobody else can read it.

* **Its own slot.** The item is put under the sender's usual DHT key, but with the salt
  `dm1-` + the first 16 bytes (hex) of `SHA-256("radio-direct-slot/1\n" ‖ sender salt ‖ "\n" ‖
  recipient SSH public key)`. So it never replaces the broadcast, and each recipient has a slot of
  their own. Listeners check, for every pinned member, that member's direct slot for their own key.
* **Signed exactly like a broadcast.** The payload carries an extra header line
  `to: SHA256:<recipient SSH fingerprint>` between `from:` and `seq:`. All the checks in the table
  above apply, plus `recipient-mismatch` (a `to:` that is not you, or a `to:` in a broadcast slot)
  and `decrypt-failed` (signed by the pinned key, but it does not decrypt for you).
* **Encrypted to the SSH key.** The body after the header is the raw bytes
  `E ‖ ChaCha20-Poly1305(text)`, not text (the only payloads that are not all UTF-8). The
  recipient's Ed25519 SSH key is converted to X25519 (as `age` does for `ssh-ed25519`
  recipients), `E` is a fresh ephemeral X25519 key, and key and nonce come from HKDF-SHA256 over
  the shared secret (salt `E ‖ recipient`, info `bittorrent-dht-radio direct/1`). The associated
  data is the signed header (`from`, `to`, `seq`, `iat`, `exp`), so nobody can lift the ciphertext
  into an item signed by someone else.
* **Size.** Encryption adds 48 bytes and the `to:` line about 55, leaving about 610 bytes for the
  text (exit 4 with the exact limit, checked before signing).
* **Decrypting needs the private key file.** ssh-agent can sign but cannot do the X25519 step. With
  `--ssh-agent` you can still send direct messages, but received ones are reported as
  `error: direct message from alice: … cannot be decrypted` and stay pending. An encrypted key file
  is unlocked (passphrase from `RADIO_SSH_KEY_PASSPHRASE` or a prompt) only when a new direct
  message arrives.
* Only the latest direct message per sender→recipient pair is on the DHT. It ages out like any item
  (about 2 hours) and is **not** re-put by `republish`. Direct messages are not `prev`-chained.
  `state.json` keeps the sender's copy of what was sent, but the receiver does not store decrypted
  text.

**Safety of message content.** Messages are data: never passed to a shell, never interpreted. When
printed to a terminal, control characters and bidi overrides are escaped.

## Config directory

Everything lives in one per-user directory (no privileges needed), chosen by `--config-dir`, then
`RADIO_CONFIG_DIR`, then the OS default:

| OS | Default |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/radio` (usually `~/.config/radio`) |
| macOS | `~/Library/Application Support/com.directionally.radio` |
| Windows | `%APPDATA%\directionally\radio\config` |

| File | Content |
| --- | --- |
| `config.toml` | name, SSH signer choice, optional salt, bootstrap/timeouts, `message_ttl`, `clock_skew_secs` |
| `circle.toml` | the pinned members (hand-readable; edit with `radio circle …`) |
| `publisher.key` | the BEP 44 Ed25519 seed (hex). Owner-only (`0600`) on Unix; on Windows it relies on your profile directory's ACL. **Keep it private**; whoever has it can publish *to the DHT* under your feed key (they still cannot forge your SSH signature). |
| `state.json`, `state.lock` | accepted seqs, last messages, diagnostics, your last signed item |
| `cache/routing.txt` | DHT nodes for the next bootstrap |

`config.toml` DHT options (all optional): `bootstrap`, `include_default_bootstrap`, `bind_address`,
`port`, `request_timeout_ms`, `bootstrap_attempts`, `bootstrap_backoff_ms`, `resolve_timeout_ms`.

## SSH keys, agents and FIDO2

* **Key file**: `--ssh-key FILE` (OpenSSH private key, Ed25519). An encrypted key needs its passphrase:
  `RADIO_SSH_KEY_PASSPHRASE` for unattended use, or a prompt when a terminal is attached.
* **ssh-agent**: `--ssh-agent IDENTITY --agent-socket PATH` where `IDENTITY` is a `.pub` file, an
  `SHA256:…` fingerprint (from `ssh-add -l`) or a public key line. It uses `$SSH_AUTH_SOCK` on
  Linux/macOS and the `\\.\pipe\openssh-ssh-agent` named pipe on Windows. The chosen identity must be
  loaded in the agent at `init`, and `radio` signs a test payload then to prove it works.
* **FIDO2 / `sk-` keys need a physical touch for every signature**, so they **cannot do unattended
  fresh signing** (a heartbeat every 15 minutes would wait for your finger). `radio` detects `sk-ssh-ed25519`
  and `sk-ecdsa-…` identities and refuses them (exit 6) with an explanation; agent signing has a
  20-second timeout so a key waiting for a touch or confirmation cannot hang `run` forever. Use a
  normal Ed25519 key (possibly a dedicated one loaded into an agent) for the radio.
* Only Ed25519 SSH keys are supported in v1.

### Verify a signature with ssh-keygen

The SSHSIG inside every item is standard. To check one by hand: take a member's public key, build an
allowed-signers file, and rebuild the armored signature from the item (the automated version of this
is `tests/ssh_interop.rs`, which signs with `radio` and verifies with `ssh-keygen -Y verify`, and the
other way round):

```sh
echo 'alice namespaces="bittorrent-dht-radio@directionally.com" ssh-ed25519 AAAA…' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I alice -n bittorrent-dht-radio@directionally.com -s payload.sig < payload.txt
# Good "bittorrent-dht-radio@directionally.com" signature for alice with ED25519 key SHA256:…
```

and, the other direction, `ssh-keygen -Y sign -n bittorrent-dht-radio@directionally.com -f id_radio payload.txt`
produces a `payload.txt.sig` that `radio` accepts when it is embedded as described above.

## Build, test, release

Requires a stable Rust toolchain (1.85+). Pure-Rust dependencies only, so cross-compiling needs no C
toolchain.

```sh
cargo build --release            # target/release/radio (radio.exe on Windows)
cargo install --path .           # installs into ~/.cargo/bin, no privileges needed
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
cargo test                       # no internet needed
```

Tests include unit tests (canonical encoding, SSHSIG, size limits, every rejection case), integration
tests with **two independent clients** (separate config dirs, separate DHT nodes) on a **private
loopback DHT** built from in-process `mainline` nodes, restart persistence, the failure paths (DHT
unreachable, UDP timeout, unresolvable DNS bootstrap with an IP fallback, clock skew, publisher
offline, expired record), `radio run` with two concurrent processes, and `ssh-keygen`/`ssh-agent`
interoperability (these need the OpenSSH tools; CI sets `RADIO_REQUIRE_SSH_KEYGEN=1` so a missing
tool fails instead of skipping). One extra test talks to the real public DHT and is `#[ignore]`d:

```sh
cargo test --test public_dht -- --ignored --nocapture
```

**CI** (`.github/workflows/ci.yml`) runs fmt, clippy and tests on Ubuntu, macOS and Windows.
**Releases** (`.github/workflows/release.yml`): pushing a tag `vX.Y.Z` (matching `Cargo.toml`) builds
`windows-amd64`, `macos-arm64`, `macos-amd64`, `linux-amd64` and `linux-arm64` (static musl),
smoke-tests every binary on its own OS (`--help`, `--version`, and `radio selftest`, a two-client
loopback publish/listen; the arm64 binary runs under qemu), and attaches the archives plus `SHA256SUMS`
to a GitHub release.

## Threat model and limits

`radio` is for small, **public** announcements among people who know each other. Know what it does
and does not give you:

* **Broadcasts are public.** Anyone who knows (or guesses) your DHT public key and salt can read your
  broadcasts; do not publish secrets there. [Direct messages](#direct-messages) are encrypted, but
  *that* one was sent, when, and its size are visible. Anyone who knows both the sender's DHT key
  and the recipient's SSH public key can tell that the slot belongs to that pair. There is no
  forward secrecy: whoever later gets the recipient's SSH private key can decrypt old direct
  messages they recorded.
* **IP metadata is exposed.** Publishing and polling are visible to the DHT nodes you talk to (and
  anyone watching them): your IP address, timing and which keys you look up. Your circle's membership
  can be inferred by someone who watches who polls your key. Use a VPN/Tor-style network layer if that
  matters.
* **Authenticity, not secrecy.** The SSH signature proves a message came from the holder of the pinned
  SSH key; the pinned-key model means a compromised *DHT publisher key* alone cannot forge messages,
  but it can replay old signed items until they expire, or publish garbage that is rejected.
* **No delivery guarantee.** DHT storage is best-effort and nodes forget items after roughly two
  hours. A message can be missed if you poll less often than that, or if too few nodes store it.
  Polling is not push: latency is your listen interval.
* **Eclipse / censorship / Sybil attacks.** An attacker who controls the DHT nodes close to a key can
  hide a feed or serve stale data (they cannot forge it). Signed expiry and the persisted highest
  `seq` bound how long stale data or a replay is useful and make rollback visible, but "nothing
  found" can be censorship as well as a silent publisher. `radio` reports `not-found`/`unreachable`
  separately instead of claiming "no news".
* **Republish ≠ liveness.** Re-putting an old signed item keeps it findable; only a freshly signed
  heartbeat proves the sender is online *now*, and only up to its issue time.
* **Clocks matter.** Expiry and the future-`iat` check use the local clock. Large skew on either side
  produces `clock-skew`/`expired` diagnostics.
* **FIDO2 touch.** Touch-required keys cannot sign unattended (see above).
* **Trust is only as good as your pinning.** Compare fingerprints out of band; there is no PKI.
* **v1 scope:** no GUI, chat history or large payloads; Ed25519 SSH keys only; IPv4 DHT only.
