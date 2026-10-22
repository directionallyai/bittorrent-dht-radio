//! The operations behind the commands: publish, republish and poll the circle.

use std::sync::OnceLock;

use anyhow::anyhow;
use mainline::SigningKey;
use ssh_key::PublicKey;

use crate::circle::{Circle, Member};
use crate::config::Config;
use crate::direct::{self, Opener};
use crate::exit::{self, coded, Coded, WithCode};
use crate::item::bencoded_len;
use crate::net::{Net, PutFailure};
use crate::output::Event;
use crate::payload::{validate_message, Payload};
use crate::publish::{self, BuildError, Built, Identity};
use crate::sshsig::{self, Signer};
use crate::state::{
    DirectState, MemberState, MemberStatus, PutRecord, Rejection, SignedItem, State, Store,
    StoredMessage,
};
use crate::util::{format_age, format_utc};
use crate::verify::{self, Accepted, Fetched, Reject, Seen, Verdict};

/// Maximum automatic re-sign attempts after a BEP 44 write conflict.
const MAX_CONFLICT_RETRIES: usize = 2;

/// A put acknowledged by fewer storage nodes than this is repeated (idempotently): a freshly
/// bootstrapped client on the public DHT sometimes reaches only a few nodes on the first try.
pub const MIN_STORED_NODES: u32 = 3;
const PUT_TOP_UP_ATTEMPTS: usize = 2;

/// Put an item; if few nodes acknowledged, repeat the identical put (same seq and value, no CAS)
/// a couple of times and report the best result.
fn put_resilient(
    net: &Net,
    item: mainline::MutableItem,
    cas: Option<i64>,
) -> Result<u32, PutFailure> {
    let mut best = net.put(item.clone(), cas)?;
    for _ in 0..PUT_TOP_UP_ATTEMPTS {
        if best >= MIN_STORED_NODES {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(700));
        if let Ok(n) = net.put(item.clone(), None) {
            best = best.max(n);
        }
    }
    Ok(best)
}

pub struct Publisher<'a> {
    pub cfg: &'a Config,
    pub ssh: &'a Signer,
    pub dht_key: &'a SigningKey,
    pub store: &'a Store,
}

#[derive(Debug, Clone)]
pub struct PublishReport {
    pub kind: &'static str,
    /// Recipient name, for a direct message.
    pub to: Option<String>,
    pub seq: i64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub stored_at: u32,
    pub bytes_bencoded: usize,
}

impl PublishReport {
    pub fn event(&self) -> Event {
        Event::Published {
            kind: self.kind.into(),
            to: self.to.clone(),
            seq: self.seq,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            stored_at: self.stored_at,
            bytes_bencoded: self.bytes_bencoded,
        }
    }
}

fn build_error_to_coded(e: BuildError) -> Coded {
    Coded {
        code: e.exit_code(),
        error: e.into(),
    }
}

fn put_error_to_coded(e: PutFailure) -> Coded {
    let code = match e {
        PutFailure::Unavailable(_) => exit::DHT_UNAVAILABLE,
        PutFailure::Rejected(_) | PutFailure::Conflict(_) => exit::ERROR,
    };
    coded(code, e)
}

fn record_put(store: &Store, rec: PutRecord, item: Option<SignedItem>, republish: bool) {
    let ok = rec.ok;
    let at = rec.at;
    let _ = store.update(|s| {
        s.publisher.last_put = Some(rec);
        if ok {
            if let Some(item) = item {
                s.publisher.last_item = Some(item);
            }
            if republish {
                s.publisher.last_republish_ok_at = Some(at);
            } else {
                s.publisher.last_publish_ok_at = Some(at);
            }
        }
    });
}

impl Publisher<'_> {
    fn identity(&self) -> Identity<'_> {
        Identity {
            name: &self.cfg.name,
            salt: self.cfg.salt.as_deref(),
            ssh: self.ssh,
            dht: self.dht_key,
        }
    }

    /// Sign `message` with a new seq and issued-at, then put it. The size limit is checked
    /// before signing.
    pub fn publish(
        &self,
        net: &Net,
        message: &str,
        ttl_secs: u64,
        chain_prev: bool,
        now: u64,
    ) -> Result<PublishReport, Coded> {
        let state = self.store.load().code(exit::ERROR)?;
        let local_last = state.publisher.last_item.as_ref().map(|i| i.seq);
        let prev = if chain_prev {
            state
                .publisher
                .last_item
                .as_ref()
                .map(|i| i.payload_sha256[..crate::payload::PREV_HEX_LEN].to_string())
        } else {
            None
        };

        // Fail fast on bad or oversized messages, before touching the network or the signer.
        let ident = self.identity();
        preflight(
            ident.name,
            message,
            publish::next_seq(local_last, now),
            now,
            ttl_secs,
            prev.is_some(),
        )
        .map_err(build_error_to_coded)?;

        let (built, stored_at) = self.put_fresh(
            net,
            self.cfg.salt.as_deref().map(str::as_bytes),
            local_last,
            "publish",
            now,
            |seq| ident.build(message, seq, now, ttl_secs, prev.clone()),
        )?;
        let seq = built.payload.seq;
        record_put(
            self.store,
            PutRecord {
                at: now,
                kind: "publish".into(),
                seq,
                ok: true,
                stored_at: Some(stored_at),
                error: None,
            },
            Some(SignedItem {
                seq,
                value_hex: hex::encode(&built.value),
                salt: self.cfg.salt.clone(),
                issued_at: built.payload.issued_at,
                expires_at: built.payload.expires_at,
                payload_sha256: hex::encode(built.payload.hash()),
                message: message.to_string(),
            }),
            false,
        );
        Ok(PublishReport {
            kind: "published",
            to: None,
            seq,
            issued_at: built.payload.issued_at,
            expires_at: built.payload.expires_at,
            stored_at,
            bytes_bencoded: bencoded_len(built.value.len()),
        })
    }

    /// Encrypt `message` to `recipient`'s SSH key, sign it, and put it in our direct slot for
    /// them. The broadcast feed is left alone. The size limit is checked before signing.
    pub fn publish_to(
        &self,
        net: &Net,
        recipient: &Member,
        message: &str,
        ttl_secs: u64,
        now: u64,
    ) -> Result<PublishReport, Coded> {
        let to = recipient.ssh_key().code(exit::CONFIG)?;
        let fingerprint = sshsig::fingerprint(&to);
        let state = self.store.load().code(exit::ERROR)?;
        let local_last = state.publisher.direct.get(&fingerprint).map(|i| i.seq);
        let ident = self.identity();
        preflight_direct(ident.name, &to, message, local_last, ttl_secs, now)?;

        let salt = direct::slot_salt(self.cfg.salt.as_deref(), &to);
        let (built, stored_at) = self.put_fresh(
            net,
            Some(salt.as_bytes()),
            local_last,
            "direct",
            now,
            |seq| ident.build_direct(&to, message, seq, now, ttl_secs),
        )?;
        let seq = built.payload.seq;
        let _ = self.store.update(|s| {
            s.publisher.last_put = Some(PutRecord {
                at: now,
                kind: "direct".into(),
                seq,
                ok: true,
                stored_at: Some(stored_at),
                error: None,
            });
            s.publisher.direct.insert(
                fingerprint,
                SignedItem {
                    seq,
                    value_hex: hex::encode(&built.value),
                    salt: Some(salt.clone()),
                    issued_at: built.payload.issued_at,
                    expires_at: built.payload.expires_at,
                    payload_sha256: hex::encode(built.payload.hash()),
                    message: message.to_string(),
                },
            );
        });
        Ok(PublishReport {
            kind: "published-direct",
            to: Some(recipient.name.clone()),
            seq,
            issued_at: built.payload.issued_at,
            expires_at: built.payload.expires_at,
            stored_at,
            bytes_bencoded: bencoded_len(built.value.len()),
        })
    }

    /// Sign with `build` and put into the slot `salt` of our feed key. The seq goes above both
    /// local state and whatever the DHT holds (state may have been lost); after a BEP 44 write
    /// conflict it re-reads and re-signs. Failed puts are recorded as `kind`.
    fn put_fresh(
        &self,
        net: &Net,
        salt: Option<&[u8]>,
        local_last: Option<i64>,
        kind: &str,
        now: u64,
        build: impl Fn(i64) -> Result<Built, BuildError>,
    ) -> Result<(Built, u32), Coded> {
        let own_key = self.dht_key.verifying_key().to_bytes();
        let on_dht = net.get_latest(&own_key, salt).item.map(|i| i.seq());
        let mut known_max = match (local_last, on_dht) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };

        let fail = |seq, e: &PutFailure| {
            record_put(
                self.store,
                PutRecord {
                    at: now,
                    kind: kind.into(),
                    seq,
                    ok: false,
                    stored_at: None,
                    error: Some(e.to_string()),
                },
                None,
                false,
            )
        };
        let mut cas = on_dht;
        let mut last_err = None;
        for _ in 0..=MAX_CONFLICT_RETRIES {
            let seq = publish::next_seq(known_max, now);
            let built = build(seq).map_err(build_error_to_coded)?;
            match put_resilient(net, built.item.clone(), cas) {
                Ok(stored_at) => return Ok((built, stored_at)),
                Err(PutFailure::Conflict(c)) => {
                    // Someone (or a stale replica) holds a different seq: re-read and go above it.
                    let latest = net.get_latest(&own_key, salt).item.map(|i| i.seq());
                    known_max = known_max.max(latest);
                    cas = latest;
                    last_err = Some(PutFailure::Conflict(c));
                }
                Err(e) => {
                    fail(seq, &e);
                    return Err(put_error_to_coded(e));
                }
            }
        }
        let e = last_err.expect("loop ran at least once");
        fail(0, &e);
        Err(put_error_to_coded(e))
    }
}

/// Re-put the last signed item byte-for-byte. The signed `issued-at`/`expires-at` and `seq`
/// do not change, so this keeps the DHT record alive but proves nothing about the sender
/// being online now.
pub fn republish(
    store: &Store,
    dht_key: &SigningKey,
    net: &Net,
    now: u64,
) -> Result<PublishReport, Coded> {
    let state = store.load().code(exit::ERROR)?;
    let item = state.publisher.last_item.ok_or_else(|| {
        coded(
            exit::STALE_ITEM,
            "nothing to republish: no message has been published from this config dir yet",
        )
    })?;
    if now >= item.expires_at {
        return Err(coded(
            exit::STALE_ITEM,
            format!(
                "the last signed item (seq {}) expired at {}; receivers would reject it. \
                 Publish a fresh heartbeat with `radio publish` instead",
                item.seq,
                format_utc(item.expires_at)
            ),
        ));
    }
    let value = hex::decode(&item.value_hex)
        .map_err(|e| coded(exit::ERROR, format!("corrupt state: {e}")))?;
    // Ed25519 is deterministic, so re-signing the same (seq, v) reproduces the identical item.
    let mi = mainline::MutableItem::new(
        dht_key.clone(),
        &value,
        item.seq,
        item.salt.as_deref().map(str::as_bytes),
    );
    match put_resilient(net, mi, None) {
        Ok(stored_at) => {
            record_put(
                store,
                PutRecord {
                    at: now,
                    kind: "republish".into(),
                    seq: item.seq,
                    ok: true,
                    stored_at: Some(stored_at),
                    error: None,
                },
                Some(item.clone()),
                true,
            );
            Ok(PublishReport {
                kind: "republished",
                to: None,
                seq: item.seq,
                issued_at: item.issued_at,
                expires_at: item.expires_at,
                stored_at,
                bytes_bencoded: bencoded_len(value.len()),
            })
        }
        Err(e) => {
            record_put(
                store,
                PutRecord {
                    at: now,
                    kind: "republish".into(),
                    seq: item.seq,
                    ok: false,
                    stored_at: None,
                    error: Some(e.to_string()),
                },
                None,
                true,
            );
            Err(put_error_to_coded(e))
        }
    }
}

/// Like [`preflight`], using the saved state to know the next seq and whether a `prev` hash
/// will be included. Needs neither the SSH signer nor the network.
pub fn preflight_for(
    store: &Store,
    cfg: &Config,
    message: &str,
    ttl_secs: u64,
    chain_prev: bool,
    now: u64,
) -> Result<(), Coded> {
    let state = store.load().code(exit::ERROR)?;
    let last = state.publisher.last_item.as_ref();
    preflight(
        &cfg.name,
        message,
        publish::next_seq(last.map(|i| i.seq), now),
        now,
        ttl_secs,
        chain_prev && last.is_some(),
    )
    .map_err(|e| Coded {
        code: e.exit_code(),
        error: e.into(),
    })
}

/// Validate, encrypt and size-check a direct message without signing anything.
pub fn preflight_direct(
    name: &str,
    to: &PublicKey,
    message: &str,
    local_last: Option<i64>,
    ttl_secs: u64,
    now: u64,
) -> Result<(), Coded> {
    publish::seal_payload(
        name,
        to,
        message,
        publish::next_seq(local_last, now),
        now,
        ttl_secs,
    )
    .map(|_| ())
    .map_err(build_error_to_coded)
}

/// Like [`preflight_direct`], using the saved state for the next seq.
pub fn preflight_direct_for(
    store: &Store,
    cfg: &Config,
    recipient: &Member,
    message: &str,
    ttl_secs: u64,
    now: u64,
) -> Result<(), Coded> {
    let to = recipient.ssh_key().code(exit::CONFIG)?;
    let state = store.load().code(exit::ERROR)?;
    let last = state
        .publisher
        .direct
        .get(&sshsig::fingerprint(&to))
        .map(|i| i.seq);
    preflight_direct(&cfg.name, &to, message, last, ttl_secs, now)
}

/// Validate and size-check a message without signing anything.
pub fn preflight(
    name: &str,
    message: &str,
    seq: i64,
    now: u64,
    ttl_secs: u64,
    with_prev: bool,
) -> Result<(), BuildError> {
    let p = Payload {
        sender: name.to_string(),
        to: None,
        seq,
        issued_at: now,
        expires_at: now.saturating_add(ttl_secs.max(1)),
        prev: with_prev.then(|| "0".repeat(crate::payload::PREV_HEX_LEN)),
        message: message.to_string(),
        sealed: Vec::new(),
    };
    let bytes = p.encode()?;
    crate::item::check_payload_fits(bytes.len())?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------------------------

/// What one query for a member's feed returned.
#[derive(Debug, Clone)]
pub enum Fetch {
    Found(Fetched),
    /// The DHT answered but has no record for this feed.
    NotFound {
        queried: u32,
        responded: u32,
    },
    /// No answer at all: DHT down, bootstrap failed, or every UDP request timed out.
    Unreachable(String),
}

#[derive(Debug, Clone)]
pub enum Outcome {
    New(Accepted),
    Seen(Accepted),
    NotFound { queried: u32, responded: u32 },
    Unreachable(String),
    Rejected(Reject),
}

/// Pure decision logic for one member.
pub fn evaluate(member: &Member, prev: &MemberState, fetch: Fetch, now: u64, skew: u64) -> Outcome {
    match fetch {
        Fetch::Unreachable(d) => Outcome::Unreachable(d),
        Fetch::NotFound { queried, responded } => Outcome::NotFound { queried, responded },
        Fetch::Found(f) => {
            let seen = Seen {
                highest_seq: prev.highest_seq,
                payload_sha256: prev
                    .last_message
                    .as_ref()
                    .filter(|m| m.seq == prev.highest_seq)
                    .map(|m| m.payload_sha256.clone()),
            };
            match verify::verify_for_member(member, &seen, &f, now, skew) {
                Ok(Verdict::New(a)) => Outcome::New(a),
                Ok(Verdict::Seen(a)) => Outcome::Seen(a),
                Err(r) => Outcome::Rejected(r),
            }
        }
    }
}

pub enum Source<'a> {
    Live(&'a Net),
    /// The DHT could not be brought up; every member is reported unreachable with this reason.
    Down(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollSummary {
    pub members: usize,
    pub new: usize,
    pub ok: usize,
    pub not_found: usize,
    pub expired: usize,
    pub unreachable: usize,
    pub rejected: usize,
}

impl PollSummary {
    /// Exit code for a one-shot `listen`: verification failures first (a security signal), then
    /// new messages, then "freshness unverifiable", then "no new message".
    pub fn exit_code(&self) -> i32 {
        if self.rejected > 0 {
            exit::VERIFY_FAILED
        } else if self.new > 0 {
            exit::OK
        } else if self.unreachable > 0 {
            exit::DHT_UNAVAILABLE
        } else {
            exit::NO_NEW
        }
    }
}

pub struct PollReport {
    pub events: Vec<Event>,
    pub summary: PollSummary,
}

pub fn fetch_member(source: &Source, member: &Member) -> Fetch {
    fetch_slot(source, member, member.salt_bytes())
}

/// Fetch the item stored under `member`'s feed key with `salt`.
pub fn fetch_slot(source: &Source, member: &Member, salt: Option<&[u8]>) -> Fetch {
    match source {
        Source::Down(d) => Fetch::Unreachable(d.clone()),
        Source::Live(net) => {
            let key = match member.dht_key() {
                Ok(k) => k,
                Err(e) => return Fetch::Unreachable(format!("invalid pinned key: {e}")),
            };
            let res = net.get_latest(&key, salt);
            match res.item {
                Some(item) => Fetch::Found(Fetched::from(&item)),
                None if res.outcome.responded() == 0 => Fetch::Unreachable(format!(
                    "no DHT node answered ({} queried, {} timed out)",
                    res.outcome.queried,
                    res.outcome.timed_out()
                )),
                None => Fetch::NotFound {
                    queried: res.outcome.queried,
                    responded: res.outcome.responded(),
                },
            }
        }
    }
}

/// Our side of direct messages: the SSH key they are encrypted to, and the decryptor, which
/// is loaded only once a new direct message actually arrives (it may need a passphrase).
pub struct Inbox {
    public: PublicKey,
    fingerprint: String,
    opener: OnceLock<Result<Opener, String>>,
    load: Box<dyn Fn() -> Result<Opener, String> + Send + Sync>,
}

impl Inbox {
    pub fn new(
        public: PublicKey,
        load: impl Fn() -> Result<Opener, String> + Send + Sync + 'static,
    ) -> Self {
        Inbox {
            fingerprint: sshsig::fingerprint(&public),
            public,
            opener: OnceLock::new(),
            load: Box::new(load),
        }
    }

    /// An inbox for the key `signer` signs with. ssh-agent keys can sign but not decrypt.
    pub fn for_signer(signer: &Signer) -> Self {
        let inbox = Inbox::new(signer.public().clone(), || Err(AGENT_CANNOT_DECRYPT.into()));
        if let Signer::File { key, .. } = signer {
            let _ = inbox
                .opener
                .set(Opener::from_private_key(key).map_err(|e| e.to_string()));
        }
        inbox
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Salt of `member`'s direct slot for us.
    pub fn slot_salt(&self, member: &Member) -> String {
        direct::slot_salt(member.salt.as_deref(), &self.public)
    }

    fn opener(&self) -> Result<&Opener, &str> {
        self.opener
            .get_or_init(|| (self.load)())
            .as_ref()
            .map_err(String::as_str)
    }
}

pub const AGENT_CANNOT_DECRYPT: &str =
    "your SSH key is used through ssh-agent, which can sign but \
     cannot decrypt; direct messages need the private key file (`radio init --ssh-key`)";

/// Poll every circle member once, update persistent state and return the events to show.
///
/// With `emit_all` (one-shot `listen`) every non-OK member is reported each time; otherwise
/// (follow/run) only changes against the persisted state are reported, so restarts do not flood.
pub fn poll_circle(
    circle: &Circle,
    store: &Store,
    source: &Source,
    now: u64,
    skew: u64,
    emit_all: bool,
) -> Result<PollReport, Coded> {
    poll_circle_with(circle, store, source, None, now, skew, emit_all)
}

/// [`poll_circle`], also checking each member's direct slot for `inbox`.
pub fn poll_circle_with(
    circle: &Circle,
    store: &Store,
    source: &Source,
    inbox: Option<&Inbox>,
    now: u64,
    skew: u64,
    emit_all: bool,
) -> Result<PollReport, Coded> {
    let salts: Vec<Option<String>> = circle
        .members
        .iter()
        .map(|m| inbox.map(|i| i.slot_salt(m)))
        .collect();
    let join = |h: std::thread::ScopedJoinHandle<'_, Fetch>| {
        h.join()
            .unwrap_or_else(|_| Fetch::Unreachable("poll thread panicked".into()))
    };
    // Query all members (and their direct slots for us) concurrently; the DHT handle is shared.
    let (fetches, direct_fetches): (Vec<Fetch>, Vec<Option<Fetch>>) = std::thread::scope(|scope| {
        let handles: Vec<_> = circle
            .members
            .iter()
            .zip(&salts)
            .map(|(m, salt)| {
                (
                    scope.spawn(move || fetch_member(source, m)),
                    salt.as_ref()
                        .map(|s| scope.spawn(move || fetch_slot(source, m, Some(s.as_bytes())))),
                )
            })
            .collect();
        handles
            .into_iter()
            .map(|(h, d)| (join(h), d.map(join)))
            .unzip()
    });

    // Load the decryptor (which may prompt for a passphrase) before taking the state lock.
    if let Some(inbox) = inbox {
        let state = store.load().code(exit::ERROR)?;
        let pending = circle.members.iter().zip(&direct_fetches).any(|(m, f)| {
            let seen = state
                .direct
                .get(&m.dht_public_key)
                .map_or(0, |d| d.highest_seq);
            matches!(f, Some(Fetch::Found(f)) if f.seq > seen)
        });
        if pending {
            let _ = inbox.opener();
        }
    }

    let mut events = Vec::new();
    let mut summary = PollSummary {
        members: circle.members.len(),
        ..Default::default()
    };
    store
        .update(|state| {
            for (((member, fetch), direct_fetch), salt) in circle
                .members
                .iter()
                .zip(fetches)
                .zip(direct_fetches)
                .zip(&salts)
            {
                let key = member.dht_public_key.clone();
                let prev = state.members.get(&key).cloned().unwrap_or_default();
                let outcome = evaluate(member, &prev, fetch, now, skew);
                apply_outcome(
                    state,
                    member,
                    &prev,
                    outcome,
                    now,
                    emit_all,
                    &mut events,
                    &mut summary,
                );
                if let (Some(inbox), Some(Fetch::Found(f)), Some(salt)) =
                    (inbox, direct_fetch, salt)
                {
                    let ctx = DirectCtx {
                        inbox,
                        salt,
                        now,
                        skew,
                        emit_all,
                    };
                    apply_direct(state, member, &f, &ctx, &mut events, &mut summary);
                }
            }
        })
        .code(exit::ERROR)?;
    Ok(PollReport { events, summary })
}

#[allow(clippy::too_many_arguments)]
fn apply_outcome(
    state: &mut State,
    member: &Member,
    prev: &MemberState,
    outcome: Outcome,
    now: u64,
    emit_all: bool,
    events: &mut Vec<Event>,
    summary: &mut PollSummary,
) {
    let name = member.name.clone();
    let mut ms = prev.clone();
    ms.name = name.clone();
    ms.last_poll_at = Some(now);

    let (status, detail) = match &outcome {
        Outcome::New(a) | Outcome::Seen(a) => {
            let is_new = matches!(outcome, Outcome::New(_));
            let p = &a.payload;
            ms.highest_seq = p.seq;
            ms.last_message = Some(StoredMessage {
                seq: p.seq,
                issued_at: p.issued_at,
                expires_at: p.expires_at,
                message: p.message.clone(),
                payload_sha256: a.payload_sha256.clone(),
            });
            ms.last_verified_at = Some(now);
            if is_new {
                summary.new += 1;
                events.push(Event::Message {
                    member: name.clone(),
                    seq: p.seq,
                    issued_at: p.issued_at,
                    expires_at: p.expires_at,
                    message: p.message.clone(),
                    ssh_fingerprint: member.ssh_fingerprint(),
                    prev: p.prev.clone(),
                    fetched_at: now,
                });
            }
            summary.ok += 1;
            (
                MemberStatus::Ok,
                format!("seq {} valid until {}", p.seq, format_utc(p.expires_at)),
            )
        }
        Outcome::NotFound { queried, responded } => {
            summary.not_found += 1;
            (
                MemberStatus::NotFound,
                format!("no record on the DHT ({responded}/{queried} nodes answered); publisher offline or record aged out"),
            )
        }
        Outcome::Unreachable(d) => {
            summary.unreachable += 1;
            (
                MemberStatus::Unreachable,
                format!("freshness could not be verified: {d}"),
            )
        }
        Outcome::Rejected(r) if r.is_soft() => {
            summary.expired += 1;
            (
                MemberStatus::Expired,
                format!("newest record is stale: {r}; publisher likely offline"),
            )
        }
        Outcome::Rejected(r) => {
            summary.rejected += 1;
            let rej = Rejection {
                at: now,
                reason: r.code().into(),
                detail: r.to_string(),
            };
            let repeated = prev
                .last_rejection
                .as_ref()
                .is_some_and(|p| p.reason == rej.reason && p.detail == rej.detail);
            if emit_all || !repeated {
                events.push(Event::Rejected {
                    member: name.clone(),
                    reason: rej.reason.clone(),
                    detail: rej.detail.clone(),
                });
            }
            ms.last_rejection = Some(rej);
            (MemberStatus::Rejected, r.to_string())
        }
    };

    let changed = prev.status != Some(status);
    if changed {
        ms.status_since = Some(now);
    }
    ms.status = Some(status);
    ms.last_poll_detail = Some(detail.clone());

    let announce = match status {
        // Rejections already produced their own event.
        MemberStatus::Rejected => false,
        MemberStatus::Ok => changed && prev.status.is_some(),
        _ => emit_all || changed,
    };
    if announce {
        events.push(Event::Status {
            member: name,
            status,
            detail,
            previous: prev.status,
            last_verified_at: ms.last_verified_at,
        });
    }
    state.members.insert(member.dht_public_key.clone(), ms);
}

struct DirectCtx<'a> {
    inbox: &'a Inbox,
    salt: &'a str,
    now: u64,
    skew: u64,
    emit_all: bool,
}

enum DirectOutcome {
    New(Accepted, String),
    Seen,
    Rejected(Reject),
    /// Verified, but our private key is not available to decrypt it (yet).
    NoKey(String),
}

fn open_direct(inbox: &Inbox, a: &Accepted) -> DirectOutcome {
    let opener = match inbox.opener() {
        Ok(o) => o,
        Err(e) => return DirectOutcome::NoKey(e.to_string()),
    };
    let header = a
        .payload
        .header()
        .expect("verified payload has a valid header");
    let text = match opener.open(&header, &a.payload.sealed) {
        Ok(bytes) => bytes,
        Err(e) => return DirectOutcome::Rejected(Reject::DecryptFailed(e.to_string())),
    };
    let text = match String::from_utf8(text) {
        Ok(t) => t,
        Err(_) => {
            return DirectOutcome::Rejected(Reject::MalformedPayload(
                "decrypted message is not valid UTF-8".into(),
            ))
        }
    };
    match validate_message(&text) {
        Ok(()) => DirectOutcome::New(a.clone(), text),
        Err(e) => {
            DirectOutcome::Rejected(Reject::MalformedPayload(format!("decrypted message: {e}")))
        }
    }
}

/// Handle what was found in `member`'s direct slot for us. Nothing there, or an expired item,
/// is normal and silent; reachability is already reported for the member's feed.
fn apply_direct(
    state: &mut State,
    member: &Member,
    fetched: &Fetched,
    ctx: &DirectCtx,
    events: &mut Vec<Event>,
    summary: &mut PollSummary,
) {
    let mut ds: DirectState = state
        .direct
        .get(&member.dht_public_key)
        .cloned()
        .unwrap_or_default();
    ds.name = member.name.clone();
    let seen = Seen {
        highest_seq: ds.highest_seq,
        payload_sha256: ds.payload_sha256.clone(),
    };
    let fp = ctx.inbox.fingerprint();
    let outcome =
        match verify::verify_direct(member, ctx.salt, fp, &seen, fetched, ctx.now, ctx.skew) {
            Ok(Verdict::New(a)) => open_direct(ctx.inbox, &a),
            Ok(Verdict::Seen(_)) => DirectOutcome::Seen,
            Err(r) if r.is_soft() => DirectOutcome::Seen,
            Err(r) => DirectOutcome::Rejected(r),
        };
    let rejection = match outcome {
        DirectOutcome::Seen => None,
        DirectOutcome::New(a, text) => {
            let p = &a.payload;
            ds.highest_seq = p.seq;
            ds.payload_sha256 = Some(a.payload_sha256.clone());
            ds.last_received_at = Some(ctx.now);
            ds.last_rejection = None;
            summary.new += 1;
            events.push(Event::DirectMessage {
                member: member.name.clone(),
                seq: p.seq,
                issued_at: p.issued_at,
                expires_at: p.expires_at,
                message: text,
                ssh_fingerprint: member.ssh_fingerprint(),
                fetched_at: ctx.now,
            });
            None
        }
        DirectOutcome::Rejected(r) => {
            summary.rejected += 1;
            Some(Rejection {
                at: ctx.now,
                reason: r.code().into(),
                detail: r.to_string(),
            })
        }
        // The seq is not advanced, so the message is decrypted once the key is available.
        DirectOutcome::NoKey(why) => Some(Rejection {
            at: ctx.now,
            reason: "no-decryption-key".into(),
            detail: format!("a direct message is waiting but cannot be decrypted: {why}"),
        }),
    };
    if let Some(rej) = rejection {
        let repeated = ds
            .last_rejection
            .as_ref()
            .is_some_and(|p| p.reason == rej.reason && p.detail == rej.detail);
        if (ctx.emit_all || !repeated) && rej.reason == "no-decryption-key" {
            events.push(Event::Error {
                context: format!("direct message from {}", member.name),
                detail: rej.detail.clone(),
            });
        } else if ctx.emit_all || !repeated {
            events.push(Event::Rejected {
                member: format!("{} (direct)", member.name),
                reason: rej.reason.clone(),
                detail: rej.detail.clone(),
            });
        }
        ds.last_rejection = Some(rej);
    }
    state.direct.insert(member.dht_public_key.clone(), ds);
}

/// Human description of how stale a member is, for `status`.
pub fn staleness(ms: &MemberState, now: u64) -> String {
    match ms.last_verified_at {
        Some(t) => format!("last verified {} ago", format_age(now.saturating_sub(t))),
        None => "never verified".to_string(),
    }
}

pub fn require_circle(circle: &Circle) -> Result<(), Coded> {
    if circle.members.is_empty() {
        return Err(Coded {
            code: exit::CONFIG,
            error: anyhow!(
                "the circle is empty: pin a member first (`radio circle add --card <file>`)"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::testkit::Keys;

    const NOW: u64 = 1_700_000_000;

    fn setup() -> (Keys, Circle, tempfile::TempDir, Store) {
        let alice = Keys::new("alice");
        let mut circle = Circle::default();
        circle.add(alice.member()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&crate::config::Paths {
            root: dir.path().to_path_buf(),
        });
        (alice, circle, dir, store)
    }

    fn fetched(keys: &Keys, seq: i64, issued: u64, ttl: u64, msg: &str) -> Fetched {
        let b = keys.identity().build(msg, seq, issued, ttl, None).unwrap();
        Fetched::from(&b.item)
    }

    fn poll(circle: &Circle, store: &Store, f: Fetch, now: u64, emit_all: bool) -> PollReport {
        // Single-member circle: emulate Source by evaluating directly.
        let member = &circle.members[0];
        let mut events = Vec::new();
        let mut summary = PollSummary {
            members: 1,
            ..Default::default()
        };
        store
            .update(|state| {
                let prev = state
                    .members
                    .get(&member.dht_public_key)
                    .cloned()
                    .unwrap_or_default();
                let outcome = evaluate(member, &prev, f, now, 120);
                apply_outcome(
                    state,
                    member,
                    &prev,
                    outcome,
                    now,
                    emit_all,
                    &mut events,
                    &mut summary,
                );
            })
            .unwrap();
        PollReport { events, summary }
    }

    #[test]
    fn new_message_then_dedup_across_restart() {
        let (alice, circle, dir, store) = setup();
        let f = fetched(&alice, 10, NOW - 5, 3600, "hello");
        let r = poll(&circle, &store, Fetch::Found(f.clone()), NOW, false);
        assert_eq!(r.summary.new, 1);
        assert!(matches!(&r.events[0], Event::Message { seq: 10, .. }));
        assert_eq!(r.summary.exit_code(), exit::OK);

        // "Restart": fresh Store on the same directory sees the persisted state.
        let store2 = Store::new(&crate::config::Paths {
            root: dir.path().to_path_buf(),
        });
        let r = poll(&circle, &store2, Fetch::Found(f), NOW + 60, false);
        assert_eq!(r.summary.new, 0);
        assert!(r.events.is_empty(), "no duplicate output: {:?}", r.events);
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        let st = store2.load().unwrap();
        assert_eq!(
            st.members[&circle.members[0].dht_public_key].highest_seq,
            10
        );
    }

    #[test]
    fn rollback_after_accepting_newer_is_a_hard_failure() {
        let (alice, circle, _d, store) = setup();
        poll(
            &circle,
            &store,
            Fetch::Found(fetched(&alice, 10, NOW, 3600, "new")),
            NOW,
            false,
        );
        let r = poll(
            &circle,
            &store,
            Fetch::Found(fetched(&alice, 9, NOW, 3600, "old")),
            NOW + 1,
            false,
        );
        assert_eq!(r.summary.rejected, 1);
        assert_eq!(r.summary.exit_code(), exit::VERIFY_FAILED);
        assert!(
            matches!(&r.events[0], Event::Rejected { reason, .. } if reason == "replay-rollback")
        );
        // Highest seq is not lowered by the rejected item.
        assert_eq!(
            store.load().unwrap().members[&circle.members[0].dht_public_key].highest_seq,
            10
        );
    }

    #[test]
    fn unreachable_is_distinct_from_no_new_message() {
        let (alice, circle, _d, store) = setup();
        poll(
            &circle,
            &store,
            Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")),
            NOW,
            false,
        );
        let r = poll(
            &circle,
            &store,
            Fetch::Unreachable("no DHT node answered".into()),
            NOW + 60,
            true,
        );
        assert_eq!(r.summary.exit_code(), exit::DHT_UNAVAILABLE);
        assert!(matches!(
            &r.events[0],
            Event::Status {
                status: MemberStatus::Unreachable,
                ..
            }
        ));
        // The member's last verified time survives the outage.
        let st = store.load().unwrap();
        assert_eq!(
            st.members[&circle.members[0].dht_public_key].last_verified_at,
            Some(NOW)
        );
    }

    #[test]
    fn publisher_offline_not_found_and_expired_are_warnings_with_no_new_exit() {
        let (alice, circle, _d, store) = setup();
        let r = poll(
            &circle,
            &store,
            Fetch::NotFound {
                queried: 8,
                responded: 8,
            },
            NOW,
            true,
        );
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        assert!(matches!(
            &r.events[0],
            Event::Status {
                status: MemberStatus::NotFound,
                ..
            }
        ));

        let stale = fetched(&alice, 11, NOW - 7200, 3600, "old news");
        let r = poll(&circle, &store, Fetch::Found(stale), NOW, true);
        assert_eq!(r.summary.expired, 1);
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        assert!(matches!(
            &r.events[0],
            Event::Status {
                status: MemberStatus::Expired,
                ..
            }
        ));
    }

    #[test]
    fn state_changes_are_announced_once_and_recovery_is_reported() {
        let (alice, circle, _d, store) = setup();
        poll(
            &circle,
            &store,
            Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")),
            NOW,
            false,
        );
        let r = poll(
            &circle,
            &store,
            Fetch::Unreachable("t".into()),
            NOW + 60,
            false,
        );
        assert_eq!(r.events.len(), 1);
        let r = poll(
            &circle,
            &store,
            Fetch::Unreachable("t".into()),
            NOW + 120,
            false,
        );
        assert!(r.events.is_empty(), "same state again is not re-announced");
        let r = poll(
            &circle,
            &store,
            Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")),
            NOW + 180,
            false,
        );
        assert!(matches!(
            &r.events[0],
            Event::Status {
                status: MemberStatus::Ok,
                previous: Some(MemberStatus::Unreachable),
                ..
            }
        ));
    }

    #[test]
    fn repeated_identical_rejection_is_not_re_announced_in_follow_mode() {
        let (alice, circle, _d, store) = setup();
        let mallory = Keys::new("alice");
        let bad = Fetched {
            key: alice.dht.verifying_key().to_bytes(),
            ..fetched(&mallory, 1, NOW, 60, "x")
        };
        let r = poll(&circle, &store, Fetch::Found(bad.clone()), NOW, false);
        assert_eq!(r.events.len(), 1);
        let r = poll(&circle, &store, Fetch::Found(bad.clone()), NOW + 1, false);
        assert!(r.events.is_empty());
        let r = poll(&circle, &store, Fetch::Found(bad), NOW + 2, true);
        assert_eq!(r.events.len(), 1, "one-shot always reports");
    }

    #[test]
    fn exit_code_precedence() {
        let s = |new, unreachable, rejected| PollSummary {
            new,
            unreachable,
            rejected,
            members: 3,
            ..Default::default()
        };
        assert_eq!(s(0, 0, 0).exit_code(), exit::NO_NEW);
        assert_eq!(s(1, 0, 0).exit_code(), exit::OK);
        assert_eq!(s(1, 1, 0).exit_code(), exit::OK);
        assert_eq!(s(0, 1, 0).exit_code(), exit::DHT_UNAVAILABLE);
        assert_eq!(s(1, 1, 1).exit_code(), exit::VERIFY_FAILED);
    }

    #[test]
    fn direct_message_waits_for_a_decryption_key_then_is_shown_once() {
        let (alice, circle, _d, store) = setup();
        let bob = Keys::new("bob");
        let member = &circle.members[0];
        let built = alice
            .identity()
            .build_direct(bob.ssh.public(), "for bob", 10, NOW, 3600)
            .unwrap();
        let f = Fetched::from(&built.item);
        let poll = |inbox: &Inbox, now, emit_all| {
            let mut events = Vec::new();
            let mut summary = PollSummary::default();
            let salt = inbox.slot_salt(member);
            store
                .update(|state| {
                    let ctx = DirectCtx {
                        inbox,
                        salt: &salt,
                        now,
                        skew: 120,
                        emit_all,
                    };
                    apply_direct(state, member, &f, &ctx, &mut events, &mut summary);
                })
                .unwrap();
            (events, summary)
        };

        let agent_only = Inbox::new(
            bob.ssh.public().clone(),
            || Err(AGENT_CANNOT_DECRYPT.into()),
        );
        let (events, summary) = poll(&agent_only, NOW, false);
        assert!(
            matches!(&events[..], [Event::Error { detail, .. }] if detail.contains("ssh-agent")),
            "{events:?}"
        );
        assert_eq!(summary.exit_code(), exit::NO_NEW);
        let (events, _) = poll(&agent_only, NOW + 1, false);
        assert!(events.is_empty(), "not repeated in follow mode: {events:?}");

        let with_key = Inbox::for_signer(&bob.ssh);
        let (events, summary) = poll(&with_key, NOW + 2, false);
        assert!(
            matches!(&events[..], [Event::DirectMessage { message, seq: 10, .. }] if message == "for bob"),
            "{events:?}"
        );
        assert_eq!(summary.exit_code(), exit::OK);
        let (events, _) = poll(&with_key, NOW + 3, true);
        assert!(events.is_empty(), "shown once: {events:?}");
    }

    #[test]
    fn preflight_checks_size_before_signing() {
        assert!(preflight("alice", "ok", 1, 1000, 60, false).is_ok());
        assert_eq!(
            preflight("alice", &"x".repeat(2000), 1, 1000, 60, false)
                .unwrap_err()
                .exit_code(),
            exit::BAD_MESSAGE
        );
        assert!(preflight("alice", "", 1, 1000, 60, false).is_err());
    }
}
