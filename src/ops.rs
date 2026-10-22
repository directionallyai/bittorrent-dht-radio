//! The operations behind the commands: publish, republish and poll the circle.

use anyhow::anyhow;
use mainline::SigningKey;

use crate::circle::{Circle, Member};
use crate::config::Config;
use crate::exit::{self, coded, Coded, WithCode};
use crate::item::bencoded_len;
use crate::net::{Net, PutFailure};
use crate::output::Event;
use crate::payload::Payload;
use crate::publish::{self, BuildError, Identity};
use crate::sshsig::Signer;
use crate::state::{
    MemberState, MemberStatus, PutRecord, Rejection, SignedItem, State, Store, StoredMessage,
};
use crate::util::{format_age, format_utc};
use crate::verify::{self, Accepted, Fetched, Reject, Seen, Verdict};

/// Maximum automatic re-sign attempts after a BEP 44 write conflict.
const MAX_CONFLICT_RETRIES: usize = 2;

pub struct Publisher<'a> {
    pub cfg: &'a Config,
    pub ssh: &'a Signer,
    pub dht_key: &'a SigningKey,
    pub store: &'a Store,
}

#[derive(Debug, Clone)]
pub struct PublishReport {
    pub kind: &'static str,
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
            seq: self.seq,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            stored_at: self.stored_at,
            bytes_bencoded: self.bytes_bencoded,
        }
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
        Identity { name: &self.cfg.name, salt: self.cfg.salt.as_deref(), ssh: self.ssh, dht: self.dht_key }
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
            state.publisher.last_item.as_ref().map(|i| i.payload_sha256[..crate::payload::PREV_HEX_LEN].to_string())
        } else {
            None
        };

        // Fail fast on bad or oversized messages, before touching the network or the signer.
        let ident = self.identity();
        preflight(ident.name, message, publish::next_seq(local_last, now), now, ttl_secs, prev.is_some())
            .map_err(|e: BuildError| Coded { code: e.exit_code(), error: e.into() })?;

        // Learn the highest seq already on the DHT so ours is above it (state may have been lost).
        let own_key = self.dht_key.verifying_key().to_bytes();
        let on_dht = net.get_latest(&own_key, self.cfg.salt.as_deref().map(str::as_bytes)).item.map(|i| i.seq());
        let mut known_max = match (local_last, on_dht) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };

        let mut cas = on_dht;
        let mut last_err = None;
        for _ in 0..=MAX_CONFLICT_RETRIES {
            let seq = publish::next_seq(known_max, now);
            let built = ident
                .build(message, seq, now, ttl_secs, prev.clone())
                .map_err(|e: BuildError| Coded { code: e.exit_code(), error: e.into() })?;
            match net.put(built.item.clone(), cas) {
                Ok(stored_at) => {
                    let bytes = bencoded_len(built.value.len());
                    let sha = hex::encode(built.payload.hash());
                    record_put(self.store, 
                        PutRecord { at: now, kind: "publish".into(), seq, ok: true, stored_at: Some(stored_at), error: None },
                        Some(SignedItem {
                            seq,
                            value_hex: hex::encode(&built.value),
                            salt: self.cfg.salt.clone(),
                            issued_at: built.payload.issued_at,
                            expires_at: built.payload.expires_at,
                            payload_sha256: sha,
                            message: message.to_string(),
                        }),
                        false,
                    );
                    return Ok(PublishReport {
                        kind: "published",
                        seq,
                        issued_at: built.payload.issued_at,
                        expires_at: built.payload.expires_at,
                        stored_at,
                        bytes_bencoded: bytes,
                    });
                }
                Err(PutFailure::Conflict(c)) => {
                    // Someone (or a stale replica) holds a different seq: re-read and go above it.
                    let latest = net.get_latest(&own_key, self.cfg.salt.as_deref().map(str::as_bytes)).item.map(|i| i.seq());
                    known_max = known_max.max(latest);
                    cas = latest;
                    last_err = Some(PutFailure::Conflict(c));
                }
                Err(e) => {
                    record_put(self.store, 
                        PutRecord { at: now, kind: "publish".into(), seq, ok: false, stored_at: None, error: Some(e.to_string()) },
                        None,
                        false,
                    );
                    return Err(put_error_to_coded(e));
                }
            }
        }
        let e = last_err.expect("loop ran at least once");
        record_put(self.store, 
            PutRecord { at: now, kind: "publish".into(), seq: 0, ok: false, stored_at: None, error: Some(e.to_string()) },
            None,
            false,
        );
        Err(put_error_to_coded(e))
    }
}

/// Re-put the last signed item byte-for-byte. The signed `issued-at`/`expires-at` and `seq`
/// do not change, so this keeps the DHT record alive but proves nothing about the sender
/// being online now.
pub fn republish(store: &Store, dht_key: &SigningKey, net: &Net, now: u64) -> Result<PublishReport, Coded> {
    let state = store.load().code(exit::ERROR)?;
    let item = state
        .publisher
        .last_item
        .ok_or_else(|| coded(exit::STALE_ITEM, "nothing to republish: no message has been published from this config dir yet"))?;
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
    let value = hex::decode(&item.value_hex).map_err(|e| coded(exit::ERROR, format!("corrupt state: {e}")))?;
    // Ed25519 is deterministic, so re-signing the same (seq, v) reproduces the identical item.
    let mi = mainline::MutableItem::new(dht_key.clone(), &value, item.seq, item.salt.as_deref().map(str::as_bytes));
    match net.put(mi, None) {
        Ok(stored_at) => {
            record_put(store, 
                PutRecord { at: now, kind: "republish".into(), seq: item.seq, ok: true, stored_at: Some(stored_at), error: None },
                Some(item.clone()),
                true,
            );
            Ok(PublishReport {
                kind: "republished",
                seq: item.seq,
                issued_at: item.issued_at,
                expires_at: item.expires_at,
                stored_at,
                bytes_bencoded: bencoded_len(value.len()),
            })
        }
        Err(e) => {
            record_put(store, 
                PutRecord { at: now, kind: "republish".into(), seq: item.seq, ok: false, stored_at: None, error: Some(e.to_string()) },
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
    .map_err(|e| Coded { code: e.exit_code(), error: e.into() })
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
        seq,
        issued_at: now,
        expires_at: now.saturating_add(ttl_secs.max(1)),
        prev: with_prev.then(|| "0".repeat(crate::payload::PREV_HEX_LEN)),
        message: message.to_string(),
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
    NotFound { queried: u32, responded: u32 },
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
    match source {
        Source::Down(d) => Fetch::Unreachable(d.clone()),
        Source::Live(net) => {
            let key = match member.dht_key() {
                Ok(k) => k,
                Err(e) => return Fetch::Unreachable(format!("invalid pinned key: {e}")),
            };
            let res = net.get_latest(&key, member.salt_bytes());
            match res.item {
                Some(item) => Fetch::Found(Fetched::from(&item)),
                None if res.outcome.responded() == 0 => Fetch::Unreachable(format!(
                    "no DHT node answered ({} queried, {} timed out)",
                    res.outcome.queried,
                    res.outcome.timed_out()
                )),
                None => Fetch::NotFound { queried: res.outcome.queried, responded: res.outcome.responded() },
            }
        }
    }
}

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
    // Query all members concurrently; the DHT handle is shared.
    let fetches: Vec<Fetch> = std::thread::scope(|scope| {
        let handles: Vec<_> = circle.members.iter().map(|m| scope.spawn(move || fetch_member(source, m))).collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Fetch::Unreachable("poll thread panicked".into())))
            .collect()
    });

    let mut events = Vec::new();
    let mut summary = PollSummary { members: circle.members.len(), ..Default::default() };
    store
        .update(|state| {
            for (member, fetch) in circle.members.iter().zip(fetches) {
                let key = member.dht_public_key.clone();
                let prev = state.members.get(&key).cloned().unwrap_or_default();
                let outcome = evaluate(member, &prev, fetch, now, skew);
                apply_outcome(state, member, &prev, outcome, now, emit_all, &mut events, &mut summary);
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
            (MemberStatus::Ok, format!("seq {} valid until {}", p.seq, format_utc(p.expires_at)))
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
            (MemberStatus::Unreachable, format!("freshness could not be verified: {d}"))
        }
        Outcome::Rejected(r) if r.is_soft() => {
            summary.expired += 1;
            (MemberStatus::Expired, format!("newest record is stale: {r}; publisher likely offline"))
        }
        Outcome::Rejected(r) => {
            summary.rejected += 1;
            let rej = Rejection { at: now, reason: r.code().into(), detail: r.to_string() };
            let repeated = prev.last_rejection.as_ref().is_some_and(|p| p.reason == rej.reason && p.detail == rej.detail);
            if emit_all || !repeated {
                events.push(Event::Rejected { member: name.clone(), reason: rej.reason.clone(), detail: rej.detail.clone() });
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
            error: anyhow!("the circle is empty: pin a member first (`radio circle add --card <file>`)"),
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
        let store = Store::new(&crate::config::Paths { root: dir.path().to_path_buf() });
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
        let mut summary = PollSummary { members: 1, ..Default::default() };
        store
            .update(|state| {
                let prev = state.members.get(&member.dht_public_key).cloned().unwrap_or_default();
                let outcome = evaluate(member, &prev, f, now, 120);
                apply_outcome(state, member, &prev, outcome, now, emit_all, &mut events, &mut summary);
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
        let store2 = Store::new(&crate::config::Paths { root: dir.path().to_path_buf() });
        let r = poll(&circle, &store2, Fetch::Found(f), NOW + 60, false);
        assert_eq!(r.summary.new, 0);
        assert!(r.events.is_empty(), "no duplicate output: {:?}", r.events);
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        let st = store2.load().unwrap();
        assert_eq!(st.members[&circle.members[0].dht_public_key].highest_seq, 10);
    }

    #[test]
    fn rollback_after_accepting_newer_is_a_hard_failure() {
        let (alice, circle, _d, store) = setup();
        poll(&circle, &store, Fetch::Found(fetched(&alice, 10, NOW, 3600, "new")), NOW, false);
        let r = poll(&circle, &store, Fetch::Found(fetched(&alice, 9, NOW, 3600, "old")), NOW + 1, false);
        assert_eq!(r.summary.rejected, 1);
        assert_eq!(r.summary.exit_code(), exit::VERIFY_FAILED);
        assert!(matches!(&r.events[0], Event::Rejected { reason, .. } if reason == "replay-rollback"));
        // Highest seq is not lowered by the rejected item.
        assert_eq!(store.load().unwrap().members[&circle.members[0].dht_public_key].highest_seq, 10);
    }

    #[test]
    fn unreachable_is_distinct_from_no_new_message() {
        let (alice, circle, _d, store) = setup();
        poll(&circle, &store, Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")), NOW, false);
        let r = poll(&circle, &store, Fetch::Unreachable("no DHT node answered".into()), NOW + 60, true);
        assert_eq!(r.summary.exit_code(), exit::DHT_UNAVAILABLE);
        assert!(matches!(&r.events[0], Event::Status { status: MemberStatus::Unreachable, .. }));
        // The member's last verified time survives the outage.
        let st = store.load().unwrap();
        assert_eq!(st.members[&circle.members[0].dht_public_key].last_verified_at, Some(NOW));
    }

    #[test]
    fn publisher_offline_not_found_and_expired_are_warnings_with_no_new_exit() {
        let (alice, circle, _d, store) = setup();
        let r = poll(&circle, &store, Fetch::NotFound { queried: 8, responded: 8 }, NOW, true);
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        assert!(matches!(&r.events[0], Event::Status { status: MemberStatus::NotFound, .. }));

        let stale = fetched(&alice, 11, NOW - 7200, 3600, "old news");
        let r = poll(&circle, &store, Fetch::Found(stale), NOW, true);
        assert_eq!(r.summary.expired, 1);
        assert_eq!(r.summary.exit_code(), exit::NO_NEW);
        assert!(matches!(&r.events[0], Event::Status { status: MemberStatus::Expired, .. }));
    }

    #[test]
    fn state_changes_are_announced_once_and_recovery_is_reported() {
        let (alice, circle, _d, store) = setup();
        poll(&circle, &store, Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")), NOW, false);
        let r = poll(&circle, &store, Fetch::Unreachable("t".into()), NOW + 60, false);
        assert_eq!(r.events.len(), 1);
        let r = poll(&circle, &store, Fetch::Unreachable("t".into()), NOW + 120, false);
        assert!(r.events.is_empty(), "same state again is not re-announced");
        let r = poll(&circle, &store, Fetch::Found(fetched(&alice, 10, NOW, 3600, "x")), NOW + 180, false);
        assert!(matches!(
            &r.events[0],
            Event::Status { status: MemberStatus::Ok, previous: Some(MemberStatus::Unreachable), .. }
        ));
    }

    #[test]
    fn repeated_identical_rejection_is_not_re_announced_in_follow_mode() {
        let (alice, circle, _d, store) = setup();
        let mallory = Keys::new("alice");
        let bad = Fetched { key: alice.dht.verifying_key().to_bytes(), ..fetched(&mallory, 1, NOW, 60, "x") };
        let r = poll(&circle, &store, Fetch::Found(bad.clone()), NOW, false);
        assert_eq!(r.events.len(), 1);
        let r = poll(&circle, &store, Fetch::Found(bad.clone()), NOW + 1, false);
        assert!(r.events.is_empty());
        let r = poll(&circle, &store, Fetch::Found(bad), NOW + 2, true);
        assert_eq!(r.events.len(), 1, "one-shot always reports");
    }

    #[test]
    fn exit_code_precedence() {
        let s = |new, unreachable, rejected| PollSummary { new, unreachable, rejected, members: 3, ..Default::default() };
        assert_eq!(s(0, 0, 0).exit_code(), exit::NO_NEW);
        assert_eq!(s(1, 0, 0).exit_code(), exit::OK);
        assert_eq!(s(1, 1, 0).exit_code(), exit::OK);
        assert_eq!(s(0, 1, 0).exit_code(), exit::DHT_UNAVAILABLE);
        assert_eq!(s(1, 1, 1).exit_code(), exit::VERIFY_FAILED);
    }

    #[test]
    fn preflight_checks_size_before_signing() {
        assert!(preflight("alice", "ok", 1, 1000, 60, false).is_ok());
        assert_eq!(
            preflight("alice", &"x".repeat(2000), 1, 1000, 60, false).unwrap_err().exit_code(),
            exit::BAD_MESSAGE
        );
        assert!(preflight("alice", "", 1, 1000, 60, false).is_err());
    }
}
