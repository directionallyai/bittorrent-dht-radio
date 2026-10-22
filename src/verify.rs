//! Verification of a fetched BEP 44 item using only local state.
//!
//! Nothing learned from the DHT is trusted: the feed key must be pinned, the SSHSIG must verify
//! against the pinned SSH key of that member in our namespace, and sender/seq inside the signed
//! payload must agree with the pinned name and the BEP 44 seq.

use thiserror::Error;

use crate::circle::{Circle, Member};
use crate::item;
use crate::payload::Payload;
use crate::sshsig::{self, SigFailure};
use crate::util::format_utc;

/// A mutable item as returned by the DHT.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub key: [u8; 32],
    pub salt: Option<Vec<u8>>,
    pub seq: i64,
    pub value: Vec<u8>,
}

impl From<&mainline::MutableItem> for Fetched {
    fn from(i: &mainline::MutableItem) -> Self {
        Fetched { key: *i.key(), salt: i.salt().map(<[u8]>::to_vec), seq: i.seq(), value: i.value().to_vec() }
    }
}

/// What we remember about a signer from earlier polls.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub highest_seq: i64,
    pub payload_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Reject {
    #[error("unknown publisher {key}: not in the pinned circle")]
    UnknownPublisher { key: String },
    #[error("feed salt mismatch: pinned {expected:?}, item has {actual:?}")]
    SaltMismatch { expected: Option<String>, actual: Option<String> },
    #[error("malformed value: {0}")]
    MalformedValue(String),
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("tampered payload: the SSH signature does not match the payload")]
    TamperedPayload,
    #[error("wrong signature namespace {0:?}")]
    WrongNamespace(String),
    #[error("feed-owner/SSH-signer mismatch: signed by {actual}, but this feed is pinned to {expected}")]
    SignerMismatch { expected: String, actual: String },
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
    #[error("sender mismatch: payload says {actual:?}, pinned member is {expected:?}")]
    SenderMismatch { expected: String, actual: String },
    #[error("seq mismatch: payload seq {payload} != BEP 44 seq {item}")]
    SeqMismatch { item: i64, payload: i64 },
    #[error("issued-at {issued_at} ({issued}) is {ahead}s in the future, beyond the allowed clock skew of {skew}s (check both clocks)")]
    ClockSkew { issued_at: u64, issued: String, ahead: u64, skew: u64 },
    #[error("replay/rollback: seq {seq} is below the highest accepted seq {highest}")]
    Rollback { seq: i64, highest: i64 },
    #[error("seq {seq} was already accepted with different content (equivocation or replay)")]
    SeqReuse { seq: i64 },
    #[error("expired at {expires} ({ago}s ago)")]
    Expired { expires_at: u64, expires: String, ago: u64 },
}

impl Reject {
    /// Stable machine-readable reason.
    pub fn code(&self) -> &'static str {
        match self {
            Reject::UnknownPublisher { .. } => "unknown-publisher",
            Reject::SaltMismatch { .. } => "salt-mismatch",
            Reject::MalformedValue(_) => "malformed-value",
            Reject::BadSignature(_) => "bad-signature",
            Reject::TamperedPayload => "tampered-payload",
            Reject::WrongNamespace(_) => "wrong-namespace",
            Reject::SignerMismatch { .. } => "signer-mismatch",
            Reject::MalformedPayload(_) => "malformed-payload",
            Reject::SenderMismatch { .. } => "sender-mismatch",
            Reject::SeqMismatch { .. } => "seq-mismatch",
            Reject::ClockSkew { .. } => "clock-skew",
            Reject::Rollback { .. } => "replay-rollback",
            Reject::SeqReuse { .. } => "seq-reuse",
            Reject::Expired { .. } => "expired",
        }
    }

    /// An expired record is the normal sign of an offline publisher, not an attack: it is
    /// reported as a stale warning rather than a verification failure.
    pub fn is_soft(&self) -> bool {
        matches!(self, Reject::Expired { .. })
    }
}

#[derive(Debug, Clone)]
pub struct Accepted {
    pub member: Member,
    pub payload: Payload,
    pub payload_sha256: String,
}

#[derive(Debug, Clone)]
pub enum Verdict {
    /// Verified and not seen before.
    New(Accepted),
    /// Verified, but the same content was already accepted earlier (dedup).
    Seen(Accepted),
}

/// Verify `fetched` against the pinned circle and what has been accepted so far.
pub fn verify_item(
    circle: &Circle,
    seen: &Seen,
    fetched: &Fetched,
    now: u64,
    skew_secs: u64,
) -> Result<Verdict, Reject> {
    let member = circle
        .find_by_dht_key(&fetched.key)
        .ok_or_else(|| Reject::UnknownPublisher { key: hex::encode(fetched.key) })?;
    verify_for_member(member, seen, fetched, now, skew_secs)
}

/// Same as [`verify_item`] when the pinned member is already known (it must own `fetched.key`).
pub fn verify_for_member(
    member: &Member,
    seen: &Seen,
    fetched: &Fetched,
    now: u64,
    skew_secs: u64,
) -> Result<Verdict, Reject> {
    if member.dht_key().ok() != Some(fetched.key) {
        return Err(Reject::UnknownPublisher { key: hex::encode(fetched.key) });
    }
    if member.salt.as_deref().map(str::as_bytes) != fetched.salt.as_deref() {
        return Err(Reject::SaltMismatch {
            expected: member.salt.clone(),
            actual: fetched.salt.as_ref().map(|s| String::from_utf8_lossy(s).into_owned()),
        });
    }

    let (payload_bytes, blob) =
        item::decode_value(&fetched.value).map_err(|e| Reject::MalformedValue(e.to_string()))?;

    let pinned = member.ssh_key().map_err(|e| Reject::BadSignature(e.to_string()))?;
    sshsig::verify_blob(&pinned, payload_bytes, blob).map_err(|f| match f {
        SigFailure::Bad(m) => Reject::BadSignature(m),
        SigFailure::WrongNamespace(ns) => Reject::WrongNamespace(ns),
        SigFailure::SignerMismatch { expected, actual } => Reject::SignerMismatch { expected, actual },
        SigFailure::Tampered => Reject::TamperedPayload,
    })?;

    // From here on the payload is authentic: it was signed by the pinned SSH key.
    let payload = Payload::decode(payload_bytes).map_err(|e| Reject::MalformedPayload(e.to_string()))?;
    if payload.sender != member.name {
        return Err(Reject::SenderMismatch { expected: member.name.clone(), actual: payload.sender });
    }
    if payload.seq != fetched.seq {
        return Err(Reject::SeqMismatch { item: fetched.seq, payload: payload.seq });
    }
    if payload.issued_at > now.saturating_add(skew_secs) {
        return Err(Reject::ClockSkew {
            issued_at: payload.issued_at,
            issued: format_utc(payload.issued_at),
            ahead: payload.issued_at - now,
            skew: skew_secs,
        });
    }

    let sha = hex::encode(payload.hash());
    let mut already_seen = false;
    if fetched.seq < seen.highest_seq {
        return Err(Reject::Rollback { seq: fetched.seq, highest: seen.highest_seq });
    }
    if fetched.seq == seen.highest_seq {
        match &seen.payload_sha256 {
            Some(prev) if *prev != sha => return Err(Reject::SeqReuse { seq: fetched.seq }),
            Some(_) => already_seen = true,
            None => {}
        }
    }
    if now >= payload.expires_at {
        return Err(Reject::Expired {
            expires_at: payload.expires_at,
            expires: format_utc(payload.expires_at),
            ago: now - payload.expires_at,
        });
    }

    let accepted = Accepted { member: member.clone(), payload, payload_sha256: sha };
    Ok(if already_seen { Verdict::Seen(accepted) } else { Verdict::New(accepted) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::testkit::Keys;
    use crate::publish::{Built, Identity};
    use crate::sshsig::Signer;

    const NOW: u64 = 1_700_000_000;

    struct Setup {
        alice: Keys,
        circle: Circle,
    }

    fn setup() -> Setup {
        let alice = Keys::new("alice");
        let mut circle = Circle::default();
        circle.add(alice.member()).unwrap();
        Setup { alice, circle }
    }

    fn fetched(b: &Built, key: &Keys) -> Fetched {
        Fetched {
            key: key.dht.verifying_key().to_bytes(),
            salt: None,
            seq: b.item.seq(),
            value: b.item.value().to_vec(),
        }
    }

    fn good(s: &Setup, seq: i64, issued: u64, ttl: u64) -> Built {
        s.alice.identity().build("hello", seq, issued, ttl, None).unwrap()
    }

    fn check(s: &Setup, seen: &Seen, f: &Fetched) -> Result<Verdict, Reject> {
        verify_item(&s.circle, seen, f, NOW, 120)
    }

    #[test]
    fn accepts_a_good_new_message() {
        let s = setup();
        let b = good(&s, 10, NOW - 5, 3600);
        match check(&s, &Seen::default(), &fetched(&b, &s.alice)).unwrap() {
            Verdict::New(a) => {
                assert_eq!(a.member.name, "alice");
                assert_eq!(a.payload.message, "hello");
            }
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn already_accepted_is_seen_not_new() {
        let s = setup();
        let b = good(&s, 10, NOW - 5, 3600);
        let f = fetched(&b, &s.alice);
        let Verdict::New(a) = check(&s, &Seen::default(), &f).unwrap() else { panic!() };
        let seen = Seen { highest_seq: 10, payload_sha256: Some(a.payload_sha256) };
        assert!(matches!(check(&s, &seen, &f).unwrap(), Verdict::Seen(_)));
    }

    #[test]
    fn unknown_publisher() {
        let s = setup();
        let mallory = Keys::new("alice"); // same name, different keys
        let b = mallory.identity().build("x", 1, NOW, 60, None).unwrap();
        let err = check(&s, &Seen::default(), &fetched(&b, &mallory)).unwrap_err();
        assert_eq!(err.code(), "unknown-publisher");
    }

    #[test]
    fn bad_signature_malformed_blob() {
        let s = setup();
        let b = good(&s, 3, NOW, 3600);
        let mut f = fetched(&b, &s.alice);
        // Keep the framing intact but replace the SSHSIG with garbage of the same length.
        let plen = u16::from_be_bytes([f.value[0], f.value[1]]) as usize;
        for byte in &mut f.value[2 + plen..] {
            *byte = 0x41;
        }
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "bad-signature");
        // Truncated framing is a malformed value.
        f.value.truncate(1);
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "malformed-value");
    }

    #[test]
    fn tampered_payload() {
        let s = setup();
        let b = good(&s, 3, NOW, 3600);
        let mut f = fetched(&b, &s.alice);
        let idx = 2 + b.payload.encode().unwrap().len() - 1; // last message byte
        f.value[idx] ^= 0x01;
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "tampered-payload");
    }

    #[test]
    fn signer_mismatch_when_feed_owner_signs_with_someone_elses_ssh_key() {
        let s = setup();
        // Alice's DHT feed key, but the payload is signed by a different SSH key.
        let other_ssh = Keys::new("alice");
        let id = Identity { name: "alice", salt: None, ssh: &other_ssh.ssh, dht: &s.alice.dht };
        let b = id.build("x", 4, NOW, 60, None).unwrap();
        assert_eq!(check(&s, &Seen::default(), &fetched(&b, &s.alice)).unwrap_err().code(), "signer-mismatch");
    }

    #[test]
    fn wrong_namespace() {
        let s = setup();
        let payload = Payload {
            sender: "alice".into(),
            seq: 4,
            issued_at: NOW,
            expires_at: NOW + 60,
            prev: None,
            message: "x".into(),
        }
        .encode()
        .unwrap();
        let Signer::File { key, .. } = &s.alice.ssh else { unreachable!() };
        let sig = key.sign("someone-else@example.com", ssh_key::HashAlg::Sha512, &payload).unwrap();
        let value = item::encode_value(&payload, &sshsig::sig_to_blob(&sig).unwrap()).unwrap();
        let f = Fetched { key: s.alice.dht.verifying_key().to_bytes(), salt: None, seq: 4, value };
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "wrong-namespace");
    }

    #[test]
    fn sender_mismatch() {
        let s = setup();
        let id = Identity { name: "bob", salt: None, ssh: &s.alice.ssh, dht: &s.alice.dht };
        let b = id.build("x", 4, NOW, 60, None).unwrap();
        assert_eq!(check(&s, &Seen::default(), &fetched(&b, &s.alice)).unwrap_err().code(), "sender-mismatch");
    }

    #[test]
    fn seq_mismatch_between_payload_and_bep44() {
        let s = setup();
        let b = good(&s, 4, NOW, 60);
        let mut f = fetched(&b, &s.alice);
        f.seq = 5;
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "seq-mismatch");
    }

    #[test]
    fn expired_is_soft() {
        let s = setup();
        let b = good(&s, 4, NOW - 7200, 3600);
        let err = check(&s, &Seen::default(), &fetched(&b, &s.alice)).unwrap_err();
        assert_eq!(err.code(), "expired");
        assert!(err.is_soft());
        assert!(matches!(err, Reject::Expired { ago: 3600, .. }));
    }

    #[test]
    fn clock_skew_tolerance_and_report() {
        let s = setup();
        // Within tolerance: accepted.
        let ok = good(&s, 4, NOW + 100, 3600);
        assert!(check(&s, &Seen::default(), &fetched(&ok, &s.alice)).is_ok());
        // Beyond tolerance: reported with the amount.
        let bad = good(&s, 5, NOW + 500, 3600);
        let err = check(&s, &Seen::default(), &fetched(&bad, &s.alice)).unwrap_err();
        assert!(matches!(err, Reject::ClockSkew { ahead: 500, skew: 120, .. }), "{err:?}");
        assert!(!err.is_soft());
        // A larger configured tolerance accepts it.
        assert!(verify_item(&s.circle, &Seen::default(), &fetched(&bad, &s.alice), NOW, 600).is_ok());
    }

    #[test]
    fn replay_rollback_and_seq_reuse() {
        let s = setup();
        let old = good(&s, 5, NOW - 10, 3600);
        let seen = Seen { highest_seq: 9, payload_sha256: Some("aa".into()) };
        let err = check(&s, &seen, &fetched(&old, &s.alice)).unwrap_err();
        assert!(matches!(err, Reject::Rollback { seq: 5, highest: 9 }));
        assert_eq!(err.code(), "replay-rollback");

        let same_seq_other_content = good(&s, 9, NOW - 10, 3600);
        let err = check(&s, &seen, &fetched(&same_seq_other_content, &s.alice)).unwrap_err();
        assert_eq!(err.code(), "seq-reuse");
    }

    #[test]
    fn salt_must_match_the_pinned_feed() {
        let s = setup();
        let b = good(&s, 4, NOW, 60);
        let mut f = fetched(&b, &s.alice);
        f.salt = Some(b"other".to_vec());
        assert_eq!(check(&s, &Seen::default(), &f).unwrap_err().code(), "salt-mismatch");
    }

    #[test]
    fn expired_replay_of_already_accepted_message_is_expired_not_new() {
        let s = setup();
        let b = good(&s, 4, NOW - 7200, 3600);
        let f = fetched(&b, &s.alice);
        let sha = hex::encode(Payload::decode(item::decode_value(&f.value).unwrap().0).unwrap().hash());
        let seen = Seen { highest_seq: 4, payload_sha256: Some(sha) };
        assert_eq!(check(&s, &seen, &f).unwrap_err().code(), "expired");
    }
}
