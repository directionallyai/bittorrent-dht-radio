//! Building signed BEP 44 items.

use mainline::{MutableItem, SigningKey};
use thiserror::Error;

use crate::item::{self, ItemError};
use crate::payload::{Payload, PayloadError};
use crate::sshsig::{self, SignError, Signer};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(transparent)]
    Payload(#[from] PayloadError),
    #[error(transparent)]
    Size(#[from] ItemError),
    #[error(transparent)]
    Sign(#[from] SignError),
}

impl BuildError {
    pub fn exit_code(&self) -> i32 {
        match self {
            BuildError::Payload(_) | BuildError::Size(_) => crate::exit::BAD_MESSAGE,
            BuildError::Sign(_) => crate::exit::SIGNING,
        }
    }
}

/// Everything needed to author items for one feed.
pub struct Identity<'a> {
    pub name: &'a str,
    pub salt: Option<&'a str>,
    pub ssh: &'a Signer,
    pub dht: &'a SigningKey,
}

/// A freshly signed item.
pub struct Built {
    pub payload: Payload,
    /// Raw BEP 44 `v` bytes.
    pub value: Vec<u8>,
    pub item: MutableItem,
}

impl Identity<'_> {
    /// Sign `message` as sequence number `seq`. The BEP 44 size limit is enforced *before* any
    /// signing happens.
    pub fn build(
        &self,
        message: &str,
        seq: i64,
        now: u64,
        ttl_secs: u64,
        prev: Option<String>,
    ) -> Result<Built, BuildError> {
        let payload = Payload {
            sender: self.name.to_string(),
            seq,
            issued_at: now,
            expires_at: now.saturating_add(ttl_secs.max(1)),
            prev,
            message: message.to_string(),
        };
        let bytes = payload.encode()?;
        item::check_payload_fits(bytes.len())?;
        let sig = self.ssh.sign(&bytes)?;
        let blob = sshsig::sig_to_blob(&sig)?;
        let value = item::encode_value(&bytes, &blob)?;
        let item = MutableItem::new(self.dht.clone(), &value, seq, self.salt.map(str::as_bytes));
        Ok(Built {
            payload,
            value,
            item,
        })
    }
}

/// Next sequence number for the feed: strictly above everything known, and never below the
/// current Unix time. Seeding from the clock keeps seq monotonic even if local state is lost.
pub fn next_seq(known_max: Option<i64>, now: u64) -> i64 {
    let floor = i64::try_from(now).unwrap_or(i64::MAX - 1);
    known_max.map_or(floor, |k| k.saturating_add(1).max(floor))
}

/// Largest message (in bytes) that fits for the given sender name and header values.
pub fn max_message_bytes(
    sender: &str,
    seq: i64,
    now: u64,
    ttl_secs: u64,
    with_prev: bool,
) -> usize {
    let one_byte = Payload {
        sender: sender.to_string(),
        seq,
        issued_at: now,
        expires_at: now + ttl_secs.max(1),
        prev: with_prev.then(|| "0".repeat(crate::payload::PREV_HEX_LEN)),
        message: "x".into(),
    };
    let header = one_byte.encode().map(|b| b.len() - 1).unwrap_or(0);
    item::MAX_RAW_V.saturating_sub(2 + item::ed25519_sshsig_len() + header)
}

#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use ssh_key::rand_core::OsRng;

    pub struct Keys {
        pub name: String,
        pub ssh: Signer,
        pub dht: SigningKey,
    }

    impl Keys {
        pub fn new(name: &str) -> Self {
            let key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
            let public = key.public_key().clone();
            let mut seed = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
            Keys {
                name: name.into(),
                ssh: Signer::File {
                    key: Box::new(key),
                    public,
                },
                dht: SigningKey::from_bytes(&seed),
            }
        }

        pub fn identity(&self) -> Identity<'_> {
            Identity {
                name: &self.name,
                salt: None,
                ssh: &self.ssh,
                dht: &self.dht,
            }
        }

        pub fn member(&self) -> crate::circle::Member {
            crate::circle::Member::new(
                &self.name,
                &sshsig::public_key_text(self.ssh.public()),
                &hex::encode(self.dht.verifying_key().to_bytes()),
                None,
            )
            .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::Keys;
    use super::*;
    use crate::item::{bencoded_len, MAX_V_BENCODED};

    #[test]
    fn builds_a_verifiable_item() {
        let k = Keys::new("alice");
        let built = k.identity().build("hi", 5, 1000, 600, None).unwrap();
        assert_eq!(built.item.seq(), 5);
        assert_eq!(built.item.value(), &built.value[..]);
        let (payload, blob) = item::decode_value(&built.value).unwrap();
        assert_eq!(
            crate::sshsig::verify_blob(k.ssh.public(), payload, blob),
            Ok(())
        );
        assert_eq!(Payload::decode(payload).unwrap(), built.payload);
    }

    #[test]
    fn message_size_boundary_exactly_1000_ok_1001_rejected() {
        let k = Keys::new("alice");
        let (seq, now, ttl) = (1_700_000_000i64, 1_700_000_000u64, 3600u64);
        let max = max_message_bytes("alice", seq, now, ttl, false);
        assert!(max > 600, "room for real messages: {max}");

        let ok = k
            .identity()
            .build(&"a".repeat(max), seq, now, ttl, None)
            .unwrap();
        assert_eq!(
            bencoded_len(ok.value.len()),
            MAX_V_BENCODED,
            "exactly 1000 bytes bencoded"
        );

        let err = k
            .identity()
            .build(&"a".repeat(max + 1), seq, now, ttl, None)
            .err()
            .unwrap();
        assert_eq!(err.exit_code(), crate::exit::BAD_MESSAGE);
        let text = err.to_string();
        assert!(text.contains("1001 bytes bencoded"), "{text}");
        assert!(text.contains("over the BEP 44 limit of 1000"), "{text}");
    }

    #[test]
    fn oversize_is_rejected_before_signing() {
        // A signer that panics if asked to sign proves the check happens first.
        let k = Keys::new("alice");
        let agent = Signer::Agent {
            socket: "/nonexistent/agent.sock".into(),
            public: k.ssh.public().clone(),
        };
        let id = Identity {
            name: "alice",
            salt: None,
            ssh: &agent,
            dht: &k.dht,
        };
        let err = id
            .build(&"x".repeat(5000), 1, 1000, 60, None)
            .err()
            .unwrap();
        assert!(matches!(err, BuildError::Size(_)), "got {err}");
    }

    #[test]
    fn multibyte_message_counts_bytes_not_chars() {
        let k = Keys::new("alice");
        let (seq, now, ttl) = (1_700_000_000i64, 1_700_000_000u64, 3600u64);
        let max = max_message_bytes("alice", seq, now, ttl, false);
        let msg = "\u{1F4E1}".repeat(max / 4);
        assert!(msg.len() <= max);
        assert!(k.identity().build(&msg, seq, now, ttl, None).is_ok());
        let too_big = "\u{1F4E1}".repeat(max / 4 + 1);
        assert!(too_big.len() > max);
        assert!(k.identity().build(&too_big, seq, now, ttl, None).is_err());
    }

    #[test]
    fn seq_is_monotonic_and_clock_seeded() {
        assert_eq!(next_seq(None, 1000), 1000);
        assert_eq!(next_seq(Some(1000), 1000), 1001);
        assert_eq!(next_seq(Some(5), 1000), 1000);
        assert_eq!(next_seq(Some(2000), 1000), 2001);
    }
}
