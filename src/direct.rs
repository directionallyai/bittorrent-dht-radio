//! Direct messages: from one member to one other, encrypted to the recipient's SSH key.
//!
//! A direct message lives in its own BEP 44 slot under the sender's usual feed key, with a salt
//! derived from the recipient's SSH key ([`slot_salt`]), so it never replaces the sender's
//! broadcast and every recipient has a separate slot. The item is an ordinary signed radio item
//! whose payload carries a `to:` header (the recipient's SSH fingerprint) and, as message text,
//! `base64(E || ChaCha20-Poly1305(plaintext))`:
//!
//! * the recipient's Ed25519 SSH key is mapped to X25519 (the same conversion `age` uses for
//!   `ssh-ed25519` recipients);
//! * `E` is a fresh ephemeral X25519 key; key and nonce come from HKDF-SHA256 over the shared
//!   secret, salted with `E || recipient`;
//! * the associated data is the signed payload header (from, to, seq, iat, exp), so the
//!   ciphertext cannot be lifted into someone else's signed item.
//!
//! Decrypting needs the recipient's private key *file*: ssh-agent can sign but cannot do X25519.

use base64ct::{Base64, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::MontgomeryPoint;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use ssh_key::{PrivateKey, PublicKey};
use thiserror::Error;

const KDF_INFO: &[u8] = b"bittorrent-dht-radio direct/1";
const SALT_DOMAIN: &[u8] = b"radio-direct-slot/1\n";
const EPHEMERAL_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Bytes added to the plaintext before base64: ephemeral key and AEAD tag.
pub const OVERHEAD: usize = EPHEMERAL_LEN + TAG_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectError {
    #[error("recipient key is not a usable Ed25519 key: {0}")]
    BadRecipient(String),
    #[error("the ciphertext is not valid base64")]
    Encoding,
    #[error("ciphertext too short")]
    Truncated,
    #[error("decryption failed: not encrypted to this key, or modified")]
    Decrypt,
}

/// BEP 44 salt of the slot where `sender_salt`'s owner puts direct messages for `recipient`.
pub fn slot_salt(sender_salt: Option<&str>, recipient: &PublicKey) -> String {
    let mut h = Sha256::new();
    h.update(SALT_DOMAIN);
    h.update(sender_salt.unwrap_or("").as_bytes());
    h.update(b"\n");
    h.update(crate::sshsig::public_key_text(recipient).as_bytes());
    format!("dm1-{}", hex::encode(&h.finalize()[..16]))
}

/// Length of the base64 text that [`seal`] produces for a plaintext of `len` bytes.
pub fn sealed_len(len: usize) -> usize {
    (len + OVERHEAD).div_ceil(3) * 4
}

/// Largest plaintext whose sealed form fits in `text_room` bytes of message text.
pub fn max_plaintext(text_room: usize) -> usize {
    (text_room / 4 * 3).saturating_sub(OVERHEAD)
}

fn montgomery(key: &PublicKey) -> Result<MontgomeryPoint, DirectError> {
    let ed = key
        .key_data()
        .ed25519()
        .ok_or_else(|| DirectError::BadRecipient(format!("{} key", key.algorithm())))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&ed.0)
        .map_err(|e| DirectError::BadRecipient(e.to_string()))?;
    Ok(vk.to_montgomery())
}

fn cipher(
    shared: &MontgomeryPoint,
    ephemeral: &[u8],
    recipient: &[u8],
) -> (ChaCha20Poly1305, [u8; 12]) {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral);
    salt.extend_from_slice(recipient);
    let mut okm = [0u8; 44];
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(KDF_INFO, &mut okm)
        .expect("44 bytes is a valid HKDF-SHA256 length");
    let key = ChaCha20Poly1305::new_from_slice(&okm[..32]).expect("32-byte key");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

/// Encrypt `plaintext` to `recipient`, binding it to `header` (the signed payload header).
pub fn seal(recipient: &PublicKey, header: &[u8], plaintext: &[u8]) -> Result<String, DirectError> {
    let r = montgomery(recipient)?;
    let mut e = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut e);
    let ephemeral = MontgomeryPoint::mul_base_clamped(e);
    let shared = r.mul_clamped(e);
    if shared.as_bytes() == &[0u8; 32] {
        return Err(DirectError::BadRecipient("low-order point".into()));
    }
    let (aead, nonce) = cipher(&shared, ephemeral.as_bytes(), r.as_bytes());
    let ct = aead
        .encrypt(
            &nonce.into(),
            AeadPayload {
                msg: plaintext,
                aad: header,
            },
        )
        .map_err(|_| DirectError::Decrypt)?;
    let mut out = Vec::with_capacity(EPHEMERAL_LEN + ct.len());
    out.extend_from_slice(ephemeral.as_bytes());
    out.extend_from_slice(&ct);
    Ok(Base64::encode_string(&out))
}

/// The recipient's side: an X25519 secret derived from their Ed25519 SSH private key.
pub struct Opener {
    scalar: [u8; 32],
    point: MontgomeryPoint,
}

impl Opener {
    pub fn from_private_key(key: &PrivateKey) -> Result<Self, DirectError> {
        let pair = key
            .key_data()
            .ed25519()
            .ok_or_else(|| DirectError::BadRecipient(format!("{} key", key.algorithm())))?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&pair.private.to_bytes());
        Ok(Opener {
            scalar: sk.to_scalar_bytes(),
            point: sk.verifying_key().to_montgomery(),
        })
    }

    /// Decrypt the base64 `body` produced by [`seal`] for the same `header`.
    pub fn open(&self, header: &[u8], body: &str) -> Result<Vec<u8>, DirectError> {
        let raw = Base64::decode_vec(body).map_err(|_| DirectError::Encoding)?;
        if raw.len() < OVERHEAD {
            return Err(DirectError::Truncated);
        }
        let (eph, ct) = raw.split_at(EPHEMERAL_LEN);
        let eph = MontgomeryPoint(eph.try_into().expect("32 bytes"));
        let shared = eph.mul_clamped(self.scalar);
        if shared.as_bytes() == &[0u8; 32] {
            return Err(DirectError::Decrypt);
        }
        let (aead, nonce) = cipher(&shared, eph.as_bytes(), self.point.as_bytes());
        aead.decrypt(
            &nonce.into(),
            AeadPayload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| DirectError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    fn key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn seal_open_roundtrip_with_predicted_length() {
        let bob = key();
        let body = seal(bob.public_key(), b"hdr", "hi bob \u{1F4E1}".as_bytes()).unwrap();
        assert_eq!(body.len(), sealed_len("hi bob \u{1F4E1}".len()));
        let plain = Opener::from_private_key(&bob)
            .unwrap()
            .open(b"hdr", &body)
            .unwrap();
        assert_eq!(plain, "hi bob \u{1F4E1}".as_bytes());
    }

    #[test]
    fn fresh_ephemeral_key_every_time() {
        let bob = key();
        let a = seal(bob.public_key(), b"h", b"same").unwrap();
        let b = seal(bob.public_key(), b"h", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_wrong_header_or_tampering_fail() {
        let (bob, eve) = (key(), key());
        let body = seal(bob.public_key(), b"from: alice", b"secret").unwrap();
        let eve = Opener::from_private_key(&eve).unwrap();
        assert_eq!(eve.open(b"from: alice", &body), Err(DirectError::Decrypt));
        let bob = Opener::from_private_key(&bob).unwrap();
        assert_eq!(bob.open(b"from: mallory", &body), Err(DirectError::Decrypt));
        let mut raw = Base64::decode_vec(&body).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        assert_eq!(
            bob.open(b"from: alice", &Base64::encode_string(&raw)),
            Err(DirectError::Decrypt)
        );
        assert_eq!(
            bob.open(b"from: alice", "not base64!"),
            Err(DirectError::Encoding)
        );
        assert_eq!(
            bob.open(b"from: alice", "AAAA"),
            Err(DirectError::Truncated)
        );
    }

    #[test]
    fn slot_salt_is_per_recipient_and_per_sender_feed() {
        let (bob, carol) = (key(), key());
        let s = slot_salt(None, bob.public_key());
        assert!(s.starts_with("dm1-") && s.len() <= 64, "{s}");
        assert_eq!(s, slot_salt(None, bob.public_key()));
        assert_ne!(s, slot_salt(None, carol.public_key()));
        assert_ne!(s, slot_salt(Some("daily"), bob.public_key()));
    }

    #[test]
    fn max_plaintext_inverts_sealed_len() {
        for room in 64..700 {
            let n = max_plaintext(room);
            assert!(sealed_len(n) <= room, "room {room}");
            assert!(sealed_len(n + 1) > room, "room {room}");
        }
    }
}
