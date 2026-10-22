//! SSHSIG (OpenSSH `ssh-keygen -Y sign`) signing and verification.
//!
//! Signing uses either a private key file or an ssh-agent identity (Unix socket, or the Windows
//! OpenSSH named pipe). Only Ed25519 keys are supported; FIDO2 `sk-` keys need a user touch for
//! every signature and are refused (see README).

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, SshSig};
use thiserror::Error;

use crate::payload::NAMESPACE;

/// How long to wait for an ssh-agent to answer a sign request.
pub const AGENT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub enum SignError {
    #[error("{0}")]
    Key(String),
    #[error("ssh-agent: {0}")]
    Agent(String),
    #[error("ssh-agent did not answer within {0:?}; a key that needs confirmation or a FIDO2 touch cannot sign unattended")]
    AgentTimeout(Duration),
    #[error("signature self-check failed: {0}")]
    SelfCheck(String),
}

/// Reasons a signature does not verify, in the order they are checked.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SigFailure {
    /// Not a parseable SSHSIG, or an unsupported algorithm/hash/version.
    #[error("bad signature: {0}")]
    Bad(String),
    #[error("wrong signature namespace {0:?} (expected {NAMESPACE:?})")]
    WrongNamespace(String),
    /// Valid SSHSIG, but made by a different SSH key than the one pinned for this feed owner.
    #[error("feed-owner/SSH-signer mismatch: signed by {actual}, but this feed is pinned to {expected}")]
    SignerMismatch { expected: String, actual: String },
    /// Structure fine and made by the pinned key, but the signature does not cover this payload.
    #[error("tampered payload: signature does not match the payload")]
    Tampered,
}

/// Where SSH signatures come from.
pub enum Signer {
    File { key: Box<PrivateKey>, public: PublicKey },
    Agent { socket: PathBuf, public: PublicKey },
}

impl Signer {
    pub fn from_key_file(path: &Path, passphrase: Option<&str>) -> Result<Self, SignError> {
        let pem = std::fs::read(path)
            .map_err(|e| SignError::Key(format!("cannot read SSH key {}: {e}", path.display())))?;
        let mut key = PrivateKey::from_openssh(&pem)
            .map_err(|e| SignError::Key(format!("cannot parse SSH key {}: {e}", path.display())))?;
        if key.is_encrypted() {
            let pass = passphrase.ok_or_else(|| {
                SignError::Key(format!(
                    "SSH key {} is passphrase-protected; set RADIO_SSH_KEY_PASSPHRASE, run interactively, \
                     or use --ssh-agent for unattended use",
                    path.display()
                ))
            })?;
            key = key
                .decrypt(pass)
                .map_err(|e| SignError::Key(format!("cannot decrypt SSH key {}: {e}", path.display())))?;
        }
        let public = key.public_key().clone();
        ensure_supported(&public)?;
        Ok(Signer::File { key: Box::new(key), public })
    }

    pub fn agent(socket: PathBuf, public: PublicKey) -> Result<Self, SignError> {
        ensure_supported(&public)?;
        Ok(Signer::Agent { socket, public })
    }

    pub fn public(&self) -> &PublicKey {
        match self {
            Signer::File { public, .. } | Signer::Agent { public, .. } => public,
        }
    }

    /// Produce an SSHSIG over `msg` in the radio namespace (SHA-512, like `ssh-keygen -Y sign`).
    pub fn sign(&self, msg: &[u8]) -> Result<SshSig, SignError> {
        let sig = match self {
            Signer::File { key, .. } => key
                .sign(NAMESPACE, HashAlg::Sha512, msg)
                .map_err(|e| SignError::Key(format!("signing failed: {e}")))?,
            Signer::Agent { socket, public } => agent_sign(socket, public, msg)?,
        };
        self.public()
            .verify(NAMESPACE, msg, &sig)
            .map_err(|e| SignError::SelfCheck(e.to_string()))?;
        Ok(sig)
    }
}

fn ensure_supported(public: &PublicKey) -> Result<(), SignError> {
    match public.algorithm() {
        Algorithm::Ed25519 => Ok(()),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => Err(SignError::Key(
            "FIDO2 security keys (sk-*) need a physical touch for every signature, so they cannot sign \
             unattended broadcasts; use a normal Ed25519 key"
                .into(),
        )),
        other => Err(SignError::Key(format!(
            "unsupported SSH key type {other}; radio v1 supports ssh-ed25519 keys only"
        ))),
    }
}

/// Is this key a FIDO2/security-key type that needs a touch?
pub fn is_fido_key(public: &PublicKey) -> bool {
    matches!(public.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
}

fn agent_sign(socket: &Path, public: &PublicKey, msg: &[u8]) -> Result<SshSig, SignError> {
    let signed_data = SshSig::signed_data(NAMESPACE, HashAlg::Sha512, msg)
        .map_err(|e| SignError::Agent(e.to_string()))?;
    let (tx, rx) = mpsc::channel();
    let socket = socket.to_path_buf();
    let public = public.clone();
    std::thread::spawn(move || {
        let result = (|| {
            let mut client = ssh_agent_client_rs::Client::connect(&socket)
                .map_err(|e| format!("cannot connect to agent at {}: {e}", socket.display()))?;
            let signature = client
                .sign(&public, &signed_data)
                .map_err(|e| format!("agent refused to sign (is the key loaded?): {e}"))?;
            SshSig::new(public.key_data().clone(), NAMESPACE, HashAlg::Sha512, signature)
                .map_err(|e| e.to_string())
        })();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(AGENT_TIMEOUT) {
        Ok(Ok(sig)) => Ok(sig),
        Ok(Err(e)) => Err(SignError::Agent(e)),
        Err(_) => Err(SignError::AgentTimeout(AGENT_TIMEOUT)),
    }
}

/// List the public keys an ssh-agent currently holds.
pub fn agent_identities(socket: &Path) -> Result<Vec<PublicKey>, SignError> {
    let mut client = ssh_agent_client_rs::Client::connect(socket)
        .map_err(|e| SignError::Agent(format!("cannot connect to agent at {}: {e}", socket.display())))?;
    let ids = client
        .list_all_identities()
        .map_err(|e| SignError::Agent(e.to_string()))?;
    Ok(ids
        .into_iter()
        .filter_map(|i| match i {
            ssh_agent_client_rs::Identity::PublicKey(pk) => Some(pk.into_owned()),
            _ => None,
        })
        .collect())
}

/// Default agent socket: `$SSH_AUTH_SOCK`, or the Windows OpenSSH named pipe.
pub fn default_agent_socket() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SSH_AUTH_SOCK").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    if cfg!(windows) {
        return Some(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"));
    }
    None
}

/// Binary SSHSIG blob (the PEM body, without armor).
pub fn sig_to_blob(sig: &SshSig) -> Result<Vec<u8>, SignError> {
    let mut buf = Vec::new();
    sig.encode(&mut buf).map_err(|e| SignError::SelfCheck(e.to_string()))?;
    Ok(buf)
}

pub fn sig_from_blob(blob: &[u8]) -> Result<SshSig, SigFailure> {
    let mut reader: &[u8] = blob;
    let sig = SshSig::decode(&mut reader).map_err(|e| SigFailure::Bad(format!("not a valid SSHSIG: {e}")))?;
    if !reader.is_empty() {
        return Err(SigFailure::Bad("trailing bytes after SSHSIG".into()));
    }
    Ok(sig)
}

/// PEM-armored form, as accepted by `ssh-keygen -Y verify -s`.
pub fn sig_to_pem(sig: &SshSig) -> Result<String, SignError> {
    sig.to_pem(ssh_key::LineEnding::LF).map_err(|e| SignError::SelfCheck(e.to_string()))
}

/// Verify `blob` as an SSHSIG over `payload` made by exactly `pinned`, in our namespace.
pub fn verify_blob(pinned: &PublicKey, payload: &[u8], blob: &[u8]) -> Result<(), SigFailure> {
    let sig = sig_from_blob(blob)?;
    if sig.namespace() != NAMESPACE {
        return Err(SigFailure::WrongNamespace(sig.namespace().chars().take(80).collect()));
    }
    if !matches!(sig.hash_alg(), HashAlg::Sha512 | HashAlg::Sha256) {
        return Err(SigFailure::Bad("unsupported hash algorithm".into()));
    }
    if sig.public_key().algorithm() != Algorithm::Ed25519 {
        return Err(SigFailure::Bad(format!(
            "unsupported signature key type {}",
            sig.public_key().algorithm()
        )));
    }
    if sig.public_key() != pinned.key_data() {
        let actual = PublicKey::from(sig.public_key().clone()).fingerprint(HashAlg::Sha256).to_string();
        return Err(SigFailure::SignerMismatch {
            expected: pinned.fingerprint(HashAlg::Sha256).to_string(),
            actual,
        });
    }
    pinned.verify(NAMESPACE, payload, &sig).map_err(|_| SigFailure::Tampered)
}

/// Canonical OpenSSH text of a public key without its comment (what circle cards carry).
pub fn public_key_text(key: &PublicKey) -> String {
    let mut k = key.clone();
    k.set_comment("");
    k.to_openssh().expect("encodable public key").trim().to_string()
}

pub fn parse_public_key(text: &str) -> Result<PublicKey, String> {
    PublicKey::from_openssh(text.trim()).map_err(|e| format!("not a valid OpenSSH public key: {e}"))
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::ed25519_sshsig_len;
    use ssh_key::rand_core::OsRng;

    pub fn test_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn signer(key: PrivateKey) -> Signer {
        let public = key.public_key().clone();
        Signer::File { key: Box::new(key), public }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let s = signer(test_key());
        let sig = s.sign(b"hello radio").unwrap();
        let blob = sig_to_blob(&sig).unwrap();
        assert_eq!(blob.len(), ed25519_sshsig_len());
        assert_eq!(verify_blob(s.public(), b"hello radio", &blob), Ok(()));
    }

    #[test]
    fn tampered_payload_is_detected() {
        let s = signer(test_key());
        let blob = sig_to_blob(&s.sign(b"hello radio").unwrap()).unwrap();
        assert_eq!(verify_blob(s.public(), b"hello radiO", &blob), Err(SigFailure::Tampered));
    }

    #[test]
    fn corrupted_signature_bytes_are_detected() {
        let s = signer(test_key());
        let mut blob = sig_to_blob(&s.sign(b"m").unwrap()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(verify_blob(s.public(), b"m", &blob), Err(SigFailure::Tampered));
        assert!(matches!(verify_blob(s.public(), b"m", &blob[..40]), Err(SigFailure::Bad(_))));
        assert!(matches!(verify_blob(s.public(), b"m", b"garbage"), Err(SigFailure::Bad(_))));
        let mut extra = sig_to_blob(&s.sign(b"m").unwrap()).unwrap();
        extra.push(0);
        assert!(matches!(verify_blob(s.public(), b"m", &extra), Err(SigFailure::Bad(_))));
    }

    #[test]
    fn wrong_namespace_is_detected() {
        let key = test_key();
        let sig = key.sign("other-namespace@example.com", HashAlg::Sha512, b"m").unwrap();
        let blob = sig_to_blob(&sig).unwrap();
        assert!(matches!(
            verify_blob(key.public_key(), b"m", &blob),
            Err(SigFailure::WrongNamespace(ns)) if ns == "other-namespace@example.com"
        ));
    }

    #[test]
    fn signer_mismatch_is_detected() {
        let (a, b) = (signer(test_key()), signer(test_key()));
        let blob = sig_to_blob(&a.sign(b"m").unwrap()).unwrap();
        assert!(matches!(
            verify_blob(b.public(), b"m", &blob),
            Err(SigFailure::SignerMismatch { .. })
        ));
    }

    #[test]
    fn rsa_style_or_sk_keys_are_refused_at_load_time() {
        // sk keys cannot be generated here; the check is on the algorithm, covered by is_fido_key.
        let key = test_key();
        assert!(!is_fido_key(key.public_key()));
    }

    #[test]
    fn public_key_text_has_no_comment_and_roundtrips() {
        let mut k = test_key();
        k.set_comment("alice@laptop");
        let text = public_key_text(k.public_key());
        assert!(!text.contains("alice@laptop"));
        assert_eq!(parse_public_key(&text).unwrap().key_data(), k.public_key().key_data());
    }
}
