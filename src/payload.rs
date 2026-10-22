//! The canonical, versioned UTF-8 payload that gets SSH-signed.
//!
//! ```text
//! radio/1
//! from: alice
//! to: SHA256:...               (direct messages only: the recipient's SSH fingerprint)
//! seq: 1761142000
//! iat: 1761142000
//! exp: 1761145600
//! prev: 0123456789abcdef      (optional)
//!
//! free-form message text      (direct messages: the raw ciphertext bytes instead)
//! ```
//!
//! Decoding is strict: the bytes must be exactly what [`Payload::encode`] would produce, so a
//! payload has a single valid byte representation.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// SSHSIG namespace; verifiers must reject any other.
pub const NAMESPACE: &str = "bittorrent-dht-radio@directionally.com";
/// First line of every payload.
pub const PROTOCOL: &str = "radio/1";
pub const MAX_NAME_LEN: usize = 32;
/// Length of the hex `prev` field (first 8 bytes of the previous payload's SHA-256).
pub const PREV_HEX_LEN: usize = 16;
/// Length of an `SHA256:` SSH fingerprint (unpadded base64 of 32 bytes).
pub const FINGERPRINT_LEN: usize = 7 + 43;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub sender: String,
    /// Direct messages only: the recipient's SSH fingerprint. The body is then `sealed`, and
    /// `message` is empty.
    pub to: Option<String>,
    /// Must equal the BEP 44 `seq` of the item carrying this payload.
    pub seq: i64,
    /// Unix seconds, UTC.
    pub issued_at: u64,
    /// Unix seconds, UTC.
    pub expires_at: u64,
    /// Short hash of the previous payload from the same sender (optional chaining).
    pub prev: Option<String>,
    pub message: String,
    /// Direct messages only: the ciphertext (binary, not text), see [`crate::direct`].
    pub sealed: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("invalid sender name {0:?}: use 1-32 characters from A-Z a-z 0-9 . _ - starting with a letter or digit")]
    BadName(String),
    #[error("message is empty")]
    EmptyMessage,
    #[error("message contains a disallowed control character (U+{0:04X}); only newline and tab are allowed")]
    ControlChar(u32),
    #[error("expiry must be after the issue time")]
    ExpiryBeforeIssue,
    #[error("sequence number must be positive")]
    BadSeq,
    #[error("prev must be {PREV_HEX_LEN} lowercase hex characters")]
    BadPrev,
    #[error("recipient must be an SHA256: SSH fingerprint")]
    BadRecipient,
    #[error("malformed payload: {0}")]
    Malformed(&'static str),
    #[error("unsupported payload version {0:?}")]
    UnsupportedVersion(String),
    #[error("payload is not valid UTF-8")]
    NotUtf8,
}

pub fn validate_name(name: &str) -> Result<(), PayloadError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(PayloadError::BadName(name.to_string()))
    }
}

pub fn validate_message(message: &str) -> Result<(), PayloadError> {
    if message.is_empty() {
        return Err(PayloadError::EmptyMessage);
    }
    if let Some(c) = message
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        return Err(PayloadError::ControlChar(c as u32));
    }
    Ok(())
}

impl Payload {
    pub fn validate(&self) -> Result<(), PayloadError> {
        self.validate_header()?;
        self.validate_body()
    }

    fn validate_body(&self) -> Result<(), PayloadError> {
        if self.to.is_none() {
            if !self.sealed.is_empty() {
                return Err(PayloadError::Malformed(
                    "only a direct message has a sealed body",
                ));
            }
            return validate_message(&self.message);
        }
        if !self.message.is_empty() {
            return Err(PayloadError::Malformed(
                "a direct message's text must be sealed",
            ));
        }
        if self.sealed.is_empty() {
            return Err(PayloadError::EmptyMessage);
        }
        Ok(())
    }

    fn validate_header(&self) -> Result<(), PayloadError> {
        validate_name(&self.sender)?;
        if let Some(to) = &self.to {
            let ok = to.len() == FINGERPRINT_LEN
                && to.strip_prefix("SHA256:").is_some_and(|b| {
                    b.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
                });
            if !ok {
                return Err(PayloadError::BadRecipient);
            }
        }
        if self.seq <= 0 {
            return Err(PayloadError::BadSeq);
        }
        if self.expires_at <= self.issued_at {
            return Err(PayloadError::ExpiryBeforeIssue);
        }
        if let Some(p) = &self.prev {
            if p.len() != PREV_HEX_LEN || !p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(PayloadError::BadPrev);
            }
        }
        Ok(())
    }

    /// Canonical encoding (the bytes that get signed).
    pub fn encode(&self) -> Result<Vec<u8>, PayloadError> {
        self.validate_body()?;
        let mut bytes = self.header()?;
        bytes.extend_from_slice(self.message.as_bytes());
        bytes.extend_from_slice(&self.sealed);
        Ok(bytes)
    }

    /// Canonical encoding up to and including the blank line before the message. A direct
    /// message's ciphertext is bound to these bytes.
    pub fn header(&self) -> Result<Vec<u8>, PayloadError> {
        self.validate_header()?;
        let mut s = format!("{PROTOCOL}\nfrom: {}\n", self.sender);
        if let Some(to) = &self.to {
            s.push_str(&format!("to: {to}\n"));
        }
        s.push_str(&format!(
            "seq: {}\niat: {}\nexp: {}\n",
            self.seq, self.issued_at, self.expires_at
        ));
        if let Some(p) = &self.prev {
            s.push_str(&format!("prev: {p}\n"));
        }
        s.push('\n');
        Ok(s.into_bytes())
    }

    /// Strict decoding; rejects anything that is not byte-for-byte canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self, PayloadError> {
        // The header is text and never contains a blank line; a direct message's body is binary.
        let Some(split) = bytes.windows(2).position(|w| w == b"\n\n") else {
            std::str::from_utf8(bytes).map_err(|_| PayloadError::NotUtf8)?;
            return Err(PayloadError::Malformed("missing blank line before message"));
        };
        let head = std::str::from_utf8(&bytes[..split]).map_err(|_| PayloadError::NotUtf8)?;
        let body = &bytes[split + 2..];
        let mut lines = head.split('\n').peekable();
        let version = lines.next().unwrap_or_default();
        if version != PROTOCOL {
            return Err(PayloadError::UnsupportedVersion(
                version.chars().take(32).collect(),
            ));
        }
        let sender = field(lines.next(), "from: ")?.to_string();
        let to = match lines.peek() {
            Some(l) if l.starts_with("to: ") => Some(field(lines.next(), "to: ")?.to_string()),
            _ => None,
        };
        let seq = field(lines.next(), "seq: ")?
            .parse::<i64>()
            .map_err(|_| PayloadError::Malformed("seq is not an integer"))?;
        let issued_at = field(lines.next(), "iat: ")?
            .parse::<u64>()
            .map_err(|_| PayloadError::Malformed("iat is not an integer"))?;
        let expires_at = field(lines.next(), "exp: ")?
            .parse::<u64>()
            .map_err(|_| PayloadError::Malformed("exp is not an integer"))?;
        let prev = match lines.next() {
            None => None,
            Some(l) => Some(field(Some(l), "prev: ")?.to_string()),
        };
        if lines.next().is_some() {
            return Err(PayloadError::Malformed("unexpected extra header line"));
        }
        let (message, sealed) = if to.is_some() {
            (String::new(), body.to_vec())
        } else {
            let text = std::str::from_utf8(body).map_err(|_| PayloadError::NotUtf8)?;
            (text.to_string(), Vec::new())
        };
        let payload = Payload {
            sender,
            to,
            seq,
            issued_at,
            expires_at,
            prev,
            message,
            sealed,
        };
        // Canonical form check (rejects leading zeros, '+', non-canonical spacing, ...).
        if payload.encode()? != bytes {
            return Err(PayloadError::Malformed("not in canonical form"));
        }
        Ok(payload)
    }

    /// Full SHA-256 of the canonical encoding.
    pub fn hash(&self) -> [u8; 32] {
        payload_hash(&self.encode().expect("valid payload"))
    }

    /// Short hash used in another payload's `prev` field.
    pub fn short_hash(&self) -> String {
        hex::encode(&self.hash()[..PREV_HEX_LEN / 2])
    }
}

pub fn payload_hash(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

fn field<'a>(line: Option<&'a str>, prefix: &'static str) -> Result<&'a str, PayloadError> {
    line.and_then(|l| l.strip_prefix(prefix))
        .ok_or(PayloadError::Malformed(
            "missing or out-of-order header field",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Payload {
        Payload {
            sender: "alice".into(),
            to: None,
            seq: 7,
            issued_at: 1_700_000_000,
            expires_at: 1_700_003_600,
            prev: Some("0123456789abcdef".into()),
            message: "hello\nworld \u{1F4E1}".into(),
            sealed: Vec::new(),
        }
    }

    #[test]
    fn canonical_encoding_is_stable() {
        let bytes = sample().encode().unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "radio/1\nfrom: alice\nseq: 7\niat: 1700000000\nexp: 1700003600\nprev: 0123456789abcdef\n\nhello\nworld \u{1F4E1}"
        );
    }

    #[test]
    fn roundtrip_with_and_without_prev() {
        let mut p = sample();
        assert_eq!(Payload::decode(&p.encode().unwrap()).unwrap(), p);
        p.prev = None;
        assert_eq!(Payload::decode(&p.encode().unwrap()).unwrap(), p);
    }

    #[test]
    fn recipient_header_roundtrips_and_is_validated() {
        let mut p = sample();
        p.to = Some(format!("SHA256:{}", "A".repeat(43)));
        p.message = String::new();
        // Binary body, including bytes that are not UTF-8 and a blank-line lookalike.
        p.sealed = vec![0xff, b'\n', b'\n', 0x00, 0x1b, 0xfe];
        let bytes = p.encode().unwrap();
        let header = p.header().unwrap();
        assert!(header.starts_with(b"radio/1\nfrom: alice\nto: SHA256:AAAA"));
        assert_eq!(bytes, [&header[..], &p.sealed[..]].concat());
        assert_eq!(Payload::decode(&bytes).unwrap(), p);
        // A `to:` line after seq is out of order.
        let to_line = format!("to: SHA256:{}\n", "A".repeat(43));
        let moved = String::from_utf8(header.clone())
            .unwrap()
            .replace(&to_line, "")
            .replace("seq: 7\n", &format!("seq: 7\n{to_line}"));
        assert!(Payload::decode(&[moved.as_bytes(), &p.sealed[..]].concat()).is_err());
        // Without `to:` the body must be text; with it, the text must be sealed.
        let mut broadcast = p.clone();
        broadcast.to = None;
        assert!(broadcast.encode().is_err());
        let mut plain = p.clone();
        plain.message = "visible".into();
        assert!(plain.encode().is_err());
        p.sealed.clear();
        assert_eq!(p.encode(), Err(PayloadError::EmptyMessage));
        p.sealed = vec![1];
        p.to = Some("SHA256:short".into());
        assert_eq!(p.encode(), Err(PayloadError::BadRecipient));
    }

    #[test]
    fn message_may_contain_blank_lines_and_header_lookalikes() {
        let mut p = sample();
        p.message = "a\n\nseq: 99\n\nb".into();
        assert_eq!(Payload::decode(&p.encode().unwrap()).unwrap(), p);
    }

    #[test]
    fn rejects_non_canonical_forms() {
        let ok = String::from_utf8(sample().encode().unwrap()).unwrap();
        for bad in [
            ok.replace("seq: 7", "seq: 07"),
            ok.replace("seq: 7", "seq: +7"),
            ok.replace("from: alice", "from:  alice"),
            ok.replace("radio/1", "radio/2"),
            ok.replace("\r", "").replace("\n\n", "\r\n\r\n"),
            ok.replace("seq: 7\niat: 1700000000\n", "iat: 1700000000\nseq: 7\n"),
        ] {
            assert!(
                Payload::decode(bad.as_bytes()).is_err(),
                "accepted: {bad:?}"
            );
        }
        assert!(matches!(
            Payload::decode(&[0xff, 0xfe]),
            Err(PayloadError::NotUtf8)
        ));
    }

    #[test]
    fn validates_fields() {
        let mut p = sample();
        p.sender = "bad name".into();
        assert!(matches!(p.encode(), Err(PayloadError::BadName(_))));
        let mut p = sample();
        p.message = String::new();
        assert_eq!(p.encode(), Err(PayloadError::EmptyMessage));
        let mut p = sample();
        p.message = "esc\u{1b}[2J".into();
        assert_eq!(p.encode(), Err(PayloadError::ControlChar(0x1b)));
        let mut p = sample();
        p.expires_at = p.issued_at;
        assert_eq!(p.encode(), Err(PayloadError::ExpiryBeforeIssue));
        let mut p = sample();
        p.prev = Some("XYZ".into());
        assert_eq!(p.encode(), Err(PayloadError::BadPrev));
    }

    #[test]
    fn hash_changes_with_content() {
        let a = sample();
        let mut b = sample();
        b.message.push('!');
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.short_hash().len(), PREV_HEX_LEN);
    }
}
