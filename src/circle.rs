//! The locally pinned circle: name -> SSH public key -> DHT publisher public key (+ salt).
//!
//! Nothing in the circle is ever learned from the DHT. Cards are exchanged out of band.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::payload::validate_name;
use crate::sshsig;
use crate::util::write_atomic;

pub const CARD_VERSION: u32 = 1;

/// A member entry, and also the shareable "circle card" (same fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub name: String,
    /// OpenSSH public key line, without comment.
    pub ssh_public_key: String,
    /// 32-byte Ed25519 BEP 44 publisher key, 64 hex characters.
    pub dht_public_key: String,
    /// Optional BEP 44 salt identifying the feed under that key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CardFile {
    radio_card: u32,
    #[serde(flatten)]
    member: Member,
}

impl Member {
    pub fn new(
        name: &str,
        ssh_public_key: &str,
        dht_public_key: &str,
        salt: Option<&str>,
    ) -> Result<Self> {
        let ssh = sshsig::parse_public_key(ssh_public_key).map_err(|e| anyhow!(e))?;
        if ssh.algorithm() != ssh_key::Algorithm::Ed25519 {
            bail!(
                "SSH key type {} is not supported; radio v1 uses ssh-ed25519 keys",
                ssh.algorithm()
            );
        }
        let m = Member {
            name: name.to_string(),
            ssh_public_key: sshsig::public_key_text(&ssh),
            dht_public_key: dht_public_key.trim().to_ascii_lowercase(),
            salt: salt.filter(|s| !s.is_empty()).map(str::to_string),
        };
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        self.ssh_key()?;
        self.dht_key()?;
        if let Some(s) = &self.salt {
            if s.len() > 64 {
                bail!("salt longer than 64 bytes");
            }
        }
        Ok(())
    }

    pub fn ssh_key(&self) -> Result<ssh_key::PublicKey> {
        sshsig::parse_public_key(&self.ssh_public_key).map_err(|e| anyhow!(e))
    }

    pub fn dht_key(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.dht_public_key).context("DHT public key must be hex")?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("DHT public key must be 32 bytes (64 hex characters)"))?;
        // Must be a valid Ed25519 point, so a typo is caught when the card is pinned.
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| anyhow!("DHT public key is not a valid Ed25519 point"))?;
        Ok(key)
    }

    pub fn salt_bytes(&self) -> Option<&[u8]> {
        self.salt.as_deref().map(str::as_bytes)
    }

    pub fn ssh_fingerprint(&self) -> String {
        self.ssh_key()
            .map(|k| sshsig::fingerprint(&k))
            .unwrap_or_else(|_| "invalid".into())
    }

    /// `SHA256:`-style fingerprint of the DHT key, for out-of-band comparison.
    pub fn dht_fingerprint(&self) -> String {
        let key = self.dht_key().unwrap_or([0; 32]);
        format!("SHA256:{}", b64(&Sha256::digest(key)))
    }

    /// Short code over the whole card (name, both keys, salt): compare it by voice or chat.
    pub fn card_code(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"radio-card/1\n");
        h.update(self.name.as_bytes());
        h.update(b"\n");
        h.update(self.ssh_public_key.as_bytes());
        h.update(b"\n");
        h.update(self.dht_public_key.as_bytes());
        h.update(b"\n");
        h.update(self.salt.as_deref().unwrap_or("").as_bytes());
        let d = hex::encode(&h.finalize()[..12]);
        d.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Human-readable card, also valid TOML.
    pub fn to_card(&self) -> String {
        let file = CardFile {
            radio_card: CARD_VERSION,
            member: self.clone(),
        };
        format!(
            "# radio circle card - share this file; verify the fingerprints out of band before pinning it.\n\
             # card code:       {}\n\
             # ssh fingerprint: {}\n\
             # dht fingerprint: {}\n{}",
            self.card_code(),
            self.ssh_fingerprint(),
            self.dht_fingerprint(),
            toml::to_string(&file).expect("card serialises")
        )
    }

    /// Parse a card from raw file bytes. Tolerates a UTF-8 BOM and UTF-16 (Windows PowerShell's
    /// `>` redirection writes UTF-16 with a BOM).
    pub fn from_card_bytes(bytes: &[u8]) -> Result<Self> {
        let text = match bytes {
            [0xff, 0xfe, rest @ ..] => decode_utf16(rest, u16::from_le_bytes)?,
            [0xfe, 0xff, rest @ ..] => decode_utf16(rest, u16::from_be_bytes)?,
            [0xef, 0xbb, 0xbf, rest @ ..] => {
                String::from_utf8(rest.to_vec()).context("card is not valid UTF-8")?
            }
            _ => String::from_utf8(bytes.to_vec()).context("card is not valid UTF-8 text")?,
        };
        Self::from_card(&text)
    }

    pub fn from_card(text: &str) -> Result<Self> {
        let file: CardFile = toml::from_str(text).context("not a valid radio circle card")?;
        if file.radio_card != CARD_VERSION {
            bail!("unsupported card version {}", file.radio_card);
        }
        let m = Member::new(
            &file.member.name,
            &file.member.ssh_public_key,
            &file.member.dht_public_key,
            file.member.salt.as_deref(),
        )?;
        Ok(m)
    }
}

fn decode_utf16(bytes: &[u8], conv: fn([u8; 2]) -> u16) -> Result<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| conv([c[0], c[1]])).collect();
    String::from_utf16(&units).context("card is not valid UTF-16")
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Circle {
    #[serde(default, rename = "member")]
    pub members: Vec<Member>,
}

impl Circle {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let c: Circle =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                for m in &c.members {
                    m.validate()
                        .with_context(|| format!("invalid circle entry {:?}", m.name))?;
                }
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Circle::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string(self)?;
        let text = format!(
            "# Locally pinned circle. Edit with `radio circle add/remove`; nothing here is ever learned from the DHT.\n{body}"
        );
        write_atomic(path, text.as_bytes(), false)
    }

    pub fn find(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }

    pub fn find_by_dht_key(&self, key: &[u8; 32]) -> Option<&Member> {
        let hexkey = hex::encode(key);
        self.members.iter().find(|m| m.dht_public_key == hexkey)
    }

    /// Pin a member. Refuses to silently replace an existing entry.
    pub fn add(&mut self, member: Member) -> Result<()> {
        member.validate()?;
        if let Some(existing) = self.find(&member.name) {
            if *existing == member {
                bail!("{} is already pinned with identical keys", member.name);
            }
            bail!(
                "a member named {:?} is already pinned with different keys; remove it first \
                 (`radio circle remove {}`) after verifying the new card out of band",
                member.name,
                member.name
            );
        }
        if let Some(other) = self
            .members
            .iter()
            .find(|m| m.dht_public_key == member.dht_public_key && m.salt == member.salt)
        {
            bail!("DHT feed key already pinned as {:?}", other.name);
        }
        self.members.push(member);
        self.members.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<Member> {
        let i = self
            .members
            .iter()
            .position(|m| m.name == name)
            .ok_or_else(|| anyhow!("no member named {name:?}"))?;
        Ok(self.members.remove(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    pub fn member(name: &str) -> (Member, mainline::SigningKey) {
        let ssh = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let dht = mainline::SigningKey::from_bytes(&seed);
        let m = Member::new(
            name,
            &sshsig::public_key_text(ssh.public_key()),
            &hex::encode(dht.verifying_key().to_bytes()),
            None,
        )
        .unwrap();
        (m, dht)
    }

    #[test]
    fn card_roundtrip() {
        let (m, _) = member("alice");
        let card = m.to_card();
        assert!(card.contains("card code:"));
        assert_eq!(Member::from_card(&card).unwrap(), m);
        let mut with_salt = m.clone();
        with_salt.salt = Some("daily".into());
        assert_eq!(Member::from_card(&with_salt.to_card()).unwrap(), with_salt);
    }

    #[test]
    fn card_survives_powershell_utf16_and_bom() {
        let (m, _) = member("alice");
        let text = m.to_card();
        let mut utf16le = vec![0xff, 0xfe];
        for u in text.encode_utf16() {
            utf16le.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(Member::from_card_bytes(&utf16le).unwrap(), m);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(text.as_bytes());
        assert_eq!(Member::from_card_bytes(&bom).unwrap(), m);
        assert_eq!(Member::from_card_bytes(text.as_bytes()).unwrap(), m);
    }

    #[test]
    fn card_rejects_bad_input() {
        let (m, _) = member("alice");
        assert!(Member::from_card("garbage").is_err());
        assert!(
            Member::from_card(&m.to_card().replace("radio_card = 1", "radio_card = 9")).is_err()
        );
        let bad = m.to_card().replace(&m.dht_public_key, &"ab".repeat(31));
        assert!(Member::from_card(&bad).is_err());
        assert!(Member::new("bad name", &m.ssh_public_key, &m.dht_public_key, None).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let (a, _) = member("alice");
        let (b, _) = member("bob");
        assert!(a.ssh_fingerprint().starts_with("SHA256:"));
        assert_ne!(a.card_code(), b.card_code());
        assert_eq!(a.card_code(), a.clone().card_code());
        let mut renamed = a.clone();
        renamed.name = "alicia".into();
        assert_ne!(a.card_code(), renamed.card_code());
    }

    #[test]
    fn circle_add_remove_and_pinning_rules() {
        let (a, _) = member("alice");
        let (b, _) = member("bob");
        let mut c = Circle::default();
        c.add(a.clone()).unwrap();
        c.add(b.clone()).unwrap();
        assert!(c.add(a.clone()).is_err());
        let mut impostor = member("alice").0;
        impostor.name = "alice".into();
        let err = c.add(impostor).unwrap_err().to_string();
        assert!(err.contains("different keys"), "{err}");
        let mut dup = member("carol").0;
        dup.dht_public_key = a.dht_public_key.clone();
        assert!(c.add(dup).is_err());
        assert_eq!(
            c.find_by_dht_key(&b.dht_key().unwrap()).unwrap().name,
            "bob"
        );
        c.remove("alice").unwrap();
        assert!(c.find("alice").is_none());
        assert!(c.remove("alice").is_err());
    }

    #[test]
    fn circle_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("circle.toml");
        let mut c = Circle::default();
        c.add(member("alice").0).unwrap();
        c.add(member("bob").0).unwrap();
        c.save(&path).unwrap();
        let loaded = Circle::load(&path).unwrap();
        assert_eq!(loaded.members, c.members);
        assert!(Circle::load(&dir.path().join("missing.toml"))
            .unwrap()
            .members
            .is_empty());
    }
}
