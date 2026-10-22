//! Persistent state: highest accepted seq per signer, last verified messages, dedup, the last
//! signed item (for `republish`) and diagnostics. Stored as JSON, updated atomically under an
//! advisory file lock so several `radio` processes and the threads of `radio run` can share it.

use std::collections::BTreeMap;
use std::fs::OpenOptions;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::util::write_atomic;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    #[serde(default)]
    pub members: BTreeMap<String, MemberState>,
    #[serde(default)]
    pub publisher: PublisherState,
    #[serde(default)]
    pub dht: DhtState,
    /// Direct messages received, per sender DHT key (hex).
    #[serde(default)]
    pub direct: BTreeMap<String, DirectState>,
}

/// What we accepted from one member's direct slot for us. Decrypted text is not stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DirectState {
    pub name: String,
    /// Highest `seq` accepted from the slot. Anything lower is a rollback.
    pub highest_seq: i64,
    pub payload_sha256: Option<String>,
    pub last_received_at: Option<u64>,
    pub last_rejection: Option<Rejection>,
}

/// Verified message as stored for dedup and `status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredMessage {
    pub seq: i64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub message: String,
    pub payload_sha256: String,
}

/// Outcome category of the latest poll of one member.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MemberStatus {
    /// A verified, unexpired record is on the DHT.
    Ok,
    /// The DHT answered but holds no record for this feed (publisher offline or record aged out).
    NotFound,
    /// The newest record's lifetime has passed.
    Expired,
    /// The DHT could not be reached or did not answer: freshness unknown.
    Unreachable,
    /// A record was found but rejected by verification.
    Rejected,
}

impl MemberStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberStatus::Ok => "ok",
            MemberStatus::NotFound => "not-found",
            MemberStatus::Expired => "expired",
            MemberStatus::Unreachable => "unreachable",
            MemberStatus::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemberState {
    /// Local label at the time of the last poll (informational; the key is the DHT key).
    pub name: String,
    /// Highest `seq` accepted so far. Anything lower is a rollback.
    pub highest_seq: i64,
    pub last_message: Option<StoredMessage>,
    pub status: Option<MemberStatus>,
    pub status_since: Option<u64>,
    /// Last time a verified record was seen on the DHT.
    pub last_verified_at: Option<u64>,
    pub last_poll_at: Option<u64>,
    pub last_poll_detail: Option<String>,
    pub last_rejection: Option<Rejection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rejection {
    pub at: u64,
    pub reason: String,
    pub detail: String,
}

/// The last signed item, kept so it can be re-put unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedItem {
    pub seq: i64,
    /// Raw BEP 44 `v` bytes, hex.
    pub value_hex: String,
    pub salt: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub payload_sha256: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PutRecord {
    pub at: u64,
    /// `publish` (fresh signature) or `republish` (same signed bytes).
    pub kind: String,
    pub seq: i64,
    pub ok: bool,
    pub stored_at: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PublisherState {
    pub last_item: Option<SignedItem>,
    pub last_put: Option<PutRecord>,
    pub last_publish_ok_at: Option<u64>,
    pub last_republish_ok_at: Option<u64>,
    /// Last direct message sent to each recipient, keyed by their SSH fingerprint.
    #[serde(default)]
    pub direct: BTreeMap<String, SignedItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DhtState {
    pub last_check_at: Option<u64>,
    pub last_check_ok: Option<bool>,
    pub last_check_detail: Option<String>,
    pub routing_nodes: Option<usize>,
    pub dht_size_estimate: Option<usize>,
}

pub struct Store {
    paths: Paths,
}

impl Store {
    pub fn new(paths: &Paths) -> Self {
        Store {
            paths: paths.clone(),
        }
    }

    pub fn load(&self) -> Result<State> {
        read_state(&self.paths)
    }

    /// Read-modify-write under an exclusive lock.
    pub fn update<R>(&self, f: impl FnOnce(&mut State) -> R) -> Result<R> {
        std::fs::create_dir_all(&self.paths.root)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.paths.lock_file())
            .context("opening state lock")?;
        let mut lock = fd_lock::RwLock::new(file);
        let _guard = lock.write().context("locking state")?;
        let mut state = read_state(&self.paths)?;
        let out = f(&mut state);
        let json = serde_json::to_vec_pretty(&state)?;
        write_atomic(&self.paths.state_file(), &json, false)?;
        Ok(out)
    }
}

fn read_state(paths: &Paths) -> Result<State> {
    match std::fs::read(paths.state_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", paths.state_file().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", paths.state_file().display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_default_and_updates_persist() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            root: dir.path().to_path_buf(),
        };
        let store = Store::new(&paths);
        assert_eq!(store.load().unwrap(), State::default());
        store
            .update(|s| {
                s.members.entry("k".into()).or_default().highest_seq = 42;
            })
            .unwrap();
        assert_eq!(
            Store::new(&paths).load().unwrap().members["k"].highest_seq,
            42
        );
    }

    #[test]
    fn concurrent_updates_do_not_lose_writes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            root: dir.path().to_path_buf(),
        };
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let paths = paths.clone();
                std::thread::spawn(move || {
                    for j in 0..5 {
                        Store::new(&paths)
                            .update(|s| {
                                s.members.insert(format!("{i}-{j}"), MemberState::default());
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(Store::new(&paths).load().unwrap().members.len(), 40);
    }
}
