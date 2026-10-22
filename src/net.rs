//! DHT access: bootstrap resolution with retry/backoff, a routing-table cache that survives
//! across runs, and BEP 44 mutable get/put through the `mainline` crate.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use futures_lite::{future::block_on, StreamExt};
use mainline::async_dht::AsyncDht;
use mainline::errors::{ConcurrencyError, PutMutableError, PutQueryError};
use mainline::{Dht, GetMutableOutcome, MutableItem, DEFAULT_BOOTSTRAP_NODES};
use thiserror::Error;

use crate::config::{DhtConfig, Paths};

/// How many cached routing-table nodes are reused as extra bootstrap peers.
const MAX_CACHED_NODES: usize = 64;

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub bootstrap: Vec<String>,
    pub include_default_bootstrap: bool,
    pub bind_address: Option<Ipv4Addr>,
    pub port: Option<u16>,
    pub request_timeout: Duration,
    pub attempts: u32,
    pub backoff: Duration,
    pub resolve_timeout: Duration,
    pub cache_path: Option<PathBuf>,
}

impl NetConfig {
    pub fn from_config(cfg: &DhtConfig, paths: &Paths) -> Self {
        NetConfig {
            bootstrap: cfg.bootstrap.clone(),
            include_default_bootstrap: cfg.include_default_bootstrap,
            bind_address: cfg.bind_address,
            port: cfg.port,
            request_timeout: Duration::from_millis(cfg.request_timeout_ms.max(50)),
            attempts: cfg.bootstrap_attempts.max(1),
            backoff: Duration::from_millis(cfg.bootstrap_backoff_ms),
            resolve_timeout: Duration::from_millis(cfg.resolve_timeout_ms.max(100)),
            cache_path: Some(paths.routing_cache()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Literal,
    Dns,
    Cached,
    Default,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::Literal => "literal",
            EntryKind::Dns => "dns",
            EntryKind::Cached => "cached",
            EntryKind::Default => "default",
        }
    }
}

/// One configured/cached bootstrap peer and what became of it.
#[derive(Debug, Clone)]
pub struct BootstrapEntry {
    pub entry: String,
    pub kind: EntryKind,
    pub resolved: Vec<SocketAddrV4>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum NetError {
    #[error("no usable bootstrap address: {0}")]
    NoBootstrap(String),
    #[error("cannot open UDP socket: {0}")]
    Bind(std::io::Error),
    #[error("DHT bootstrap failed after {attempts} attempt(s): no bootstrap peer answered")]
    BootstrapFailed { attempts: u32 },
}

/// Resolve bootstrap strings. Literal `IP:port` is used as-is; hostnames go through the system
/// resolver on a helper thread so a dead resolver cannot hang the process.
pub fn resolve_entries(cfg: &NetConfig) -> Vec<BootstrapEntry> {
    let mut out = Vec::new();
    let mut listed: Vec<(String, EntryKind)> = cfg
        .bootstrap
        .iter()
        .map(|s| (s.clone(), EntryKind::Literal))
        .collect();
    if cfg.bootstrap.is_empty() || cfg.include_default_bootstrap {
        listed.extend(
            DEFAULT_BOOTSTRAP_NODES
                .iter()
                .map(|s| (s.to_string(), EntryKind::Default)),
        );
    }
    if let Some(path) = &cfg.cache_path {
        listed.extend(read_cache(path).into_iter().map(|s| (s, EntryKind::Cached)));
    }
    for (entry, kind) in listed {
        out.push(resolve_one(&entry, kind, cfg.resolve_timeout));
    }
    out
}

fn resolve_one(entry: &str, kind: EntryKind, timeout: Duration) -> BootstrapEntry {
    let mk = |kind, resolved: Vec<SocketAddrV4>, error: Option<String>| BootstrapEntry {
        entry: entry.to_string(),
        kind,
        resolved,
        error,
    };
    match entry.parse::<SocketAddr>() {
        Ok(SocketAddr::V4(a)) => return mk(kind, vec![a], None),
        Ok(SocketAddr::V6(_)) => {
            return mk(
                kind,
                vec![],
                Some("IPv6 bootstrap peers are not supported by the DHT client".into()),
            )
        }
        Err(_) => {}
    }
    let kind = if kind == EntryKind::Literal {
        EntryKind::Dns
    } else {
        kind
    };
    let (tx, rx) = mpsc::channel();
    let host = entry.to_string();
    std::thread::spawn(move || {
        let r = host
            .to_socket_addrs()
            .map(|it| {
                it.filter_map(|a| match a {
                    SocketAddr::V4(a) => Some(a),
                    _ => None,
                })
                .collect::<Vec<_>>()
            })
            .map_err(|e| e.to_string());
        let _ = tx.send(r);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) if !addrs.is_empty() => mk(kind, addrs, None),
        Ok(Ok(_)) => mk(kind, vec![], Some("resolved to no IPv4 address".into())),
        Ok(Err(e)) => mk(kind, vec![], Some(format!("cannot resolve: {e}"))),
        Err(_) => mk(
            kind,
            vec![],
            Some(format!("DNS lookup timed out after {timeout:?}")),
        ),
    }
}

pub fn read_cache(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| l.parse::<SocketAddrV4>().is_ok())
                .take(MAX_CACHED_NODES)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// A live DHT client.
pub struct Net {
    dht: AsyncDht,
    pub entries: Vec<BootstrapEntry>,
    pub attempts_used: u32,
    cache_path: Option<PathBuf>,
}

/// Snapshot used by `status`/`doctor`.
#[derive(Debug, Clone)]
pub struct Health {
    pub routing_nodes: usize,
    pub dht_size_estimate: usize,
    pub public_address: Option<SocketAddrV4>,
    pub firewalled: bool,
    pub local_addr: SocketAddrV4,
}

/// Outcome of a mutable GET.
#[derive(Debug, Clone)]
pub struct GetResult {
    pub item: Option<MutableItem>,
    pub outcome: GetMutableOutcome,
}

impl GetResult {
    /// Nobody answered: the DHT is unreachable (or every UDP request timed out).
    pub fn no_responses(&self) -> bool {
        self.item.is_none() && self.outcome.responded() == 0
    }
}

#[derive(Debug, Error)]
pub enum PutFailure {
    #[error("DHT unavailable: {0}")]
    Unavailable(String),
    #[error("storage nodes rejected the item: {0}")]
    Rejected(String),
    #[error("write conflict: {0}")]
    Conflict(String),
}

impl Net {
    /// Resolve bootstrap peers, start the node and wait until it has a routing table, retrying
    /// with exponential backoff.
    pub fn connect(cfg: &NetConfig, mut progress: impl FnMut(&str)) -> Result<Net, NetError> {
        let entries = resolve_entries(cfg);
        for e in &entries {
            if let Some(err) = &e.error {
                progress(&format!(
                    "bootstrap {} ({}): {err}",
                    e.entry,
                    e.kind.as_str()
                ));
            }
        }
        let mut addrs: Vec<SocketAddrV4> = entries
            .iter()
            .flat_map(|e| e.resolved.iter().copied())
            .collect();
        addrs.sort();
        addrs.dedup();
        if addrs.is_empty() {
            let detail = entries
                .iter()
                .map(|e| {
                    format!(
                        "{}: {}",
                        e.entry,
                        e.error.as_deref().unwrap_or("no addresses")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(NetError::NoBootstrap(if detail.is_empty() {
                "none configured".into()
            } else {
                detail
            }));
        }

        let mut builder = Dht::builder();
        builder
            .bootstrap(&addrs)
            .request_timeout(cfg.request_timeout);
        if let Some(a) = cfg.bind_address {
            builder.bind_address(a);
        }
        if let Some(p) = cfg.port {
            builder.port(p);
        }
        let dht = builder.build().map_err(NetError::Bind)?.as_async();

        let mut delay = cfg.backoff;
        for attempt in 1..=cfg.attempts {
            if block_on(dht.bootstrapped()) {
                return Ok(Net {
                    dht,
                    entries,
                    attempts_used: attempt,
                    cache_path: cfg.cache_path.clone(),
                });
            }
            if attempt < cfg.attempts {
                progress(&format!(
                    "bootstrap attempt {attempt}/{} failed; retrying in {delay:?}",
                    cfg.attempts
                ));
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
        Err(NetError::BootstrapFailed {
            attempts: cfg.attempts,
        })
    }

    /// Fetch the most recent item for `(key, salt)`.
    pub fn get_latest(&self, key: &[u8; 32], salt: Option<&[u8]>) -> GetResult {
        block_on(async {
            let mut detailed = self.dht.get_mutable_detailed(key, salt, None);
            let mut best: Option<MutableItem> = None;
            while let Some(item) = detailed.items.next().await {
                let better = match &best {
                    None => true,
                    Some(b) => {
                        item.seq() > b.seq() || (item.seq() == b.seq() && item.value() > b.value())
                    }
                };
                if better {
                    best = Some(item);
                }
            }
            let outcome = detailed.outcome.recv().await;
            GetResult {
                item: best,
                outcome,
            }
        })
    }

    /// PUT a mutable item (optionally with a BEP 44 compare-and-swap on the previous `seq`).
    pub fn put(&self, item: MutableItem, cas: Option<i64>) -> Result<u32, PutFailure> {
        match block_on(self.dht.put_mutable(item, cas)) {
            Ok(outcome) => Ok(outcome.stored_at),
            Err(PutMutableError::Query(PutQueryError::NoClosestNodes)) => Err(
                PutFailure::Unavailable("no DHT nodes to store at (routing table empty)".into()),
            ),
            Err(PutMutableError::Query(PutQueryError::Timeout)) => Err(PutFailure::Unavailable(
                "UDP timeout: no storage node answered".into(),
            )),
            Err(PutMutableError::Query(PutQueryError::ErrorResponse(e))) => {
                Err(PutFailure::Rejected(format!("{e:?}")))
            }
            Err(PutMutableError::Concurrency(c)) => Err(PutFailure::Conflict(match c {
                ConcurrencyError::CasFailed => "CAS mismatch: the stored seq differs".to_string(),
                other => other.to_string(),
            })),
        }
    }

    pub fn health(&self) -> Health {
        let info = block_on(self.dht.info());
        let nodes = block_on(self.dht.to_bootstrap());
        Health {
            routing_nodes: nodes.len(),
            dht_size_estimate: info.dht_size_estimate().0,
            public_address: info.public_address(),
            firewalled: info.firewalled(),
            local_addr: info.local_addr(),
        }
    }

    /// Persist the routing table so the next run can bootstrap from known-good nodes.
    pub fn save_routing_cache(&self) {
        let Some(path) = &self.cache_path else { return };
        let mut nodes = block_on(self.dht.to_bootstrap());
        nodes.truncate(MAX_CACHED_NODES);
        if nodes.is_empty() {
            return; // keep the previous cache rather than clobbering it with nothing
        }
        let _ = crate::util::write_atomic(path, (nodes.join("\n") + "\n").as_bytes(), false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(bootstrap: &[&str]) -> NetConfig {
        NetConfig {
            bootstrap: bootstrap.iter().map(|s| s.to_string()).collect(),
            include_default_bootstrap: false,
            bind_address: Some(Ipv4Addr::LOCALHOST),
            port: None,
            request_timeout: Duration::from_millis(200),
            attempts: 1,
            backoff: Duration::from_millis(10),
            resolve_timeout: Duration::from_secs(5),
            cache_path: None,
        }
    }

    #[test]
    fn literal_entries_need_no_dns() {
        let e = resolve_entries(&cfg(&["127.0.0.1:6881"]));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].kind, EntryKind::Literal);
        assert_eq!(e[0].resolved, vec!["127.0.0.1:6881".parse().unwrap()]);
    }

    #[test]
    fn unresolvable_host_is_reported_but_literal_still_works() {
        let e = resolve_entries(&cfg(&["does-not-exist.invalid:6881", "127.0.0.1:6881"]));
        assert_eq!(e[0].kind, EntryKind::Dns);
        assert!(
            e[0].resolved.is_empty() && e[0].error.is_some(),
            "{:?}",
            e[0]
        );
        assert_eq!(e[1].resolved.len(), 1);
    }

    #[test]
    fn ipv6_literal_is_flagged() {
        let e = resolve_entries(&cfg(&["[::1]:6881"]));
        assert!(e[0].error.as_deref().unwrap().contains("IPv6"));
    }

    #[test]
    fn nothing_resolvable_is_a_distinct_error() {
        let err = Net::connect(&cfg(&["does-not-exist.invalid:6881"]), |_| {})
            .err()
            .unwrap();
        assert!(matches!(err, NetError::NoBootstrap(_)), "{err}");
    }

    #[test]
    fn cache_reads_only_valid_literals() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("routing.txt");
        std::fs::write(&p, "1.2.3.4:6881\nnot-an-addr\n\n5.6.7.8:1\n").unwrap();
        assert_eq!(read_cache(&p), vec!["1.2.3.4:6881", "5.6.7.8:1"]);
        assert!(read_cache(&dir.path().join("missing")).is_empty());
    }
}
