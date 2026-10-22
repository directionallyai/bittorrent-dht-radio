//! Per-user configuration directory and `config.toml`.
//!
//! One directory holds everything, so it is easy to back up, move or point tests at:
//!
//! ```text
//! config.toml      settings (name, SSH signer choice, bootstrap, timeouts)
//! circle.toml      pinned circle members
//! publisher.key    BEP 44 Ed25519 seed, hex (owner-only permissions on Unix)
//! state.json       highest accepted seq per signer, last messages, diagnostics, last signed item
//! state.lock       advisory lock file for state.json
//! cache/routing.txt  DHT routing-table nodes saved for the next bootstrap
//! ```

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::payload::validate_name;
use crate::util::write_atomic;

pub const ENV_CONFIG_DIR: &str = "RADIO_CONFIG_DIR";
pub const ENV_SSH_PASSPHRASE: &str = "RADIO_SSH_KEY_PASSPHRASE";

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// `--config-dir`, then `$RADIO_CONFIG_DIR`, then the per-user default for this OS:
    /// Linux `~/.config/radio`, macOS `~/Library/Application Support/com.directionally.radio`,
    /// Windows `%APPDATA%\directionally\radio\config`.
    pub fn resolve(cli: Option<&Path>) -> Result<Self> {
        let root = if let Some(p) = cli {
            p.to_path_buf()
        } else if let Some(p) = std::env::var_os(ENV_CONFIG_DIR).filter(|p| !p.is_empty()) {
            PathBuf::from(p)
        } else {
            directories::ProjectDirs::from("com", "directionally", "radio")
                .ok_or_else(|| anyhow!("cannot determine a per-user config directory; pass --config-dir"))?
                .config_dir()
                .to_path_buf()
        };
        Ok(Paths { root })
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn circle_file(&self) -> PathBuf {
        self.root.join("circle.toml")
    }
    pub fn publisher_key(&self) -> PathBuf {
        self.root.join("publisher.key")
    }
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.root.join("state.lock")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }
    pub fn routing_cache(&self) -> PathBuf {
        self.cache_dir().join("routing.txt")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SshConfig {
    /// Sign with a private key file (passphrase from `RADIO_SSH_KEY_PASSPHRASE` or a prompt).
    File { key_path: PathBuf },
    /// Sign through ssh-agent with the identity whose public key is given.
    Agent {
        public_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socket: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DhtConfig {
    /// Literal `IP:port` (or optional `host:port`) bootstrap peers. Empty = mainline defaults.
    pub bootstrap: Vec<String>,
    /// Also use the mainline default bootstrap hosts when `bootstrap` is non-empty.
    pub include_default_bootstrap: bool,
    pub bind_address: Option<Ipv4Addr>,
    pub port: Option<u16>,
    pub request_timeout_ms: u64,
    pub bootstrap_attempts: u32,
    pub bootstrap_backoff_ms: u64,
    pub resolve_timeout_ms: u64,
}

impl Default for DhtConfig {
    fn default() -> Self {
        DhtConfig {
            bootstrap: vec![],
            include_default_bootstrap: false,
            bind_address: None,
            port: None,
            request_timeout_ms: 2000,
            bootstrap_attempts: 3,
            bootstrap_backoff_ms: 1000,
            resolve_timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Sender name carried in every payload; must match what members pin for you.
    pub name: String,
    /// Optional BEP 44 salt for your feed.
    pub salt: Option<String>,
    pub ssh: SshConfig,
    /// Default lifetime of a signed message (`humantime` syntax).
    pub message_ttl: String,
    /// How far in the future an `issued-at` may be before it is rejected, in seconds.
    pub clock_skew_secs: u64,
    pub dht: DhtConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: String::new(),
            salt: None,
            ssh: SshConfig::File { key_path: PathBuf::new() },
            message_ttl: "24h".into(),
            clock_skew_secs: 120,
            dht: DhtConfig::default(),
        }
    }
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Self> {
        let path = paths.config_file();
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!("not initialised: {} not found (run `radio init` first)", path.display())
            } else {
                anyhow!("reading {}: {e}", path.display())
            }
        })?;
        let cfg: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate().with_context(|| format!("invalid {}", path.display()))?;
        Ok(cfg)
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        self.validate()?;
        let text = format!(
            "# radio configuration. Bootstrap peers: literal IP:port entries are used as-is; \
             host:port entries are resolved with the system resolver.\n{}",
            toml::to_string(self)?
        );
        write_atomic(&paths.config_file(), text.as_bytes(), false)
    }

    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        crate::util::parse_duration(&self.message_ttl)?;
        if let Some(s) = &self.salt {
            if s.len() > 64 {
                bail!("salt longer than 64 bytes");
            }
        }
        Ok(())
    }

    pub fn ttl(&self) -> Result<std::time::Duration> {
        crate::util::parse_duration(&self.message_ttl)
    }
}

/// Load the BEP 44 publisher key (a 32-byte Ed25519 seed stored as hex).
pub fn load_publisher_key(paths: &Paths) -> Result<mainline::SigningKey> {
    let path = paths.publisher_key();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading publisher key {} (run `radio init`)", path.display()))?;
    let bytes = hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{} must contain a 32-byte seed", path.display()))?;
    Ok(mainline::SigningKey::from_bytes(&seed))
}

/// Create a fresh publisher key. Refuses to overwrite an existing one.
pub fn create_publisher_key(paths: &Paths) -> Result<mainline::SigningKey> {
    use rand_core::RngCore;
    let path = paths.publisher_key();
    if path.exists() {
        bail!("{} already exists; refusing to overwrite the publisher key", path.display());
    }
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    write_atomic(&path, format!("{}\n", hex::encode(seed)).as_bytes(), true)?;
    Ok(mainline::SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip_both_signer_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path())).unwrap();
        let mut cfg = Config { name: "alice".into(), ..Default::default() };
        cfg.ssh = SshConfig::File { key_path: "/home/a/.ssh/id_ed25519".into() };
        cfg.dht.bootstrap = vec!["127.0.0.1:6881".into()];
        cfg.save(&paths).unwrap();
        assert_eq!(Config::load(&paths).unwrap(), cfg);
        cfg.ssh = SshConfig::Agent { public_key: "ssh-ed25519 AAAA".into(), socket: None };
        cfg.save(&paths).unwrap();
        assert_eq!(Config::load(&paths).unwrap(), cfg);
    }

    #[test]
    fn load_reports_not_initialised() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path())).unwrap();
        let err = Config::load(&paths).unwrap_err().to_string();
        assert!(err.contains("not initialised"), "{err}");
    }

    #[test]
    fn publisher_key_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(Some(dir.path())).unwrap();
        let k = create_publisher_key(&paths).unwrap();
        assert_eq!(load_publisher_key(&paths).unwrap().verifying_key(), k.verifying_key());
        assert!(create_publisher_key(&paths).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.publisher_key()).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn explicit_dir_wins_over_env() {
        let p = Paths::resolve(Some(Path::new("/tmp/explicit"))).unwrap();
        assert_eq!(p.root, Path::new("/tmp/explicit"));
    }
}
