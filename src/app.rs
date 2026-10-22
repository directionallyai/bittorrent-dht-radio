//! Shared command implementations (used by the CLI, `selftest` and the integration tests).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use ssh_key::PublicKey;

use crate::circle::{Circle, Member};
use crate::config::{self, Config, Paths, SshConfig, ENV_SSH_PASSPHRASE};
use crate::direct::Opener;
use crate::exit::{self, coded, Coded, WithCode};
use crate::net::{Net, NetConfig, NetError};
use crate::ops::{Inbox, AGENT_CANNOT_DECRYPT};
use crate::payload::validate_name;
use crate::sshsig::{self, Signer};

/// How the SSH signing key is chosen at `init`. There is deliberately no autodiscovery.
#[derive(Debug, Clone)]
pub enum SshChoice {
    /// A private key file.
    KeyFile(PathBuf),
    /// An ssh-agent identity: a `.pub` file path, an `SHA256:` fingerprint or an OpenSSH public key line.
    Agent {
        identity: String,
        socket: Option<PathBuf>,
    },
}

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub name: String,
    pub ssh: SshChoice,
    pub salt: Option<String>,
    pub bootstrap: Vec<String>,
    pub dht: Option<crate::config::DhtConfig>,
}

/// Create the config dir, the dedicated BEP 44 publisher key and `config.toml`. Returns the
/// member's shareable card.
pub fn init(paths: &Paths, opts: &InitOptions) -> Result<Member, Coded> {
    validate_name(&opts.name).code(exit::CONFIG)?;
    if paths.config_file().exists() {
        return Err(coded(
            exit::CONFIG,
            format!(
                "{} already exists; this config dir is initialised (use `radio card` to show your card, \
                 or pick another --config-dir)",
                paths.config_file().display()
            ),
        ));
    }
    if paths.publisher_key().exists() {
        return Err(coded(
            exit::CONFIG,
            format!(
                "{} exists without a config.toml; refusing to touch it",
                paths.publisher_key().display()
            ),
        ));
    }

    let (ssh_cfg, signer) = match &opts.ssh {
        SshChoice::KeyFile(path) => {
            let path = std::fs::canonicalize(path)
                .with_context(|| format!("SSH key {}", path.display()))
                .code(exit::SIGNING)?;
            let signer = signer_from_file(&path)?;
            (SshConfig::File { key_path: path }, signer)
        }
        SshChoice::Agent { identity, socket } => {
            let sock = socket
                .clone()
                .or_else(sshsig::default_agent_socket)
                .ok_or_else(|| {
                    coded(
                        exit::SIGNING,
                        "no ssh-agent socket: SSH_AUTH_SOCK is not set; pass --agent-socket",
                    )
                })?;
            let public = resolve_agent_identity(&sock, identity)?;
            let signer = Signer::agent(sock, public.clone()).code(exit::SIGNING)?;
            (
                SshConfig::Agent {
                    public_key: sshsig::public_key_text(&public),
                    socket: socket.clone(),
                },
                signer,
            )
        }
    };

    // Prove now that unattended signing works with this choice (prompts/touch would show up here).
    signer.sign(b"radio init self-test").code(exit::SIGNING)?;

    let mut cfg = Config {
        name: opts.name.clone(),
        salt: opts.salt.clone(),
        ssh: ssh_cfg,
        ..Default::default()
    };
    if let Some(d) = &opts.dht {
        cfg.dht = d.clone();
    }
    if !opts.bootstrap.is_empty() {
        cfg.dht.bootstrap = opts.bootstrap.clone();
    }
    cfg.validate().code(exit::CONFIG)?;

    std::fs::create_dir_all(&paths.root)
        .with_context(|| format!("creating {}", paths.root.display()))
        .code(exit::ERROR)?;
    let dht = config::create_publisher_key(paths).code(exit::ERROR)?;
    cfg.save(paths).code(exit::ERROR)?;
    Circle::default()
        .save(&paths.circle_file())
        .code(exit::ERROR)?;

    Member::new(
        &cfg.name,
        &sshsig::public_key_text(signer.public()),
        &hex::encode(dht.verifying_key().to_bytes()),
        cfg.salt.as_deref(),
    )
    .code(exit::ERROR)
}

fn resolve_agent_identity(socket: &Path, spec: &str) -> Result<PublicKey, Coded> {
    let held = sshsig::agent_identities(socket).code(exit::SIGNING)?;
    let wanted: Option<PublicKey> = if spec.starts_with("SHA256:") {
        None
    } else if let Ok(text) = std::fs::read_to_string(spec) {
        Some(
            sshsig::parse_public_key(text.lines().next().unwrap_or(""))
                .map_err(|e| coded(exit::SIGNING, format!("{spec}: {e}")))?,
        )
    } else {
        Some(sshsig::parse_public_key(spec).map_err(|e| {
            coded(exit::SIGNING, format!("--ssh-agent expects a .pub file, an SHA256: fingerprint or a public key line: {e}"))
        })?)
    };
    let found = held.into_iter().find(|k| match &wanted {
        Some(w) => k.key_data() == w.key_data(),
        None => sshsig::fingerprint(k) == spec,
    });
    let key = found.ok_or_else(|| {
        coded(
            exit::SIGNING,
            format!(
                "the ssh-agent does not hold the requested identity {spec:?} (see `ssh-add -L`)"
            ),
        )
    })?;
    if sshsig::is_fido_key(&key) {
        return Err(coded(exit::SIGNING, "FIDO2 security keys need a touch per signature and cannot sign unattended; use an Ed25519 key"));
    }
    Ok(key)
}

/// SSH key passphrase: `RADIO_SSH_KEY_PASSPHRASE`, else a prompt when a terminal is attached.
pub fn passphrase(allow_prompt: bool) -> Option<String> {
    if let Ok(p) = std::env::var(ENV_SSH_PASSPHRASE) {
        return Some(p);
    }
    if allow_prompt && std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        return rpassword::prompt_password("SSH key passphrase (leave empty if none): ")
            .ok()
            .filter(|p| !p.is_empty());
    }
    None
}

/// Load a key-file signer, asking for a passphrase only if the key is actually encrypted.
pub fn signer_from_file(path: &Path) -> Result<Signer, Coded> {
    let encrypted = std::fs::read(path)
        .ok()
        .and_then(|b| ssh_key::PrivateKey::from_openssh(&b).ok())
        .is_some_and(|k| k.is_encrypted());
    let pass = if encrypted { passphrase(true) } else { None };
    Signer::from_key_file(path, pass.as_deref()).code(exit::SIGNING)
}

pub fn load_signer(cfg: &Config) -> Result<Signer, Coded> {
    match &cfg.ssh {
        SshConfig::File { key_path } => signer_from_file(key_path),
        SshConfig::Agent { public_key, socket } => {
            let public =
                sshsig::parse_public_key(public_key).map_err(|e| coded(exit::CONFIG, e))?;
            let sock = socket
                .clone()
                .or_else(sshsig::default_agent_socket)
                .ok_or_else(|| {
                    coded(
                        exit::SIGNING,
                        "no ssh-agent socket: SSH_AUTH_SOCK is not set",
                    )
                })?;
            Signer::agent(sock, public).code(exit::SIGNING)
        }
    }
}

/// The SSH public key for this config without needing a passphrase or the agent.
pub fn ssh_public(cfg: &Config) -> Result<PublicKey, Coded> {
    match &cfg.ssh {
        SshConfig::File { key_path } => {
            let bytes = std::fs::read(key_path)
                .with_context(|| format!("reading {}", key_path.display()))
                .code(exit::SIGNING)?;
            let key = ssh_key::PrivateKey::from_openssh(&bytes)
                .map_err(|e| anyhow!("{}: {e}", key_path.display()))
                .code(exit::SIGNING)?;
            Ok(key.public_key().clone())
        }
        SshConfig::Agent { public_key, .. } => {
            sshsig::parse_public_key(public_key).map_err(|e| coded(exit::CONFIG, e))
        }
    }
}

/// What `listen` needs to receive direct messages: our SSH public key now, and the private key
/// (possibly prompting for its passphrase) only once a direct message has to be decrypted.
pub fn inbox(cfg: &Config) -> Result<Inbox, Coded> {
    let public = ssh_public(cfg)?;
    let ssh = cfg.ssh.clone();
    Ok(Inbox::new(public, move || match &ssh {
        SshConfig::File { key_path } => match signer_from_file(key_path)
            .map_err(|e| e.to_string())?
        {
            Signer::File { key, .. } => Opener::from_private_key(&key).map_err(|e| e.to_string()),
            Signer::Agent { .. } => unreachable!("loaded from a key file"),
        },
        SshConfig::Agent { .. } => Err(AGENT_CANNOT_DECRYPT.into()),
    }))
}

pub fn own_card(paths: &Paths, cfg: &Config) -> Result<Member, Coded> {
    let dht = config::load_publisher_key(paths).code(exit::CONFIG)?;
    let ssh = ssh_public(cfg)?;
    Member::new(
        &cfg.name,
        &sshsig::public_key_text(&ssh),
        &hex::encode(dht.verifying_key().to_bytes()),
        cfg.salt.as_deref(),
    )
    .code(exit::ERROR)
}

pub fn load_circle(paths: &Paths) -> Result<Circle, Coded> {
    Circle::load(&paths.circle_file()).code(exit::CONFIG)
}

pub fn load_config(paths: &Paths) -> Result<Config, Coded> {
    Config::load(paths).code(exit::CONFIG)
}

/// Connect to the DHT; the error carries exit code 11.
pub fn connect(cfg: &Config, paths: &Paths, progress: impl FnMut(&str)) -> Result<Net, Coded> {
    let nc = NetConfig::from_config(&cfg.dht, paths);
    Net::connect(&nc, progress).map_err(|e| {
        let code = match &e {
            NetError::Bind(_) => exit::ERROR,
            _ => exit::DHT_UNAVAILABLE,
        };
        coded(code, e)
    })
}
