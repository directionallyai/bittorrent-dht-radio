#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Output};

use mainline::Testnet;
use radio::circle::Member;
use radio::config::Paths;
use radio::selftest::{make_identity, pin};

/// A private loopback DHT (a handful of in-process `mainline` nodes).
pub fn testnet() -> Testnet {
    Testnet::builder(6)
        .bind_address(Ipv4Addr::LOCALHOST)
        .build()
        .expect("loopback testnet")
}

/// One independent client: its own config dir, SSH key, publisher key and DHT node.
pub struct Client {
    pub dir: tempfile::TempDir,
    pub paths: Paths,
    pub card: Member,
}

impl Client {
    pub fn new(name: &str, bootstrap: &[String]) -> Client {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            root: dir.path().join(name),
        };
        let card = make_identity(&paths, name, bootstrap).expect("init");
        Client { dir, paths, card }
    }

    pub fn trust(&self, other: &Client) {
        pin(&self.paths, &other.card).expect("pin");
    }

    pub fn cli(&self, args: &[&str]) -> Out {
        run_cli(&self.paths.root, args)
    }

    pub fn state(&self) -> radio::state::State {
        radio::state::Store::new(&self.paths).load().unwrap()
    }

    /// Edit config.toml in place.
    pub fn edit_config(&self, f: impl FnOnce(&mut radio::config::Config)) {
        let mut cfg = radio::config::Config::load(&self.paths).unwrap();
        f(&mut cfg);
        cfg.save(&self.paths).unwrap();
    }
}

/// Two clients that pinned each other, on the same testnet.
pub fn pair(net: &Testnet) -> (Client, Client) {
    let a = Client::new("alice", &net.bootstrap);
    let b = Client::new("bob", &net.bootstrap);
    a.trust(&b);
    b.trust(&a);
    (a, b)
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn json_lines(&self) -> Vec<serde_json::Value> {
        self.stdout
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    pub fn events_of(&self, kind: &str) -> Vec<serde_json::Value> {
        self.json_lines()
            .into_iter()
            .filter(|v| v["type"] == kind)
            .collect()
    }
}

impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

pub fn radio_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_radio"))
}

pub fn command(config_dir: &std::path::Path, args: &[&str]) -> Command {
    let mut c = Command::new(radio_bin());
    c.arg("--config-dir").arg(config_dir).args(args);
    c.env_remove("RADIO_SSH_KEY_PASSPHRASE")
        .env_remove("RADIO_CONFIG_DIR")
        .stdin(std::process::Stdio::null());
    c
}

pub fn run_cli(config_dir: &std::path::Path, args: &[&str]) -> Out {
    let o: Output = command(config_dir, args).output().expect("spawn radio");
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// A loopback UDP port with nothing listening (connection-refused style failures).
pub fn dead_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}
