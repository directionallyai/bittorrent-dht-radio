//! `radio selftest`: two independent clients publish and listen concurrently over a private
//! loopback DHT. Needs no internet, no ssh-keygen and no existing configuration, so it is a
//! quick way to prove that a downloaded binary works on this OS.

use std::net::Ipv4Addr;
use std::time::Duration;

use mainline::Testnet;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::app::{self, InitOptions, SshChoice};
use crate::config::{DhtConfig, Paths};
use crate::exit::{self, coded, Coded, WithCode};
use crate::ops::{self, Publisher, Source};
use crate::output::{Event, Printer};
use crate::state::Store;
use crate::util::now_secs;

/// Loopback DHT parameters shared by `selftest` and tests.
pub fn loopback_dht(bootstrap: &[String]) -> DhtConfig {
    DhtConfig {
        bootstrap: bootstrap.to_vec(),
        include_default_bootstrap: false,
        bind_address: Some(Ipv4Addr::LOCALHOST),
        port: None,
        request_timeout_ms: 500,
        bootstrap_attempts: 3,
        bootstrap_backoff_ms: 100,
        resolve_timeout_ms: 2000,
    }
}

/// Create an identity in `paths` with a freshly generated Ed25519 SSH key file.
pub fn make_identity(
    paths: &Paths,
    name: &str,
    bootstrap: &[String],
) -> Result<crate::circle::Member, Coded> {
    let key =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| coded(exit::ERROR, e))?;
    std::fs::create_dir_all(&paths.root).code(exit::ERROR)?;
    let key_path = paths.root.join("ssh_id_ed25519");
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| coded(exit::ERROR, e))?;
    std::fs::write(&key_path, pem.as_bytes()).code(exit::ERROR)?;
    app::init(
        paths,
        &InitOptions {
            name: name.into(),
            ssh: SshChoice::KeyFile(key_path),
            salt: None,
            bootstrap: vec![],
            dht: Some(loopback_dht(bootstrap)),
        },
    )
}

pub fn pin(paths: &Paths, member: &crate::circle::Member) -> Result<(), Coded> {
    let mut circle = app::load_circle(paths)?;
    circle.add(member.clone()).code(exit::CONFIG)?;
    circle.save(&paths.circle_file()).code(exit::ERROR)
}

pub fn run(printer: &Printer) -> Result<i32, Coded> {
    let say = |m: &str| {
        printer.emit(&Event::Note {
            detail: m.to_string(),
        })
    };
    let testnet = Testnet::builder(6)
        .bind_address(Ipv4Addr::LOCALHOST)
        .build()
        .map_err(|e| coded(exit::ERROR, format!("cannot start loopback DHT: {e}")))?;
    say(&format!(
        "private loopback DHT with {} nodes",
        testnet.nodes.len()
    ));

    let dir = tempfile::tempdir().code(exit::ERROR)?;
    let (pa, pb) = (
        Paths {
            root: dir.path().join("alice"),
        },
        Paths {
            root: dir.path().join("bob"),
        },
    );
    let alice = make_identity(&pa, "alice", &testnet.bootstrap)?;
    let bob = make_identity(&pb, "bob", &testnet.bootstrap)?;
    pin(&pa, &bob)?;
    pin(&pb, &alice)?;
    say("two independent clients initialised and pinned each other");

    // Both publish and listen concurrently, each with its own DHT node.
    let results: Vec<Result<String, Coded>> = std::thread::scope(|s| {
        let h1 = s.spawn(|| exchange(&pa, "alice", "hello from alice", "bob", "hello from bob"));
        let h2 = s.spawn(|| exchange(&pb, "bob", "hello from bob", "alice", "hello from alice"));
        [h1, h2]
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(coded(exit::ERROR, "thread panicked")))
            })
            .collect()
    });
    for r in results {
        say(&r?);
    }
    println!("selftest ok: published, retrieved and verified over real BEP 44 operations; restart produced no duplicates");
    Ok(exit::OK)
}

/// Publish `mine`, then wait until `theirs` from `peer` verifies; then a second poll must be quiet.
fn exchange(
    paths: &Paths,
    me: &str,
    mine: &str,
    peer: &str,
    theirs: &str,
) -> Result<String, Coded> {
    let cfg = app::load_config(paths)?;
    let circle = app::load_circle(paths)?;
    let ssh = app::load_signer(&cfg)?;
    let dht_key = crate::config::load_publisher_key(paths).code(exit::CONFIG)?;
    let net = app::connect(&cfg, paths, |_| {})?;
    let store = Store::new(paths);
    Publisher {
        cfg: &cfg,
        ssh: &ssh,
        dht_key: &dht_key,
        store: &store,
    }
    .publish(&net, mine, 600, true, now_secs())?;

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let report = ops::poll_circle(
            &circle,
            &store,
            &Source::Live(&net),
            now_secs(),
            cfg.clock_skew_secs,
            true,
        )?;
        let got = report.events.iter().any(|e| matches!(e, Event::Message { member, message, .. } if member == peer && message == theirs));
        if got {
            let again = ops::poll_circle(
                &circle,
                &store,
                &Source::Live(&net),
                now_secs(),
                cfg.clock_skew_secs,
                false,
            )?;
            if again.summary.new != 0 {
                return Err(coded(
                    exit::ERROR,
                    format!("{me}: duplicate message on second poll"),
                ));
            }
            return Ok(format!("{me} received and verified {peer}'s message"));
        }
        if std::time::Instant::now() > deadline {
            return Err(coded(
                exit::ERROR,
                format!("{me}: did not receive {peer}'s message in time"),
            ));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}
