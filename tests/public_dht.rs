//! Optional end-to-end check against the real public mainline DHT.
//!
//! Ignored by default (needs internet and UDP egress, and public DHT behaviour varies).
//! Run by hand with:  cargo test --test public_dht -- --ignored --nocapture

mod common;

use radio::app::{self, InitOptions, SshChoice};
use radio::config::{load_publisher_key, Paths};
use radio::exit;
use radio::ops::{self, Publisher, Source};
use radio::state::Store;
use radio::util::now_secs;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

fn identity(root: &std::path::Path, name: &str) -> (Paths, radio::circle::Member) {
    let paths = Paths {
        root: root.join(name),
    };
    std::fs::create_dir_all(&paths.root).unwrap();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let key_path = paths.root.join("id");
    std::fs::write(
        &key_path,
        key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let card = app::init(
        &paths,
        &InitOptions {
            name: name.into(),
            ssh: SshChoice::KeyFile(key_path),
            salt: Some("radio-public-test".into()),
            bootstrap: vec![],
            dht: None,
        },
    )
    .unwrap();
    (paths, card)
}

#[test]
#[ignore = "needs internet access to the public mainline DHT"]
fn publish_and_listen_over_the_public_dht() {
    let dir = tempfile::tempdir().unwrap();
    let (pa, ca) = identity(dir.path(), "alice");
    let (pb, _cb) = identity(dir.path(), "bob");
    radio::selftest::pin(&pb, &ca).unwrap();

    let cfg = app::load_config(&pa).unwrap();
    let ssh = app::load_signer(&cfg).unwrap();
    let key = load_publisher_key(&pa).unwrap();
    let net_a =
        app::connect(&cfg, &pa, |m| eprintln!("alice: {m}")).expect("bootstrap on the public DHT");
    let store_a = Store::new(&pa);
    let report = Publisher {
        cfg: &cfg,
        ssh: &ssh,
        dht_key: &key,
        store: &store_a,
    }
    .publish(&net_a, "public DHT smoke test", 600, true, now_secs())
    .expect("put on the public DHT");
    eprintln!(
        "alice published seq {} to {} node(s)",
        report.seq, report.stored_at
    );

    let cfg_b = app::load_config(&pb).unwrap();
    let circle = app::load_circle(&pb).unwrap();
    let net_b =
        app::connect(&cfg_b, &pb, |m| eprintln!("bob: {m}")).expect("bootstrap on the public DHT");
    let store_b = Store::new(&pb);
    for attempt in 1..=6 {
        let r = ops::poll_circle(
            &circle,
            &store_b,
            &Source::Live(&net_b),
            now_secs(),
            120,
            true,
        )
        .unwrap();
        eprintln!("bob poll {attempt}: {:?}", r.summary);
        if r.summary.exit_code() == exit::OK {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    panic!("bob did not retrieve alice's message from the public DHT");
}
