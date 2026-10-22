//! Commands that need no network: init, card, circle management, exit codes.

mod common;

use common::*;
use radio::exit;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

fn write_key(dir: &std::path::Path, name: &str, passphrase: Option<&str>) -> std::path::PathBuf {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    key.set_comment("test");
    if let Some(p) = passphrase {
        key = key.encrypt(&mut OsRng, p).unwrap();
    }
    let path = dir.join(name);
    std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    path
}

#[test]
fn init_creates_config_publisher_key_and_prints_card() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", None);
    let cfgdir = dir.path().join("cfg");
    let out = run_cli(
        &cfgdir,
        &[
            "init",
            "--name",
            "alice",
            "--ssh-key",
            key.to_str().unwrap(),
            "--bootstrap",
            "127.0.0.1:6881",
        ],
    );
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stdout.contains("ssh_public_key = \"ssh-ed25519 "),
        "{out:?}"
    );
    assert!(out.stdout.contains("dht_public_key = \""), "{out:?}");
    assert!(out.stdout.contains("# ssh fingerprint: SHA256:"), "{out:?}");
    assert!(out.stdout.contains("# card code:"), "{out:?}");
    for f in ["config.toml", "circle.toml", "publisher.key"] {
        assert!(cfgdir.join(f).exists(), "{f}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(cfgdir.join("publisher.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    // The DHT publisher key is a different key from the SSH key.
    let card = run_cli(&cfgdir, &["card"]);
    assert_eq!(card.code, exit::OK);
    assert_eq!(card.stdout, out.stdout);
    let seed = std::fs::read_to_string(cfgdir.join("publisher.key")).unwrap();
    assert!(!std::fs::read_to_string(&key).unwrap().contains(seed.trim()));

    // Re-initialising refuses to clobber.
    let again = run_cli(
        &cfgdir,
        &[
            "init",
            "--name",
            "alice",
            "--ssh-key",
            key.to_str().unwrap(),
        ],
    );
    assert_eq!(again.code, exit::CONFIG, "{again:?}");
}

#[test]
fn init_requires_an_explicit_signer_choice() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_cli(dir.path(), &["init", "--name", "alice"]);
    assert_eq!(out.code, 2, "usage error: {out:?}");
    assert!(
        out.stderr.contains("--ssh-key") && out.stderr.contains("--ssh-agent"),
        "{out:?}"
    );
    assert!(
        !dir.path().join("config.toml").exists(),
        "no autodiscovery of ~/.ssh keys"
    );
}

#[test]
fn init_rejects_bad_names_and_missing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", None);
    let out = run_cli(
        &dir.path().join("c1"),
        &[
            "init",
            "--name",
            "bad name",
            "--ssh-key",
            key.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, exit::CONFIG, "{out:?}");
    let out = run_cli(
        &dir.path().join("c2"),
        &["init", "--name", "alice", "--ssh-key", "/nonexistent/key"],
    );
    assert_eq!(out.code, exit::SIGNING, "{out:?}");
}

#[test]
fn encrypted_key_needs_passphrase_from_env_when_unattended() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", Some("s3cret"));
    let out = run_cli(
        &dir.path().join("c1"),
        &[
            "init",
            "--name",
            "alice",
            "--ssh-key",
            key.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, exit::SIGNING, "{out:?}");
    assert!(out.stderr.contains("passphrase"), "{out:?}");

    let mut cmd = command(
        &dir.path().join("c2"),
        &[
            "init",
            "--name",
            "alice",
            "--ssh-key",
            key.to_str().unwrap(),
        ],
    );
    cmd.env("RADIO_SSH_KEY_PASSPHRASE", "s3cret");
    let o = cmd.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn circle_card_exchange_and_fingerprint_display() {
    let dir = tempfile::tempdir().unwrap();
    let mk = |name: &str| {
        let key = write_key(dir.path(), &format!("{name}_id"), None);
        let cfg = dir.path().join(name);
        let out = run_cli(
            &cfg,
            &["init", "--name", name, "--ssh-key", key.to_str().unwrap()],
        );
        assert_eq!(out.code, 0, "{out:?}");
        let card_file = dir.path().join(format!("{name}.card"));
        std::fs::write(&card_file, &out.stdout).unwrap();
        (cfg, card_file, out.stdout)
    };
    let (alice, alice_card, _) = mk("alice");
    let (bob, bob_card, bob_text) = mk("bob");

    // Without --yes and without a terminal there is no confirmation: nothing is pinned.
    let out = run_cli(
        &alice,
        &["circle", "add", "--card", bob_card.to_str().unwrap()],
    );
    assert_eq!(out.code, exit::CONFIG, "{out:?}");
    assert!(
        out.stderr.contains("SSH fingerprint: SHA256:") && out.stderr.contains("card code:"),
        "{out:?}"
    );
    assert!(run_cli(&alice, &["circle", "list"])
        .stdout
        .contains("empty"));

    let out = run_cli(
        &alice,
        &[
            "circle",
            "add",
            "--card",
            bob_card.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(out.code, exit::OK, "{out:?}");
    let list = run_cli(&alice, &["circle", "list"]);
    assert!(
        list.stdout.contains("bob")
            && list.stdout.contains("SHA256:")
            && list.stdout.contains("DHT key:"),
        "{list:?}"
    );

    // Re-adding, or pinning a different key under the same name, is refused.
    assert_eq!(
        run_cli(
            &alice,
            &[
                "circle",
                "add",
                "--card",
                bob_card.to_str().unwrap(),
                "--yes"
            ]
        )
        .code,
        exit::CONFIG
    );
    let impostor = bob_text.replace(
        &bob_text
            .lines()
            .find(|l| l.starts_with("dht_public_key"))
            .unwrap()
            .to_string(),
        &format!("dht_public_key = \"{}\"", "ab".repeat(32)),
    );
    let impostor_file = dir.path().join("impostor.card");
    std::fs::write(&impostor_file, impostor).unwrap();
    let out = run_cli(
        &alice,
        &[
            "circle",
            "add",
            "--card",
            impostor_file.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(out.code, exit::CONFIG, "{out:?}");

    // Export a pinned member's card and re-import it elsewhere.
    let exported = run_cli(&alice, &["circle", "export", "bob"]);
    assert_eq!(exported.code, 0);
    assert!(exported.stdout.contains("name = \"bob\""));
    let out = run_cli(
        &bob,
        &[
            "circle",
            "add",
            "--card",
            alice_card.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(out.code, 0, "{out:?}");

    // Explicit keys instead of a card.
    let card = radio::circle::Member::from_card(&bob_text).unwrap();
    let carol = dir.path().join("carol_cfg");
    let key = write_key(dir.path(), "carol_id", None);
    assert_eq!(
        run_cli(
            &carol,
            &[
                "init",
                "--name",
                "carol",
                "--ssh-key",
                key.to_str().unwrap()
            ]
        )
        .code,
        0
    );
    let out = run_cli(
        &carol,
        &[
            "circle",
            "add",
            "--name",
            "bob",
            "--ssh-key",
            &card.ssh_public_key,
            "--dht-key",
            &card.dht_public_key,
            "--yes",
        ],
    );
    assert_eq!(out.code, 0, "{out:?}");

    // JSON listing, then removal.
    let j = run_cli(&alice, &["--json", "circle", "list"]);
    assert_eq!(j.json_lines()[0]["name"], "bob");
    assert_eq!(run_cli(&alice, &["circle", "remove", "bob"]).code, 0);
    assert_eq!(
        run_cli(&alice, &["circle", "remove", "bob"]).code,
        exit::CONFIG
    );
}

#[test]
fn bad_card_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", None);
    let cfg = dir.path().join("cfg");
    assert_eq!(
        run_cli(
            &cfg,
            &[
                "init",
                "--name",
                "alice",
                "--ssh-key",
                key.to_str().unwrap()
            ]
        )
        .code,
        0
    );
    let bad = dir.path().join("bad.card");
    std::fs::write(
        &bad,
        "radio_card = 1\nname = \"x\"\nssh_public_key = \"nope\"\ndht_public_key = \"00\"\n",
    )
    .unwrap();
    assert_eq!(
        run_cli(
            &cfg,
            &["circle", "add", "--card", bad.to_str().unwrap(), "--yes"]
        )
        .code,
        exit::CONFIG
    );
}

#[test]
fn publish_validates_before_any_network_or_signing() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", None);
    let cfg = dir.path().join("cfg");
    // Bootstrap points nowhere; a bad message must fail with exit 4 without touching the network.
    assert_eq!(
        run_cli(
            &cfg,
            &[
                "init",
                "--name",
                "alice",
                "--ssh-key",
                key.to_str().unwrap(),
                "--bootstrap",
                "127.0.0.1:9"
            ]
        )
        .code,
        0
    );
    let out = run_cli(&cfg, &["publish", "--message", ""]);
    assert_eq!(out.code, exit::BAD_MESSAGE, "{out:?}");
    let out = run_cli(&cfg, &["publish", "--message", &"x".repeat(5000)]);
    assert_eq!(out.code, exit::BAD_MESSAGE, "{out:?}");
    assert!(out.stderr.contains("over the BEP 44 limit"), "{out:?}");
    let out = run_cli(&cfg, &["publish", "--message", "esc\u{1b}[2J"]);
    assert_eq!(out.code, exit::BAD_MESSAGE, "{out:?}");
    let bin = dir.path().join("bin.txt");
    std::fs::write(&bin, [0xffu8, 0xfe, 0xfd]).unwrap();
    let out = run_cli(&cfg, &["publish", "--file", bin.to_str().unwrap()]);
    assert_eq!(out.code, exit::BAD_MESSAGE, "{out:?}");
}

#[test]
fn help_documents_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_cli(dir.path(), &["--help"]);
    assert_eq!(out.code, 0);
    for needle in [
        "Exit codes:",
        "10  listen: no new message",
        "11  DHT unavailable",
        "12  verification failure",
    ] {
        assert!(out.stdout.contains(needle), "missing {needle:?}: {out:?}");
    }
}

#[test]
fn message_content_is_never_executed_and_terminal_escapes_are_neutralised() {
    // The message is stored/printed as data. Escape sequences cannot be published (rejected),
    // and anything already in state is sanitised when printed.
    assert_eq!(
        radio::util::sanitize_for_terminal("a\u{1b}]0;title\u{7}b"),
        "a\\u{1b}]0;title\\u{7}b"
    );
    assert!(
        radio::payload::validate_message("$(touch /tmp/pwned)").is_ok(),
        "shell syntax is just text"
    );
}

#[test]
fn card_out_writes_utf8_and_powershell_utf16_cards_can_be_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let key = write_key(dir.path(), "id", None);
    let alice = dir.path().join("alice");
    let card_file = dir.path().join("alice.card");
    let out = run_cli(
        &alice,
        &[
            "init",
            "--name",
            "alice",
            "--ssh-key",
            key.to_str().unwrap(),
            "--card-out",
            card_file.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stdout.is_empty(),
        "card goes to the file, not stdout: {out:?}"
    );
    let text = std::fs::read_to_string(&card_file).unwrap();
    assert!(text.contains("name = \"alice\""));

    // Windows PowerShell's `>` produces UTF-16LE with a BOM; importing must still work.
    let mut utf16 = vec![0xffu8, 0xfe];
    for u in text.encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    let ps_card = dir.path().join("alice_ps.card");
    std::fs::write(&ps_card, utf16).unwrap();
    let bob = dir.path().join("bob");
    let bkey = write_key(dir.path(), "bid", None);
    assert_eq!(
        run_cli(
            &bob,
            &["init", "--name", "bob", "--ssh-key", bkey.to_str().unwrap()]
        )
        .code,
        0
    );
    let out = run_cli(
        &bob,
        &[
            "circle",
            "add",
            "--card",
            ps_card.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(out.code, exit::OK, "{out:?}");

    let exported = dir.path().join("out.card");
    assert_eq!(
        run_cli(
            &bob,
            &[
                "circle",
                "export",
                "alice",
                "--out",
                exported.to_str().unwrap()
            ]
        )
        .code,
        0
    );
    assert_eq!(std::fs::read_to_string(&exported).unwrap(), text);
}
