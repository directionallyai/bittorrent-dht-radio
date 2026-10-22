//! Failure paths: each must surface the right status and exit code.

mod common;

use common::*;
use radio::app;
use radio::config::load_publisher_key;
use radio::exit;
use radio::item;
use radio::ops::Publisher;
use radio::payload::{Payload, NAMESPACE};
use radio::sshsig;
use radio::state::Store;
use radio::util::now_secs;

fn publish_as(c: &Client, msg: &str, now: u64, ttl: u64) {
    let cfg = app::load_config(&c.paths).unwrap();
    let ssh = app::load_signer(&cfg).unwrap();
    let key = load_publisher_key(&c.paths).unwrap();
    let net = app::connect(&cfg, &c.paths, |_| {}).unwrap();
    let store = Store::new(&c.paths);
    Publisher {
        cfg: &cfg,
        ssh: &ssh,
        dht_key: &key,
        store: &store,
    }
    .publish(&net, msg, ttl, true, now)
    .unwrap();
}

/// Put an arbitrary `v` under `c`'s DHT feed key (what a compromised or malicious publisher key
/// holder could do), with a valid BEP 44 signature.
fn put_raw(c: &Client, seq: i64, value: &[u8]) {
    let key = load_publisher_key(&c.paths).unwrap();
    let cfg = app::load_config(&c.paths).unwrap();
    let dht = app::connect(&cfg, &c.paths, |_| {}).unwrap();
    dht.put(mainline::MutableItem::new(key, value, seq, None), None)
        .expect("raw put");
}

fn listen_json(c: &Client) -> Out {
    c.cli(&["--json", "listen"])
}

fn tamper_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        ("tampered", "tampered-payload"),
        ("other-ssh-key", "signer-mismatch"),
        ("namespace", "wrong-namespace"),
        ("sender", "sender-mismatch"),
    ]
}

#[test]
fn dht_unreachable_dead_bootstrap_port() {
    let dead = format!("127.0.0.1:{}", dead_udp_port());
    let a = Client::new("alice", std::slice::from_ref(&dead));
    let b = Client::new("bob", &[dead]);
    a.trust(&b);
    b.trust(&a);
    for c in [&a, &b] {
        c.edit_config(|cfg| {
            cfg.dht.bootstrap_attempts = 2;
            cfg.dht.request_timeout_ms = 200;
        });
    }
    let out = b.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::DHT_UNAVAILABLE, "{out:?}");
    let status = out.events_of("status");
    assert_eq!(status[0]["status"], "unreachable", "{out:?}");

    let out = a.cli(&["publish", "--message", "x"]);
    assert_eq!(out.code, exit::DHT_UNAVAILABLE, "{out:?}");
    assert!(out.stderr.contains("bootstrap failed"), "{out:?}");
}

#[test]
fn udp_timeout_blackhole_bootstrap() {
    // A socket that is open but never answers: every UDP request times out.
    let hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = format!("127.0.0.1:{}", hole.local_addr().unwrap().port());
    let a = Client::new("alice", std::slice::from_ref(&addr));
    let b = Client::new("bob", &[addr]);
    b.trust(&a);
    b.edit_config(|cfg| {
        cfg.dht.bootstrap_attempts = 2;
        cfg.dht.request_timeout_ms = 200;
    });
    let started = std::time::Instant::now();
    let out = b.cli(&["listen"]);
    assert_eq!(out.code, exit::DHT_UNAVAILABLE, "{out:?}");
    assert!(out.stderr.contains("unreachable"), "{out:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    drop(hole);
}

#[test]
fn unresolvable_dns_bootstrap_with_ip_bootstrap_still_working() {
    let net = testnet();
    let (a, b) = pair(&net);
    for c in [&a, &b] {
        c.edit_config(|cfg| {
            cfg.dht
                .bootstrap
                .insert(0, "does-not-exist.invalid:6881".into())
        });
    }
    let out = a.cli(&["publish", "--message", "dns fallback"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stderr.contains("does-not-exist.invalid") && out.stderr.contains("cannot resolve"),
        "{out:?}"
    );
    let out = b.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert_eq!(out.events_of("message")[0]["message"], "dns fallback");
    assert_eq!(
        out.events_of("note").len(),
        1,
        "unresolvable host is reported once: {out:?}"
    );
}

#[test]
fn only_unresolvable_bootstrap_is_dht_unavailable() {
    let net = testnet();
    let (a, b) = pair(&net);
    let _ = a;
    b.edit_config(|cfg| cfg.dht.bootstrap = vec!["does-not-exist.invalid:6881".into()]);
    let out = b.cli(&["listen"]);
    assert_eq!(out.code, exit::DHT_UNAVAILABLE, "{out:?}");
    assert!(
        out.stderr.contains("no usable bootstrap address"),
        "{out:?}"
    );
}

#[test]
fn clock_skew_small_tolerated_large_reported() {
    let net = testnet();
    let (a, b) = pair(&net);
    // Issued 60s in the future: within the default 120s tolerance.
    publish_as(&a, "slightly ahead", now_secs() + 60, 3600);
    let out = listen_json(&b);
    assert_eq!(out.code, exit::OK, "{out:?}");

    // Issued 1h in the future: reported, not accepted.
    publish_as(&a, "far ahead", now_secs() + 3600, 3600);
    let out = listen_json(&b);
    assert_eq!(out.code, exit::VERIFY_FAILED, "{out:?}");
    let rej = &out.events_of("rejected")[0];
    assert_eq!(rej["reason"], "clock-skew");
    assert!(
        rej["detail"].as_str().unwrap().contains("clock skew"),
        "{out:?}"
    );

    // A larger configured tolerance accepts it.
    b.edit_config(|cfg| cfg.clock_skew_secs = 7200);
    let out = listen_json(&b);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert_eq!(out.events_of("message")[0]["message"], "far ahead");
}

#[test]
fn publisher_offline_no_record_is_a_warning_with_no_new_exit() {
    let net = testnet();
    let (_a, b) = pair(&net); // alice never published
    let out = b.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::NO_NEW, "{out:?}");
    let st = &out.events_of("status")[0];
    assert_eq!(st["status"], "not-found", "{out:?}");
    assert!(
        st["detail"].as_str().unwrap().contains("publisher offline"),
        "{out:?}"
    );
    // Human output carries a per-member warning on stderr.
    let out = b.cli(&["listen"]);
    assert!(out.stderr.contains("warning: alice: not-found"), "{out:?}");
}

#[test]
fn record_expired_is_reported_stale() {
    let net = testnet();
    let (a, b) = pair(&net);
    publish_as(&a, "short lived", now_secs() - 7200, 60);
    let out = b.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::NO_NEW, "{out:?}");
    assert!(out.events_of("message").is_empty());
    let st = &out.events_of("status")[0];
    assert_eq!(st["status"], "expired", "{out:?}");
    let out = b.cli(&["listen"]);
    assert!(out.stderr.contains("warning: alice: expired"), "{out:?}");
}

#[test]
fn later_outage_after_success_is_unverifiable_not_no_new() {
    let net = testnet();
    let (a, b) = pair(&net);
    assert_eq!(a.cli(&["publish", "--message", "hi"]).code, exit::OK);
    assert_eq!(b.cli(&["listen"]).code, exit::OK);
    // Point bob at a dead DHT: freshness cannot be verified even though a message was seen.
    b.edit_config(|cfg| {
        cfg.dht.bootstrap = vec![format!("127.0.0.1:{}", dead_udp_port())];
        cfg.dht.bootstrap_attempts = 1;
        cfg.dht.request_timeout_ms = 200;
    });
    // Also drop the cached routing table so it cannot rescue the lookup.
    let _ = std::fs::remove_file(b.paths.routing_cache());
    let out = b.cli(&["listen"]);
    assert_eq!(out.code, exit::DHT_UNAVAILABLE, "{out:?}");
    assert!(out.stderr.contains("last verified message"), "{out:?}");
}

#[test]
fn rejections_over_a_real_dht_have_specific_diagnostics_and_exit_12() {
    let net = testnet();
    for (case, reason) in tamper_cases() {
        let (a, b) = pair(&net);
        let cfg = app::load_config(&a.paths).unwrap();
        let ssh = app::load_signer(&cfg).unwrap();
        let now = now_secs();
        let seq = now as i64;
        let payload = Payload {
            sender: if case == "sender" {
                "mallory".into()
            } else {
                "alice".into()
            },
            to: None,
            seq,
            issued_at: now,
            expires_at: now + 600,
            prev: None,
            message: "forged".into(),
        };
        let bytes = payload.encode().unwrap();
        let value = match case {
            "tampered" => {
                let blob = sshsig::sig_to_blob(&ssh.sign(&bytes).unwrap()).unwrap();
                let mut tampered = bytes.clone();
                *tampered.last_mut().unwrap() ^= 1;
                item::encode_value(&tampered, &blob).unwrap()
            }
            "other-ssh-key" => {
                let other = radio::selftest::make_identity(
                    &radio::config::Paths {
                        root: a.dir.path().join("other"),
                    },
                    "other",
                    &net.bootstrap,
                )
                .unwrap();
                let _ = other;
                let cfg2 = app::load_config(&radio::config::Paths {
                    root: a.dir.path().join("other"),
                })
                .unwrap();
                let ssh2 = app::load_signer(&cfg2).unwrap();
                item::encode_value(
                    &bytes,
                    &sshsig::sig_to_blob(&ssh2.sign(&bytes).unwrap()).unwrap(),
                )
                .unwrap()
            }
            "namespace" => {
                let radio::sshsig::Signer::File { key, .. } = &ssh else {
                    unreachable!()
                };
                let sig = key
                    .sign("not-radio@example.com", ssh_key::HashAlg::Sha512, &bytes)
                    .unwrap();
                item::encode_value(&bytes, &sshsig::sig_to_blob(&sig).unwrap()).unwrap()
            }
            _ => item::encode_value(
                &bytes,
                &sshsig::sig_to_blob(&ssh.sign(&bytes).unwrap()).unwrap(),
            )
            .unwrap(),
        };
        put_raw(&a, seq, &value);

        let out = listen_json(&b);
        assert_eq!(out.code, exit::VERIFY_FAILED, "{case}: {out:?}");
        let rej = &out.events_of("rejected")[0];
        assert_eq!(rej["reason"], reason, "{case}: {out:?}");
        assert!(
            out.events_of("message").is_empty(),
            "{case}: forged message must not be shown"
        );
        // Nothing was accepted into state.
        assert_eq!(b.state().members.values().next().unwrap().highest_seq, 0);
    }
    assert_eq!(NAMESPACE, "bittorrent-dht-radio@directionally.com");
}

#[test]
fn rollback_and_seq_reuse_detected_end_to_end_with_pinned_state() {
    // Bob has already accepted a high seq (persisted); a lower-seq item for the same feed is a
    // replay/rollback even though its signatures are valid.
    let net = testnet();
    let (a, b) = pair(&net);
    publish_as(&a, "old", now_secs() - 100, 3600);
    // Pretend bob had previously accepted a far higher seq.
    let a_key = a.card.dht_public_key.clone();
    Store::new(&b.paths)
        .update(|s| {
            let m = s.members.entry(a_key.clone()).or_default();
            m.highest_seq = i64::MAX / 2;
            m.last_message = None;
        })
        .unwrap();
    let out = listen_json(&b);
    assert_eq!(out.code, exit::VERIFY_FAILED, "{out:?}");
    assert_eq!(out.events_of("rejected")[0]["reason"], "replay-rollback");
}

#[test]
fn not_initialised_and_empty_circle_are_config_errors() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_cli(dir.path(), &["listen"]);
    assert_eq!(out.code, exit::CONFIG, "{out:?}");
    assert!(out.stderr.contains("not initialised"), "{out:?}");

    let net = testnet();
    let a = Client::new("alice", &net.bootstrap);
    let out = a.cli(&["listen"]);
    assert_eq!(out.code, exit::CONFIG, "{out:?}");
    assert!(out.stderr.contains("circle is empty"), "{out:?}");
}
