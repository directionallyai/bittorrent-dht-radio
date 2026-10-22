//! Two independent clients on a private loopback DHT: real BEP 44 puts and gets, SSH-signed,
//! verified against locally pinned keys.

mod common;

use common::*;
use radio::app;
use radio::config::load_publisher_key;
use radio::exit;
use radio::ops::{self, Publisher, Source};
use radio::output::Event;
use radio::state::{MemberStatus, Store};
use radio::util::now_secs;

fn publish_as(c: &Client, msg: &str, now: u64, ttl: u64) -> ops::PublishReport {
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
    .unwrap()
}

#[test]
fn a_publishes_b_listens_and_verifies_cli() {
    let net = testnet();
    let (a, b) = pair(&net);
    let out = a.cli(&["publish", "--message", "hello from alice"]);
    assert_eq!(out.code, exit::OK, "{out:?}");

    let out = b.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    let msgs = out.events_of("message");
    assert_eq!(msgs.len(), 1, "{out:?}");
    assert_eq!(msgs[0]["member"], "alice");
    assert_eq!(msgs[0]["message"], "hello from alice");
    assert!(msgs[0]["ssh_fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));

    // Human-readable output too.
    let out = a.cli(&["publish", "--message", "second"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    let out = b.cli(&["listen"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(out.stdout.contains("alice: second"), "{out:?}");
}

#[test]
fn both_directions_concurrently_via_library() {
    let net = testnet();
    let (a, b) = pair(&net);
    let (ra, rb) = std::thread::scope(|s| {
        let ha = s.spawn(|| {
            publish_as(&a, "from a", now_secs(), 600);
            poll_until(&a, "bob", "from b")
        });
        let hb = s.spawn(|| {
            publish_as(&b, "from b", now_secs(), 600);
            poll_until(&b, "alice", "from a")
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });
    assert!(
        ra && rb,
        "both clients must see each other's verified message"
    );
}

fn poll_until(c: &Client, from: &str, text: &str) -> bool {
    let cfg = app::load_config(&c.paths).unwrap();
    let circle = app::load_circle(&c.paths).unwrap();
    let net = app::connect(&cfg, &c.paths, |_| {}).unwrap();
    let store = Store::new(&c.paths);
    for _ in 0..40 {
        let r =
            ops::poll_circle(&circle, &store, &Source::Live(&net), now_secs(), 120, true).unwrap();
        if r.events.iter().any(|e| matches!(e, Event::Message { member, message, .. } if member == from && message == text)) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

#[test]
fn restart_produces_no_duplicates_and_keeps_roster_and_seqs() {
    let net = testnet();
    let (a, b) = pair(&net);
    assert_eq!(a.cli(&["publish", "--message", "once"]).code, exit::OK);

    let first = b.cli(&["--json", "listen"]);
    assert_eq!(first.code, exit::OK, "{first:?}");
    assert_eq!(first.events_of("message").len(), 1);
    let seq_after_first = b.state().members.values().next().unwrap().highest_seq;
    assert!(seq_after_first > 0);

    // A new process (a "restart") must not print the same message again.
    let second = b.cli(&["--json", "listen"]);
    assert_eq!(second.code, exit::NO_NEW, "{second:?}");
    assert!(second.events_of("message").is_empty(), "{second:?}");

    // State and roster survived.
    let st = b.state();
    assert_eq!(
        st.members.values().next().unwrap().highest_seq,
        seq_after_first
    );
    assert_eq!(
        st.members
            .values()
            .next()
            .unwrap()
            .last_message
            .as_ref()
            .unwrap()
            .message,
        "once"
    );
    let list = b.cli(&["circle", "list"]);
    assert!(list.stdout.contains("alice"), "{list:?}");

    // A genuinely new message is shown exactly once.
    assert_eq!(a.cli(&["publish", "--message", "twice"]).code, exit::OK);
    let third = b.cli(&["--json", "listen"]);
    assert_eq!(third.events_of("message").len(), 1);
    assert_eq!(third.events_of("message")[0]["message"], "twice");
    assert_eq!(b.cli(&["listen"]).code, exit::NO_NEW);
}

#[test]
fn follow_mode_prints_each_message_once_across_restart() {
    let net = testnet();
    let (a, b) = pair(&net);
    assert_eq!(a.cli(&["publish", "--message", "m1"]).code, exit::OK);
    // `listen --follow` has no exit-after, so drive it with the library loop semantics instead:
    // first pass reports, later passes are quiet.
    let cfg = app::load_config(&b.paths).unwrap();
    let circle = app::load_circle(&b.paths).unwrap();
    let nets = app::connect(&cfg, &b.paths, |_| {}).unwrap();
    let store = Store::new(&b.paths);
    let r1 =
        ops::poll_circle(&circle, &store, &Source::Live(&nets), now_secs(), 120, true).unwrap();
    assert_eq!(r1.summary.new, 1);
    let r2 = ops::poll_circle(
        &circle,
        &store,
        &Source::Live(&nets),
        now_secs(),
        120,
        false,
    )
    .unwrap();
    assert!(r2.events.is_empty());
    drop(nets);
    let nets = app::connect(&cfg, &b.paths, |_| {}).unwrap();
    let r3 = ops::poll_circle(
        &circle,
        &Store::new(&b.paths),
        &Source::Live(&nets),
        now_secs(),
        120,
        false,
    )
    .unwrap();
    assert!(
        r3.events.is_empty(),
        "restart must not re-announce: {:?}",
        r3.events
    );
}

#[test]
fn republish_keeps_signed_timestamp_fresh_heartbeat_changes_it() {
    let net = testnet();
    let (a, b) = pair(&net);
    let t0 = now_secs() - 1000; // keep every issued-at in the past (no clock-skew rejection)
    let first = publish_as(&a, "heartbeat", t0, 3600);

    // Republish later, with a different "now": the signed item must be identical.
    let cfg = app::load_config(&a.paths).unwrap();
    let key = load_publisher_key(&a.paths).unwrap();
    let dht = app::connect(&cfg, &a.paths, |_| {}).unwrap();
    let store = Store::new(&a.paths);
    let before = store.load().unwrap().publisher.last_item.unwrap();
    let rep = ops::republish(&store, &key, &dht, t0 + 600).unwrap();
    let after = store.load().unwrap().publisher.last_item.unwrap();
    assert_eq!(rep.kind, "republished");
    assert_eq!(
        (rep.seq, rep.issued_at, rep.expires_at),
        (first.seq, first.issued_at, first.expires_at)
    );
    assert_eq!(before, after, "republish must not change the signed item");
    assert_eq!(
        store.load().unwrap().publisher.last_republish_ok_at,
        Some(t0 + 600)
    );
    assert_eq!(store.load().unwrap().publisher.last_publish_ok_at, Some(t0));

    // What B reads from the DHT is still the original signed timestamp.
    let out = b.cli(&["--json", "listen"]);
    let m = &out.events_of("message")[0];
    assert_eq!(m["issued_at"].as_u64().unwrap(), t0);

    // A fresh heartbeat re-signs: new seq, new issued-at.
    let second = publish_as(&a, "heartbeat", t0 + 700, 3600);
    assert!(second.seq > first.seq);
    assert_eq!(second.issued_at, t0 + 700);
    let out = b.cli(&["--json", "listen"]);
    let m = &out.events_of("message")[0];
    assert_eq!(m["issued_at"].as_u64().unwrap(), t0 + 700);
    assert_eq!(m["seq"].as_i64().unwrap(), second.seq);
}

#[test]
fn republish_cli_messages_and_exit_codes() {
    let net = testnet();
    let (a, _b) = pair(&net);
    // Nothing published yet.
    let out = a.cli(&["republish"]);
    assert_eq!(out.code, exit::STALE_ITEM, "{out:?}");
    assert_eq!(a.cli(&["publish", "--message", "x"]).code, exit::OK);
    let out = a.cli(&["republish"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stderr.contains("does not prove the sender is online"),
        "{out:?}"
    );
    assert!(out.stdout.contains("republished"), "{out:?}");
}

#[test]
fn republish_refuses_an_expired_item() {
    let net = testnet();
    let (a, _b) = pair(&net);
    let t0 = now_secs() - 7200;
    publish_as(&a, "old", t0, 60);
    let out = a.cli(&["republish"]);
    assert_eq!(out.code, exit::STALE_ITEM, "{out:?}");
    assert!(out.stderr.contains("expired"), "{out:?}");
}

#[test]
fn max_size_message_roundtrips_over_the_dht() {
    let net = testnet();
    let (a, b) = pair(&net);
    let now = now_secs();
    let max = radio::publish::max_message_bytes("alice", now as i64, now, 3600, false);
    let msg = "m".repeat(max);
    let out = a.cli(&[
        "--json",
        "publish",
        "--no-prev",
        "--ttl",
        "1h",
        "--message",
        &msg,
    ]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert_eq!(out.events_of("published")[0]["bytes_bencoded"], 1000);
    let out = b.cli(&["--json", "listen"]);
    assert_eq!(
        out.events_of("message")[0]["message"]
            .as_str()
            .unwrap()
            .len(),
        max
    );

    let too_big = "m".repeat(max + 1);
    let out = a.cli(&["publish", "--no-prev", "--ttl", "1h", "--message", &too_big]);
    assert_eq!(out.code, exit::BAD_MESSAGE, "{out:?}");
    assert!(
        out.stderr.contains("over the BEP 44 limit of 1000"),
        "{out:?}"
    );
}

#[test]
fn status_reports_members_and_put_results() {
    let net = testnet();
    let (a, b) = pair(&net);
    assert_eq!(
        a.cli(&["publish", "--message", "status check"]).code,
        exit::OK
    );
    assert_eq!(b.cli(&["listen"]).code, exit::OK);
    let out = b.cli(&["status"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stdout.contains("alice") && out.stdout.contains("status: ok"),
        "{out:?}"
    );
    let out = a.cli(&["status"]);
    assert!(out.stdout.contains("last put:         ok"), "{out:?}");
    let j = a.cli(&["--json", "status"]).json_lines().remove(0);
    assert_eq!(j["publisher"]["last_put"]["ok"], true);
    assert_eq!(
        b.state().members.values().next().unwrap().status,
        Some(MemberStatus::Ok)
    );

    let out = b.cli(&["doctor"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    assert!(
        out.stdout.contains("bootstrapped") && out.stdout.contains("member alice"),
        "{out:?}"
    );
}
