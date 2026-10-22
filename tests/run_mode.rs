//! `radio run`: two unattended processes publish and listen at the same time.

mod common;

use std::process::Stdio;
use std::time::Duration;

use common::*;

#[test]
fn two_unattended_runs_exchange_heartbeats_and_republish() {
    let net = testnet();
    let (a, b) = pair(&net);
    let status_a = a.dir.path().join("status_a.txt");
    let status_b = b.dir.path().join("status_b.txt");
    std::fs::write(&status_a, "alice ok v1\n").unwrap();
    std::fs::write(&status_b, "bob ok v1\n").unwrap();

    let spawn = |c: &Client, status: &std::path::Path| {
        command(
            &c.paths.root,
            &[
                "--json",
                "run",
                "--status-file",
                status.to_str().unwrap(),
                "--publish-every",
                "1s",
                "--listen-every",
                "1s",
                "--jitter",
                "10%",
                "--republish-every",
                "2s",
                "--exit-after",
                "9s",
            ],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
    };
    let ca = spawn(&a, &status_a);
    let cb = spawn(&b, &status_b);

    // Change the status files mid-run: the next heartbeat must carry the new content.
    std::thread::sleep(Duration::from_secs(4));
    std::fs::write(&status_a, "alice ok v2\n").unwrap();
    std::fs::write(&status_b, "bob ok v2\n").unwrap();

    let (oa, ob) = (
        ca.wait_with_output().unwrap(),
        cb.wait_with_output().unwrap(),
    );
    let to_out = |o: std::process::Output| Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    };
    let (oa, ob) = (to_out(oa), to_out(ob));
    assert_eq!(oa.code, 0, "{oa:?}");
    assert_eq!(ob.code, 0, "{ob:?}");

    for (me, out, peer, v2) in [
        ("alice", &oa, "bob", "bob ok v2"),
        ("bob", &ob, "alice", "alice ok v2"),
    ] {
        let published: Vec<_> = out.events_of("published");
        let fresh: Vec<_> = published
            .iter()
            .filter(|e| e["kind"] == "published")
            .collect();
        let rep: Vec<_> = published
            .iter()
            .filter(|e| e["kind"] == "republished")
            .collect();
        assert!(fresh.len() >= 3, "{me} should publish repeatedly: {out:?}");
        let seqs: Vec<_> = fresh.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
        assert!(
            seqs.windows(2).all(|w| w[1] > w[0]),
            "{me}: seq must increase: {seqs:?}"
        );
        let issued: Vec<_> = fresh
            .iter()
            .map(|e| e["issued_at"].as_u64().unwrap())
            .collect();
        assert!(
            issued.last() > issued.first(),
            "{me}: fresh heartbeats advance issued-at"
        );
        assert!(!rep.is_empty(), "{me} should republish: {out:?}");
        // Every republish repeats an earlier signed item unchanged.
        for r in &rep {
            let seq = r["seq"].as_i64().unwrap();
            let orig = fresh
                .iter()
                .find(|f| f["seq"].as_i64().unwrap() == seq)
                .expect("republished seq was published");
            assert_eq!(orig["issued_at"], r["issued_at"]);
            assert_eq!(orig["expires_at"], r["expires_at"]);
        }
        // Listening happened concurrently and saw the peer, including the changed status file.
        let msgs: Vec<_> = out.events_of("message");
        assert!(
            msgs.len() >= 2,
            "{me} should hear several heartbeats from {peer}: {out:?}"
        );
        assert!(msgs.iter().all(|m| m["member"] == peer));
        assert!(
            msgs.iter().any(|m| m["message"] == v2),
            "{me} should see {peer}'s updated status: {out:?}"
        );
        // No duplicates: every (member, seq) is printed once.
        let mut seen = std::collections::HashSet::new();
        for m in &msgs {
            assert!(
                seen.insert(m["seq"].as_i64().unwrap()),
                "duplicate output for {m}"
            );
        }
    }
}

#[test]
fn run_survives_dht_outage_at_start_and_reports_it() {
    let dead = format!("127.0.0.1:{}", dead_udp_port());
    let c = Client::new("alice", &[dead]);
    c.edit_config(|cfg| {
        cfg.dht.bootstrap_attempts = 1;
        cfg.dht.request_timeout_ms = 200;
    });
    let out = c.cli(&[
        "--json",
        "run",
        "--message",
        "hb",
        "--publish-every",
        "1s",
        "--listen-every",
        "1s",
        "--exit-after",
        "3s",
    ]);
    assert_eq!(
        out.code, 0,
        "an unattended run keeps going through outages: {out:?}"
    );
    let errors = out.events_of("error");
    assert!(
        !errors.is_empty() && errors[0]["context"] == "publish",
        "{out:?}"
    );
}
