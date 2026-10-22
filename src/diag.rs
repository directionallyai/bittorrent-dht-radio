//! `radio status` (saved state, no network) and `radio doctor` (live checks).

use serde_json::json;

use crate::app;
use crate::config::{Config, Paths, SshConfig};
use crate::exit::{self, Coded, WithCode};
use crate::net::{self, EntryKind, Net, NetConfig};
use crate::ops::{self, Fetch, Outcome};
use crate::sshsig;
use crate::state::{MemberState, Store};
use crate::util::{format_age, format_utc, now_secs};

fn ago(now: u64, t: Option<u64>) -> String {
    t.map(|t| format!("{} ago ({})", format_age(now.saturating_sub(t)), format_utc(t)))
        .unwrap_or_else(|| "never".into())
}

fn signer_desc(cfg: &Config) -> String {
    match &cfg.ssh {
        SshConfig::File { key_path } => format!("private key file {}", key_path.display()),
        SshConfig::Agent { socket, .. } => format!(
            "ssh-agent ({})",
            socket.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "default socket".into())
        ),
    }
}

pub fn status(paths: &Paths, json: bool) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    let circle = app::load_circle(paths)?;
    let state = Store::new(paths).load().code(exit::ERROR)?;
    let card = app::own_card(paths, &cfg)?;
    let now = now_secs();
    let cached = net::read_cache(&paths.routing_cache()).len();

    let members: Vec<_> = circle
        .members
        .iter()
        .map(|m| (m, state.members.get(&m.dht_public_key).cloned().unwrap_or_default()))
        .collect();

    if json {
        let item = state.publisher.last_item.as_ref();
        let v = json!({
            "type": "status",
            "config_dir": paths.root,
            "name": cfg.name,
            "ssh_fingerprint": card.ssh_fingerprint(),
            "dht_public_key": card.dht_public_key,
            "signer": signer_desc(&cfg),
            "publisher": {
                "last_item": item.map(|i| json!({
                    "seq": i.seq, "issued_at": i.issued_at, "expires_at": i.expires_at,
                    "expired": now >= i.expires_at, "message": i.message,
                })),
                "last_put": state.publisher.last_put,
                "last_publish_ok_at": state.publisher.last_publish_ok_at,
                "last_republish_ok_at": state.publisher.last_republish_ok_at,
            },
            "dht": {
                "cached_routing_nodes": cached,
                "bootstrap_configured": cfg.dht.bootstrap,
                "last_check": state.dht,
            },
            "members": members.iter().map(|(m, s)| json!({
                "name": m.name,
                "ssh_fingerprint": m.ssh_fingerprint(),
                "dht_public_key": m.dht_public_key,
                "status": s.status.map(|x| x.as_str()),
                "status_since": s.status_since,
                "highest_seq": s.highest_seq,
                "last_message": s.last_message,
                "last_verified_at": s.last_verified_at,
                "last_poll_at": s.last_poll_at,
                "last_poll_detail": s.last_poll_detail,
                "last_rejection": s.last_rejection,
            })).collect::<Vec<_>>(),
        });
        println!("{v}");
        return Ok(exit::OK);
    }

    println!("radio status  ({})", paths.root.display());
    println!("  sender:        {}", cfg.name);
    println!("  SSH signer:    {} [{}]", signer_desc(&cfg), card.ssh_fingerprint());
    println!("  DHT feed key:  {}{}", card.dht_public_key, cfg.salt.as_ref().map(|s| format!(" (salt {s:?})")).unwrap_or_default());
    println!("\nPublishing");
    match &state.publisher.last_item {
        Some(i) => println!(
            "  last signed item: seq {}, issued {}, {} {}",
            i.seq,
            format_utc(i.issued_at),
            if now >= i.expires_at { "EXPIRED" } else { "valid until" },
            format_utc(i.expires_at)
        ),
        None => println!("  last signed item: none yet"),
    }
    match &state.publisher.last_put {
        Some(p) if p.ok => println!(
            "  last put:         ok, {} seq {} stored at {} node(s), {}",
            p.kind,
            p.seq,
            p.stored_at.unwrap_or(0),
            ago(now, Some(p.at))
        ),
        Some(p) => println!("  last put:         FAILED ({}) {}: {}", p.kind, ago(now, Some(p.at)), p.error.as_deref().unwrap_or("?")),
        None => println!("  last put:         none yet"),
    }
    println!("  last publish ok:   {}", ago(now, state.publisher.last_publish_ok_at));
    println!(
        "  last republish ok: {}   (republish re-sends the same signed item; it does not advance the timestamp or prove liveness)",
        ago(now, state.publisher.last_republish_ok_at)
    );
    println!("\nDHT");
    println!("  bootstrap:        {}", if cfg.dht.bootstrap.is_empty() { "mainline defaults".into() } else { cfg.dht.bootstrap.join(", ") });
    println!("  cached routing nodes for next start: {cached}");
    match (state.dht.last_check_at, state.dht.last_check_ok) {
        (Some(t), Some(ok)) => println!(
            "  last doctor check: {} {} - {}",
            if ok { "ok" } else { "FAILED" },
            ago(now, Some(t)),
            state.dht.last_check_detail.as_deref().unwrap_or("")
        ),
        _ => println!("  last doctor check: never (run `radio doctor`)"),
    }
    println!("\nCircle ({} member(s))", members.len());
    for (m, s) in &members {
        print_member(m.name.as_str(), &m.ssh_fingerprint(), s, now);
    }
    Ok(exit::OK)
}

fn print_member(name: &str, fp: &str, s: &MemberState, now: u64) {
    let status = s.status.map(|x| x.as_str()).unwrap_or("not polled yet");
    let flag = match s.status {
        Some(crate::state::MemberStatus::Ok) | None => "",
        _ => "  <-- WARNING",
    };
    println!("  {name}  [{fp}]\n    status: {status}{flag}  (since {})", ago(now, s.status_since));
    println!("    highest accepted seq: {}   {}", s.highest_seq, ops::staleness(s, now));
    if let Some(m) = &s.last_message {
        let first = m.message.lines().next().unwrap_or("");
        println!("    last message: {:?} (issued {})", crate::util::sanitize_for_terminal(first), format_utc(m.issued_at));
    }
    if let Some(d) = &s.last_poll_detail {
        println!("    last poll: {} - {}", ago(now, s.last_poll_at), crate::util::sanitize_for_terminal(d));
    }
    if let Some(r) = &s.last_rejection {
        println!("    last rejection: {} ({}): {}", r.reason, ago(now, Some(r.at)), crate::util::sanitize_for_terminal(&r.detail));
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

struct Report {
    json: bool,
    worst: Level,
    exit: i32,
}

impl Report {
    fn check(&mut self, level: Level, name: &str, detail: impl std::fmt::Display, code_if_fail: i32) {
        let tag = match level {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        if self.json {
            println!("{}", json!({"type": "check", "name": name, "level": tag.to_lowercase(), "detail": detail.to_string()}));
        } else {
            println!("[{tag:>4}] {name}: {detail}");
        }
        if level == Level::Fail {
            self.worst = Level::Fail;
            if self.exit == exit::OK {
                self.exit = code_if_fail;
            }
        } else if level == Level::Warn && self.worst == Level::Ok {
            self.worst = Level::Warn;
        }
    }
}

pub fn doctor(paths: &Paths, json: bool) -> Result<i32, Coded> {
    let mut r = Report { json, worst: Level::Ok, exit: exit::OK };
    let now = now_secs();

    let cfg = match app::load_config(paths) {
        Ok(c) => c,
        Err(e) => {
            r.check(Level::Fail, "config", &e, exit::CONFIG);
            return Ok(r.exit);
        }
    };
    r.check(Level::Ok, "config", format!("{} (sender {:?})", paths.config_file().display(), cfg.name), exit::CONFIG);

    let circle = match app::load_circle(paths) {
        Ok(c) => c,
        Err(e) => {
            r.check(Level::Fail, "circle", &e, exit::CONFIG);
            return Ok(r.exit);
        }
    };
    if circle.members.is_empty() {
        r.check(Level::Warn, "circle", "empty: nobody to listen to (`radio circle add --card FILE`)", exit::CONFIG);
    } else {
        r.check(Level::Ok, "circle", format!("{} pinned member(s)", circle.members.len()), exit::CONFIG);
    }

    let dht_key = match crate::config::load_publisher_key(paths) {
        Ok(k) => k,
        Err(e) => {
            r.check(Level::Fail, "publisher key", format!("{e:#}"), exit::CONFIG);
            return Ok(r.exit);
        }
    };
    r.check(Level::Ok, "publisher key", format!("DHT feed key {}", hex::encode(dht_key.verifying_key().to_bytes())), exit::CONFIG);

    // SSH signer: prove that unattended signing works right now.
    match app::load_signer(&cfg).and_then(|s| s.sign(b"radio doctor").map(|_| s).code(exit::SIGNING)) {
        Ok(s) => r.check(Level::Ok, "ssh signer", format!("signed a test payload with {} [{}]", signer_desc(&cfg), sshsig::fingerprint(s.public())), exit::SIGNING),
        Err(e) => r.check(Level::Fail, "ssh signer", e, exit::SIGNING),
    }

    // Bootstrap resolution.
    let nc = NetConfig::from_config(&cfg.dht, paths);
    let entries = net::resolve_entries(&nc);
    let mut resolvable = 0;
    for e in &entries {
        match &e.error {
            None => {
                resolvable += e.resolved.len();
                if e.kind != EntryKind::Cached {
                    r.check(Level::Ok, "bootstrap", format!("{} ({}) -> {} address(es)", e.entry, e.kind.as_str(), e.resolved.len()), exit::DHT_UNAVAILABLE);
                }
            }
            Some(err) => r.check(Level::Warn, "bootstrap", format!("{} ({}): {err}", e.entry, e.kind.as_str()), exit::DHT_UNAVAILABLE),
        }
    }
    let cached = entries.iter().filter(|e| e.kind == EntryKind::Cached).count();
    r.check(Level::Ok, "routing cache", format!("{cached} cached node(s) available as extra bootstrap peers"), exit::DHT_UNAVAILABLE);
    if resolvable == 0 {
        r.check(Level::Fail, "dht", "no bootstrap address could be resolved", exit::DHT_UNAVAILABLE);
        record_dht(paths, now, false, "no bootstrap address could be resolved", None, None);
        return Ok(r.exit);
    }

    let started = std::time::Instant::now();
    let net = match Net::connect(&nc, |m| {
        if !json {
            eprintln!("note: {m}");
        }
    }) {
        Ok(n) => n,
        Err(e) => {
            r.check(Level::Fail, "dht", &e, exit::DHT_UNAVAILABLE);
            record_dht(paths, now, false, &e.to_string(), None, None);
            return Ok(r.exit);
        }
    };
    let h = net.health();
    r.check(
        Level::Ok,
        "dht",
        format!(
            "bootstrapped in {:.1}s (attempt {}); routing table {} node(s), DHT size estimate ~{}",
            started.elapsed().as_secs_f32(),
            net.attempts_used,
            h.routing_nodes,
            h.dht_size_estimate
        ),
        exit::DHT_UNAVAILABLE,
    );
    r.check(
        if h.firewalled { Level::Warn } else { Level::Ok },
        "reachability",
        format!(
            "local {}, public {}{}",
            h.local_addr,
            h.public_address.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into()),
            if h.firewalled { " (probably firewalled/NATed: fine for a client; you can still put and get)" } else { "" }
        ),
        exit::DHT_UNAVAILABLE,
    );
    if h.routing_nodes < 8 {
        r.check(Level::Warn, "routing table", format!("only {} node(s); lookups may be unreliable", h.routing_nodes), exit::DHT_UNAVAILABLE);
    }
    record_dht(paths, now, true, "bootstrapped", Some(h.routing_nodes), Some(h.dht_size_estimate));

    // Own record on the DHT.
    let state = Store::new(paths).load().code(exit::ERROR)?;
    let own = net.get_latest(&dht_key.verifying_key().to_bytes(), cfg.salt.as_deref().map(str::as_bytes));
    match (&own.item, state.publisher.last_item.as_ref()) {
        (Some(i), Some(l)) if i.seq() == l.seq => r.check(Level::Ok, "own record", format!("on the DHT with seq {} (matches last signed item)", i.seq()), exit::DHT_UNAVAILABLE),
        (Some(i), Some(l)) => r.check(Level::Warn, "own record", format!("DHT holds seq {} but the last signed item is seq {}", i.seq(), l.seq), exit::DHT_UNAVAILABLE),
        (Some(i), None) => r.check(Level::Ok, "own record", format!("on the DHT with seq {}", i.seq()), exit::DHT_UNAVAILABLE),
        (None, Some(l)) if now < l.expires_at => r.check(Level::Warn, "own record", format!("not found on the DHT although seq {} is still valid: try `radio republish`", l.seq), exit::DHT_UNAVAILABLE),
        (None, Some(l)) => r.check(Level::Warn, "own record", format!("not on the DHT and the last item (seq {}) expired: publish a fresh heartbeat", l.seq), exit::DHT_UNAVAILABLE),
        (None, None) => r.check(Level::Ok, "own record", "nothing published yet", exit::DHT_UNAVAILABLE),
    }

    // Members, evaluated without consuming messages (state is not modified).
    let source = ops::Source::Live(&net);
    for m in &circle.members {
        let prev = state.members.get(&m.dht_public_key).cloned().unwrap_or_default();
        let outcome = ops::evaluate(m, &prev, ops::fetch_member(&source, m), now, cfg.clock_skew_secs);
        let (level, text) = match outcome {
            Outcome::New(a) => (Level::Ok, format!("verified message seq {} (not yet shown; run `radio listen`)", a.payload.seq)),
            Outcome::Seen(a) => (Level::Ok, format!("verified, seq {} already seen", a.payload.seq)),
            Outcome::NotFound { responded, queried } => (Level::Warn, format!("no record on the DHT ({responded}/{queried} nodes answered): publisher offline or aged out; {}", ops::staleness(&prev, now))),
            Outcome::Unreachable(d) => (Level::Warn, format!("freshness unverifiable: {d}; {}", ops::staleness(&prev, now))),
            Outcome::Rejected(rej) if rej.is_soft() => (Level::Warn, format!("{rej}; {}", ops::staleness(&prev, now))),
            Outcome::Rejected(rej) => (Level::Fail, format!("REJECTED [{}]: {rej}", rej.code())),
        };
        r.check(level, &format!("member {}", m.name), text, exit::VERIFY_FAILED);
    }
    let _ = Fetch::Unreachable(String::new());
    net.save_routing_cache();
    if !json {
        println!(
            "\n{}",
            match r.worst {
                Level::Ok => "all checks passed",
                Level::Warn => "passed with warnings",
                Level::Fail => "problems found",
            }
        );
    }
    Ok(r.exit)
}

fn record_dht(paths: &Paths, now: u64, ok: bool, detail: &str, nodes: Option<usize>, size: Option<usize>) {
    let _ = Store::new(paths).update(|s| {
        s.dht.last_check_at = Some(now);
        s.dht.last_check_ok = Some(ok);
        s.dht.last_check_detail = Some(detail.to_string());
        s.dht.routing_nodes = nodes;
        s.dht.dht_size_estimate = size;
    });
}
