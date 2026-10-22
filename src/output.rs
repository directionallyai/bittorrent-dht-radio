//! Events emitted by `listen`/`run`, in human-readable or JSON-lines form.

use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;

use crate::state::MemberStatus;
use crate::util::{format_age, format_utc, now_secs, sanitize_for_terminal};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Event {
    /// A verified message that has not been shown before.
    Message {
        member: String,
        seq: i64,
        issued_at: u64,
        expires_at: u64,
        message: String,
        ssh_fingerprint: String,
        prev: Option<String>,
        fetched_at: u64,
    },
    /// A verified, decrypted direct message addressed to us that has not been shown before.
    DirectMessage {
        member: String,
        seq: i64,
        issued_at: u64,
        expires_at: u64,
        message: String,
        ssh_fingerprint: String,
        fetched_at: u64,
    },
    /// Per-member state: stale, offline, unreachable or recovered.
    Status {
        member: String,
        status: MemberStatus,
        detail: String,
        previous: Option<MemberStatus>,
        last_verified_at: Option<u64>,
    },
    /// A fetched record failed verification.
    Rejected {
        member: String,
        reason: String,
        detail: String,
    },
    /// Our own publish / republish result.
    Published {
        kind: String,
        /// Recipient of a direct message.
        #[serde(skip_serializing_if = "Option::is_none")]
        to: Option<String>,
        seq: i64,
        issued_at: u64,
        expires_at: u64,
        stored_at: u32,
        bytes_bencoded: usize,
    },
    /// Something went wrong that did not stop the process (run mode).
    Error { context: String, detail: String },
    /// Informational note (bootstrap warnings and the like).
    Note { detail: String },
}

pub struct Printer {
    json: bool,
    lock: Mutex<()>,
}

impl Printer {
    pub fn new(json: bool) -> Self {
        Printer {
            json,
            lock: Mutex::new(()),
        }
    }

    pub fn is_json(&self) -> bool {
        self.json
    }

    pub fn emit(&self, event: &Event) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.json {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(
                out,
                "{}",
                serde_json::to_string(event).expect("event serialises")
            );
            let _ = out.flush();
            return;
        }
        match event {
            Event::Message {
                member,
                seq,
                issued_at,
                expires_at,
                message,
                ..
            } => {
                let msg = sanitize_for_terminal(message);
                let meta = format!("seq {seq}, expires {}", format_utc(*expires_at));
                let mut out = std::io::stdout().lock();
                if msg.contains('\n') {
                    let _ = writeln!(out, "{} {member} ({meta}):", format_utc(*issued_at));
                    for line in msg.lines() {
                        let _ = writeln!(out, "  {line}");
                    }
                } else {
                    let _ = writeln!(out, "{} {member}: {msg} ({meta})", format_utc(*issued_at));
                }
                let _ = out.flush();
            }
            Event::DirectMessage {
                member,
                seq,
                issued_at,
                expires_at,
                message,
                ..
            } => {
                let msg = sanitize_for_terminal(message);
                let meta = format!("direct, seq {seq}, expires {}", format_utc(*expires_at));
                let mut out = std::io::stdout().lock();
                if msg.contains('\n') {
                    let _ = writeln!(out, "{} {member} -> you ({meta}):", format_utc(*issued_at));
                    for line in msg.lines() {
                        let _ = writeln!(out, "  {line}");
                    }
                } else {
                    let _ = writeln!(
                        out,
                        "{} {member} -> you: {msg} ({meta})",
                        format_utc(*issued_at)
                    );
                }
                let _ = out.flush();
            }
            Event::Status {
                member,
                status,
                detail,
                previous,
                last_verified_at,
            } => {
                let age = last_verified_at
                    .map(|t| {
                        format!(
                            "; last verified message {} ago",
                            format_age(now_secs().saturating_sub(t))
                        )
                    })
                    .unwrap_or_else(|| "; no verified message yet".into());
                let line = match (status, previous) {
                    (MemberStatus::Ok, Some(prev)) if *prev != MemberStatus::Ok => {
                        format!("{member}: recovered, {detail} (was {})", prev.as_str())
                    }
                    (MemberStatus::Ok, _) => format!("{member}: {detail}"),
                    (s, _) => format!("warning: {member}: {} - {detail}{age}", s.as_str()),
                };
                eprintln!("{line}");
            }
            Event::Rejected {
                member,
                reason,
                detail,
            } => {
                eprintln!(
                    "REJECTED {member}: {reason}: {}",
                    sanitize_for_terminal(detail)
                );
            }
            Event::Published {
                kind,
                to,
                seq,
                issued_at,
                expires_at,
                stored_at,
                bytes_bencoded,
            } => {
                let note = if kind == "republished" {
                    " [same signed item; timestamp unchanged]"
                } else {
                    ""
                };
                let kind = match to {
                    Some(to) => format!("published to {to} (encrypted)"),
                    None => kind.clone(),
                };
                println!(
                    "{kind}: seq {seq}, issued {}, expires {}, stored at {stored_at} DHT node(s), value {bytes_bencoded}/1000 bytes{note}",
                    format_utc(*issued_at),
                    format_utc(*expires_at)
                );
            }
            Event::Error { context, detail } => eprintln!("error: {context}: {detail}"),
            Event::Note { detail } => eprintln!("note: {detail}"),
        }
    }
}
