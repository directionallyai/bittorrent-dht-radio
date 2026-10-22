//! `radio run`: publish and listen concurrently on independent intervals, unattended.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use mainline::SigningKey;

use crate::app;
use crate::circle::Circle;
use crate::config::{Config, Paths};
use crate::exit::{self, Coded};
use crate::net::Net;
use crate::ops::{self, Publisher, Source};
use crate::output::{Event, Printer};
use crate::sshsig::Signer;
use crate::state::Store;
use crate::util::{now_secs, Jitter};

/// Where the heartbeat message comes from.
#[derive(Debug, Clone)]
pub enum MessageSource {
    /// Re-read on every publish so the file can change between heartbeats.
    File(PathBuf),
    Fixed(String),
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub message: MessageSource,
    pub publish_every: Duration,
    pub listen_every: Duration,
    pub jitter: Option<Jitter>,
    /// Also re-put the last signed item unchanged on this interval (does NOT advance the signed
    /// timestamp and does not prove the sender is online).
    pub republish_every: Option<Duration>,
    pub ttl: Duration,
    pub chain_prev: bool,
    /// Stop after this long (used by tests and smoke checks).
    pub exit_after: Option<Duration>,
}

/// Cooperative shutdown with interruptible sleeps.
#[derive(Default)]
pub struct Shutdown {
    flag: Mutex<bool>,
    cv: Condvar,
}

impl Shutdown {
    pub fn trigger(&self) {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cv.notify_all();
    }

    pub fn is_set(&self) -> bool {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sleep up to `d`; returns true if shutdown was requested.
    pub fn wait(&self, d: Duration) -> bool {
        let guard = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, d, |stop| !*stop)
            .unwrap_or_else(|e| e.into_inner());
        *guard
    }
}

/// Lazily (re)connects the shared DHT client; failures are retried on the next cycle.
struct NetHolder<'a> {
    cfg: &'a Config,
    paths: &'a Paths,
    inner: Mutex<Option<Arc<Net>>>,
}

impl NetHolder<'_> {
    fn get(&self, printer: &Printer) -> Result<Arc<Net>, Coded> {
        let mut slot = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = slot.as_ref() {
            return Ok(n.clone());
        }
        let net = Arc::new(app::connect(self.cfg, self.paths, |m| {
            printer.emit(&Event::Note {
                detail: m.to_string(),
            })
        })?);
        *slot = Some(net.clone());
        Ok(net)
    }

    /// Drop the client so the next cycle bootstraps again (e.g. after a network change).
    fn invalidate(&self) {
        let old = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(n) = old {
            n.save_routing_cache();
        }
    }

    fn save_cache(&self) {
        if let Some(n) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            n.save_routing_cache();
        }
    }
}

fn next_delay(base: Duration, jitter: &Option<Jitter>) -> Duration {
    base + jitter.map(|j| j.sample(base)).unwrap_or_default()
}

fn read_message(src: &MessageSource) -> Result<String, String> {
    match src {
        MessageSource::Fixed(m) => Ok(m.clone()),
        MessageSource::File(p) => {
            crate::cli::read_message_file(p).map_err(|e| format!("{}: {e}", p.display()))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    paths: &Paths,
    cfg: &Config,
    circle: &Circle,
    ssh: &Signer,
    dht_key: &SigningKey,
    opts: &RunOptions,
    printer: &Printer,
    shutdown: &Shutdown,
) -> Result<(), Coded> {
    let store_owned = Store::new(paths);
    let store = &store_owned;
    let holder_owned = NetHolder {
        cfg,
        paths,
        inner: Mutex::new(None),
    };
    let holder = &holder_owned;
    let publisher_owned = Publisher {
        cfg,
        ssh,
        dht_key,
        store,
    };
    let publisher = &publisher_owned;
    let skew = cfg.clock_skew_secs;

    std::thread::scope(|scope| {
        // Publisher: fresh signature (new seq, new issued-at) every interval.
        scope.spawn(move || loop {
            if shutdown.is_set() {
                break;
            }
            let result = read_message(&opts.message)
                .map_err(|e| ("reading message".to_string(), e))
                .and_then(|msg| {
                    let net = holder
                        .get(printer)
                        .map_err(|e| ("publish".to_string(), e.to_string()))?;
                    publisher
                        .publish(&net, &msg, opts.ttl.as_secs(), opts.chain_prev, now_secs())
                        .map_err(|e| {
                            if e.code == exit::DHT_UNAVAILABLE {
                                holder.invalidate();
                            }
                            ("publish".to_string(), e.to_string())
                        })
                });
            match result {
                Ok(report) => printer.emit(&report.event()),
                Err((context, detail)) => printer.emit(&Event::Error { context, detail }),
            }
            if shutdown.wait(next_delay(opts.publish_every, &opts.jitter)) {
                break;
            }
        });

        // Listener.
        scope.spawn(move || loop {
            if shutdown.is_set() {
                break;
            }
            let (source_net, down);
            match holder.get(printer) {
                Ok(n) => {
                    source_net = Some(n);
                    down = String::new();
                }
                Err(e) => {
                    source_net = None;
                    down = e.to_string();
                }
            }
            let source = match &source_net {
                Some(n) => Source::Live(n),
                None => Source::Down(down),
            };
            match ops::poll_circle(circle, store, &source, now_secs(), skew, false) {
                Ok(report) => {
                    for e in &report.events {
                        printer.emit(e);
                    }
                    if report.summary.members > 0
                        && report.summary.unreachable == report.summary.members
                    {
                        holder.invalidate();
                    } else {
                        holder.save_cache();
                    }
                }
                Err(e) => printer.emit(&Event::Error {
                    context: "listen".into(),
                    detail: e.to_string(),
                }),
            }
            if shutdown.wait(next_delay(opts.listen_every, &opts.jitter)) {
                break;
            }
        });

        // Optional keep-alive: re-put the same signed item.
        if let Some(every) = opts.republish_every {
            scope.spawn(move || loop {
                if shutdown.wait(next_delay(every, &opts.jitter)) {
                    break;
                }
                let result = holder
                    .get(printer)
                    .and_then(|net| ops::republish(store, dht_key, &net, now_secs()));
                match result {
                    Ok(report) => printer.emit(&report.event()),
                    Err(e) => {
                        if e.code == exit::DHT_UNAVAILABLE {
                            holder.invalidate();
                        }
                        printer.emit(&Event::Error {
                            context: "republish".into(),
                            detail: e.to_string(),
                        });
                    }
                }
            });
        }

        if let Some(d) = opts.exit_after {
            scope.spawn(move || {
                if !shutdown.wait(d) {
                    shutdown.trigger();
                }
            });
        }
    });

    holder.save_cache();
    Ok(())
}
