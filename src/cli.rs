//! Command-line interface.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::app::{self, InitOptions, SshChoice};
use crate::circle::{Circle, Member};
use crate::config::{self, Paths};
use crate::exit::{self, coded, Coded, WithCode};
use crate::ops::{self, Publisher, Source};
use crate::output::{Event, Printer};
use crate::payload::NAMESPACE;
use crate::run::{self, MessageSource, RunOptions, Shutdown};
use crate::state::Store;
use crate::util::{self, now_secs, Jitter};

const EXIT_CODES: &str = "\
Exit codes:
   0  ok (listen: at least one new verified message)
   1  unexpected error
   2  command-line usage error
   3  not initialised, or configuration/circle problem
   4  message invalid: empty, or too large (BEP 44 limit: bencoded value <= 1000 bytes)
   5  republish: nothing to republish, or the stored signed item has expired
   6  signing failed (SSH key unreadable, ssh-agent unavailable, FIDO2 touch needed)
  10  listen: no new message (everything reachable and verified)
  11  DHT unavailable: bootstrap failed / UDP timeouts; freshness could not be verified
  12  verification failure (bad signature, unknown publisher, rollback, ...)";

#[derive(Parser, Debug)]
#[command(name = "radio", version, about = "Recurring SSH-signed broadcasts over the BitTorrent DHT (BEP 44)", after_help = EXIT_CODES)]
pub struct Cli {
    /// Config directory (default: per-user directory for this OS; see README)
    #[arg(long, global = true, env = "RADIO_CONFIG_DIR", value_name = "DIR")]
    pub config_dir: Option<PathBuf>,

    /// Machine-readable output: JSON lines on stdout
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create the config dir and publisher key, and choose the SSH signing key
    Init(InitArgs),
    /// Print your shareable circle card (name, SSH key, DHT key, salt) with fingerprints
    Card {
        /// Write the card to this file (UTF-8) instead of stdout
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Manage the locally pinned circle of members you listen to
    #[command(subcommand)]
    Circle(CircleCmd),
    /// Sign a message and put it on the DHT now
    Publish(PublishArgs),
    /// Re-put the last signed item UNCHANGED to keep it alive (does not advance the signed
    /// timestamp and does not prove the sender is online)
    Republish,
    /// Poll every circle member's feed and print verified new messages and state changes
    Listen(ListenArgs),
    /// Publish and listen at the same time on independent intervals, unattended
    Run(RunArgs),
    /// Show saved state: last put/get results, republish times, per-member staleness (no network)
    Status,
    /// Live diagnostics: signer, bootstrap, routing table, own record, members
    Doctor,
    /// Run a two-client publish/listen check on a private loopback DHT (no internet needed)
    Selftest,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("signer").required(true).args(["ssh_key", "ssh_agent"])))]
pub struct InitArgs {
    /// Your sender name (1-32 chars: letters, digits, . _ -)
    #[arg(long)]
    pub name: String,
    /// Sign with this OpenSSH private key file (Ed25519)
    #[arg(long, value_name = "PRIVATE_KEY_FILE")]
    pub ssh_key: Option<PathBuf>,
    /// Sign through ssh-agent with this identity: a .pub file, an SHA256: fingerprint or a public key line
    #[arg(long, value_name = "IDENTITY")]
    pub ssh_agent: Option<String>,
    /// ssh-agent socket (default: $SSH_AUTH_SOCK, or the OpenSSH named pipe on Windows)
    #[arg(long, value_name = "PATH")]
    pub agent_socket: Option<PathBuf>,
    /// Optional BEP 44 salt for your feed
    #[arg(long)]
    pub salt: Option<String>,
    /// Bootstrap peer(s) as IP:port (default: public mainline routers)
    #[arg(long, value_name = "IP:PORT")]
    pub bootstrap: Vec<String>,
    /// Also write your card to this file (UTF-8; handy on Windows PowerShell where `>` writes UTF-16)
    #[arg(long, value_name = "FILE")]
    pub card_out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum CircleCmd {
    /// Pin a member from a card file, or from explicit keys
    Add(CircleAddArgs),
    /// List pinned members with fingerprints
    List,
    /// Unpin a member (their accepted-seq history is kept)
    Remove { name: String },
    /// Print a pinned member's card (or yours when no name is given)
    Export {
        name: Option<String>,
        /// Write the card to this file (UTF-8) instead of stdout
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
pub struct CircleAddArgs {
    /// Card file to import (`-` for stdin)
    #[arg(long, value_name = "FILE", conflicts_with_all = ["name", "ssh_key", "ssh_key_file", "dht_key", "salt"])]
    pub card: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    /// OpenSSH public key line
    #[arg(long, conflicts_with = "ssh_key_file")]
    pub ssh_key: Option<String>,
    /// OpenSSH public key file (.pub)
    #[arg(long, value_name = "FILE")]
    pub ssh_key_file: Option<PathBuf>,
    /// The member's DHT publisher public key (64 hex chars)
    #[arg(long, value_name = "HEX")]
    pub dht_key: Option<String>,
    #[arg(long)]
    pub salt: Option<String>,
    /// Pin without asking for confirmation (only after verifying fingerprints out of band)
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("src").required(true).args(["message", "file"])))]
pub struct PublishArgs {
    /// Message text
    #[arg(long, short)]
    pub message: Option<String>,
    /// Read the message from a file (`-` for stdin)
    #[arg(long, short, value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// How long the signed message stays valid (default: config message_ttl, 24h)
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
    /// Do not include the previous-message hash
    #[arg(long)]
    pub no_prev: bool,
}

#[derive(Args, Debug)]
pub struct ListenArgs {
    /// Keep polling instead of exiting after one pass
    #[arg(long)]
    pub follow: bool,
    /// Poll interval in follow mode
    #[arg(long, default_value = "60s", value_name = "DURATION")]
    pub interval: String,
    /// Random extra delay per poll: a duration (`10s`) or a percentage (`10%`)
    #[arg(long, value_name = "DURATION|PERCENT")]
    pub jitter: Option<String>,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("src").required(true).args(["status_file", "message"])))]
pub struct RunArgs {
    /// File whose contents are published as the heartbeat (re-read every cycle)
    #[arg(long, value_name = "FILE")]
    pub status_file: Option<PathBuf>,
    /// Fixed heartbeat message instead of a file
    #[arg(long)]
    pub message: Option<String>,
    #[arg(long, default_value = "15m", value_name = "DURATION")]
    pub publish_every: String,
    #[arg(long, default_value = "60s", value_name = "DURATION")]
    pub listen_every: String,
    /// Random extra delay added to each interval: a duration (`30s`) or a percentage (`10%`)
    #[arg(long, value_name = "DURATION|PERCENT")]
    pub jitter: Option<String>,
    /// Also re-put the last signed item unchanged on this interval (keeps the record alive; does
    /// NOT advance the signed timestamp and does NOT prove the sender is online)
    #[arg(long, value_name = "DURATION")]
    pub republish_every: Option<String>,
    /// Lifetime of each signed heartbeat (default: max(3 x publish-every, 1h))
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
    #[arg(long)]
    pub no_prev: bool,
    /// Stop after this long (for tests and smoke checks)
    #[arg(long, value_name = "DURATION", hide = true)]
    pub exit_after: Option<String>,
}

pub fn read_message_file(path: &Path) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin().read_to_end(&mut bytes)?;
    } else {
        bytes = std::fs::read(path)?;
    }
    let text = String::from_utf8(bytes).map_err(|_| anyhow!("not valid UTF-8 text"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

pub fn dispatch(cli: Cli) -> Result<i32, Coded> {
    let paths = Paths::resolve(cli.config_dir.as_deref()).code(exit::CONFIG)?;
    let printer = Printer::new(cli.json);
    match cli.command {
        Command::Init(a) => cmd_init(&paths, a, cli.json),
        Command::Card { out } => cmd_card(&paths, out.as_deref(), cli.json),
        Command::Circle(c) => cmd_circle(&paths, c, cli.json),
        Command::Publish(a) => cmd_publish(&paths, a, &printer),
        Command::Republish => cmd_republish(&paths, &printer),
        Command::Listen(a) => cmd_listen(&paths, a, &printer),
        Command::Run(a) => cmd_run(&paths, a, &printer),
        Command::Status => crate::diag::status(&paths, cli.json),
        Command::Doctor => crate::diag::doctor(&paths, cli.json),
        Command::Selftest => crate::selftest::run(&printer),
    }
}

fn note(printer: &Printer) -> impl FnMut(&str) + '_ {
    move |m| {
        printer.emit(&Event::Note {
            detail: m.to_string(),
        })
    }
}

fn print_card_to(m: &Member, json: bool, out: Option<&Path>) -> Result<(), Coded> {
    if let Some(path) = out {
        util::write_atomic(path, m.to_card().as_bytes(), false).code(exit::ERROR)?;
        eprintln!("card written to {}", path.display());
        return Ok(());
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "type": "card", "name": m.name, "ssh_public_key": m.ssh_public_key,
                "dht_public_key": m.dht_public_key, "salt": m.salt,
                "ssh_fingerprint": m.ssh_fingerprint(), "dht_fingerprint": m.dht_fingerprint(),
                "card_code": m.card_code(),
            })
        );
    } else {
        print!("{}", m.to_card());
    }
    Ok(())
}

fn cmd_init(paths: &Paths, a: InitArgs, json: bool) -> Result<i32, Coded> {
    let ssh = match (a.ssh_key, a.ssh_agent) {
        (Some(p), None) => SshChoice::KeyFile(p),
        (None, Some(id)) => SshChoice::Agent {
            identity: id,
            socket: a.agent_socket,
        },
        _ => unreachable!("clap enforces exactly one signer"),
    };
    let card = app::init(
        paths,
        &InitOptions {
            name: a.name,
            ssh,
            salt: a.salt,
            bootstrap: a.bootstrap,
            dht: None,
        },
    )?;
    if !json {
        eprintln!("Initialised {}", paths.root.display());
        eprintln!("Share this card with the people who should listen to you; they must verify the");
        eprintln!("fingerprints with you out of band (voice call, in person) before pinning it.\n");
    }
    print_card_to(&card, json, a.card_out.as_deref())?;
    Ok(exit::OK)
}

fn cmd_card(paths: &Paths, out: Option<&Path>, json: bool) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    print_card_to(&app::own_card(paths, &cfg)?, json, out)?;
    Ok(exit::OK)
}

fn confirm(prompt: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes")
}

fn describe_member(m: &Member) -> String {
    format!(
        "  name:            {}\n  SSH fingerprint: {}\n  DHT key:         {}\n  DHT fingerprint: {}\n  salt:            {}\n  card code:       {}",
        m.name,
        m.ssh_fingerprint(),
        m.dht_public_key,
        m.dht_fingerprint(),
        m.salt.as_deref().unwrap_or("(none)"),
        m.card_code()
    )
}

fn cmd_circle(paths: &Paths, cmd: CircleCmd, json: bool) -> Result<i32, Coded> {
    match cmd {
        CircleCmd::Add(a) => {
            let member = if let Some(card) = a.card {
                let bytes = if card == "-" {
                    let mut b = Vec::new();
                    std::io::stdin().read_to_end(&mut b).code(exit::CONFIG)?;
                    b
                } else {
                    std::fs::read(&card)
                        .with_context(|| format!("reading card {card}"))
                        .code(exit::CONFIG)?
                };
                Member::from_card_bytes(&bytes).code(exit::CONFIG)?
            } else {
                let name = a.name.ok_or_else(|| {
                    coded(
                        exit::CONFIG,
                        "give --card FILE, or --name with --ssh-key/--ssh-key-file and --dht-key",
                    )
                })?;
                let ssh = match (a.ssh_key, a.ssh_key_file) {
                    (Some(k), _) => k,
                    (None, Some(f)) => std::fs::read_to_string(&f)
                        .with_context(|| format!("reading {}", f.display()))
                        .code(exit::CONFIG)?
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_string(),
                    _ => return Err(coded(exit::CONFIG, "missing --ssh-key or --ssh-key-file")),
                };
                let dht = a
                    .dht_key
                    .ok_or_else(|| coded(exit::CONFIG, "missing --dht-key"))?;
                Member::new(&name, &ssh, &dht, a.salt.as_deref()).code(exit::CONFIG)?
            };
            let mut circle = app::load_circle(paths)?;
            // Fail on conflicts before asking the user anything.
            let mut probe = Circle {
                members: circle.members.clone(),
            };
            probe.add(member.clone()).code(exit::CONFIG)?;

            eprintln!("Member to pin:\n{}\n", describe_member(&member));
            if !a.yes && !confirm("Have you verified these fingerprints with the owner out of band? Pin this member?") {
                return Err(coded(exit::CONFIG, "not pinned: confirmation declined (use --yes in scripts, after verifying out of band)"));
            }
            circle.add(member.clone()).code(exit::CONFIG)?;
            circle.save(&paths.circle_file()).code(exit::ERROR)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"type": "pinned", "name": member.name})
                );
            } else {
                println!("pinned {}", member.name);
            }
            Ok(exit::OK)
        }
        CircleCmd::List => {
            let circle = app::load_circle(paths)?;
            if json {
                for m in &circle.members {
                    println!(
                        "{}",
                        serde_json::json!({
                            "type": "member", "name": m.name, "ssh_public_key": m.ssh_public_key,
                            "dht_public_key": m.dht_public_key, "salt": m.salt,
                            "ssh_fingerprint": m.ssh_fingerprint(), "dht_fingerprint": m.dht_fingerprint(),
                            "card_code": m.card_code(),
                        })
                    );
                }
            } else if circle.members.is_empty() {
                println!("(circle is empty; pin a member with `radio circle add --card FILE`)");
            } else {
                for m in &circle.members {
                    println!("{}\n", describe_member(m));
                }
            }
            Ok(exit::OK)
        }
        CircleCmd::Remove { name } => {
            let mut circle = app::load_circle(paths)?;
            let m = circle.remove(&name).code(exit::CONFIG)?;
            circle.save(&paths.circle_file()).code(exit::ERROR)?;
            println!(
                "removed {} (their accepted-seq history is kept in state.json)",
                m.name
            );
            Ok(exit::OK)
        }
        CircleCmd::Export { name, out } => {
            match name {
                Some(n) => {
                    let circle = app::load_circle(paths)?;
                    let m = circle
                        .find(&n)
                        .ok_or_else(|| coded(exit::CONFIG, format!("no member named {n:?}")))?;
                    print_card_to(m, json, out.as_deref())?;
                }
                None => return cmd_card(paths, out.as_deref(), json),
            }
            Ok(exit::OK)
        }
    }
}

fn read_publish_message(a: &PublishArgs) -> Result<String, Coded> {
    match (&a.message, &a.file) {
        (Some(m), _) => Ok(m.clone()),
        (None, Some(f)) => read_message_file(f)
            .map_err(|e| coded(exit::BAD_MESSAGE, format!("{}: {e}", f.display()))),
        _ => unreachable!("clap enforces one source"),
    }
}

fn cmd_publish(paths: &Paths, a: PublishArgs, printer: &Printer) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    let message = read_publish_message(&a)?;
    let ttl = match &a.ttl {
        Some(t) => util::parse_duration(t).code(exit::CONFIG)?,
        None => cfg.ttl().code(exit::CONFIG)?,
    };
    // Cheap local checks first: no signer prompt or network for an oversized message.
    let store = Store::new(paths);
    ops::preflight_for(
        &store,
        &cfg,
        &message,
        ttl.as_secs(),
        !a.no_prev,
        now_secs(),
    )?;

    let ssh = app::load_signer(&cfg)?;
    let dht_key = config::load_publisher_key(paths).code(exit::CONFIG)?;
    let net = app::connect(&cfg, paths, note(printer))?;
    let report = Publisher {
        cfg: &cfg,
        ssh: &ssh,
        dht_key: &dht_key,
        store: &store,
    }
    .publish(&net, &message, ttl.as_secs(), !a.no_prev, now_secs())?;
    net.save_routing_cache();
    printer.emit(&report.event());
    Ok(exit::OK)
}

fn cmd_republish(paths: &Paths, printer: &Printer) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    let dht_key = config::load_publisher_key(paths).code(exit::CONFIG)?;
    // republish needs no SSH signature: the item was signed earlier and is sent byte-for-byte.
    let net = app::connect(&cfg, paths, note(printer))?;
    let store = Store::new(paths);
    let report = ops::republish(&store, &dht_key, &net, now_secs())?;
    net.save_routing_cache();
    printer.emit(&report.event());
    if !printer.is_json() {
        eprintln!(
            "note: republish re-sent the same signed item. The signed timestamp ({}) did not advance and this \
             does not prove the sender is online now; use `radio publish` for a fresh heartbeat.",
            util::format_utc(report.issued_at)
        );
    }
    Ok(exit::OK)
}

fn cmd_listen(paths: &Paths, a: ListenArgs, printer: &Printer) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    let circle = app::load_circle(paths)?;
    ops::require_circle(&circle)?;
    let store = Store::new(paths);
    let skew = cfg.clock_skew_secs;
    let interval = util::parse_duration(&a.interval).code(exit::CONFIG)?;
    let jitter = a
        .jitter
        .as_deref()
        .map(Jitter::parse)
        .transpose()
        .code(exit::CONFIG)?;

    let net = match app::connect(&cfg, paths, note(printer)) {
        Ok(n) => Ok(n),
        Err(e) if e.code == exit::DHT_UNAVAILABLE => Err(e.to_string()),
        Err(e) => return Err(e),
    };

    if !a.follow {
        let source = match &net {
            Ok(n) => Source::Live(n),
            Err(d) => Source::Down(d.clone()),
        };
        let report = ops::poll_circle(&circle, &store, &source, now_secs(), skew, true)?;
        for e in &report.events {
            printer.emit(e);
        }
        if let Ok(n) = &net {
            n.save_routing_cache();
        }
        return Ok(report.summary.exit_code());
    }

    let shutdown = Arc::new(Shutdown::default());
    {
        let s = shutdown.clone();
        let _ = ctrlc::set_handler(move || s.trigger());
    }
    let mut net = net.ok().map(Arc::new);
    let mut first = true;
    while !shutdown.is_set() {
        if net.is_none() {
            net = app::connect(&cfg, paths, note(printer)).ok().map(Arc::new);
        }
        let source = match &net {
            Some(n) => Source::Live(n),
            None => Source::Down("DHT bootstrap failed; will retry".into()),
        };
        // The first pass reports everything; later passes only changes.
        let report = ops::poll_circle(&circle, &store, &source, now_secs(), skew, first)?;
        first = false;
        for e in &report.events {
            printer.emit(e);
        }
        if report.summary.unreachable == report.summary.members {
            net = None;
        } else if let Some(n) = &net {
            n.save_routing_cache();
        }
        let delay = interval + jitter.map(|j| j.sample(interval)).unwrap_or_default();
        if shutdown.wait(delay) {
            break;
        }
    }
    Ok(exit::OK)
}

fn cmd_run(paths: &Paths, a: RunArgs, printer: &Printer) -> Result<i32, Coded> {
    let cfg = app::load_config(paths)?;
    let circle = app::load_circle(paths)?;
    let publish_every = util::parse_duration(&a.publish_every).code(exit::CONFIG)?;
    let listen_every = util::parse_duration(&a.listen_every).code(exit::CONFIG)?;
    if publish_every.is_zero() || listen_every.is_zero() {
        return Err(coded(exit::CONFIG, "intervals must be greater than zero"));
    }
    let ttl = match &a.ttl {
        Some(t) => util::parse_duration(t).code(exit::CONFIG)?,
        None => (publish_every * 3).max(Duration::from_secs(3600)),
    };
    let opts = RunOptions {
        message: match (a.status_file, a.message) {
            (Some(f), _) => MessageSource::File(f),
            (None, Some(m)) => MessageSource::Fixed(m),
            _ => unreachable!("clap enforces one source"),
        },
        publish_every,
        listen_every,
        jitter: a
            .jitter
            .as_deref()
            .map(Jitter::parse)
            .transpose()
            .code(exit::CONFIG)?,
        republish_every: a
            .republish_every
            .as_deref()
            .map(util::parse_duration)
            .transpose()
            .code(exit::CONFIG)?,
        ttl,
        chain_prev: !a.no_prev,
        exit_after: a
            .exit_after
            .as_deref()
            .map(util::parse_duration)
            .transpose()
            .code(exit::CONFIG)?,
    };
    let ssh = app::load_signer(&cfg)?;
    let dht_key = config::load_publisher_key(paths).code(exit::CONFIG)?;
    let shutdown = Arc::new(Shutdown::default());
    {
        let s = shutdown.clone();
        let _ = ctrlc::set_handler(move || s.trigger());
    }
    printer.emit(&Event::Note {
        detail: format!(
            "running as {:?} (namespace {NAMESPACE}): publish every {:?}, listen every {:?}{}; Ctrl-C to stop",
            cfg.name,
            opts.publish_every,
            opts.listen_every,
            opts.republish_every.map(|r| format!(", republish every {r:?} (unchanged item; not a liveness signal)")).unwrap_or_default()
        ),
    });
    run::run(
        paths, &cfg, &circle, &ssh, &dht_key, &opts, printer, &shutdown,
    )?;
    Ok(exit::OK)
}
