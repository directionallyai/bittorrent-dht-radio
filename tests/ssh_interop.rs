//! Interoperability with OpenSSH: our SSHSIG must verify with `ssh-keygen -Y verify`, and
//! signatures made by `ssh-keygen -Y sign` must verify with ours. Also exercises signing through
//! a real `ssh-agent`.
//!
//! These tests need the OpenSSH client tools. Locally they are skipped when the tools are
//! missing; CI sets `RADIO_REQUIRE_SSH_KEYGEN=1` so a missing tool is a failure.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use radio::item;
use radio::payload::NAMESPACE;
use radio::sshsig::{self, Signer};

fn tool_available(name: &str) -> bool {
    // `ssh-keygen -?`/`ssh-add -?` exit non-zero but prove the binary exists.
    Command::new(name).arg("-?").output().is_ok()
}

fn require_or_skip(tools: &[&str]) -> bool {
    let missing: Vec<_> = tools.iter().filter(|t| !tool_available(t)).collect();
    if missing.is_empty() {
        return true;
    }
    if std::env::var("RADIO_REQUIRE_SSH_KEYGEN").is_ok_and(|v| v == "1") {
        panic!("RADIO_REQUIRE_SSH_KEYGEN=1 but {missing:?} not found");
    }
    eprintln!("SKIPPED: {missing:?} not available");
    false
}

fn keygen(dir: &Path, name: &str, extra: &[&str]) -> PathBuf {
    let path = dir.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "interop-test", "-f"])
        .arg(&path)
        .args(extra)
        .status()
        .unwrap();
    assert!(status.success());
    path
}

fn allowed_signers(dir: &Path, principal: &str, key: &Path) -> PathBuf {
    let pubkey = std::fs::read_to_string(key.with_extension("pub"))
        .unwrap_or_else(|_| std::fs::read_to_string(format!("{}.pub", key.display())).unwrap());
    let path = dir.join("allowed_signers");
    std::fs::write(
        &path,
        format!("{principal} namespaces=\"{NAMESPACE}\" {}", pubkey.trim()),
    )
    .unwrap();
    path
}

fn ssh_keygen_verify(
    allowed: &Path,
    principal: &str,
    namespace: &str,
    sig: &Path,
    data: &[u8],
) -> bool {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(allowed)
        .args(["-I", principal, "-n", namespace, "-s"])
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    child.wait().unwrap().success()
}

#[test]
fn our_sshsig_verifies_with_ssh_keygen() {
    if !require_or_skip(&["ssh-keygen"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(dir.path(), "id", &[]);
    let signer = Signer::from_key_file(&key, None).unwrap();
    let payload = b"radio/1\nfrom: alice\nseq: 1\niat: 1\nexp: 2\n\nhello from interop";
    let sig = signer.sign(payload).unwrap();
    let sig_file = dir.path().join("payload.sig");
    std::fs::write(&sig_file, sshsig::sig_to_pem(&sig).unwrap()).unwrap();
    let allowed = allowed_signers(dir.path(), "alice", &key);

    assert!(
        ssh_keygen_verify(&allowed, "alice", NAMESPACE, &sig_file, payload),
        "ssh-keygen must accept our signature"
    );
    // Negative controls: other data, other namespace, other principal.
    assert!(!ssh_keygen_verify(
        &allowed,
        "alice",
        NAMESPACE,
        &sig_file,
        b"different payload"
    ));
    assert!(!ssh_keygen_verify(
        &allowed,
        "alice",
        "other@example.com",
        &sig_file,
        payload
    ));
    assert!(!ssh_keygen_verify(
        &allowed, "mallory", NAMESPACE, &sig_file, payload
    ));
}

#[test]
fn signature_inside_a_dht_value_reconstructs_to_a_valid_openssh_signature() {
    if !require_or_skip(&["ssh-keygen"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(dir.path(), "id", &[]);
    let signer = Signer::from_key_file(&key, None).unwrap();
    let dht = mainline::SigningKey::from_bytes(&[7; 32]);
    let built = radio::publish::Identity {
        name: "alice",
        salt: None,
        ssh: &signer,
        dht: &dht,
    }
    .build(
        "verify me with ssh-keygen",
        1_700_000_000,
        1_700_000_000,
        3600,
        None,
    )
    .unwrap();
    // Take the raw BEP 44 `v`, split it, and rebuild the armored signature from the blob.
    let (payload, blob) = item::decode_value(&built.value).unwrap();
    let sig = sshsig::sig_from_blob(blob).unwrap();
    let sig_file = dir.path().join("v.sig");
    std::fs::write(&sig_file, sshsig::sig_to_pem(&sig).unwrap()).unwrap();
    let allowed = allowed_signers(dir.path(), "alice", &key);
    assert!(ssh_keygen_verify(
        &allowed, "alice", NAMESPACE, &sig_file, payload
    ));
}

#[test]
fn ssh_keygen_signatures_verify_with_ours() {
    if !require_or_skip(&["ssh-keygen"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(dir.path(), "id", &[]);
    let payload = b"signed by ssh-keygen itself";
    let data_file = dir.path().join("data.txt");
    std::fs::write(&data_file, payload).unwrap();
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-q", "-n", NAMESPACE, "-f"])
        .arg(&key)
        .arg(&data_file)
        .status()
        .unwrap();
    assert!(status.success());
    let pem = std::fs::read_to_string(dir.path().join("data.txt.sig")).unwrap();
    let sig = ssh_key::SshSig::from_pem(pem).unwrap();
    let blob = sshsig::sig_to_blob(&sig).unwrap();
    let public = sshsig::parse_public_key(
        &std::fs::read_to_string(format!("{}.pub", key.display())).unwrap(),
    )
    .unwrap();
    assert_eq!(sshsig::verify_blob(&public, payload, &blob), Ok(()));
    assert!(sshsig::verify_blob(&public, b"other", &blob).is_err());
}

#[test]
fn ssh_keygen_encrypted_key_with_passphrase_signs_for_us() {
    if !require_or_skip(&["ssh-keygen"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enc");
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "hunter2", "-f"])
        .arg(&path)
        .status()
        .unwrap()
        .success());
    assert!(Signer::from_key_file(&path, None).is_err());
    let s = Signer::from_key_file(&path, Some("hunter2")).unwrap();
    let blob = sshsig::sig_to_blob(&s.sign(b"x").unwrap()).unwrap();
    assert_eq!(sshsig::verify_blob(s.public(), b"x", &blob), Ok(()));
}

#[cfg(unix)]
struct Agent {
    child: std::process::Child,
    sock: PathBuf,
}

#[cfg(unix)]
impl Agent {
    fn start(dir: &Path) -> Agent {
        // Unix socket paths are length-limited (104 bytes on macOS): keep it short.
        let _ = dir;
        let sock = PathBuf::from(format!("/tmp/radio-test-agent-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(sock.exists(), "ssh-agent did not create its socket");
        Agent { child, sock }
    }

    fn add(&self, key: &Path) {
        let st = Command::new("ssh-add")
            .arg(key)
            .env("SSH_AUTH_SOCK", &self.sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "ssh-add failed");
    }
}

#[cfg(unix)]
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
#[test]
fn signing_through_a_real_ssh_agent_end_to_end() {
    if !require_or_skip(&["ssh-keygen", "ssh-agent", "ssh-add"]) {
        return;
    }
    use common::*;
    use radio::exit;
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::start(dir.path());
    let key = keygen(dir.path(), "agentkey", &[]);
    agent.add(&key);
    // Remove the private key from disk: signing must go through the agent only.
    let pubfile = PathBuf::from(format!("{}.pub", key.display()));
    std::fs::remove_file(&key).unwrap();

    let net = testnet();
    let bob = Client::new("bob", &net.bootstrap);

    // Alice chooses the agent identity explicitly.
    let alice_dir = dir.path().join("alice");
    let out = run_cli(
        &alice_dir,
        &[
            "init",
            "--name",
            "alice",
            "--ssh-agent",
            pubfile.to_str().unwrap(),
            "--agent-socket",
            agent.sock.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, exit::OK, "{out:?}");
    let paths = radio::config::Paths {
        root: alice_dir.clone(),
    };
    let mut cfg = radio::config::Config::load(&paths).unwrap();
    cfg.dht = radio::selftest::loopback_dht(&net.bootstrap);
    cfg.save(&paths).unwrap();
    let card = radio::circle::Member::from_card(&out.stdout).unwrap();
    radio::selftest::pin(&bob.paths, &card).unwrap();
    radio::selftest::pin(&paths, &bob.card).unwrap();

    let out = run_cli(&alice_dir, &["publish", "--message", "signed by the agent"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    let out = bob.cli(&["--json", "listen"]);
    assert_eq!(out.code, exit::OK, "{out:?}");
    let m = &out.events_of("message")[0];
    assert_eq!(m["message"], "signed by the agent");
    assert_eq!(
        m["ssh_fingerprint"].as_str().unwrap(),
        card.ssh_fingerprint()
    );

    // Selecting an identity the agent does not hold fails clearly at init time.
    let other = keygen(dir.path(), "notloaded", &[]);
    let out = run_cli(
        &dir.path().join("carol"),
        &[
            "init",
            "--name",
            "carol",
            "--ssh-agent",
            &format!("{}.pub", other.display()),
            "--agent-socket",
            agent.sock.to_str().unwrap(),
        ],
    );
    assert_eq!(out.code, exit::SIGNING, "{out:?}");
    assert!(out.stderr.contains("does not hold"), "{out:?}");

    // With the agent gone, doctor reports a signing problem instead of hanging.
    drop(agent);
    let out = run_cli(&alice_dir, &["doctor"]);
    assert_eq!(out.code, exit::SIGNING, "{out:?}");
    assert!(out.stdout.contains("ssh signer"), "{out:?}");
}
