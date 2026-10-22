//! Process exit codes. These are part of the CLI contract (see README).

/// Command succeeded; for `listen`, at least one new verified message was printed.
pub const OK: i32 = 0;
/// Unexpected internal or I/O error.
pub const ERROR: i32 = 1;
// 2 is reserved for command-line usage errors (clap's default).
/// Not initialised, or configuration/circle problem.
pub const CONFIG: i32 = 3;
/// Message invalid: empty, too large for a BEP 44 value (> 1000 bytes), or not valid text.
pub const BAD_MESSAGE: i32 = 4;
/// Nothing to republish, or the stored signed item has already expired.
pub const STALE_ITEM: i32 = 5;
/// Signing failed (SSH key unreadable, ssh-agent unreachable or identity missing, FIDO2 touch needed).
pub const SIGNING: i32 = 6;
/// `listen`: everything was reachable and verified, but there is no new message.
pub const NO_NEW: i32 = 10;
/// DHT unavailable (bootstrap failed, UDP timeouts): freshness could not be verified / put failed.
pub const DHT_UNAVAILABLE: i32 = 11;
/// A record was fetched but failed verification (bad signature, unknown publisher, rollback, ...).
pub const VERIFY_FAILED: i32 = 12;

/// An error carrying the exit code the process should use.
#[derive(Debug)]
pub struct Coded {
    pub code: i32,
    pub error: anyhow::Error,
}

impl std::fmt::Display for Coded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for Coded {}

pub trait WithCode<T> {
    fn code(self, code: i32) -> Result<T, Coded>;
}

impl<T, E: Into<anyhow::Error>> WithCode<T> for Result<T, E> {
    fn code(self, code: i32) -> Result<T, Coded> {
        self.map_err(|e| Coded { code, error: e.into() })
    }
}

pub fn coded(code: i32, msg: impl std::fmt::Display) -> Coded {
    Coded { code, error: anyhow::anyhow!("{msg}") }
}
