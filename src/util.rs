//! Small helpers: time formatting, durations, atomic file writes, terminal-safe text.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};

/// Current time as seconds since the Unix epoch (UTC).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days -> civil date algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Compact human duration such as `3m 20s` for status output.
pub fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86_399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600),
    }
}

/// Parse `15m`, `60s`, `1h30m`, ... (humantime syntax).
pub fn parse_duration(s: &str) -> Result<Duration> {
    humantime::parse_duration(s.trim()).map_err(|e| anyhow!("invalid duration {s:?}: {e}"))
}

/// A jitter spec: either a fixed maximum duration (`30s`) or a percentage of the interval (`10%`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Jitter {
    Fixed(Duration),
    Percent(f64),
}

impl Jitter {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(p) = s.strip_suffix('%') {
            let pct: f64 = p.trim().parse().with_context(|| format!("invalid jitter {s:?}"))?;
            if !(0.0..=100.0).contains(&pct) {
                return Err(anyhow!("jitter percentage must be between 0 and 100"));
            }
            Ok(Jitter::Percent(pct))
        } else {
            Ok(Jitter::Fixed(parse_duration(s)?))
        }
    }

    /// A random extra delay in `[0, max]` for the given base interval.
    pub fn sample(&self, interval: Duration) -> Duration {
        let max = match self {
            Jitter::Fixed(d) => *d,
            Jitter::Percent(p) => interval.mul_f64(p / 100.0),
        };
        if max.is_zero() {
            return Duration::ZERO;
        }
        max.mul_f64(random_unit())
    }
}

/// Uniform random number in `[0, 1)`.
pub fn random_unit() -> f64 {
    use rand_core::RngCore;
    let n = rand_core::OsRng.next_u64() >> 11;
    n as f64 / (1u64 << 53) as f64
}

/// Write a file atomically (temp file in the same directory + rename).
pub fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("{} has no parent", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all().ok();
    }
    let _ = private; // Windows: the per-user profile directory ACL protects the file.
    fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Make untrusted text safe to print on a terminal: control characters (including ESC) are
/// replaced by `\u{..}` escapes; newlines and tabs are kept.
pub fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c.is_control() && c != '\n' && c != '\t') || is_bidi_override(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn is_bidi_override(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_709_210_096), "2024-02-29T12:34:56Z");
        assert_eq!(format_utc(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn jitter_parse_and_bounds() {
        assert_eq!(Jitter::parse("10%").unwrap(), Jitter::Percent(10.0));
        assert_eq!(Jitter::parse("5s").unwrap(), Jitter::Fixed(Duration::from_secs(5)));
        assert!(Jitter::parse("150%").is_err());
        for _ in 0..100 {
            let d = Jitter::Percent(10.0).sample(Duration::from_secs(100));
            assert!(d <= Duration::from_secs(10));
        }
    }

    #[test]
    fn sanitizes_escape_sequences() {
        assert_eq!(sanitize_for_terminal("a\u{1b}[31mb\nc"), "a\\u{1b}[31mb\nc");
        assert_eq!(sanitize_for_terminal("plain ünïcode"), "plain ünïcode");
    }
}
