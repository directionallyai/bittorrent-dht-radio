//! The BEP 44 `v` value: framing of payload + SSHSIG, and the 1000-byte limit.
//!
//! `v` raw bytes = `u16be payload_len | payload | SSHSIG blob` (binary SSHSIG, i.e. the PEM body
//! without armor). BEP 44 limits the *bencoded* `v` to 1000 bytes; for a byte string that is
//! `"<len>:" + bytes`, so the largest raw value is 996 bytes.

use thiserror::Error;

/// BEP 44: bencoded `v` must be at most this many bytes.
pub const MAX_V_BENCODED: usize = 1000;

/// Length of an Ed25519 SSHSIG blob with our namespace and SHA-512:
/// magic(6) + version(4) + pubkey(4+51) + namespace(4+N) + reserved(4) + hash alg(4+6)
/// + signature(4 + (4+11+4+64)).
pub const fn ed25519_sshsig_len() -> usize {
    6 + 4 + (4 + 51) + (4 + crate::payload::NAMESPACE.len()) + 4 + (4 + 6) + (4 + (4 + 11 + 4 + 64))
}

/// Bencoded length of a byte string of `raw` bytes.
pub fn bencoded_len(raw: usize) -> usize {
    raw.to_string().len() + 1 + raw
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ItemError {
    #[error(
        "value is {bencoded} bytes bencoded, over the BEP 44 limit of {MAX_V_BENCODED} by {over} bytes; \
         shorten the message (the payload header and SSH signature use {overhead} bytes, leaving {room} bytes for the message with this name/seq)"
    )]
    TooLarge {
        bencoded: usize,
        over: usize,
        overhead: usize,
        room: usize,
    },
    #[error("malformed value: {0}")]
    Malformed(&'static str),
}

/// Largest raw value length whose bencoding fits in 1000 bytes.
pub const MAX_RAW_V: usize = 996;

/// Predict the raw value length for a payload of `payload_len` bytes signed by an Ed25519 key.
pub fn predicted_raw_len(payload_len: usize) -> usize {
    2 + payload_len + ed25519_sshsig_len()
}

/// Check, *before signing*, that a payload of this size will fit.
pub fn check_payload_fits(payload_len: usize) -> Result<(), ItemError> {
    let raw = predicted_raw_len(payload_len);
    if bencoded_len(raw) <= MAX_V_BENCODED {
        return Ok(());
    }
    let bencoded = bencoded_len(raw);
    let fixed = 2 + ed25519_sshsig_len();
    Err(ItemError::TooLarge {
        bencoded,
        over: bencoded - MAX_V_BENCODED,
        overhead: fixed,
        room: MAX_RAW_V.saturating_sub(fixed),
    })
}

/// Assemble the raw `v` bytes. Enforces the size limit.
pub fn encode_value(payload: &[u8], sshsig_blob: &[u8]) -> Result<Vec<u8>, ItemError> {
    let plen: u16 = payload
        .len()
        .try_into()
        .map_err(|_| ItemError::Malformed("payload longer than 65535 bytes"))?;
    let mut v = Vec::with_capacity(2 + payload.len() + sshsig_blob.len());
    v.extend_from_slice(&plen.to_be_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(sshsig_blob);
    let bencoded = bencoded_len(v.len());
    if bencoded > MAX_V_BENCODED {
        let fixed = 2 + sshsig_blob.len();
        return Err(ItemError::TooLarge {
            bencoded,
            over: bencoded - MAX_V_BENCODED,
            overhead: fixed,
            room: MAX_RAW_V.saturating_sub(fixed),
        });
    }
    Ok(v)
}

/// Split raw `v` bytes into `(payload, sshsig_blob)`.
pub fn decode_value(v: &[u8]) -> Result<(&[u8], &[u8]), ItemError> {
    if bencoded_len(v.len()) > MAX_V_BENCODED {
        return Err(ItemError::Malformed("value exceeds the BEP 44 size limit"));
    }
    if v.len() < 2 {
        return Err(ItemError::Malformed("value shorter than its length prefix"));
    }
    let plen = u16::from_be_bytes([v[0], v[1]]) as usize;
    let rest = &v[2..];
    if plen == 0 || plen >= rest.len() {
        return Err(ItemError::Malformed(
            "payload length prefix does not fit the value",
        ));
    }
    Ok((&rest[..plen], &rest[plen..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bencoded_len_matches_bencode() {
        assert_eq!(bencoded_len(0), 2);
        assert_eq!(bencoded_len(9), 11);
        assert_eq!(bencoded_len(10), 13);
        assert_eq!(bencoded_len(996), 1000);
        assert_eq!(bencoded_len(997), 1001);
        assert_eq!(bencoded_len(MAX_RAW_V), MAX_V_BENCODED);
    }

    #[test]
    fn boundary_exactly_1000_ok_1001_rejected() {
        let sig = vec![0u8; ed25519_sshsig_len()];
        // payload sized so that raw = 996 => bencoded = 1000
        let payload_ok = vec![b'x'; MAX_RAW_V - 2 - sig.len()];
        let v = encode_value(&payload_ok, &sig).unwrap();
        assert_eq!(bencoded_len(v.len()), 1000);
        assert!(check_payload_fits(payload_ok.len()).is_ok());

        let payload_big = vec![b'x'; MAX_RAW_V - 2 - sig.len() + 1];
        let err = encode_value(&payload_big, &sig).unwrap_err();
        assert!(
            matches!(
                err,
                ItemError::TooLarge {
                    bencoded: 1001,
                    over: 1,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(matches!(
            check_payload_fits(payload_big.len()),
            Err(ItemError::TooLarge {
                bencoded: 1001,
                over: 1,
                ..
            })
        ));
    }

    #[test]
    fn decode_roundtrip_and_malformed() {
        let v = encode_value(b"payload", b"signature").unwrap();
        assert_eq!(
            decode_value(&v).unwrap(),
            (&b"payload"[..], &b"signature"[..])
        );
        assert!(decode_value(&[]).is_err());
        assert!(decode_value(&[0, 0, 1]).is_err());
        assert!(decode_value(&[0, 9, 1, 2]).is_err());
        assert!(decode_value(&vec![0u8; 1200]).is_err());
    }
}
