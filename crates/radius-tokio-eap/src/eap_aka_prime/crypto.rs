//! EAP-AKA' key derivation and MAC (RFC 5448 §3.3).
//!
//! Two distinct constructions live here:
//!
//! 1. **CK' / IK' derivation** — the 3GPP TS 33.402 §A.2 key
//!    binding that ties the UMTS CK/IK to the access-network
//!    identity, so a vector minted for one access network can't
//!    be replayed against another.
//! 2. **PRF'** — the HMAC-SHA-256 iterated PRF that expands the
//!    bound key into `MK = K_encr | K_aut | K_re | MSK | EMSK`
//!    (208 bytes total).
//!
//! Plus a small `compute_mac` helper that wraps HMAC-SHA-256
//! truncated to 16 bytes, since RFC 5448 §3.3 mandates 128-bit
//! `AT_MAC` for the AKA' family while reusing the same packet
//! canonicalisation as EAP-AKA (full packet, `AT_MAC` value field
//! zeroed before MAC computation).

use radius_tokio::hmac_sha256;

/// CK' || IK' (32 bytes), CK' = first 16, IK' = second 16.
pub type CkIkPrime = [u8; 32];

/// Length of the derived key block (`K_encr | K_aut | K_re | MSK |
/// EMSK` = 16 + 32 + 32 + 64 + 64 = 208 bytes).
pub const MK_LEN: usize = 16 + 32 + 32 + 64 + 64;

/// Derive `CK' || IK'` per 3GPP TS 33.402 Annex A.2 as cited by
/// RFC 5448 §3.3.
///
/// ```text
///   S = FC | P0 | L0 | P1 | L1
///   FC = 0x20
///   P0 = access-network name (octet string from AT_KDF_INPUT)
///   L0 = length(P0) (2 bytes BE)
///   P1 = SQN ⊕ AK (6 bytes — the first 6 octets of AUTN)
///   L1 = 0x00 0x06
///   CK' || IK' = HMAC-SHA-256(CK || IK, S)
/// ```
///
/// `autn` supplies SQN ⊕ AK in its first 6 bytes (TS 33.102 §6.3.2
/// — AUTN = `SQN ⊕ AK | AMF | MAC`, and we want the masked SQN as
/// it appeared on the air).
///
/// # Panics
///
/// Panics if `network_name.len()` exceeds `u16::MAX` (real access
/// network names are at most a few dozen bytes per TS 24.302).
#[must_use]
pub fn derive_ck_ik_prime(
    ck: &[u8; 16],
    ik: &[u8; 16],
    autn: &[u8; 16],
    network_name: &[u8],
) -> CkIkPrime {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);

    let name_len = u16::try_from(network_name.len()).expect("network name fits in u16");
    let mut s = Vec::with_capacity(1 + network_name.len() + 2 + 6 + 2);
    s.push(0x20); // FC
    s.extend_from_slice(network_name); // P0
    s.extend_from_slice(&name_len.to_be_bytes()); // L0
    s.extend_from_slice(&autn[..6]); // P1 = SQN ⊕ AK
    s.extend_from_slice(&[0x00, 0x06]); // L1

    hmac_sha256::compute(&key, &s)
}

/// RFC 5448 §3.4 PRF'. Computes `T1 | T2 | …` until `out.len()`
/// bytes have been produced, where:
///
/// * `T1 = HMAC-SHA-256(K, S || 0x01)`
/// * `Tn = HMAC-SHA-256(K, T(n−1) || S || n)`
///
/// `n` is a single octet, so `out.len()` is bounded at
/// 255 × 32 = 8160 bytes — we never come close. Output is
/// truncated to `out.len()` on the last block.
///
/// # Panics
///
/// Panics if `out.len()` would require more than 255 PRF'
/// iterations (8160 bytes) — unreachable for any AKA' derivation
/// (the longest is 208 bytes for `MK`).
pub fn prf_prime(key: &[u8], s: &[u8], out: &mut [u8]) {
    let mut prev: [u8; 32] = [0; 32];
    let mut have_prev = false;
    let mut written = 0usize;
    let mut n: u8 = 1;
    while written < out.len() {
        let mut msg = Vec::with_capacity(if have_prev {
            32 + s.len() + 1
        } else {
            s.len() + 1
        });
        if have_prev {
            msg.extend_from_slice(&prev);
        }
        msg.extend_from_slice(s);
        msg.push(n);
        prev = hmac_sha256::compute(key, &msg);
        have_prev = true;

        let take = (out.len() - written).min(32);
        out[written..written + take].copy_from_slice(&prev[..take]);
        written += take;
        n = n.checked_add(1).expect("PRF' iteration counter overflow");
    }
}

/// Derived key material as laid out in RFC 5448 §3.3.
#[derive(Debug)]
pub struct DerivedKeys {
    /// 128-bit attribute-encryption key (unused today — emitted
    /// only by methods that include `AT_ENCR_DATA`).
    pub k_encr: [u8; 16],
    /// 256-bit authentication key for `AT_MAC` (HMAC-SHA-256-128).
    pub k_aut: [u8; 32],
    /// 256-bit re-auth key (unused today — would be needed for
    /// `AT_REAUTH_*` fast-reauth attributes).
    pub k_re: [u8; 32],
    /// 512-bit Master Session Key, exported to the NAS in
    /// MS-MPPE-{Send,Recv}-Key per RFC 5247 §1.2.
    pub msk: [u8; 64],
    /// 512-bit Extended Master Session Key, kept locally for any
    /// future EMSK-rooted derivation (RFC 5295).
    pub emsk: [u8; 64],
}

/// Derive `K_encr | K_aut | K_re | MSK | EMSK` per RFC 5448 §3.3.
///
/// `identity` is the peer identity actually bound to the keys —
/// either the permanent IMSI-based identity ("6…@realm") or the
/// `AT_IDENTITY` the peer supplied in an `AKA-Identity` exchange.
#[must_use]
pub fn derive_keys(ck_ik_prime: &CkIkPrime, identity: &[u8]) -> DerivedKeys {
    // RFC 5448 §3.3:
    //   MK = PRF'(IK' | CK', "EAP-AKA'" | Identity)
    // Note: the PRF' key order is IK' || CK' (NOT CK' || IK').
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&ck_ik_prime[16..]); // IK'
    key[16..].copy_from_slice(&ck_ik_prime[..16]); // CK'

    let mut s = Vec::with_capacity(8 + identity.len());
    s.extend_from_slice(b"EAP-AKA'");
    s.extend_from_slice(identity);

    let mut mk = [0u8; MK_LEN];
    prf_prime(&key, &s, &mut mk);

    let mut out = DerivedKeys {
        k_encr: [0; 16],
        k_aut: [0; 32],
        k_re: [0; 32],
        msk: [0; 64],
        emsk: [0; 64],
    };
    out.k_encr.copy_from_slice(&mk[0..16]);
    out.k_aut.copy_from_slice(&mk[16..48]);
    out.k_re.copy_from_slice(&mk[48..80]);
    out.msk.copy_from_slice(&mk[80..144]);
    out.emsk.copy_from_slice(&mk[144..208]);
    out
}

/// Compute `AT_MAC` = `HMAC-SHA-256(K_aut, packet)[..16]`.
///
/// `packet` MUST be the *complete* EAP packet (from the `Code`
/// byte through the last attribute) with the 16-byte `AT_MAC`
/// value field already zeroed — see
/// [`crate::eap_aka_prime::attr::zero_mac_in_place`]. RFC 4187
/// §10.15 / RFC 5448 §3.3.
#[must_use]
pub fn compute_mac(k_aut: &[u8; 32], packet: &[u8]) -> [u8; 16] {
    let full = hmac_sha256::compute(k_aut, packet);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_prime_truncates_to_requested_length() {
        let key = [0x11u8; 32];
        let mut out = [0u8; 13];
        prf_prime(&key, b"seed", &mut out);
        // We don't have public KATs for PRF' as a standalone
        // primitive (RFC 5448 doesn't include them), but we can
        // check the first block is HMAC-SHA-256(key, "seed"|0x01)
        // truncated to 13 bytes.
        let mut expected_msg = b"seed".to_vec();
        expected_msg.push(0x01);
        let expected = hmac_sha256::compute(&key, &expected_msg);
        assert_eq!(out, expected[..13]);
    }

    #[test]
    fn prf_prime_chains_block_two() {
        // 40 bytes spans two HMAC blocks; bytes 32..40 are the
        // first 8 bytes of T2 = HMAC(K, T1 | S | 2).
        let key = [0x22u8; 32];
        let s = b"chain";
        let mut out = [0u8; 40];
        prf_prime(&key, s, &mut out);

        let mut m1 = s.to_vec();
        m1.push(1);
        let t1 = hmac_sha256::compute(&key, &m1);

        let mut m2 = t1.to_vec();
        m2.extend_from_slice(s);
        m2.push(2);
        let t2 = hmac_sha256::compute(&key, &m2);

        assert_eq!(&out[..32], &t1[..]);
        assert_eq!(&out[32..], &t2[..8]);
    }

    #[test]
    fn derived_keys_have_distinct_segments() {
        // Self-consistency check: each segment is bit-for-bit a
        // slice of the PRF' stream, so re-running prf_prime over
        // the same inputs must reproduce all five fields.
        let ck_ik = [0x33u8; 32];
        let identity = b"6001010000000001@nai.epc.mnc001.mcc262.3gppnetwork.org";
        let derived = derive_keys(&ck_ik, identity);

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&ck_ik[16..]);
        key[16..].copy_from_slice(&ck_ik[..16]);
        let mut s = b"EAP-AKA'".to_vec();
        s.extend_from_slice(identity);
        let mut mk = [0u8; MK_LEN];
        prf_prime(&key, &s, &mut mk);

        assert_eq!(derived.k_encr, mk[0..16]);
        assert_eq!(derived.k_aut, mk[16..48]);
        assert_eq!(derived.k_re, mk[48..80]);
        assert_eq!(derived.msk, mk[80..144]);
        assert_eq!(derived.emsk, mk[144..208]);
    }

    #[test]
    fn ck_ik_prime_includes_network_name_in_input() {
        // Different network names ⇒ different CK'/IK' bindings.
        let ck = [0x44u8; 16];
        let ik = [0x55u8; 16];
        let autn = [0x66u8; 16];
        let a = derive_ck_ik_prime(&ck, &ik, &autn, b"WLAN");
        let b = derive_ck_ik_prime(&ck, &ik, &autn, b"5G:mnc001.mcc262.3gppnetwork.org");
        assert_ne!(a, b);
    }

    #[test]
    fn mac_is_truncated_hmac_sha256() {
        let key = [0x77u8; 32];
        let packet = b"\x01\x02fake EAP packet bytes";
        let mac = compute_mac(&key, packet);
        let full = hmac_sha256::compute(&key, packet);
        assert_eq!(mac, full[..16]);
    }
}
