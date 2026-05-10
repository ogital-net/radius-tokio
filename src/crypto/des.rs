//! Safe wrapper for single-key DES ECB encryption via `aws-lc-sys`.
//!
//! DES is cryptographically broken. Its use here is limited to the
//! MS-CHAP wire format (RFC 2433 / RFC 2759) where the `DesEncrypt`
//! helper requires it for the `ChallengeResponse` function (§8.5).
//!
//! Only the subset needed by MS-CHAP is exposed:
//!
//! * [`DesKey::from_56bits`] — expand a 7-byte (56-bit) key to the
//!   8-byte DES key format with odd parity, then compute the key
//!   schedule.
//! * [`DesKey::ecb_encrypt`] — encrypt a single 8-byte block (ECB,
//!   no padding).

use std::mem::MaybeUninit;

use aws_lc_sys::{
    DES_cblock, DES_cblock_st, DES_ecb_encrypt, DES_key_schedule, DES_ks, DES_set_key_unchecked,
    DES_set_odd_parity, DES_ENCRYPT,
};

/// A single-DES key schedule derived from 7 bytes of key material.
///
/// Constructed via [`DesKey::from_56bits`]. The only DES primitive
/// used by MS-CHAP's `ChallengeResponse` function (RFC 2759 §8.5 /
/// RFC 2433 §A.5).
pub(crate) struct DesKey {
    schedule: DES_key_schedule,
}

impl DesKey {
    /// Construct a DES key schedule from 7 bytes (56 bits) of key
    /// material.
    ///
    /// The 56 bits are spread into the high 7 bits (`[7:1]`) of each
    /// output byte (RFC 2759 §9.3 / FIPS PUB 46-2), bit 0 of each
    /// byte is then set to odd parity by `DES_set_odd_parity`, and
    /// the resulting 8-byte key is passed to `DES_set_key_unchecked`
    /// to fill the key schedule.
    pub(crate) fn from_56bits(key56: &[u8; 7]) -> Self {
        let mut key8 = expand_56_to_64(*key56);

        // SAFETY: key8 is a valid 8-byte buffer for the duration of
        // this call. DES_cblock is repr-compatible with [u8; 8].
        unsafe {
            DES_set_odd_parity(key8.as_mut_ptr().cast::<DES_cblock>());
        }

        let mut schedule = MaybeUninit::<DES_ks>::uninit();
        // SAFETY: key8 and schedule are valid, non-overlapping pointers
        // for their respective types. DES_set_key_unchecked initializes
        // all 128 bytes of the schedule before we call assume_init.
        unsafe {
            DES_set_key_unchecked(key8.as_ptr().cast::<DES_cblock>(), schedule.as_mut_ptr());
            Self {
                schedule: schedule.assume_init(),
            }
        }
    }

    /// Encrypt a single 8-byte block with this key (ECB mode, no
    /// padding).
    pub(crate) fn ecb_encrypt(&self, block: &[u8; 8]) -> [u8; 8] {
        let input = DES_cblock_st { bytes: *block };
        let mut output = DES_cblock_st { bytes: [0u8; 8] };
        // SAFETY: input and output are valid DES_cblock values.
        // self.schedule is fully initialized by from_56bits.
        // DES_ENCRYPT is the correct constant to request encryption.
        unsafe {
            DES_ecb_encrypt(
                std::ptr::addr_of!(input),
                std::ptr::addr_of_mut!(output),
                std::ptr::addr_of!(self.schedule),
                DES_ENCRYPT,
            );
        }
        output.bytes
    }
}

/// Expand 7 raw key bytes (56 bits) into the 8-byte DES key format.
///
/// Each output byte receives 7 consecutive bits of the raw key in
/// positions `[7:1]`, leaving position `[0]` as zero. The caller
/// should pass the result to `DES_set_odd_parity` before scheduling.
///
/// The mapping, illustrated in RFC 2759 §9.3:
///
/// ```text
/// out[0] bits[7:1] = key56[0] bits[7:1]
/// out[1] bits[7:1] = key56[0] bit[0]  ++ key56[1] bits[7:2]
/// out[2] bits[7:1] = key56[1] bits[1:0] ++ key56[2] bits[7:3]
/// ...
/// out[7] bits[7:1] = key56[6] bits[6:0]
/// ```
fn expand_56_to_64(k: [u8; 7]) -> [u8; 8] {
    [
        k[0] & 0xFE,
        k[0] << 7 | (k[1] >> 1) & 0xFE,
        k[1] << 6 | (k[2] >> 2) & 0xFE,
        k[2] << 5 | (k[3] >> 3) & 0xFE,
        k[3] << 4 | (k[4] >> 4) & 0xFE,
        k[4] << 3 | (k[5] >> 5) & 0xFE,
        k[5] << 2 | (k[6] >> 6) & 0xFE,
        k[6] << 1,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Key expansion — RFC 2759 §9.3 known-answer test.
    //
    // The section gives two "raw" (7-byte) DES keys derived from the
    // NT password hash of "MyPw" and their parity-corrected 8-byte
    // forms.  We verify both the raw expansion and the final parity
    // correction.
    // ---------------------------------------------------------------

    const RAW_KEY_1: [u8; 7] = [0xFC, 0x15, 0x6A, 0xF7, 0xED, 0xCD, 0x6C];
    const PARITY_KEY_1: [u8; 8] = [0xFD, 0x0B, 0x5B, 0x5E, 0x7F, 0x6E, 0x34, 0xD9];

    const RAW_KEY_2: [u8; 7] = [0x0E, 0xDD, 0xE3, 0x33, 0x7D, 0x42, 0x7F];
    const PARITY_KEY_2: [u8; 8] = [0x0E, 0x6E, 0x79, 0x67, 0x37, 0xEA, 0x08, 0xFE];

    #[test]
    fn expand_then_parity_key1() {
        let mut expanded = expand_56_to_64(RAW_KEY_1);
        unsafe {
            DES_set_odd_parity(expanded.as_mut_ptr().cast::<DES_cblock>());
        }
        assert_eq!(expanded, PARITY_KEY_1);
    }

    #[test]
    fn expand_then_parity_key2() {
        let mut expanded = expand_56_to_64(RAW_KEY_2);
        unsafe {
            DES_set_odd_parity(expanded.as_mut_ptr().cast::<DES_cblock>());
        }
        assert_eq!(expanded, PARITY_KEY_2);
    }

    // ---------------------------------------------------------------
    // ChallengeResponse — RFC 2759 §9.2 known-answer test.
    //
    // The section traces a complete MS-CHAPv2 exchange for user
    // "User" / password "clientPass".  We verify each of the three
    // individual DES encryptions that make up the 24-byte NT-Response.
    //
    //   Challenge      = D0 2E 43 86 BC E9 12 26
    //   PasswordHash   = 44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE
    //   ZPasswordHash  = PasswordHash || 00 00 00 00 00 (padded to 21 bytes)
    //   NT-Response    = 82 30 9E CD 8D 70 8B 5E
    //                    A0 8F AA 39 81 CD 83 54
    //                    42 33 11 4A 3D 85 D6 DF
    // ---------------------------------------------------------------

    const CHALLENGE: [u8; 8] = [0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26];

    const KEY_A: [u8; 7] = [0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8];
    const KEY_B: [u8; 7] = [0xD6, 0x11, 0x47, 0x44, 0x11, 0xF5, 0x69];
    const KEY_C: [u8; 7] = [0x89, 0xAE, 0x00, 0x00, 0x00, 0x00, 0x00];

    const RESP_A: [u8; 8] = [0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E];
    const RESP_B: [u8; 8] = [0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54];
    const RESP_C: [u8; 8] = [0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF];

    #[test]
    fn challenge_response_rfc2759_part_a() {
        assert_eq!(DesKey::from_56bits(&KEY_A).ecb_encrypt(&CHALLENGE), RESP_A);
    }

    #[test]
    fn challenge_response_rfc2759_part_b() {
        assert_eq!(DesKey::from_56bits(&KEY_B).ecb_encrypt(&CHALLENGE), RESP_B);
    }

    #[test]
    fn challenge_response_rfc2759_part_c() {
        assert_eq!(DesKey::from_56bits(&KEY_C).ecb_encrypt(&CHALLENGE), RESP_C);
    }

    #[test]
    fn drop_without_use() {
        // DES_key_schedule has no heap resources; drop must not panic.
        let _k = DesKey::from_56bits(&KEY_A);
    }
}
