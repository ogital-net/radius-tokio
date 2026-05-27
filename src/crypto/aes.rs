//! Safe wrappers for AES-128 and AES-256 block and CBC operations.
//!
//! RADIUS itself does not call AES directly, but two adjacent
//! protocol surfaces do:
//!
//! * **MS-MPPE key transport (RFC 2548 §2.4.2 / §2.4.3)** delivers
//!   session keys to a NAS using an MD5-keystream construction; the
//!   AES variants in current Microsoft NPS deployments substitute
//!   AES-128 in CBC mode for the keystream step.
//! * **EAP method derivations** — EAP-FAST (RFC 4851 §5.1), EAP-TEAP
//!   (RFC 7170 §5.4), EAP-AKA' (RFC 5448 §3.4.1) — wrap session
//!   keys with AES-128 in ECB or CBC.
//!
//! Exposed here so the companion `radius-tokio-eap` crate and
//! out-of-tree handlers do not need to link a second crypto stack.
//!
//! # API shape
//!
//! Keys are split by length: [`Aes128Key`] (16-byte) and
//! [`Aes256Key`] (32-byte). Each wraps a pre-expanded `AES_KEY`
//! schedule for either encryption or decryption — distinct types
//! prevent feeding a decryption schedule to an encrypt call (which
//! would silently produce garbage).
//!
//! Padding is **not** applied. CBC callers MUST pass input that is
//! an exact multiple of [`BLOCK_SIZE`]; the EAP / MPPE framings
//! handle their own padding (typically zero or PKCS#7 above the
//! wire) and we keep this layer policy-free. The IV is borrowed
//! mutably and updated in place to match the underlying aws-lc API,
//! letting callers chain successive segments without re-creating
//! the schedule.

use std::mem::MaybeUninit;

use aws_lc_sys::{
    AES_cbc_encrypt, AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key,
    AES_DECRYPT, AES_ENCRYPT, AES_KEY,
};

use super::cleanse;

/// AES block size in bytes (16, fixed by the cipher).
pub const BLOCK_SIZE: usize = aws_lc_sys::AES_BLOCK_SIZE as usize;

/// One AES block (16 bytes).
pub type Block = [u8; BLOCK_SIZE];

// ---------------------------------------------------------------------------
// AES-128
// ---------------------------------------------------------------------------

/// AES-128 expanded key schedule.
///
/// Built from a 16-byte key via [`Aes128Key::new_encrypt`] or
/// [`Aes128Key::new_decrypt`]; the variant determines which
/// direction is valid. Dropping the value clears the schedule
/// bytes via `OPENSSL_cleanse`.
pub struct Aes128Key {
    sched: AES_KEY,
    direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

impl Aes128Key {
    /// Build an encryption schedule from a 16-byte key.
    #[must_use]
    pub fn new_encrypt(key: &[u8; 16]) -> Self {
        Self {
            sched: build_schedule(key, Direction::Encrypt),
            direction: Direction::Encrypt,
        }
    }

    /// Build a decryption schedule from a 16-byte key.
    #[must_use]
    pub fn new_decrypt(key: &[u8; 16]) -> Self {
        Self {
            sched: build_schedule(key, Direction::Decrypt),
            direction: Direction::Decrypt,
        }
    }

    /// Encrypt one 16-byte block under this key.
    ///
    /// # Panics
    ///
    /// Panics if the key was built with [`new_decrypt`](Self::new_decrypt).
    #[must_use]
    pub fn encrypt_block(&self, block: &Block) -> Block {
        assert_eq!(
            self.direction,
            Direction::Encrypt,
            "encrypt_block requires an encryption schedule"
        );
        let mut out = [0u8; BLOCK_SIZE];
        // SAFETY: input and output are 16 bytes each (AES block size);
        // sched is an initialised encryption schedule for this key.
        unsafe { AES_encrypt(block.as_ptr(), out.as_mut_ptr(), &raw const self.sched) };
        out
    }

    /// Decrypt one 16-byte block under this key.
    ///
    /// # Panics
    ///
    /// Panics if the key was built with [`new_encrypt`](Self::new_encrypt).
    #[must_use]
    pub fn decrypt_block(&self, block: &Block) -> Block {
        assert_eq!(
            self.direction,
            Direction::Decrypt,
            "decrypt_block requires a decryption schedule"
        );
        let mut out = [0u8; BLOCK_SIZE];
        // SAFETY: input and output are 16 bytes each (AES block size);
        // sched is an initialised decryption schedule for this key.
        unsafe { AES_decrypt(block.as_ptr(), out.as_mut_ptr(), &raw const self.sched) };
        out
    }

    /// CBC-encrypt `input` into `output` in place of the supplied
    /// `iv` (which is updated to the trailing ciphertext block, so
    /// callers can stream a longer message in segments).
    ///
    /// # Errors
    ///
    /// Returns [`AesError`] if `input.len()` is not a multiple of
    /// [`BLOCK_SIZE`] or `output.len()` differs from `input.len()`,
    /// or the schedule is for decryption.
    pub fn cbc_encrypt(
        &self,
        input: &[u8],
        output: &mut [u8],
        iv: &mut Block,
    ) -> Result<(), AesError> {
        if self.direction != Direction::Encrypt {
            return Err(AesError::WrongDirection);
        }
        cbc(input, output, iv, &self.sched, AES_ENCRYPT)
    }

    /// CBC-decrypt `input` into `output`. Mirror of
    /// [`cbc_encrypt`](Self::cbc_encrypt).
    ///
    /// # Errors
    ///
    /// As for [`cbc_encrypt`](Self::cbc_encrypt).
    pub fn cbc_decrypt(
        &self,
        input: &[u8],
        output: &mut [u8],
        iv: &mut Block,
    ) -> Result<(), AesError> {
        if self.direction != Direction::Decrypt {
            return Err(AesError::WrongDirection);
        }
        cbc(input, output, iv, &self.sched, AES_DECRYPT)
    }
}

impl Drop for Aes128Key {
    fn drop(&mut self) {
        cleanse_schedule(&mut self.sched);
    }
}

// ---------------------------------------------------------------------------
// AES-256
// ---------------------------------------------------------------------------

/// AES-256 expanded key schedule. Mirrors [`Aes128Key`] for 32-byte keys.
pub struct Aes256Key {
    sched: AES_KEY,
    direction: Direction,
}

impl Aes256Key {
    /// Build an encryption schedule from a 32-byte key.
    #[must_use]
    pub fn new_encrypt(key: &[u8; 32]) -> Self {
        Self {
            sched: build_schedule(key, Direction::Encrypt),
            direction: Direction::Encrypt,
        }
    }

    /// Build a decryption schedule from a 32-byte key.
    #[must_use]
    pub fn new_decrypt(key: &[u8; 32]) -> Self {
        Self {
            sched: build_schedule(key, Direction::Decrypt),
            direction: Direction::Decrypt,
        }
    }

    /// Encrypt one 16-byte block. See [`Aes128Key::encrypt_block`].
    ///
    /// # Panics
    ///
    /// Panics if the key was built with [`new_decrypt`](Self::new_decrypt).
    #[must_use]
    pub fn encrypt_block(&self, block: &Block) -> Block {
        assert_eq!(
            self.direction,
            Direction::Encrypt,
            "encrypt_block requires an encryption schedule"
        );
        let mut out = [0u8; BLOCK_SIZE];
        // SAFETY: as for Aes128Key::encrypt_block.
        unsafe { AES_encrypt(block.as_ptr(), out.as_mut_ptr(), &raw const self.sched) };
        out
    }

    /// Decrypt one 16-byte block. See [`Aes128Key::decrypt_block`].
    ///
    /// # Panics
    ///
    /// Panics if the key was built with [`new_encrypt`](Self::new_encrypt).
    #[must_use]
    pub fn decrypt_block(&self, block: &Block) -> Block {
        assert_eq!(
            self.direction,
            Direction::Decrypt,
            "decrypt_block requires a decryption schedule"
        );
        let mut out = [0u8; BLOCK_SIZE];
        // SAFETY: as for Aes128Key::decrypt_block.
        unsafe { AES_decrypt(block.as_ptr(), out.as_mut_ptr(), &raw const self.sched) };
        out
    }

    /// CBC-encrypt. See [`Aes128Key::cbc_encrypt`].
    ///
    /// # Errors
    ///
    /// As for [`Aes128Key::cbc_encrypt`].
    pub fn cbc_encrypt(
        &self,
        input: &[u8],
        output: &mut [u8],
        iv: &mut Block,
    ) -> Result<(), AesError> {
        if self.direction != Direction::Encrypt {
            return Err(AesError::WrongDirection);
        }
        cbc(input, output, iv, &self.sched, AES_ENCRYPT)
    }

    /// CBC-decrypt. See [`Aes128Key::cbc_decrypt`].
    ///
    /// # Errors
    ///
    /// As for [`Aes128Key::cbc_decrypt`].
    pub fn cbc_decrypt(
        &self,
        input: &[u8],
        output: &mut [u8],
        iv: &mut Block,
    ) -> Result<(), AesError> {
        if self.direction != Direction::Decrypt {
            return Err(AesError::WrongDirection);
        }
        cbc(input, output, iv, &self.sched, AES_DECRYPT)
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        cleanse_schedule(&mut self.sched);
    }
}

// ---------------------------------------------------------------------------
// Errors and shared helpers
// ---------------------------------------------------------------------------

/// CBC misuse errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// Input length is not a multiple of [`BLOCK_SIZE`].
    UnalignedInput {
        /// The offending input length in bytes.
        len: usize,
    },
    /// Output buffer length does not match input length.
    OutputLenMismatch {
        /// The input length in bytes.
        input: usize,
        /// The (incorrect) output length in bytes.
        output: usize,
    },
    /// Attempted to encrypt with a decryption schedule or vice-versa.
    WrongDirection,
}

impl std::fmt::Display for AesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnalignedInput { len } => {
                write!(
                    f,
                    "AES-CBC input length {len} is not a multiple of {BLOCK_SIZE}"
                )
            }
            Self::OutputLenMismatch { input, output } => {
                write!(
                    f,
                    "AES-CBC output length {output} does not match input length {input}"
                )
            }
            Self::WrongDirection => f.write_str("AES schedule direction does not match operation"),
        }
    }
}

impl std::error::Error for AesError {}

fn build_schedule(key: &[u8], dir: Direction) -> AES_KEY {
    // SAFETY: AES_set_{encrypt,decrypt}_key writes every field of the
    // schedule on success; MaybeUninit gives a properly aligned
    // allocation without reading uninitialized memory.
    let mut sched = MaybeUninit::<AES_KEY>::uninit();
    // SAFETY: key is a valid slice; bits is the bit length; sched is
    // a writable AES_KEY allocation.
    let ret = unsafe {
        let bits = u32::try_from(key.len() * 8).expect("AES key length fits in u32");
        match dir {
            Direction::Encrypt => AES_set_encrypt_key(key.as_ptr(), bits, sched.as_mut_ptr()),
            Direction::Decrypt => AES_set_decrypt_key(key.as_ptr(), bits, sched.as_mut_ptr()),
        }
    };
    // aws-lc returns 0 on success; non-zero indicates an invalid key
    // size, which we have already constrained at the type level.
    assert_eq!(ret, 0, "AES_set_{dir:?}_key failed");
    // SAFETY: AES_set_*_key returned 0, all fields are initialised.
    unsafe { sched.assume_init() }
}

fn cleanse_schedule(sched: &mut AES_KEY) {
    // SAFETY: round_key is the only sensitive field; cleanse zeroes
    // it through OPENSSL_cleanse. We treat the whole AES_KEY as the
    // sensitive region to be safe against future field additions.
    let bytes = std::mem::size_of::<AES_KEY>();
    let ptr = std::ptr::from_mut::<AES_KEY>(sched).cast::<u8>();
    // SAFETY: ptr is valid for `bytes` bytes; AES_KEY has no Drop
    // impl that would object to the rewrite.
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, bytes) };
    cleanse(slice);
}

fn cbc(
    input: &[u8],
    output: &mut [u8],
    iv: &mut Block,
    sched: &AES_KEY,
    enc: i32,
) -> Result<(), AesError> {
    if input.len() % BLOCK_SIZE != 0 {
        return Err(AesError::UnalignedInput { len: input.len() });
    }
    if output.len() != input.len() {
        return Err(AesError::OutputLenMismatch {
            input: input.len(),
            output: output.len(),
        });
    }
    if input.is_empty() {
        return Ok(());
    }
    // SAFETY: input/output are checked to be equal length and a
    // multiple of BLOCK_SIZE; sched is an initialised schedule for
    // the requested direction; iv is a mutable 16-byte slice;
    // enc ∈ {AES_ENCRYPT, AES_DECRYPT}.
    unsafe {
        AES_cbc_encrypt(
            input.as_ptr(),
            output.as_mut_ptr(),
            input.len(),
            sched,
            iv.as_mut_ptr(),
            enc,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    // FIPS 197 Appendix B.1: AES-128 with key=000102…0f, input=00112233…ff.
    #[test]
    fn fips197_aes128_known_answer() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct = Aes128Key::new_encrypt(&key).encrypt_block(&plaintext);
        assert_eq!(hex(&ct), "69c4e0d86a7b0430d8cdb78070b4c55a");
        let pt = Aes128Key::new_decrypt(&key).decrypt_block(&ct);
        assert_eq!(pt, plaintext);
    }

    // FIPS 197 Appendix C.3: AES-256 with key=000102…1f, input=00112233…ff.
    #[test]
    fn fips197_aes256_known_answer() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct = Aes256Key::new_encrypt(&key).encrypt_block(&plaintext);
        assert_eq!(hex(&ct), "8ea2b7ca516745bfeafc49904b496089");
        let pt = Aes256Key::new_decrypt(&key).decrypt_block(&ct);
        assert_eq!(pt, plaintext);
    }

    // NIST SP 800-38A Appendix F.2.1 / F.2.2: AES-128-CBC with the
    // well-known key/IV/plaintext quadruple.
    #[test]
    fn sp800_38a_aes128_cbc_round_trip() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected_ct = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];

        let mut iv_enc = iv;
        let mut ct = vec![0u8; plaintext.len()];
        Aes128Key::new_encrypt(&key)
            .cbc_encrypt(&plaintext, &mut ct, &mut iv_enc)
            .unwrap();
        assert_eq!(ct, expected_ct);

        let mut iv_dec = iv;
        let mut pt = vec![0u8; ct.len()];
        Aes128Key::new_decrypt(&key)
            .cbc_decrypt(&ct, &mut pt, &mut iv_dec)
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn cbc_rejects_unaligned_input() {
        let key = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut out = [0u8; 15];
        let err = Aes128Key::new_encrypt(&key)
            .cbc_encrypt(&[0u8; 15], &mut out, &mut iv)
            .unwrap_err();
        assert_eq!(err, AesError::UnalignedInput { len: 15 });
    }

    #[test]
    fn cbc_rejects_wrong_direction() {
        let key = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut out = [0u8; 16];
        let err = Aes128Key::new_decrypt(&key)
            .cbc_encrypt(&[0u8; 16], &mut out, &mut iv)
            .unwrap_err();
        assert_eq!(err, AesError::WrongDirection);
    }
}
