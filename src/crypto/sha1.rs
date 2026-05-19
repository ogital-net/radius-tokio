//! Safe wrappers for the SHA-1 functions in `aws-lc-sys`.
//!
//! SHA-1 is not recommended for new cryptographic uses. Its inclusion
//! here is limited to the MS-CHAPv2 wire format (RFC 2759) where the
//! `ChallengeHash` (§8.2) and `GenerateAuthenticatorResponse` (§8.7)
//! functions mandate it.
//!
//! Only the incremental streaming API is exposed; one-shot and
//! block-transform primitives are omitted as they are not needed by
//! the MS-CHAPv2 code paths.

use std::mem::MaybeUninit;

use aws_lc_sys::{SHA1_Final, SHA1_Init, SHA1_Update, SHA_CTX};

/// SHA-1 digest length in bytes (20).
pub(crate) const DIGEST_LENGTH: usize = aws_lc_sys::SHA_DIGEST_LENGTH as usize;

/// Incremental SHA-1 digest context.
///
/// Call [`update`][Sha1::update] one or more times, then
/// [`finalize`][Sha1::finalize]. `finalize` consumes `self` to
/// prevent reuse of a finished context.
pub(crate) struct Sha1 {
    ctx: SHA_CTX,
}

impl Sha1 {
    /// Initializes a new SHA-1 context.
    pub(crate) fn new() -> Self {
        // SAFETY: SHA1_Init writes every field of sha_state_st before
        // we call assume_init. MaybeUninit gives a properly aligned
        // allocation without reading uninitialized memory.
        let mut ctx = MaybeUninit::<SHA_CTX>::uninit();
        let ret = unsafe { SHA1_Init(ctx.as_mut_ptr()) };
        // aws-lc returns 1 unconditionally for a valid (non-null) pointer.
        assert_eq!(ret, 1, "SHA1_Init failed");
        // SAFETY: SHA1_Init returned 1, all fields are initialized.
        Self {
            ctx: unsafe { ctx.assume_init() },
        }
    }

    /// Feeds `data` into the digest. May be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialized and not yet finalized. data is a
        // valid slice for the duration of this call.
        let ret = unsafe {
            SHA1_Update(
                &raw mut self.ctx,
                data.as_ptr().cast::<std::os::raw::c_void>(),
                data.len(),
            )
        };
        assert_eq!(ret, 1, "SHA1_Update failed");
    }

    /// Finalizes the digest and returns the 20-byte output.
    pub(crate) fn finalize(mut self) -> [u8; DIGEST_LENGTH] {
        let mut out = [0u8; DIGEST_LENGTH];
        // SAFETY: out is exactly DIGEST_LENGTH bytes. ctx is
        // initialized and not previously finalized.
        let ret = unsafe { SHA1_Final(out.as_mut_ptr(), &raw mut self.ctx) };
        assert_eq!(ret, 1, "SHA1_Final failed");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS PUB 180-1 / RFC 3174 §7.3 known-answer vectors.
    const VECTORS: &[(&[u8], &str)] = &[
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                write!(s, "{b:02x}").unwrap();
                s
            })
    }

    #[test]
    fn incremental_known_answers() {
        for (input, expected) in VECTORS {
            let mut ctx = Sha1::new();
            ctx.update(input);
            assert_eq!(hex(&ctx.finalize()), *expected, "input = {input:?}");
        }
    }

    #[test]
    fn incremental_multi_update() {
        // "abc" fed one byte at a time.
        let mut ctx = Sha1::new();
        for b in b"abc" {
            ctx.update(std::slice::from_ref(b));
        }
        assert_eq!(
            hex(&ctx.finalize()),
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        );
    }

    #[test]
    fn drop_without_finalize() {
        // SHA_CTX has no heap resources; drop without finalize must not panic.
        let _ctx = Sha1::new();
    }

    // ---------------------------------------------------------------
    // ChallengeHash — RFC 2759 §9.2 known-answer test.
    //
    //   PeerChallenge         = 21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E
    //   AuthenticatorChallenge= 5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28
    //   UserName              = "User" (55 73 65 72)
    //   Challenge             = D0 2E 43 86 BC E9 12 26
    // ---------------------------------------------------------------
    #[test]
    fn challenge_hash_rfc2759() {
        let peer_challenge: [u8; 16] = [
            0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33,
            0x7C, 0x7E,
        ];
        let auth_challenge: [u8; 16] = [
            0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26,
            0x26, 0x28,
        ];
        let username = b"User";
        let expected: [u8; 8] = [0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26];

        let mut ctx = Sha1::new();
        ctx.update(&peer_challenge);
        ctx.update(&auth_challenge);
        ctx.update(username);
        let digest = ctx.finalize();
        assert_eq!(&digest[..8], expected);
    }
}
