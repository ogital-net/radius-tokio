//! Safe wrapper for HMAC-MD5.
//!
//! HMAC-MD5 is the only HMAC variant the RADIUS wire protocol uses
//! (Message-Authenticator, RFC 3579). This module is intentionally
//! single-purpose: no digest selector enum, no one-shot helper, no
//! generic plumbing.
//!
//! Two backends are available:
//!
//! * Default — `aws-lc-sys`'s `HMAC_*` interface.
//! * `md5-asm` feature — pure-Rust HMAC construction (RFC 2104)
//!   layered on top of the in-tree [`Md5`][super::md5::Md5] wrapper,
//!   which itself dispatches to the vendored
//!   [`animetosho/md5-optimisation`](https://github.com/animetosho/md5-optimisation)
//!   block compressor. The public surface is identical either way.

/// HMAC-MD5 tag length in bytes. Equal to the MD5 digest length.
#[cfg(not(feature = "md5-asm"))]
pub(crate) const TAG_LEN: usize = aws_lc_sys::MD5_DIGEST_LENGTH as usize;
#[cfg(feature = "md5-asm")]
pub(crate) const TAG_LEN: usize = super::md5::DIGEST_LENGTH;

// ---------------------------------------------------------------------------
// aws-lc-sys backend (default)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "md5-asm"))]
use std::mem::MaybeUninit;

#[cfg(not(feature = "md5-asm"))]
use aws_lc_sys::{HMAC_CTX_cleanup, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_CTX};

/// Incremental HMAC-MD5 context backed by a stack-allocated `HMAC_CTX`.
///
/// Call [`update`][HmacMd5::update] one or more times, then
/// [`finalize`][HmacMd5::finalize]. `finalize` consumes `self` to
/// prevent reuse after the context is cleaned up.
#[cfg(not(feature = "md5-asm"))]
pub(crate) struct HmacMd5 {
    ctx: HMAC_CTX,
}

#[cfg(not(feature = "md5-asm"))]
impl HmacMd5 {
    /// Initializes a new HMAC-MD5 context with the given `key`.
    pub(crate) fn new(key: &[u8]) -> Self {
        // SAFETY: HMAC_CTX is a C struct with no padding invariants;
        // zeroing it is the correct initial state, equivalent to
        // HMAC_CTX_init.
        let mut ctx = unsafe { MaybeUninit::<HMAC_CTX>::zeroed().assume_init() };
        // SAFETY: ctx is zero-initialized. key is a valid slice for
        // key.len() bytes. EVP_md5() returns a pointer to a static,
        // immutable EVP_MD object and never returns NULL. impl_ is
        // NULL (use the default engine).
        let ret = unsafe {
            HMAC_Init_ex(
                &mut ctx,
                key.as_ptr().cast(),
                key.len(),
                aws_lc_sys::EVP_md5(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ret, 1, "HMAC_Init_ex failed");
        Self { ctx }
    }

    /// Feeds `data` into the running HMAC. May be called multiple times.
    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: ctx is initialized and not yet finalized. data is a
        // valid slice for the duration of this call.
        let ret = unsafe { HMAC_Update(&mut self.ctx, data.as_ptr(), data.len()) };
        assert_eq!(ret, 1, "HMAC_Update failed");
    }

    /// Finalizes the HMAC and returns the 16-byte tag.
    pub(crate) fn finalize(mut self) -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        let mut out_len: std::os::raw::c_uint = 0;
        // SAFETY: ctx is initialized and not previously finalized. tag
        // is 16 bytes — exactly the MD5 digest size.
        let ret = unsafe { HMAC_Final(&mut self.ctx, tag.as_mut_ptr(), &mut out_len) };
        assert_eq!(ret, 1, "HMAC_Final failed");
        debug_assert_eq!(out_len as usize, TAG_LEN);
        tag
    }
}

#[cfg(not(feature = "md5-asm"))]
impl Drop for HmacMd5 {
    fn drop(&mut self) {
        // SAFETY: ctx is initialized. HMAC_CTX_cleanup is idempotent and
        // safe to call even after HMAC_Final has run.
        unsafe { HMAC_CTX_cleanup(&mut self.ctx) };
    }
}

// ---------------------------------------------------------------------------
// md5-asm backend (RFC 2104 layered on the in-tree Md5 wrapper)
// ---------------------------------------------------------------------------

#[cfg(feature = "md5-asm")]
use super::md5::{Md5, BLOCK_SIZE};

/// Incremental HMAC-MD5 context backed by the in-tree [`Md5`] wrapper.
///
/// Plain RFC 2104 construction: `HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))`,
/// where `K'` is `K` truncated by `H` if `len(K) > B`, else `K` zero-padded
/// to `B = 64` bytes.
///
/// The ipad-prefixed inner state is precomputed at construction time so
/// `update` only feeds the message and `finalize` runs the outer hash.
/// No allocation on the steady-state path.
#[cfg(feature = "md5-asm")]
pub(crate) struct HmacMd5 {
    inner: Md5,
    /// `K' ⊕ opad`, ready to feed into the outer MD5. Zeroized on drop.
    opad: [u8; BLOCK_SIZE],
}

#[cfg(feature = "md5-asm")]
impl HmacMd5 {
    /// Initializes a new HMAC-MD5 context with the given `key`.
    pub(crate) fn new(key: &[u8]) -> Self {
        // RFC 2104 §2: if the key is longer than the block size, hash
        // it first; otherwise zero-pad to the block size.
        let mut k_prime = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let h = super::md5::digest(key);
            k_prime[..h.len()].copy_from_slice(&h);
        } else {
            k_prime[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; BLOCK_SIZE];
        let mut opad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] = k_prime[i] ^ 0x36;
            opad[i] = k_prime[i] ^ 0x5c;
        }
        // Wipe the derived key material; ipad/opad still encode it,
        // but `k_prime` itself is no longer needed.
        for b in &mut k_prime {
            // SAFETY: `b` is a live, properly aligned u8 in `k_prime`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }

        let mut inner = Md5::new();
        inner.update(&ipad);
        // ipad held key-derived bytes; clear it before it leaves scope.
        for b in &mut ipad {
            // SAFETY: `b` is a live, properly aligned u8 in `ipad`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }

        Self { inner, opad }
    }

    /// Feeds `data` into the running HMAC. May be called multiple times.
    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC and returns the 16-byte tag.
    pub(crate) fn finalize(mut self) -> [u8; TAG_LEN] {
        // Take the inner Md5 out so we can `finalize` it (which is
        // by-value); replace it with a fresh, throwaway context so
        // `Drop` has a valid `Md5` to drop.
        let inner_digest = core::mem::replace(&mut self.inner, Md5::new()).finalize();
        let mut outer = Md5::new();
        outer.update(&self.opad);
        // opad encodes the key; clear it now that the outer hash has
        // absorbed it. Drop will run its own clear too, but doing it
        // here narrows the live window.
        for b in &mut self.opad {
            // SAFETY: `b` is a live, properly aligned u8 in `self.opad`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        outer.update(&inner_digest);
        outer.finalize()
    }
}

#[cfg(feature = "md5-asm")]
impl Drop for HmacMd5 {
    fn drop(&mut self) {
        // `opad` holds `K' XOR 0x5c`, which trivially reveals K. Wipe
        // it on drop so a freed stack frame doesn't leak key material.
        // Volatile writes prevent the optimizer from eliding the clear
        // for a value about to go out of scope.
        for b in &mut self.opad {
            // SAFETY: `b` points to a live, properly aligned u8 inside
            // `self.opad`; volatile access through a unique reference
            // is always sound.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        // `inner` carries an MD5 state derived from `K' XOR ipad`. Its
        // wrapper has no public clearing hook; the buffered bytes were
        // wiped in `new`/`finalize`, and the running A/B/C/D words are
        // 16 bytes that go out of scope with this drop.
    }
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

    // RFC 2202 §2 test vectors for HMAC-MD5.
    #[test]
    fn known_answers() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
                b"Hi There",
                "9294727a3638bb1c13f48ef8158bfc9d",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "750c783e6ab0b503eaa86e310a5db738",
            ),
            (&[0xaa; 16], &[0xdd; 50], "56be34521d144c88dbb8c733f0e8b3f6"),
            (
                &[
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                ],
                &[0xcd; 50],
                "697eaf0aca3a3aea3a75164746ffaa79",
            ),
            (
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
            ),
            (
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger \
                  Than One Block-Size Data",
                "6f630fad67cda0ee1fb1f562db3aa53e",
            ),
        ];

        for (key, data, expected) in cases {
            let mut ctx = HmacMd5::new(key);
            ctx.update(data);
            assert_eq!(hex(&ctx.finalize()), *expected, "key.len() = {}", key.len());
        }
    }

    #[test]
    fn multi_update_matches_single() {
        let key = b"Jefe";
        let full = b"what do ya want for nothing?";

        let mut a = HmacMd5::new(key);
        a.update(full);
        let single = a.finalize();

        let mut b = HmacMd5::new(key);
        for byte in full {
            b.update(std::slice::from_ref(byte));
        }
        assert_eq!(b.finalize(), single);
    }

    #[test]
    fn drop_without_finalize() {
        drop(HmacMd5::new(b"key"));
    }
}
