//! Safe wrapper for the `RAND_bytes` function in `aws-lc-sys`.

use std::mem::MaybeUninit;

/// Fills `buf` with cryptographically secure random bytes.
///
/// Each element is fully initialized after this call returns. The caller may
/// use [`MaybeUninit::slice_assume_init_ref`] (or equivalent) to read the
/// result once this function returns.
///
/// # Panics
///
/// Panics if `RAND_bytes` returns an error. The aws-lc implementation always
/// returns 1 (success); the assert exists to catch any future behavioral change.
pub(crate) fn fill(buf: &mut [MaybeUninit<u8>]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: buf is a valid, writable slice for buf.len() bytes. RAND_bytes
    // writes exactly buf.len() bytes and does not read the existing contents,
    // so uninitialized memory is safe to pass. The return value is checked
    // below; aws-lc always returns 1.
    let ret = unsafe { aws_lc_sys::RAND_bytes(buf.as_mut_ptr().cast::<u8>(), buf.len()) };
    assert_eq!(ret, 1, "RAND_bytes failed");
}

/// Fills `buf` with cryptographically secure random bytes from
/// aws-lc's `RAND_bytes`.
///
/// Suitable for nonces, EAP session identifiers, RADIUS Request
/// Authenticators, MS-MPPE salts, and other places that require an
/// unpredictable bit string. The underlying generator is the same
/// CSPRNG used by the TLS stack in this crate.
///
/// # Panics
///
/// Panics if `RAND_bytes` returns an error. aws-lc always returns 1
/// for non-empty buffers; the assert exists to catch any future
/// behavioral change rather than silently shipping deterministic
/// bytes into security-critical code paths.
pub fn fill_secure(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: buf is a valid, writable slice for buf.len() bytes;
    // RAND_bytes writes exactly that many bytes. Return value
    // asserted below.
    let ret = unsafe { aws_lc_sys::RAND_bytes(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(ret, 1, "RAND_bytes failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_16_bytes() {
        let mut buf = [MaybeUninit::uninit(); 16];
        fill(&mut buf);
        // SAFETY: fill initializes every byte.
        let buf: &[u8; 16] = unsafe { &*buf.as_ptr().cast::<[u8; 16]>() };
        // A random 16-byte buffer being all zeros would be astronomically
        // unlikely; treat it as a signal that the call did nothing.
        assert_ne!(buf, &[0u8; 16]);
    }

    #[test]
    fn fill_empty_is_noop() {
        fill(&mut []);
    }

    #[test]
    fn fill_secure_populates_buffer() {
        let mut buf = [0u8; 32];
        fill_secure(&mut buf);
        // 32 zero bytes from a CSPRNG would be astronomically
        // unlikely; treat that as a signal the call was a no-op.
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn fill_secure_empty_is_noop() {
        fill_secure(&mut []);
    }

    #[test]
    fn fill_secure_independent_calls_differ() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_secure(&mut a);
        fill_secure(&mut b);
        assert_ne!(a, b);
    }
}
