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
}
