//! EAP-Message reassembly view (RFC 3579 §3.1; attribute type 79).
//!
//! A single EAP packet may exceed the 253-byte cap on a RADIUS
//! attribute value. Implementations split the EAP payload across
//! multiple `EAP-Message` attributes carried back-to-back; the
//! receiver concatenates the value bytes of every `EAP-Message` it
//! finds, in attribute order, to recover the original EAP packet.
//!
//! This module exposes:
//!
//! * [`fragments`] — a borrowed iterator over the value bytes of each
//!   `EAP-Message` slot, in source order.
//! * [`reassemble_into`] — append the concatenated payload to a
//!   caller-supplied buffer (the only allocation point — and only when
//!   you actually want a contiguous slice).
//!
//! No allocation happens unless the caller asks for a contiguous
//! payload; consumers that can stream EAP fragments (e.g. straight
//! into a method engine) should use [`fragments`].

/// RADIUS attribute type for EAP-Message (RFC 3579 §3.1).
pub const TYPE: u8 = 79;

/// Iterate every `EAP-Message` value in attribute order.
///
/// Each yielded slice borrows from `attrs` directly (no copy). Stops
/// at the first malformed attribute slot — partial EAP payloads are
/// never silently truncated for the caller; pair this with
/// [`super::attributes::iter`] if you need to surface the parse
/// error.
pub fn fragments(attrs: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    super::attributes::iter(attrs)
        .map_while(Result::ok)
        .filter(|raw| raw.attribute_type() == TYPE)
        .map(|raw| raw.value())
}

/// Concatenate every `EAP-Message` value into `out`, returning the
/// total number of bytes appended.
///
/// `out` is *appended to*, not cleared — the caller controls reuse of
/// the buffer.
pub fn reassemble_into(attrs: &[u8], out: &mut Vec<u8>) -> usize {
    let start = out.len();
    for fragment in fragments(attrs) {
        out.extend_from_slice(fragment);
    }
    out.len() - start
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(attrs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        for (typ, val) in attrs {
            v.push(*typ);
            v.push(u8::try_from(2 + val.len()).unwrap());
            v.extend_from_slice(val);
        }
        v
    }

    #[test]
    fn collects_in_order_skips_others() {
        let bytes = region(&[
            (TYPE, &[1, 2, 3]),
            (1, b"username"),
            (TYPE, &[4, 5]),
            (TYPE, &[6]),
        ]);
        let frags: Vec<&[u8]> = fragments(&bytes).collect();
        assert_eq!(frags, vec![&[1, 2, 3][..], &[4, 5][..], &[6][..]]);

        let mut out = Vec::new();
        let n = reassemble_into(&bytes, &mut out);
        assert_eq!(n, 6);
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn empty_when_no_eap_attributes() {
        let bytes = region(&[(1, b"x"), (5, &[0, 0, 0, 1])]);
        assert_eq!(fragments(&bytes).count(), 0);
        let mut out = Vec::new();
        assert_eq!(reassemble_into(&bytes, &mut out), 0);
        assert!(out.is_empty());
    }
}
