//! MS-CHAPv1 / MS-CHAPv2 verification (RFC 2433 / RFC 2759), carried
//! via the Microsoft VSAs defined in RFC 2548.
//!
//! Both schemes ride inside `Vendor-Specific` (attribute 26) under the
//! Microsoft PEN (311):
//!
//! | Per-vendor type | Name              | Used by   |
//! |-----------------|-------------------|-----------|
//! | 1               | MS-CHAP-Response  | v1        |
//! | 11              | MS-CHAP-Challenge | v1 + v2   |
//! | 25              | MS-CHAP2-Response | v2        |
//!
//! These helpers parse the wire encoding by hand rather than going
//! through the typed VSA accessors so the `auth` module does not need
//! to depend on the `dict-microsoft` cargo feature.
//!
//! # Cryptography
//!
//! Both versions ultimately call `ChallengeResponse` (RFC 2759 §8.5):
//! pad the 16-byte NT password hash to 21 bytes with zeros, split into
//! three 7-byte DES keys, and ECB-encrypt the 8-byte challenge with
//! each. v2 first derives the 8-byte challenge from the peer /
//! authenticator challenges and the username via SHA-1 (RFC 2759 §8.2).
//!
//! The NT password hash is `MD4(UTF-16LE(password))`. Consumers that
//! store the NT hash directly should pass [`MsChapSecret::NtHash`] to
//! avoid round-tripping through cleartext.
//!
//! # LM responses
//!
//! The LM-Response half of `MS-CHAP-Response` is intentionally not
//! consulted. We always validate against the NT-Response field.
//! Microsoft has deprecated LM for over a decade and supporting it
//! would require an OEM codepage dependency.

use super::VerifyOutcome;
use crate::codec::attributes::AttributeError;
use crate::crypto::{cleanse, ct_eq, des::DesKey, md4, sha1::Sha1};
use crate::server::Request;

/// Microsoft Private Enterprise Number (RFC 2548).
const MS_VENDOR_ID: u32 = 311;
/// `Vendor-Specific` attribute type (RFC 2865 §5.26).
const VSA_TYPE: u8 = 26;
/// `User-Name` attribute type (RFC 2865 §5.1).
const USER_NAME_TYPE: u8 = 1;

// Microsoft per-vendor type codes (RFC 2548).
const VT_MS_CHAP_RESPONSE: u8 = 1;
const VT_MS_CHAP_CHALLENGE: u8 = 11;
const VT_MS_CHAP2_RESPONSE: u8 = 25;

// MS-CHAP-Response (RFC 2548 §2.1.3) wire layout: 50 octets total
// = ident(1) || flags(1) || lm-resp(24) || nt-resp(24).
const MS_CHAP_RESPONSE_LEN: usize = 50;
const MS_CHAP_RESPONSE_NT_OFFSET: usize = 2 + 24;

// MS-CHAP2-Response (RFC 2548 §2.3.2) wire layout: 50 octets total
// = ident(1) || flags(1) || peer-challenge(16) || reserved(8) || nt-resp(24).
const MS_CHAP2_RESPONSE_LEN: usize = 50;
const MS_CHAP2_RESPONSE_PEER_OFFSET: usize = 2;
const MS_CHAP2_RESPONSE_NT_OFFSET: usize = 2 + 16 + 8;

const MS_CHAP_V1_CHALLENGE_LEN: usize = 8;
const MS_CHAP_V2_CHALLENGE_LEN: usize = 16;

// `Magic server to client signing constant` (RFC 2759 §8.7).
const MAGIC1: &[u8; 39] = b"Magic server to client signing constant";
// `Pad to make it do more than one iteration` (RFC 2759 §8.7).
const MAGIC2: &[u8; 41] = b"Pad to make it do more than one iteration";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Selector for the password material the verifier should use.
///
/// Identity stores that keep the NT hash directly should prefer
/// [`Self::NtHash`]; stores that keep cleartext can pass
/// [`Self::Cleartext`] and let the helper derive the hash.
#[derive(Debug, Clone, Copy)]
pub enum MsChapSecret<'a> {
    /// Cleartext password, interpreted as UTF-8. Re-encoded as
    /// UTF-16LE and MD4-hashed to derive the NT password hash.
    Cleartext(&'a str),
    /// Pre-computed NT password hash (MD4 of UTF-16LE password).
    NtHash(&'a [u8; 16]),
}

impl MsChapSecret<'_> {
    fn nt_hash(self) -> [u8; 16] {
        match self {
            Self::NtHash(h) => *h,
            Self::Cleartext(p) => nt_password_hash(p),
        }
    }
}

/// Compute the NT password hash defined by RFC 2759 §8.3:
/// `MD4(UTF-16LE(password))`.
///
/// Exposed so callers that store the NT hash can derive it once and
/// then pass [`MsChapSecret::NtHash`] on the request path.
#[must_use]
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut buf = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
    let hash = md4::digest(&buf);
    cleanse(&mut buf);
    hash
}

/// Verify an MS-CHAPv1 credential (RFC 2433 + RFC 2548 §2.1).
///
/// Returns:
///
/// * [`VerifyOutcome::Match`] / [`VerifyOutcome::Mismatch`] when the
///   `MS-CHAP-Challenge` (8 octets) and `MS-CHAP-Response` (50 octets)
///   VSAs are both present and well-formed.
/// * [`VerifyOutcome::Missing`] when either VSA is absent.
/// * [`VerifyOutcome::Malformed`] when a VSA is present but its inner
///   length does not match the RFC.
///
/// Verification always uses the NT-Response field; the LM-Response
/// half is ignored by design (see module docs).
///
/// # Errors
///
/// Forwards [`AttributeError`] from the attribute list iterator.
pub fn verify_v1(
    request: &Request<'_>,
    expected_password: MsChapSecret<'_>,
) -> Result<VerifyOutcome, AttributeError> {
    let Some(challenge) = first_ms_vsa(request, VT_MS_CHAP_CHALLENGE)? else {
        return Ok(VerifyOutcome::Missing);
    };
    let Some(response) = first_ms_vsa(request, VT_MS_CHAP_RESPONSE)? else {
        return Ok(VerifyOutcome::Missing);
    };
    if challenge.len() != MS_CHAP_V1_CHALLENGE_LEN || response.len() != MS_CHAP_RESPONSE_LEN {
        return Ok(VerifyOutcome::Malformed);
    }
    let mut challenge_arr = [0u8; 8];
    challenge_arr.copy_from_slice(challenge);
    let mut nt_response = [0u8; 24];
    nt_response.copy_from_slice(&response[MS_CHAP_RESPONSE_NT_OFFSET..MS_CHAP_RESPONSE_LEN]);

    let mut nt_hash = expected_password.nt_hash();
    let expected = challenge_response(challenge_arr, &nt_hash);
    cleanse(&mut nt_hash);

    Ok(if ct_eq(&expected, &nt_response) {
        VerifyOutcome::Match
    } else {
        VerifyOutcome::Mismatch
    })
}

/// Verify an MS-CHAPv2 credential (RFC 2759 + RFC 2548 §2.3).
///
/// Returns:
///
/// * [`VerifyOutcome::Match`] / [`VerifyOutcome::Mismatch`] when
///   `MS-CHAP-Challenge` (16 octets), `MS-CHAP2-Response` (50 octets),
///   and `User-Name` are all present and well-formed.
/// * [`VerifyOutcome::Missing`] when any of those attributes is absent
///   or malformed (the request is using some other auth scheme).
///
/// On `Match`, the handler will typically also call
/// [`v2_success_response`] to compute the `AuthenticatorResponse`
/// string for the `MS-CHAP2-Success` VSA.
///
/// # Errors
///
/// Forwards [`AttributeError`] from the attribute list iterator.
pub fn verify_v2(
    request: &Request<'_>,
    expected_password: MsChapSecret<'_>,
) -> Result<VerifyOutcome, AttributeError> {
    let Some(parts) = decode_v2_inputs(request)? else {
        return Ok(VerifyOutcome::Missing);
    };
    let V2Inputs {
        auth_challenge,
        peer_challenge,
        nt_response,
        username,
    } = parts;

    let expected = v2_nt_response(
        &auth_challenge,
        &peer_challenge,
        username,
        expected_password,
    );

    Ok(if ct_eq(&expected, &nt_response) {
        VerifyOutcome::Match
    } else {
        VerifyOutcome::Mismatch
    })
}

/// Compute the MS-CHAPv2 NT-Response (RFC 2759 §8.1) directly from
/// raw inputs, without going through the `MS-CHAP-Challenge` /
/// `MS-CHAP2-Response` Microsoft VSAs that bare RADIUS uses.
///
/// `EAP-MSCHAPv2` (EAP type 26, RFC 2759 +
/// draft-kamath-pppext-eap-mschapv2) ships these fields inside an
/// `EAP-Message` payload rather than as VSAs. Consumers terminating EAP-MSCHAPv2 themselves parse the EAP
/// frame and feed the resulting authenticator challenge, peer
/// challenge, username, and password into this helper to compute the
/// expected 24-byte NT-Response, then compare in constant time.
///
/// `username` is fed through the same `DOMAIN\` stripping as
/// [`verify_v2`]; pass the raw User-Name value (or the EAP identity).
#[must_use]
pub fn v2_nt_response(
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &[u8],
    password: MsChapSecret<'_>,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, auth_challenge, strip_domain(username));
    let mut nt_hash = password.nt_hash();
    let resp = challenge_response(challenge, &nt_hash);
    cleanse(&mut nt_hash);
    resp
}

/// Compute the MS-CHAPv2 `AuthenticatorResponse` (RFC 2759 §8.7) for a
/// successful authentication.
///
/// The returned 42-byte value is the ASCII string `"S="` followed by
/// 40 uppercase hex characters; place it in the `MS-CHAP2-Success` VSA
/// of the Access-Accept reply.
///
/// Returns `Ok(None)` if any of the attributes the function needs are
/// missing or malformed; the caller should normally have already
/// established a successful [`verify_v2`] call before invoking
/// this helper.
///
/// # Errors
///
/// Forwards [`AttributeError`] from the attribute list iterator.
pub fn v2_success_response(
    request: &Request<'_>,
    expected_password: MsChapSecret<'_>,
) -> Result<Option<[u8; 42]>, AttributeError> {
    let Some(parts) = decode_v2_inputs(request)? else {
        return Ok(None);
    };
    let V2Inputs {
        auth_challenge,
        peer_challenge,
        nt_response,
        username,
    } = parts;

    Ok(Some(v2_authenticator_response(
        &auth_challenge,
        &peer_challenge,
        &nt_response,
        username,
        expected_password,
    )))
}

/// Compute the MS-CHAPv2 `AuthenticatorResponse` (RFC 2759 §8.7) from
/// raw inputs.
///
/// Companion to [`v2_nt_response`] for consumers terminating
/// EAP-MSCHAPv2 themselves: parse the EAP frame, then feed the four
/// raw fields plus the password into this helper to obtain the
/// 42-byte ASCII string `"S=<40 uppercase hex>"` that goes in the
/// `MSCHAPv2` Success message.
///
/// `username` follows the same `DOMAIN\` stripping rule as
/// [`verify_v2`].
#[must_use]
pub fn v2_authenticator_response(
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
    username: &[u8],
    password: MsChapSecret<'_>,
) -> [u8; 42] {
    let mut nt_hash = password.nt_hash();
    let mut password_hash_hash = md4::digest(&nt_hash);
    cleanse(&mut nt_hash);

    let mut s = Sha1::new();
    s.update(&password_hash_hash);
    s.update(nt_response);
    s.update(MAGIC1);
    let digest1 = s.finalize();
    cleanse(&mut password_hash_hash);

    let challenge = challenge_hash(peer_challenge, auth_challenge, strip_domain(username));
    let mut s = Sha1::new();
    s.update(&digest1);
    s.update(&challenge);
    s.update(MAGIC2);
    let digest2 = s.finalize();

    let mut out = [0u8; 42];
    out[0] = b'S';
    out[1] = b'=';
    for (i, byte) in digest2.iter().enumerate() {
        out[2 + i * 2] = HEX_UPPER[(byte >> 4) as usize];
        out[2 + i * 2 + 1] = HEX_UPPER[(byte & 0x0f) as usize];
    }
    out
}

/// Inputs shared between v2 verification and the `AuthenticatorResponse`
/// computation. Borrows the username from the underlying packet buffer.
struct V2Inputs<'a> {
    auth_challenge: [u8; 16],
    peer_challenge: [u8; 16],
    nt_response: [u8; 24],
    username: &'a [u8],
}

fn decode_v2_inputs<'a>(request: &Request<'a>) -> Result<Option<V2Inputs<'a>>, AttributeError> {
    let Some(challenge) = first_ms_vsa(request, VT_MS_CHAP_CHALLENGE)? else {
        return Ok(None);
    };
    let Some(response) = first_ms_vsa(request, VT_MS_CHAP2_RESPONSE)? else {
        return Ok(None);
    };
    if challenge.len() != MS_CHAP_V2_CHALLENGE_LEN || response.len() != MS_CHAP2_RESPONSE_LEN {
        return Ok(None);
    }
    let Some(username_attr) = request.first_raw(USER_NAME_TYPE)? else {
        return Ok(None);
    };

    let mut auth_challenge = [0u8; 16];
    auth_challenge.copy_from_slice(challenge);
    let mut peer_challenge = [0u8; 16];
    peer_challenge.copy_from_slice(
        &response[MS_CHAP2_RESPONSE_PEER_OFFSET..MS_CHAP2_RESPONSE_PEER_OFFSET + 16],
    );
    let mut nt_response = [0u8; 24];
    nt_response.copy_from_slice(&response[MS_CHAP2_RESPONSE_NT_OFFSET..MS_CHAP2_RESPONSE_LEN]);

    Ok(Some(V2Inputs {
        auth_challenge,
        peer_challenge,
        nt_response,
        username: strip_domain(username_attr.value()),
    }))
}

/// `ChallengeResponse` (RFC 2759 §8.5): zero-pad the 16-byte hash to
/// 21 bytes, slice into three 7-byte DES keys, and ECB-encrypt the
/// 8-byte challenge with each.
fn challenge_response(challenge: [u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut zpad = [0u8; 21];
    zpad[..16].copy_from_slice(password_hash);

    let mut out = [0u8; 24];
    for i in 0..3 {
        let mut key = [0u8; 7];
        key.copy_from_slice(&zpad[i * 7..i * 7 + 7]);
        let block = DesKey::from_56bits(&key).ecb_encrypt(&challenge);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
        cleanse(&mut key);
    }
    cleanse(&mut zpad);
    out
}

/// `ChallengeHash` (RFC 2759 §8.2): SHA-1 over the peer challenge,
/// authenticator challenge, and username; the first 8 bytes of the
/// digest are the 8-byte challenge fed into `ChallengeResponse`.
fn challenge_hash(
    peer_challenge: &[u8; 16],
    auth_challenge: &[u8; 16],
    username: &[u8],
) -> [u8; 8] {
    let mut ctx = Sha1::new();
    ctx.update(peer_challenge);
    ctx.update(auth_challenge);
    ctx.update(username);
    let digest = ctx.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Strip an optional `DOMAIN\` prefix from a User-Name. RFC 2759 §8.2
/// specifies that the username fed to `ChallengeHash` is "the username
/// (without any Windows NT domain prefix)".
fn strip_domain(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'\\') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Locate the inner data slice of the first Microsoft VSA carrying the
/// given per-vendor type. Returns `Ok(None)` if no such VSA is present;
/// returns `Err` if the attribute list is malformed before one could be
/// located.
fn first_ms_vsa<'a>(
    request: &Request<'a>,
    vendor_type: u8,
) -> Result<Option<&'a [u8]>, AttributeError> {
    for slot in request.attributes_iter() {
        let raw = slot?;
        if raw.attribute_type() != VSA_TYPE {
            continue;
        }
        let val = raw.value();
        let Some((pen, rest)) = val.split_first_chunk::<4>() else {
            continue;
        };
        if u32::from_be_bytes(*pen) != MS_VENDOR_ID {
            continue;
        }
        let Some((header, data)) = rest.split_first_chunk::<2>() else {
            continue;
        };
        let [v_type, v_len] = *header;
        if v_type != vendor_type {
            continue;
        }
        let Some(data_len) = (v_len as usize).checked_sub(2) else {
            continue;
        };
        let Some(inner) = data.get(..data_len) else {
            continue;
        };
        return Ok(Some(inner));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::header::Code;
    use crate::server::Client;
    use std::sync::Arc;

    // RFC 2759 §9.2 trace ----------------------------------------------------
    const USER_NAME: &[u8] = b"User";
    const PASSWORD: &str = "clientPass";
    const AUTH_CHALLENGE: [u8; 16] = [
        0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26,
        0x28,
    ];
    const PEER_CHALLENGE: [u8; 16] = [
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C,
        0x7E,
    ];
    const PASSWORD_HASH: [u8; 16] = [
        0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6, 0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89,
        0xAE,
    ];
    const NT_RESPONSE: [u8; 24] = [
        0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E, 0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83,
        0x54, 0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
    ];
    const AUTH_RESPONSE: &[u8; 42] = b"S=407A5589115FD0D6209F510FE9C04566932CDA56";

    const REQ_AUTH: [u8; 16] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
        0x00,
    ];

    fn make_request<'a>(client: &'a Arc<Client>, attrs: &'a [u8]) -> Request<'a> {
        Request::new(
            Code::ACCESS_REQUEST,
            9,
            REQ_AUTH,
            attrs,
            client,
            "127.0.0.1:1812".parse().unwrap(),
        )
    }

    /// `type || length || value`.
    fn attr(typ: u8, val: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + val.len());
        v.push(typ);
        #[allow(clippy::cast_possible_truncation)]
        v.push((val.len() + 2) as u8);
        v.extend_from_slice(val);
        v
    }

    /// Wrap a Microsoft VSA payload in the type-26 / vendor-311 envelope.
    fn ms_vsa(vendor_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut inner = Vec::with_capacity(6 + payload.len());
        inner.extend_from_slice(&MS_VENDOR_ID.to_be_bytes());
        inner.push(vendor_type);
        #[allow(clippy::cast_possible_truncation)]
        inner.push((payload.len() + 2) as u8);
        inner.extend_from_slice(payload);
        attr(VSA_TYPE, &inner)
    }

    fn build_v2_response_field() -> [u8; 50] {
        let mut buf = [0u8; 50];
        buf[0] = 0x00; // ident
        buf[1] = 0x00; // flags
        buf[MS_CHAP2_RESPONSE_PEER_OFFSET..MS_CHAP2_RESPONSE_PEER_OFFSET + 16]
            .copy_from_slice(&PEER_CHALLENGE);
        // reserved (8) stays zero
        buf[MS_CHAP2_RESPONSE_NT_OFFSET..].copy_from_slice(&NT_RESPONSE);
        buf
    }

    #[test]
    fn nt_password_hash_rfc2759() {
        assert_eq!(nt_password_hash(PASSWORD), PASSWORD_HASH);
    }

    #[test]
    fn challenge_hash_rfc2759() {
        let challenge = challenge_hash(&PEER_CHALLENGE, &AUTH_CHALLENGE, USER_NAME);
        assert_eq!(challenge, [0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26]);
    }

    #[test]
    fn challenge_response_rfc2759() {
        let challenge = [0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26];
        assert_eq!(challenge_response(challenge, &PASSWORD_HASH), NT_RESPONSE);
    }

    #[test]
    fn strip_domain_keeps_bare_username() {
        assert_eq!(strip_domain(b"alice"), b"alice");
    }

    #[test]
    fn strip_domain_removes_prefix() {
        assert_eq!(strip_domain(b"CORP\\alice"), b"alice");
    }

    // ---- v2 -----------------------------------------------------------------

    fn build_v2_attrs() -> Vec<u8> {
        let mut attrs = attr(USER_NAME_TYPE, USER_NAME);
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP_CHALLENGE, &AUTH_CHALLENGE));
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP2_RESPONSE, &build_v2_response_field()));
        attrs
    }

    #[test]
    fn v2_match_with_cleartext_secret() {
        let attrs = build_v2_attrs();
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Match,
        );
    }

    #[test]
    fn v2_match_with_nt_hash_secret() {
        let attrs = build_v2_attrs();
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::NtHash(&PASSWORD_HASH)).unwrap(),
            VerifyOutcome::Match,
        );
    }

    #[test]
    fn v2_mismatch_on_wrong_password() {
        let attrs = build_v2_attrs();
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::Cleartext("wrong")).unwrap(),
            VerifyOutcome::Mismatch,
        );
    }

    #[test]
    fn v2_missing_when_no_vsas() {
        let attrs = attr(USER_NAME_TYPE, USER_NAME);
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Missing,
        );
    }

    #[test]
    fn v2_missing_when_no_username() {
        let mut attrs = ms_vsa(VT_MS_CHAP_CHALLENGE, &AUTH_CHALLENGE);
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP2_RESPONSE, &build_v2_response_field()));
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Missing,
        );
    }

    #[test]
    fn v2_strips_domain_prefix_in_username() {
        let mut attrs = attr(USER_NAME_TYPE, b"CORP\\User");
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP_CHALLENGE, &AUTH_CHALLENGE));
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP2_RESPONSE, &build_v2_response_field()));
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v2(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Match,
        );
    }

    #[test]
    fn v2_authenticator_response_rfc2759() {
        let attrs = build_v2_attrs();
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        let got = v2_success_response(&req, MsChapSecret::Cleartext(PASSWORD))
            .unwrap()
            .expect("inputs present");
        assert_eq!(&got, AUTH_RESPONSE);
    }

    // ---- v1 -----------------------------------------------------------------
    //
    // RFC 2759 publishes a complete v2 trace but no v1 trace. We
    // construct the v1 NT-Response by running ChallengeResponse against
    // an arbitrary 8-byte challenge and the RFC 2759 PasswordHash, then
    // wrap it on the wire and verify the round-trip.

    const V1_CHALLENGE: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];

    fn build_v1_response_field(nt_resp: &[u8; 24]) -> [u8; 50] {
        let mut buf = [0u8; 50];
        buf[0] = 0x42; // ident
        buf[1] = 0x01; // Use-NT flag
                       // LM-Response (24) left zero — intentionally ignored.
        buf[MS_CHAP_RESPONSE_NT_OFFSET..MS_CHAP_RESPONSE_LEN].copy_from_slice(nt_resp);
        buf
    }

    #[test]
    fn v1_round_trip_match() {
        let nt_resp = challenge_response(V1_CHALLENGE, &PASSWORD_HASH);
        let mut attrs = ms_vsa(VT_MS_CHAP_CHALLENGE, &V1_CHALLENGE);
        attrs.extend_from_slice(&ms_vsa(
            VT_MS_CHAP_RESPONSE,
            &build_v1_response_field(&nt_resp),
        ));
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v1(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Match,
        );
    }

    #[test]
    fn v1_mismatch_on_wrong_password() {
        let nt_resp = challenge_response(V1_CHALLENGE, &PASSWORD_HASH);
        let mut attrs = ms_vsa(VT_MS_CHAP_CHALLENGE, &V1_CHALLENGE);
        attrs.extend_from_slice(&ms_vsa(
            VT_MS_CHAP_RESPONSE,
            &build_v1_response_field(&nt_resp),
        ));
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v1(&req, MsChapSecret::Cleartext("wrong")).unwrap(),
            VerifyOutcome::Mismatch,
        );
    }

    #[test]
    fn v1_missing_when_no_vsas() {
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &[]);
        assert_eq!(
            verify_v1(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Missing,
        );
    }

    #[test]
    fn v1_malformed_challenge_length() {
        let mut attrs = ms_vsa(VT_MS_CHAP_CHALLENGE, &[0u8; 7]); // wrong: must be 8
        attrs.extend_from_slice(&ms_vsa(
            VT_MS_CHAP_RESPONSE,
            &build_v1_response_field(&[0u8; 24]),
        ));
        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        assert_eq!(
            verify_v1(&req, MsChapSecret::Cleartext(PASSWORD)).unwrap(),
            VerifyOutcome::Malformed,
        );
    }

    #[test]
    fn first_ms_vsa_skips_other_vendors() {
        // Build a non-Microsoft VSA followed by a Microsoft challenge.
        let mut other = Vec::new();
        other.extend_from_slice(&9u32.to_be_bytes()); // Cisco PEN
        other.push(1);
        other.push(2 + 4); // length
        other.extend_from_slice(b"abcd");
        let mut attrs = attr(VSA_TYPE, &other);
        attrs.extend_from_slice(&ms_vsa(VT_MS_CHAP_CHALLENGE, &AUTH_CHALLENGE));

        let client = Arc::new(Client::new(b"unused".as_slice()));
        let req = make_request(&client, &attrs);
        let found = first_ms_vsa(&req, VT_MS_CHAP_CHALLENGE).unwrap().unwrap();
        assert_eq!(found, &AUTH_CHALLENGE);
    }
}
