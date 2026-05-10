//! Sensible-defaults PKI helpers for RadSec onboarding.
//!
//! RadSec (RFC 6614) demands a working mTLS PKI before the protocol
//! does anything useful: a CA, a server certificate, and one client
//! certificate per NAS. Setting that up correctly with `openssl`
//! one-liners is a known source of friction. This module wraps the
//! `aws-lc-sys` libcrypto surface to spin up an X.509 PKI with
//! defaults that satisfy RFC 6614 §2.3 and the relevant CABF /
//! RFC 5280 hygiene rules out of the box.
//!
//! # Scope
//!
//! Deliberately small. The module does **not** aspire to be a
//! general-purpose PKI library — there is no CSR support, no CRL,
//! no OCSP, no encrypted-key PEM, no custom extensions. What it
//! does is:
//!
//! * Generate ECDSA P-256 (default) or RSA-2048 private keys.
//! * Build a self-signed CA certificate.
//! * Issue server and client leaf certificates with the right
//!   key-usage / extended-key-usage / SAN baggage for RadSec.
//! * Round-trip everything through PEM (PKCS#8 for keys).
//!
//! Anything beyond that is the consumer's PKI's problem.
//!
//! # Defaults (and why)
//!
//! | Setting | Default | Reason |
//! |---|---|---|
//! | Key algorithm | ECDSA P-256 | Smaller, faster, RFC 8422; widely supported by NAS firmware. |
//! | Signature digest | SHA-256 | RFC 5280 baseline; SHA-1 is dead. |
//! | Serial | 128-bit `BN_rand` | RFC 5280 §4.1.2.2 unpredictability. |
//! | CA validity | 10 years | Long enough not to require frequent rotation; short enough to bound damage. |
//! | Leaf validity | 2 years | Pragmatic for private mTLS; CABF 397-day rules don't apply off the WebPKI. |
//! | Server EKU | serverAuth | RFC 6614 §2.3. |
//! | Client EKU | clientAuth | RFC 6614 §2.3. |
//! | Server KU | digitalSignature, keyEncipherment | TLS 1.2 cipher suites need both. |
//! | Client KU | digitalSignature | mTLS client auth signs the handshake transcript. |
//! | SubjectKeyIdentifier | hash of SPKI | RFC 5280 §4.2.1.2. |
//! | AuthorityKeyIdentifier | issuer's SKI | RFC 5280 §4.2.1.1. |
//! | SAN | mandatory for leaves | RFC 6614 §2.3; CABF; modern verifiers require SAN. |
//! | BasicConstraints (CA) | `CA:TRUE` | RFC 5280 §4.2.1.9. |
//! | BasicConstraints (leaf) | `CA:FALSE` | RFC 5280 §4.2.1.9. |
//!
//! # Example
//!
//! ```no_run
//! use radius_tokio::pki::{CertificateAuthority, SubjectAltName};
//! use std::net::IpAddr;
//!
//! // 1. Spin up a private CA.
//! let ca = CertificateAuthority::new("RadSec Root").unwrap();
//!
//! // 2. Issue the server cert your RadSec listener will present.
//! let server = ca
//!     .issue_server(
//!         "radsec.example.com",
//!         &[SubjectAltName::Dns("radsec.example.com".into())],
//!     )
//!     .unwrap();
//!
//! // 3. Issue a client cert per NAS.
//! let nas = ca
//!     .issue_client(
//!         "nas-1",
//!         &[SubjectAltName::Ip("10.0.0.5".parse::<IpAddr>().unwrap())],
//!     )
//!     .unwrap();
//!
//! // Now feed `server.chain_pem` + `server.key_pem` to the
//! // listener's TlsContext, and ship `nas.chain_pem` + `nas.key_pem`
//! // (plus `ca.cert_pem()`) to the NAS.
//! ```

#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::ffi::{c_int, c_long, c_void, CString};
use std::net::IpAddr;
use std::ptr::NonNull;

use aws_lc_sys::{
    ASN1_INTEGER_free, BIO_new, BIO_read, BIO_s_mem, BN_free, BN_new, BN_rand, BN_to_ASN1_INTEGER,
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
    EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_keygen, EVP_PKEY_keygen_init, EVP_sha256,
    NID_X9_62_prime256v1, NID_authority_key_identifier, NID_basic_constraints, NID_ext_key_usage,
    NID_key_usage, NID_secp384r1, NID_subject_alt_name, NID_subject_key_identifier,
    PEM_write_bio_PKCS8PrivateKey, PEM_write_bio_X509, X509V3_EXT_conf_nid, X509V3_set_ctx,
    X509_EXTENSION_free, X509_NAME_add_entry_by_txt, X509_NAME_free, X509_NAME_new, X509_add_ext,
    X509_gmtime_adj, X509_new, X509_set_issuer_name, X509_set_pubkey, X509_set_serialNumber,
    X509_set_subject_name, X509_set_version, X509_sign, ASN1_INTEGER, BIGNUM, EVP_PKEY_CTX,
    EVP_PKEY_EC, EVP_PKEY_RSA, MBSTRING_UTF8, X509V3_CTX, X509_NAME,
};

use super::tls::{pop_err, BioOwned, EvpPkeyOwned, TlsError, X509Owned};

// ============================================================================
// Public types
// ============================================================================

/// Asymmetric key algorithm choice for [`PrivateKey::generate`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA over the P-256 curve. Default; small, fast, RFC 8422.
    #[default]
    EcdsaP256,
    /// ECDSA over the P-384 curve.
    EcdsaP384,
    /// RSA with a 2048-bit modulus. Use only if a NAS doesn't speak ECDSA.
    Rsa2048,
    /// RSA with a 3072-bit modulus.
    Rsa3072,
}

/// Subject Alternative Name entry. RFC 6614 leaves don't validate
/// without one; the issuer functions reject empty SAN lists.
#[derive(Debug, Clone)]
pub enum SubjectAltName {
    /// `dNSName` SAN.
    Dns(String),
    /// `iPAddress` SAN.
    Ip(IpAddr),
}

/// An asymmetric private key with its associated public key.
pub struct PrivateKey {
    pkey: EvpPkeyOwned,
}

// SAFETY: After construction the `EVP_PKEY` is read-only — we never
// hand out `&mut` access and aws-lc tolerates concurrent reads.
unsafe impl Send for PrivateKey {}
// SAFETY: see above.
unsafe impl Sync for PrivateKey {}

/// An X.509 certificate.
pub struct Certificate {
    cert: X509Owned,
}

// SAFETY: After construction the `X509` is read-only.
unsafe impl Send for Certificate {}
// SAFETY: see above.
unsafe impl Sync for Certificate {}

/// A leaf certificate as issued by a [`CertificateAuthority`],
/// bundled with everything needed to ship it to a peer.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    /// PEM-encoded leaf certificate.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded chain: leaf followed by issuer CA. This is what
    /// you feed to `TlsContext::server_chain_pem` and what RFC 6614
    /// peers expect on the wire.
    pub chain_pem: Vec<u8>,
    /// PKCS#8-encoded PEM private key. Unencrypted.
    pub key_pem: Vec<u8>,
}

/// A self-signed certificate authority and its private key.
///
/// Hold on to this for the lifetime of your private PKI; it's the
/// only thing that can issue or revoke certs against the trust
/// anchor it represents.
pub struct CertificateAuthority {
    cert: Certificate,
    key: PrivateKey,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

// ============================================================================
// PrivateKey
// ============================================================================

impl PrivateKey {
    /// Generate a fresh private key.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if the underlying `EVP_PKEY_keygen`
    /// pipeline fails (entropy source error, OOM, …).
    pub fn generate(alg: KeyAlgorithm) -> Result<Self, TlsError> {
        let (id, set_param): (c_int, fn(*mut EVP_PKEY_CTX) -> c_int) = match alg {
            KeyAlgorithm::EcdsaP256 => (EVP_PKEY_EC, |ctx| {
                // SAFETY: ctx is a freshly-initialized keygen context.
                unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) }
            }),
            KeyAlgorithm::EcdsaP384 => (EVP_PKEY_EC, |ctx| {
                // SAFETY: ctx is a freshly-initialized keygen context.
                unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) }
            }),
            KeyAlgorithm::Rsa2048 => (EVP_PKEY_RSA, |ctx| {
                // SAFETY: ctx is a freshly-initialized keygen context.
                unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) }
            }),
            KeyAlgorithm::Rsa3072 => (EVP_PKEY_RSA, |ctx| {
                // SAFETY: ctx is a freshly-initialized keygen context.
                unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) }
            }),
        };

        // SAFETY: id is a valid EVP_PKEY type id; engine is NULL.
        let ctx_raw = unsafe { EVP_PKEY_CTX_new_id(id, std::ptr::null_mut()) };
        let ctx =
            EvpPkeyCtxOwned(NonNull::new(ctx_raw).ok_or(TlsError::Init("EVP_PKEY_CTX_new_id"))?);

        // SAFETY: ctx valid; init returns 1 on success.
        if unsafe { EVP_PKEY_keygen_init(ctx.0.as_ptr()) } != 1 {
            return Err(TlsError::Ssl(pop_err("EVP_PKEY_keygen_init")));
        }
        if set_param(ctx.0.as_ptr()) != 1 {
            return Err(TlsError::Ssl(pop_err("EVP_PKEY_CTX_set_*")));
        }

        let mut pkey_raw: *mut aws_lc_sys::EVP_PKEY = std::ptr::null_mut();
        // SAFETY: ctx valid; out-param is a stack slot we own.
        if unsafe { EVP_PKEY_keygen(ctx.0.as_ptr(), &mut pkey_raw) } != 1 {
            return Err(TlsError::Ssl(pop_err("EVP_PKEY_keygen")));
        }
        let pkey = EvpPkeyOwned(
            NonNull::new(pkey_raw).ok_or(TlsError::Ssl("EVP_PKEY_keygen returned NULL".into()))?,
        );
        Ok(Self { pkey })
    }

    /// Parse an unencrypted PEM-encoded private key (PKCS#8 or
    /// algorithm-specific PEM).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Pem`] if the input is not a valid
    /// private-key PEM block.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let bio = new_mem_bio_readonly(pem)?;
        // SAFETY: bio valid; NULL out-param / cb / userdata are
        // documented as legal for unencrypted keys.
        let raw = unsafe {
            aws_lc_sys::PEM_read_bio_PrivateKey(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        drop(bio);
        let pkey = EvpPkeyOwned(NonNull::new(raw).ok_or(TlsError::Pem("private key"))?);
        Ok(Self { pkey })
    }

    /// Encode this key as unencrypted PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if `PEM_write_bio_PKCS8PrivateKey` fails.
    pub fn to_pem_pkcs8(&self) -> Result<Vec<u8>, TlsError> {
        let bio = new_mem_bio()?;
        // SAFETY: bio valid; remaining args choose the unencrypted
        // PKCS#8 encoding path: enc = NULL, pass = NULL, pass_len = 0,
        // cb = None, userdata = NULL.
        let r = unsafe {
            PEM_write_bio_PKCS8PrivateKey(
                bio.0.as_ptr(),
                self.pkey.0.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                None,
                std::ptr::null_mut(),
            )
        };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("PEM_write_bio_PKCS8PrivateKey")));
        }
        Ok(bio_drain(&bio))
    }
}

// ============================================================================
// Certificate
// ============================================================================

impl Certificate {
    /// Parse a PEM-encoded X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Pem`] if the input is not a single valid
    /// certificate PEM block.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let bio = new_mem_bio_readonly(pem)?;
        // SAFETY: bio valid; remaining args may be NULL.
        let raw = unsafe {
            aws_lc_sys::PEM_read_bio_X509(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        drop(bio);
        let cert = X509Owned(NonNull::new(raw).ok_or(TlsError::Pem("certificate"))?);
        Ok(Self { cert })
    }

    /// Encode this certificate as PEM.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if `PEM_write_bio_X509` fails.
    pub fn to_pem(&self) -> Result<Vec<u8>, TlsError> {
        let bio = new_mem_bio()?;
        // SAFETY: bio and cert pointers valid; PEM_write_bio_X509
        // returns 1 on success.
        let r = unsafe { PEM_write_bio_X509(bio.0.as_ptr(), self.cert.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("PEM_write_bio_X509")));
        }
        Ok(bio_drain(&bio))
    }
}

// ============================================================================
// CertificateAuthority
// ============================================================================

/// Default CA validity: 10 years.
const CA_VALIDITY_SECS: c_long = 10 * 365 * 24 * 60 * 60;
/// Default leaf validity: 2 years.
const LEAF_VALIDITY_SECS: c_long = 2 * 365 * 24 * 60 * 60;

impl CertificateAuthority {
    /// Generate a fresh ECDSA P-256 key and build a self-signed CA
    /// certificate with `common_name` as both Subject and Issuer DN.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] on key-generation or signing failure.
    pub fn new(common_name: &str) -> Result<Self, TlsError> {
        Self::with_key(common_name, PrivateKey::generate(KeyAlgorithm::default())?)
    }

    /// As [`Self::new`] but takes a caller-supplied private key.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] on signing failure.
    pub fn with_key(common_name: &str, key: PrivateKey) -> Result<Self, TlsError> {
        let cert = build_cert(&BuildSpec {
            subject_cn: common_name,
            subject_key: &key,
            issuer_cn: common_name,
            issuer_key: &key,
            issuer_cert: None,
            validity_secs: CA_VALIDITY_SECS,
            profile: Profile::Ca,
            sans: &[],
        })?;
        let cert_pem = cert.to_pem()?;
        let key_pem = key.to_pem_pkcs8()?;
        Ok(Self {
            cert,
            key,
            cert_pem,
            key_pem,
        })
    }

    /// Load a previously-issued CA cert + key from PEM.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Pem`] if either input fails to parse.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        let cert = Certificate::from_pem(cert_pem)?;
        let key = PrivateKey::from_pem(key_pem)?;
        Ok(Self {
            cert,
            key,
            cert_pem: cert_pem.to_vec(),
            key_pem: key_pem.to_vec(),
        })
    }

    /// PEM-encoded CA certificate. This is the trust anchor you
    /// distribute to peers as the `client_ca_pem` argument to
    /// `TlsContext`.
    #[must_use]
    pub fn cert_pem(&self) -> &[u8] {
        &self.cert_pem
    }

    /// PEM-encoded CA private key (unencrypted PKCS#8). Keep secret.
    #[must_use]
    pub fn key_pem(&self) -> &[u8] {
        &self.key_pem
    }

    /// Issue a server certificate (EKU `serverAuth`, KU
    /// `digitalSignature + keyEncipherment`) suitable for a RadSec
    /// listener.
    ///
    /// `sans` MUST be non-empty. Modern TLS verifiers ignore the
    /// CN and require at least one SAN entry; this function
    /// rejects an empty list rather than letting a broken cert
    /// ship.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Pem`] if `sans` is empty, or
    /// [`TlsError::Ssl`] on signing failure.
    pub fn issue_server(
        &self,
        common_name: &str,
        sans: &[SubjectAltName],
    ) -> Result<IssuedCertificate, TlsError> {
        self.issue(common_name, sans, Profile::Server)
    }

    /// Issue a client certificate (EKU `clientAuth`, KU
    /// `digitalSignature`) for a RadSec NAS.
    ///
    /// # Errors
    ///
    /// As [`Self::issue_server`].
    pub fn issue_client(
        &self,
        common_name: &str,
        sans: &[SubjectAltName],
    ) -> Result<IssuedCertificate, TlsError> {
        self.issue(common_name, sans, Profile::Client)
    }

    fn issue(
        &self,
        common_name: &str,
        sans: &[SubjectAltName],
        profile: Profile,
    ) -> Result<IssuedCertificate, TlsError> {
        if sans.is_empty() {
            return Err(TlsError::Pem("leaf certificate requires at least one SAN"));
        }
        let key = PrivateKey::generate(KeyAlgorithm::default())?;
        let cert = build_cert(&BuildSpec {
            subject_cn: common_name,
            subject_key: &key,
            issuer_cn: cn_of(&self.cert)?.as_str(),
            issuer_key: &self.key,
            issuer_cert: Some(&self.cert),
            validity_secs: LEAF_VALIDITY_SECS,
            profile,
            sans,
        })?;
        let cert_pem = cert.to_pem()?;
        let key_pem = key.to_pem_pkcs8()?;
        let mut chain_pem = cert_pem.clone();
        chain_pem.extend_from_slice(&self.cert_pem);
        Ok(IssuedCertificate {
            cert_pem,
            chain_pem,
            key_pem,
        })
    }
}

// ============================================================================
// Certificate builder (private)
// ============================================================================

#[derive(Clone, Copy)]
enum Profile {
    Ca,
    Server,
    Client,
}

struct BuildSpec<'a> {
    subject_cn: &'a str,
    subject_key: &'a PrivateKey,
    issuer_cn: &'a str,
    issuer_key: &'a PrivateKey,
    /// `None` for a self-signed CA; `Some(&ca.cert)` for a leaf.
    issuer_cert: Option<&'a Certificate>,
    validity_secs: c_long,
    profile: Profile,
    sans: &'a [SubjectAltName],
}

fn build_cert(spec: &BuildSpec<'_>) -> Result<Certificate, TlsError> {
    // SAFETY: X509_new allocates; NULL on OOM.
    let cert_raw = unsafe { X509_new() };
    let cert = X509Owned(NonNull::new(cert_raw).ok_or(TlsError::Init("X509_new"))?);

    // Version 3 (encoded as 2 in the wire format).
    // SAFETY: cert valid.
    if unsafe { X509_set_version(cert.0.as_ptr(), 2) } != 1 {
        return Err(TlsError::Ssl(pop_err("X509_set_version")));
    }

    // Random 128-bit serial. RFC 5280 §4.1.2.2 wants unpredictability;
    // CABF baselines mandate >= 64 bits of entropy. 128 is the
    // standard belt-and-braces value.
    set_random_serial(&cert)?;

    // Validity.
    // SAFETY: cert valid; X509_get_notBefore/notAfter return interior
    // pointers; X509_gmtime_adj returns the same pointer or NULL.
    unsafe {
        let nb = aws_lc_sys::X509_getm_notBefore(cert.0.as_ptr());
        if X509_gmtime_adj(nb, 0).is_null() {
            return Err(TlsError::Ssl(pop_err("X509_gmtime_adj notBefore")));
        }
        let na = aws_lc_sys::X509_getm_notAfter(cert.0.as_ptr());
        if X509_gmtime_adj(na, spec.validity_secs).is_null() {
            return Err(TlsError::Ssl(pop_err("X509_gmtime_adj notAfter")));
        }
    }

    // Subject and issuer DNs.
    let subject_name = build_name(spec.subject_cn)?;
    // SAFETY: both pointers valid; X509_set_subject_name copies internally.
    if unsafe { X509_set_subject_name(cert.0.as_ptr(), subject_name.0.as_ptr()) } != 1 {
        return Err(TlsError::Ssl(pop_err("X509_set_subject_name")));
    }
    drop(subject_name);

    let issuer_name = build_name(spec.issuer_cn)?;
    // SAFETY: both pointers valid; X509_set_issuer_name copies internally.
    if unsafe { X509_set_issuer_name(cert.0.as_ptr(), issuer_name.0.as_ptr()) } != 1 {
        return Err(TlsError::Ssl(pop_err("X509_set_issuer_name")));
    }
    drop(issuer_name);

    // Subject public key.
    // SAFETY: both pointers valid; X509_set_pubkey bumps the EVP_PKEY refcount.
    if unsafe { X509_set_pubkey(cert.0.as_ptr(), spec.subject_key.pkey.0.as_ptr()) } != 1 {
        return Err(TlsError::Ssl(pop_err("X509_set_pubkey")));
    }

    // Extensions. We set up a v3 ctx so SKI / AKI can reference the
    // issuer cert (for self-signed leaves the issuer == subject).
    let issuer_for_ctx = spec
        .issuer_cert
        .map_or(cert.0.as_ptr(), |c| c.cert.0.as_ptr());
    let mut v3ctx: V3CtxStorage = V3CtxStorage::new();
    // SAFETY: v3ctx is a stack-allocated zero-initialized
    // X509V3_CTX; X509V3_set_ctx populates the issuer/subject
    // pointers it needs and never takes ownership.
    unsafe {
        X509V3_set_ctx(
            v3ctx.as_mut_ptr(),
            issuer_for_ctx,
            cert.0.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
    }

    add_extensions(&cert, v3ctx.as_mut_ptr(), spec.profile, spec.sans)?;

    // Sign with the issuer's key under SHA-256.
    // SAFETY: cert and key valid; EVP_sha256 returns a static md ptr.
    let sig_len = unsafe {
        X509_sign(
            cert.0.as_ptr(),
            spec.issuer_key.pkey.0.as_ptr(),
            EVP_sha256(),
        )
    };
    if sig_len <= 0 {
        return Err(TlsError::Ssl(pop_err("X509_sign")));
    }

    Ok(Certificate { cert })
}

fn set_random_serial(cert: &X509Owned) -> Result<(), TlsError> {
    // SAFETY: BN_new returns NULL on OOM.
    let bn_raw = unsafe { BN_new() };
    let bn = BignumOwned(NonNull::new(bn_raw).ok_or(TlsError::Init("BN_new"))?);
    // BN_rand: 128 bits, top bit unset (top = -1), no constraints on
    // the bottom (bottom = 0). The top = -1 form keeps the high bit
    // free so the encoded ASN.1 INTEGER stays positive.
    // SAFETY: bn valid.
    if unsafe { BN_rand(bn.0.as_ptr(), 128, -1, 0) } != 1 {
        return Err(TlsError::Ssl(pop_err("BN_rand")));
    }
    // SAFETY: bn valid; ai = NULL means BN_to_ASN1_INTEGER allocates.
    let ai_raw = unsafe { BN_to_ASN1_INTEGER(bn.0.as_ptr(), std::ptr::null_mut()) };
    let ai =
        Asn1IntegerOwned(NonNull::new(ai_raw).ok_or(TlsError::Ssl(pop_err("BN_to_ASN1_INTEGER")))?);
    // SAFETY: cert and ai valid; X509_set_serialNumber copies the integer.
    if unsafe { X509_set_serialNumber(cert.0.as_ptr(), ai.0.as_ptr()) } != 1 {
        return Err(TlsError::Ssl(pop_err("X509_set_serialNumber")));
    }
    Ok(())
}

fn build_name(cn: &str) -> Result<X509NameOwned, TlsError> {
    // SAFETY: X509_NAME_new allocates; NULL on OOM.
    let raw = unsafe { X509_NAME_new() };
    let name = X509NameOwned(NonNull::new(raw).ok_or(TlsError::Init("X509_NAME_new"))?);
    let cn_field = CString::new("CN").expect("static literal");
    // SAFETY: name valid; bytes is a non-NUL UTF-8 slice with explicit length.
    let r = unsafe {
        X509_NAME_add_entry_by_txt(
            name.0.as_ptr(),
            cn_field.as_ptr(),
            MBSTRING_UTF8,
            cn.as_ptr(),
            isize::try_from(cn.len()).map_err(|_| TlsError::Pem("CN too long"))?,
            -1,
            0,
        )
    };
    if r != 1 {
        return Err(TlsError::Ssl(pop_err("X509_NAME_add_entry_by_txt")));
    }
    Ok(name)
}

fn add_extensions(
    cert: &X509Owned,
    v3ctx: *mut X509V3_CTX,
    profile: Profile,
    sans: &[SubjectAltName],
) -> Result<(), TlsError> {
    let (bc, ku, eku_opt): (&str, &str, Option<&str>) = match profile {
        Profile::Ca => ("critical,CA:TRUE", "critical,keyCertSign,cRLSign", None),
        Profile::Server => (
            "critical,CA:FALSE",
            "critical,digitalSignature,keyEncipherment",
            Some("serverAuth"),
        ),
        Profile::Client => (
            "critical,CA:FALSE",
            "critical,digitalSignature",
            Some("clientAuth"),
        ),
    };

    add_ext_by_nid(cert, v3ctx, NID_basic_constraints, bc)?;
    add_ext_by_nid(cert, v3ctx, NID_key_usage, ku)?;
    if let Some(eku) = eku_opt {
        add_ext_by_nid(cert, v3ctx, NID_ext_key_usage, eku)?;
    }

    if !sans.is_empty() {
        let san_str = encode_sans(sans);
        add_ext_by_nid(cert, v3ctx, NID_subject_alt_name, &san_str)?;
    }

    add_ext_by_nid(cert, v3ctx, NID_subject_key_identifier, "hash")?;
    // AKI references the issuer's SKI. For a self-signed CA the
    // issuer == subject, so "keyid:always" still produces a valid
    // (and useful) AKI.
    add_ext_by_nid(cert, v3ctx, NID_authority_key_identifier, "keyid:always")?;
    Ok(())
}

fn add_ext_by_nid(
    cert: &X509Owned,
    v3ctx: *mut X509V3_CTX,
    nid: c_int,
    value: &str,
) -> Result<(), TlsError> {
    let cvalue = CString::new(value).map_err(|_| TlsError::Pem("interior NUL in extension"))?;
    // SAFETY: v3ctx populated by build_cert; conf = NULL is the
    // documented "no openssl.conf" path; cvalue is a valid C string
    // that lives until after the call.
    let ext_raw = unsafe { X509V3_EXT_conf_nid(std::ptr::null_mut(), v3ctx, nid, cvalue.as_ptr()) };
    if ext_raw.is_null() {
        return Err(TlsError::Ssl(pop_err("X509V3_EXT_conf_nid")));
    }
    // SAFETY: cert and ext valid; X509_add_ext copies the extension
    // (loc = -1 appends).
    let r = unsafe { X509_add_ext(cert.0.as_ptr(), ext_raw, -1) };
    // SAFETY: ext_raw was allocated by X509V3_EXT_conf_nid and
    // X509_add_ext does not take ownership.
    unsafe { X509_EXTENSION_free(ext_raw) };
    if r != 1 {
        return Err(TlsError::Ssl(pop_err("X509_add_ext")));
    }
    Ok(())
}

fn encode_sans(sans: &[SubjectAltName]) -> String {
    let mut parts = Vec::with_capacity(sans.len());
    for san in sans {
        match san {
            SubjectAltName::Dns(d) => parts.push(format!("DNS:{d}")),
            SubjectAltName::Ip(ip) => parts.push(format!("IP:{ip}")),
        }
    }
    parts.join(",")
}

fn cn_of(cert: &Certificate) -> Result<String, TlsError> {
    // SAFETY: cert valid; X509_get_subject_name returns interior ptr.
    let name = unsafe { aws_lc_sys::X509_get_subject_name(cert.cert.0.as_ptr()) };
    if name.is_null() {
        return Err(TlsError::Ssl("CA has no subject DN".into()));
    }
    let mut buf = [0u8; 256];
    // SAFETY: buf valid; X509_NAME_get_text_by_NID writes a NUL-terminated
    // UTF-8 string into buf and returns its length excluding the NUL.
    let n = unsafe {
        aws_lc_sys::X509_NAME_get_text_by_NID(
            name,
            aws_lc_sys::NID_commonName,
            buf.as_mut_ptr().cast::<std::os::raw::c_char>(),
            c_int::try_from(buf.len()).unwrap_or(c_int::MAX),
        )
    };
    if n < 0 {
        return Err(TlsError::Ssl("CA subject has no CN".into()));
    }
    let n = usize::try_from(n).expect("n >= 0");
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

// ============================================================================
// FFI helpers (memory BIO, owned newtypes)
// ============================================================================

fn new_mem_bio() -> Result<BioOwned, TlsError> {
    // SAFETY: BIO_s_mem returns a static method pointer; BIO_new
    // allocates.
    let raw = unsafe { BIO_new(BIO_s_mem()) };
    NonNull::new(raw)
        .map(BioOwned)
        .ok_or(TlsError::Init("BIO_new(BIO_s_mem)"))
}

fn new_mem_bio_readonly(data: &[u8]) -> Result<BioOwned, TlsError> {
    // SAFETY: BIO_new_mem_buf with explicit length never reads past
    // data.len(); the BIO does not take ownership.
    let raw = unsafe {
        aws_lc_sys::BIO_new_mem_buf(
            data.as_ptr().cast::<c_void>(),
            isize::try_from(data.len()).map_err(|_| TlsError::Pem("input too large"))?,
        )
    };
    NonNull::new(raw)
        .map(BioOwned)
        .ok_or(TlsError::Init("BIO_new_mem_buf"))
}

/// Drain a memory BIO via repeated `BIO_read` into a `Vec<u8>`.
fn bio_drain(bio: &BioOwned) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: bio valid; buf is a 4 KiB stack slice; len fits
        // in c_int. Negative return = no data; zero = EOF.
        let n = unsafe {
            BIO_read(
                bio.0.as_ptr(),
                buf.as_mut_ptr().cast::<c_void>(),
                c_int::try_from(buf.len()).unwrap_or(c_int::MAX),
            )
        };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..usize::try_from(n).expect("n > 0")]);
    }
    out
}

struct EvpPkeyCtxOwned(NonNull<EVP_PKEY_CTX>);
impl Drop for EvpPkeyCtxOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; never freed elsewhere.
        unsafe { EVP_PKEY_CTX_free(self.0.as_ptr()) };
    }
}

struct BignumOwned(NonNull<BIGNUM>);
impl Drop for BignumOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; never freed elsewhere.
        unsafe { BN_free(self.0.as_ptr()) };
    }
}

struct Asn1IntegerOwned(NonNull<ASN1_INTEGER>);
impl Drop for Asn1IntegerOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; never freed elsewhere.
        unsafe { ASN1_INTEGER_free(self.0.as_ptr()) };
    }
}

struct X509NameOwned(NonNull<X509_NAME>);
impl Drop for X509NameOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; never freed elsewhere.
        unsafe { X509_NAME_free(self.0.as_ptr()) };
    }
}

/// Storage for an `X509V3_CTX` whose layout is opaque to us.
/// `X509V3_set_ctx` populates by-pointer; we stack-allocate a
/// zero-initialized buffer of the right size.
#[repr(transparent)]
struct V3CtxStorage(std::mem::MaybeUninit<X509V3_CTX>);

impl V3CtxStorage {
    fn new() -> Self {
        Self(std::mem::MaybeUninit::zeroed())
    }
    fn as_mut_ptr(&mut self) -> *mut X509V3_CTX {
        self.0.as_mut_ptr()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_p256_key_and_round_trips_pem() {
        let k = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let pem = k.to_pem_pkcs8().unwrap();
        assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        let _ = PrivateKey::from_pem(&pem).unwrap();
    }

    #[test]
    fn generates_rsa_key_and_round_trips_pem() {
        let k = PrivateKey::generate(KeyAlgorithm::Rsa2048).unwrap();
        let pem = k.to_pem_pkcs8().unwrap();
        let _ = PrivateKey::from_pem(&pem).unwrap();
    }

    #[test]
    fn ca_self_signs_and_round_trips() {
        let ca = CertificateAuthority::new("Test Root").unwrap();
        assert!(ca.cert_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(ca.key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
        let reloaded = CertificateAuthority::from_pem(ca.cert_pem(), ca.key_pem()).unwrap();
        assert_eq!(reloaded.cert_pem(), ca.cert_pem());
    }

    #[test]
    fn issues_server_and_client_certs() {
        let ca = CertificateAuthority::new("Test Root").unwrap();
        let s = ca
            .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
            .unwrap();
        assert!(s.cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        // Chain = leaf || CA, so two BEGIN lines.
        assert_eq!(
            s.chain_pem
                .windows(b"-----BEGIN CERTIFICATE-----".len())
                .filter(|w| *w == b"-----BEGIN CERTIFICATE-----")
                .count(),
            2
        );

        let c = ca
            .issue_client("nas-1", &[SubjectAltName::Ip("10.0.0.5".parse().unwrap())])
            .unwrap();
        let _ = Certificate::from_pem(&c.cert_pem).unwrap();
    }

    #[test]
    fn rejects_leaf_without_san() {
        let ca = CertificateAuthority::new("Test Root").unwrap();
        let err = ca.issue_server("radsec.test", &[]).unwrap_err();
        assert!(matches!(err, TlsError::Pem(_)));
    }

    #[test]
    fn issued_pki_drives_a_real_handshake() {
        // Plug the generated PKI into the existing TlsContext +
        // test client to verify chain validation, EKUs, and SAN
        // are all wired correctly. If anything in `add_extensions`
        // or `build_cert` is wrong this handshake fails.
        use crate::crypto::tls::test_client::client_side as tc;
        use crate::crypto::tls::{HandshakeState, TlsConnection, TlsContext};

        let ca = CertificateAuthority::new("Test Root").unwrap();
        let server = ca
            .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
            .unwrap();
        let client = ca
            .issue_client("nas-1", &[SubjectAltName::Dns("nas-1".into())])
            .unwrap();

        let ctx =
            TlsContext::server(&server.chain_pem, &server.key_pem, Some(ca.cert_pem())).unwrap();
        let mut server_conn = TlsConnection::accept(&ctx).unwrap();

        let mut client_conn = tc::builder(ca.cert_pem())
            .unwrap()
            .with_client_cert(&client.chain_pem, &client.key_pem)
            .unwrap()
            .build()
            .unwrap();

        let mut buf = [0u8; 16 * 1024];
        for _ in 0..32 {
            let s = client_conn.process().unwrap();
            let n = client_conn.take_output(&mut buf).unwrap();
            if n > 0 {
                server_conn.feed_input(&buf[..n]).unwrap();
            }
            let _ = server_conn.process().unwrap();
            let n = server_conn.take_output(&mut buf).unwrap();
            if n > 0 {
                client_conn.feed_input(&buf[..n]).unwrap();
            }
            if !server_conn.is_handshaking() && matches!(s, HandshakeState::Established) {
                break;
            }
        }
        assert!(!server_conn.is_handshaking(), "server handshake stalled");
        assert!(server_conn.peer_certificate().is_some());
    }
}
