//! TLS server-side wrapper for RadSec (RFC 6614), built on
//! `aws-lc-sys`'s libssl surface.
//!
//! # Design
//!
//! This module is the only place in the crate that calls libssl
//! directly. All `unsafe` is confined here, every block carries a
//! `// SAFETY:` comment, and every owned C handle is wrapped in a
//! newtype with a `Drop` impl that calls the matching `*_free`.
//!
//! # Transport-decoupled
//!
//! The wrapper is **not** wired to a socket. Each [`TlsConnection`]
//! drives its handshake and record layer through a pair of in-memory
//! BIOs:
//!
//! ```text
//!   network bytes  ──feed_input──▶  rbio  ──▶  SSL_read   ──▶  plaintext
//!   plaintext      ──SSL_write──▶  wbio  ──▶  take_output──▶  network bytes
//! ```
//!
//! The async runtime owns the actual TCP socket and pumps bytes
//! through these methods — same shape as `rustls::Connection`. This
//! lets the same wrapper sit behind a Tokio task, a blocking
//! threadpool worker, or a fuzz harness, without `BIO_set_nbio`
//! gymnastics.
//!
//! # Server-side only (for now)
//!
//! The crate is a RADIUS *server*. RadSec listeners always speak
//! TLS server, so [`TlsContext`] hard-codes `TLS_server_method` and
//! [`TlsConnection`] hard-codes `SSL_accept`. An outbound RadSec
//! proxy (post-0.1) will need a parallel client-side path.
//!
//! # Authorization model
//!
//! Mutual TLS is mandatory in RadSec. The wrapper configures
//! `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` and lets
//! libssl perform standard chain validation against the supplied
//! client-CA bundle. There is no application-level verify callback;
//! consumers run their authorization *after* a successful handshake
//! by inspecting [`TlsConnection::peer_certificate`]:
//!
//! * **IP-gated mode.** The listener narrows the per-connection
//!   trust store to a single client's CA before the handshake. A
//!   passing chain check *is* the authorization — nothing else to
//!   do.
//! * **Cert-keyed mode.** The listener uses a wide trust store, the
//!   handshake completes against any chain it accepts, and the
//!   consumer maps `peer_certificate()` (Subject DN, SAN, SPKI
//!   pin) to a registered client. Unknown peers get the connection
//!   torn down at the application layer.
//!
//! Either path keeps the wrapper free of generic parameters,
//! `extern "C"` callbacks, and `SSL_CTX` ex-data plumbing.

// FFI wrapper module: the pedantic doc-formatting and panic-doc
// lints add noise without value here. Several `expect("len > 0")`
// sites are unreachable by construction (the prior length check
// already returned `Err` for non-positive lengths), and the doc
// prose mixes uppercase TLS / X.509 acronyms ("SubjectPublicKeyInfo",
// "SPKI", "RadSec", "OpenSSL") that the markdown linter wants
// backticked even though they're not Rust identifiers.
#![allow(
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps,
    clippy::match_same_arms
)]

use std::ffi::{c_int, c_void, CStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::NonNull;
use std::sync::Arc;

use aws_lc_sys::{
    ASN1_STRING_get0_data, ASN1_STRING_length, BIO_free, BIO_new, BIO_new_mem_buf, BIO_read,
    BIO_s_mem, BIO_write, ERR_error_string_n, ERR_get_error, EVP_PKEY_free, GENERAL_NAMES_free,
    NID_subject_alt_name, OPENSSL_sk_num, OPENSSL_sk_value, PEM_read_bio_PrivateKey,
    PEM_read_bio_X509, SSL_CTX_check_private_key, SSL_CTX_free, SSL_CTX_new,
    SSL_CTX_set1_cert_store, SSL_CTX_set_min_proto_version, SSL_CTX_set_verify,
    SSL_CTX_use_PrivateKey, SSL_CTX_use_certificate, SSL_accept, SSL_free, SSL_get_error,
    SSL_get_peer_certificate, SSL_new, SSL_pending, SSL_read, SSL_set1_verify_cert_store,
    SSL_set_bio, SSL_write, TLS_server_method, X509_NAME_oneline, X509_STORE_add_cert,
    X509_STORE_new, X509_free, X509_get_ext_d2i, X509_get_subject_name, BIO, EVP_PKEY,
    GENERAL_NAME, GEN_DNS, GEN_IPADD, SSL, SSL_CTX, SSL_ERROR_NONE, SSL_ERROR_WANT_READ,
    SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER,
    TLS1_2_VERSION, X509, X509_STORE,
};

// ============================================================================
// Errors
// ============================================================================

/// Errors produced by the TLS wrapper.
#[derive(Debug)]
pub enum TlsError {
    /// `SSL_CTX_new` or `SSL_new` returned NULL.
    Init(&'static str),
    /// PEM parse failed: `cert`, `key`, or trust anchor.
    Pem(&'static str),
    /// Certificate / key mismatch surfaced by `SSL_CTX_check_private_key`.
    KeyMismatch,
    /// Handshake failed; the embedded message comes from
    /// `ERR_error_string_n` against the top of the libssl error
    /// queue. Chain-validation failures land here.
    Handshake(String),
    /// Plaintext read / write failed mid-session.
    Io(String),
    /// Generic libssl error not specifically handled above.
    Ssl(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Init(what) => write!(f, "tls init failed: {what}"),
            TlsError::Pem(what) => write!(f, "tls pem parse failed: {what}"),
            TlsError::KeyMismatch => write!(f, "tls cert/key mismatch"),
            TlsError::Handshake(msg) => write!(f, "tls handshake failed: {msg}"),
            TlsError::Io(msg) => write!(f, "tls io failed: {msg}"),
            TlsError::Ssl(msg) => write!(f, "tls error: {msg}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// Pop and format the top of the libssl error queue.
pub(super) fn pop_err(prefix: &str) -> String {
    // SAFETY: ERR_get_error has no preconditions; returns 0 if the
    // queue is empty.
    let code = unsafe { ERR_get_error() };
    if code == 0 {
        return format!("{prefix}: (no libssl error in queue)");
    }
    let mut buf = [0u8; 256];
    // SAFETY: buf is a valid 256-byte mutable slice. ERR_error_string_n
    // writes a NUL-terminated string into the supplied buffer up to
    // the supplied size. Cast to `c_char` because its signedness is
    // platform-dependent (i8 on x86_64-linux/glibc, u8 on aarch64).
    unsafe {
        ERR_error_string_n(
            code,
            buf.as_mut_ptr().cast::<std::os::raw::c_char>(),
            buf.len(),
        );
    }
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let msg = String::from_utf8_lossy(&buf[..nul_pos]);
    format!("{prefix}: {msg}")
}

// ============================================================================
// Owned handles
// ============================================================================

/// Owning newtype for `SSL_CTX*`.
pub(super) struct SslCtx(pub(super) NonNull<SSL_CTX>);

// SAFETY: `SSL_CTX` is documented as safe to share between threads
// once fully configured. The wrapper finishes all mutating setup
// (cert/key install, trust store, verify mode) before the value is
// wrapped in `Arc<SslCtx>` and exposed; from then on every access
// is read-only (`SSL_new` per BoringSSL is thread-safe against a
// shared `SSL_CTX*`).
unsafe impl Send for SslCtx {}
unsafe impl Sync for SslCtx {}

impl Drop for SslCtx {
    fn drop(&mut self) {
        // SAFETY: pointer was checked non-null at construction and
        // never freed elsewhere in the wrapper.
        unsafe { SSL_CTX_free(self.0.as_ptr()) };
    }
}

/// Owning newtype for `SSL*`.
pub(super) struct SslHandle(pub(super) NonNull<SSL>);

impl Drop for SslHandle {
    fn drop(&mut self) {
        // SAFETY: SSL_free also frees the BIOs we attached via
        // SSL_set_bio (per BoringSSL semantics: SSL takes ownership).
        unsafe { SSL_free(self.0.as_ptr()) };
    }
}

/// Owning newtype for a `BIO*` we have *not yet* handed to libssl.
///
/// Once a `BIO` is attached to an `SSL` via `SSL_set_bio`, libssl
/// owns the free; the wrapper drops this newtype via
/// [`forget_into_ssl`] to suppress the `Drop` here.
pub(super) struct BioOwned(pub(super) NonNull<BIO>);

impl Drop for BioOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null, never freed; we only Drop while
        // libssl has not taken ownership.
        unsafe { BIO_free(self.0.as_ptr()) };
    }
}

impl BioOwned {
    /// Surrender ownership to libssl. Returns the raw pointer and
    /// suppresses our Drop.
    pub(super) fn forget_into_ssl(self) -> *mut BIO {
        let p = self.0.as_ptr();
        std::mem::forget(self);
        p
    }
}

/// Owning newtype for `X509*`.
pub(super) struct X509Owned(pub(super) NonNull<X509>);

impl Drop for X509Owned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; X509_free decrements the refcount.
        unsafe { X509_free(self.0.as_ptr()) };
    }
}

impl X509Owned {
    /// Parse a single X.509 certificate from PEM bytes.
    pub(super) fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let bio = new_mem_bio_readonly(pem)?;
        // SAFETY: bio is a valid BIO* with `pem` as its read buffer.
        // The remaining args are NULL: no password callback / userdata
        // are needed for an unencrypted certificate PEM block.
        let raw = unsafe {
            PEM_read_bio_X509(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        drop(bio);
        NonNull::new(raw)
            .map(X509Owned)
            .ok_or(TlsError::Pem("certificate"))
    }

    /// Encode this certificate as PEM.
    pub(super) fn to_pem(&self) -> Result<Vec<u8>, TlsError> {
        let bio = new_mem_bio()?;
        // SAFETY: bio and cert pointers valid; PEM_write_bio_X509
        // returns 1 on success.
        let r = unsafe { aws_lc_sys::PEM_write_bio_X509(bio.0.as_ptr(), self.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("PEM_write_bio_X509")));
        }
        Ok(bio_drain(&bio))
    }

    /// DER-encoded bytes of the certificate.
    pub(super) fn to_der(&self) -> Result<Vec<u8>, TlsError> {
        // SAFETY: passing a NULL out-pointer to i2d_X509 returns the
        // required length without writing anything.
        let len = unsafe { aws_lc_sys::i2d_X509(self.0.as_ptr(), std::ptr::null_mut()) };
        if len <= 0 {
            return Err(TlsError::Ssl(pop_err("i2d_X509 length")));
        }
        let mut buf = vec![0u8; usize::try_from(len).expect("len > 0")];
        let mut p = buf.as_mut_ptr();
        // SAFETY: buf is at least `len` bytes; i2d_X509 writes
        // exactly `len` bytes and advances the pointer.
        let written = unsafe { aws_lc_sys::i2d_X509(self.0.as_ptr(), &mut p) };
        if written != len {
            return Err(TlsError::Ssl(pop_err("i2d_X509 write")));
        }
        Ok(buf)
    }

    /// Subject DN rendered as the OpenSSL one-line text
    /// representation (`/CN=foo/O=bar`). Returns an empty string
    /// if the cert has no Subject DN.
    ///
    /// **Diagnostic use only.** This format is the legacy OpenSSL
    /// rendering, not RFC 4514 LDAP DN form, and it is not safely
    /// parseable: CN/O values may contain `/` and `=`. For
    /// identity matching consult
    /// [`subject_alt_names`](Self::subject_alt_names) (RFC 6125
    /// §6.4.4 / RFC 6614 §2.3) or
    /// [`spki_sha256`](Self::spki_sha256) instead.
    pub(super) fn subject_display(&self) -> String {
        // SAFETY: cert valid; X509_get_subject_name returns an
        // interior pointer owned by the X509.
        let name = unsafe { X509_get_subject_name(self.0.as_ptr()) };
        if name.is_null() {
            return String::new();
        }
        // 512 covers the realistic worst case for an RFC 5280 DN
        // (~6 RDNs each at their X.520 upper bound). X509_NAME_oneline
        // truncates rather than failing if the buffer is too small.
        let mut buf = [0u8; 512];
        // SAFETY: buf valid; X509_NAME_oneline writes a
        // NUL-terminated string up to buf_size bytes; with a
        // non-null buf the return value points into our buffer.
        let ptr = unsafe {
            X509_NAME_oneline(
                name,
                buf.as_mut_ptr().cast::<std::os::raw::c_char>(),
                c_int::try_from(buf.len()).unwrap_or(c_int::MAX),
            )
        };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: ptr came from our buffer and is NUL-terminated.
        let cstr = unsafe { CStr::from_ptr(ptr) };
        cstr.to_string_lossy().into_owned()
    }

    /// SHA-256 hash of the SubjectPublicKeyInfo (the canonical
    /// "SPKI pin").
    pub(super) fn spki_sha256(&self) -> Result<[u8; 32], TlsError> {
        // SAFETY: X509_get_X509_PUBKEY returns an interior pointer
        // (no ownership transfer).
        let pubkey = unsafe { aws_lc_sys::X509_get_X509_PUBKEY(self.0.as_ptr()) };
        if pubkey.is_null() {
            return Err(TlsError::Ssl(pop_err("X509_get_X509_PUBKEY")));
        }
        // SAFETY: NULL out-pointer => length query.
        let len = unsafe { aws_lc_sys::i2d_X509_PUBKEY(pubkey, std::ptr::null_mut()) };
        if len <= 0 {
            return Err(TlsError::Ssl(pop_err("i2d_X509_PUBKEY length")));
        }
        let mut der = vec![0u8; usize::try_from(len).expect("len > 0")];
        let mut p = der.as_mut_ptr();
        // SAFETY: der has `len` bytes of capacity; i2d_X509_PUBKEY
        // writes exactly `len` bytes and advances the pointer.
        let written = unsafe { aws_lc_sys::i2d_X509_PUBKEY(pubkey, &mut p) };
        if written != len {
            return Err(TlsError::Ssl(pop_err("i2d_X509_PUBKEY write")));
        }
        let mut hash = [0u8; 32];
        // SAFETY: SHA256 takes (data, len, out); out must be 32
        // bytes; returns NULL only on internal allocation failure.
        let r = unsafe { aws_lc_sys::SHA256(der.as_ptr(), der.len(), hash.as_mut_ptr()) };
        if r.is_null() {
            return Err(TlsError::Ssl(pop_err("SHA256")));
        }
        Ok(hash)
    }

    /// Decode the certificate's `subjectAltName` extension into a
    /// list of [`SubjectAltName`] entries. Returns an empty vector
    /// if the extension is absent. Entries with types other than
    /// `dNSName` and `iPAddress` are silently skipped — those are
    /// the only types RFC 6614 §2.3 mandates support for and the
    /// only ones the SAN matchers in `radius-tokio` consume.
    pub(super) fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, TlsError> {
        // SAFETY: cert valid; `X509_get_ext_d2i` returns a
        // freshly-decoded `GENERAL_NAMES*` (caller-owned) when the
        // extension exists, NULL otherwise. We pass NULL for the
        // critical/index out-params since we want neither.
        let raw = unsafe {
            X509_get_ext_d2i(
                self.0.as_ptr(),
                NID_subject_alt_name,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let Some(stack) = NonNull::new(raw.cast::<aws_lc_sys::stack_st_GENERAL_NAME>()) else {
            return Ok(Vec::new());
        };
        let _guard = GeneralNamesGuard(stack);
        // SAFETY: stack is a valid `GENERAL_NAMES*`; the cast to
        // `OPENSSL_STACK*` matches BoringSSL's stack ABI.
        let count = unsafe { OPENSSL_sk_num(stack.as_ptr().cast()) };
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: 0 <= i < count; the returned `GENERAL_NAME*`
            // is borrowed from the stack and remains valid until
            // `GENERAL_NAMES_free` runs (via the guard).
            let gn = unsafe { OPENSSL_sk_value(stack.as_ptr().cast(), i) }.cast::<GENERAL_NAME>();
            let Some(gn) = NonNull::new(gn) else { continue };
            // SAFETY: gn valid; reading the discriminant before the
            // matching union arm.
            let ty = unsafe { (*gn.as_ptr()).type_ };
            if ty == GEN_DNS {
                // SAFETY: when `type_ == GEN_DNS`, `d.dNSName` is
                // the active union arm and points at an
                // `ASN1_IA5STRING` owned by the stack.
                let s = unsafe { (*gn.as_ptr()).d.dNSName };
                if let Some(name) = read_asn1_string_utf8(s) {
                    out.push(SubjectAltName::Dns(name));
                }
            } else if ty == GEN_IPADD {
                // SAFETY: when `type_ == GEN_IPADD`, `d.iPAddress`
                // is the active union arm and points at an
                // `ASN1_OCTET_STRING` owned by the stack.
                let s = unsafe { (*gn.as_ptr()).d.iPAddress };
                if let Some(ip) = read_asn1_ip(s) {
                    out.push(SubjectAltName::Ip(ip));
                }
            }
        }
        Ok(out)
    }
}

/// RAII guard that frees a `GENERAL_NAMES*` (a `STACK_OF(GENERAL_NAME)`)
/// returned by `X509_get_ext_d2i`. `GENERAL_NAMES_free` walks the
/// stack and frees each entry plus the stack itself.
struct GeneralNamesGuard(NonNull<aws_lc_sys::stack_st_GENERAL_NAME>);

impl Drop for GeneralNamesGuard {
    fn drop(&mut self) {
        // SAFETY: pointer non-null and was obtained from
        // `X509_get_ext_d2i(NID_subject_alt_name, ...)`, which
        // documents `GENERAL_NAMES_free` as the matching free.
        unsafe { GENERAL_NAMES_free(self.0.as_ptr()) };
    }
}

/// Read an `ASN1_STRING` (IA5/UTF-8 family) as a `String`. Returns
/// `None` if the pointer is null or the bytes aren't valid UTF-8.
fn read_asn1_string_utf8(s: *const aws_lc_sys::ASN1_STRING) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: s non-null; the two ASN1_STRING accessors are
    // documented as borrowing-only and length-bounded.
    let (data, len) = unsafe {
        (
            ASN1_STRING_get0_data(s),
            usize::try_from(ASN1_STRING_length(s)).ok()?,
        )
    };
    if data.is_null() {
        return None;
    }
    // SAFETY: the accessors above guarantee `data` points at `len`
    // valid bytes owned by the ASN1_STRING.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Read an `ASN1_OCTET_STRING` carrying a SAN `iPAddress` value.
/// RFC 5280 §4.2.1.6 fixes the encoding at exactly 4 octets (IPv4)
/// or 16 octets (IPv6); other lengths are skipped.
fn read_asn1_ip(s: *const aws_lc_sys::ASN1_STRING) -> Option<IpAddr> {
    if s.is_null() {
        return None;
    }
    // SAFETY: see `read_asn1_string_utf8`.
    let (data, len) = unsafe {
        (
            ASN1_STRING_get0_data(s),
            usize::try_from(ASN1_STRING_length(s)).ok()?,
        )
    };
    if data.is_null() {
        return None;
    }
    // SAFETY: `data` points at `len` valid bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Build an empty memory BIO (writable).
pub(super) fn new_mem_bio() -> Result<BioOwned, TlsError> {
    // SAFETY: BIO_s_mem returns a static method pointer; BIO_new
    // allocates.
    let raw = unsafe { BIO_new(BIO_s_mem()) };
    NonNull::new(raw)
        .map(BioOwned)
        .ok_or(TlsError::Init("BIO_new(BIO_s_mem)"))
}

/// Drain a memory BIO via repeated `BIO_read` into a `Vec<u8>`.
pub(super) fn bio_drain(bio: &BioOwned) -> Vec<u8> {
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

/// Owning newtype for `EVP_PKEY*`.
pub(super) struct EvpPkeyOwned(pub(super) NonNull<EVP_PKEY>);

impl Drop for EvpPkeyOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; EVP_PKEY_free decrements the refcount.
        unsafe { EVP_PKEY_free(self.0.as_ptr()) };
    }
}

impl EvpPkeyOwned {
    /// Parse a private key (any algorithm) from unencrypted PEM
    /// bytes (PKCS#8 or algorithm-specific).
    pub(super) fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        let bio = new_mem_bio_readonly(pem)?;
        // SAFETY: bio valid; NULL out-param / cb / userdata are
        // documented as legal for unencrypted keys.
        let raw = unsafe {
            PEM_read_bio_PrivateKey(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        drop(bio);
        NonNull::new(raw)
            .map(EvpPkeyOwned)
            .ok_or(TlsError::Pem("private key"))
    }

    /// Encode this key as unencrypted PKCS#8 PEM.
    pub(super) fn to_pem_pkcs8(&self) -> Result<Vec<u8>, TlsError> {
        let bio = new_mem_bio()?;
        // SAFETY: bio valid; remaining args choose the unencrypted
        // PKCS#8 encoding path: enc = NULL, pass = NULL, pass_len = 0,
        // cb = None, userdata = NULL.
        let r = unsafe {
            aws_lc_sys::PEM_write_bio_PKCS8PrivateKey(
                bio.0.as_ptr(),
                self.0.as_ptr(),
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

/// Owning newtype for `X509_STORE*`.
struct X509StoreOwned(NonNull<X509_STORE>);

impl Drop for X509StoreOwned {
    fn drop(&mut self) {
        // SAFETY: pointer non-null; X509_STORE_free decrements the refcount.
        unsafe { aws_lc_sys::X509_STORE_free(self.0.as_ptr()) };
    }
}

// SAFETY: The store is read-only after construction (we only ever
// add CAs at build time, then hand it to libssl). BoringSSL /
// aws-lc allow concurrent reads against the same X509_STORE.
unsafe impl Send for X509StoreOwned {}
// SAFETY: see above.
unsafe impl Sync for X509StoreOwned {}

// ============================================================================
// PEM parsing helpers
// ============================================================================

/// Build a memory-backed BIO that *reads* from `data`. The returned
/// BIO does not own `data` — caller must keep it alive while the BIO
/// is in use. We never re-export this BIO past the immediate parse
/// call, so its lifetime is bounded by the stack frame.
pub(super) fn new_mem_bio_readonly(data: &[u8]) -> Result<BioOwned, TlsError> {
    // SAFETY: BIO_new_mem_buf with len = -1 would treat `data` as a
    // C string; we always supply a positive length so the BIO sees
    // exactly `data.len()` bytes regardless of NUL content.
    let raw = unsafe {
        BIO_new_mem_buf(
            data.as_ptr().cast::<c_void>(),
            isize::try_from(data.len()).map_err(|_| TlsError::Pem("input too large"))?,
        )
    };
    NonNull::new(raw)
        .map(BioOwned)
        .ok_or(TlsError::Init("BIO_new_mem_buf"))
}

// ============================================================================
// PeerCertificate
// ============================================================================

/// A Subject Alternative Name entry, both for issuance
/// (see [`crate::pki`]) and for matching peer certificates
/// (see [`PeerCertificate::subject_alt_names`]).
///
/// RFC 6614 §2.3 mandates that RadSec leaf certificates carry a
/// SAN with a `dNSName` and / or `iPAddress` identifying the peer.
/// Per RFC 6125 §6.4.4 the Common Name in the Subject DN is
/// deprecated for identity matching — consumers should always key
/// off SAN entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAltName {
    /// `dNSName` SAN entry. The contained string is the literal
    /// IA5/UTF-8 value as it appears in the certificate (no
    /// case-folding, no IDNA processing).
    Dns(String),
    /// `iPAddress` SAN entry. RFC 5280 fixes the wire encoding at
    /// 4 octets (IPv4) or 16 octets (IPv6).
    Ip(IpAddr),
}

/// Owned view of the peer's leaf certificate.
///
/// Holds an additional refcount on the underlying `X509`; freeing
/// happens when this value is dropped.
pub struct PeerCertificate {
    cert: X509Owned,
}

// SAFETY: After construction the underlying X509 is accessed only
// through read-only APIs (Subject DN, SPKI hash, DER encoding); we
// never mutate. BoringSSL / aws-lc tolerates concurrent reads of an
// X509 through these accessors. Sending the value across an .await
// point or sharing a `&PeerCertificate` with a `ClientStore`
// implementation is therefore sound.
unsafe impl Send for PeerCertificate {}
// SAFETY: see above.
unsafe impl Sync for PeerCertificate {}

impl PeerCertificate {
    /// Wrap an owned `X509*` (e.g. from `SSL_get_peer_certificate`)
    /// without bumping the refcount.
    fn from_owned(cert: NonNull<X509>) -> Self {
        Self {
            cert: X509Owned(cert),
        }
    }

    /// DER-encoded bytes of the certificate. Allocates.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if `i2d_X509` fails.
    pub fn to_der(&self) -> Result<Vec<u8>, TlsError> {
        self.cert.to_der()
    }

    /// Subject DN rendered as the OpenSSL one-line text
    /// representation (`/CN=foo/O=bar`).
    ///
    /// **Diagnostic use only.** This format is the legacy OpenSSL
    /// rendering, not RFC 4514 LDAP DN form, and it is not safely
    /// parseable: CN/O values may contain `/` and `=`. For
    /// identity matching consult
    /// [`subject_alt_names`](Self::subject_alt_names) (RFC 6125
    /// §6.4.4 / RFC 6614 §2.3) or
    /// [`spki_sha256`](Self::spki_sha256) instead.
    #[must_use]
    pub fn subject_display(&self) -> String {
        self.cert.subject_display()
    }

    /// SHA-256 hash of the SubjectPublicKeyInfo, the canonical
    /// "SPKI pin" used by RadSec deployments to bind a peer to a
    /// specific key (independent of the issuer / chain).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if `i2d_X509_PUBKEY` fails.
    pub fn spki_sha256(&self) -> Result<[u8; 32], TlsError> {
        self.cert.spki_sha256()
    }

    /// Decode the leaf's `subjectAltName` extension into a list of
    /// [`SubjectAltName`] entries. This is the recommended way to
    /// identify a RadSec peer in cert-keyed mode (RFC 6125 §6.4.4
    /// deprecates Common Name matching).
    ///
    /// Returns an empty vector when the certificate has no SAN
    /// extension. Entries with types other than `dNSName` and
    /// `iPAddress` are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if the underlying decode fails.
    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, TlsError> {
        self.cert.subject_alt_names()
    }
}

// ============================================================================
// TlsContext
// ============================================================================

/// Listener-wide TLS configuration.
///
/// Holds the server certificate + key plus the trust material used
/// to verify peers. One `TlsContext` typically backs an entire
/// listener; cloning is cheap (the inner state is shared via `Arc`).
#[derive(Clone)]
pub struct TlsContext {
    inner: Arc<SslCtx>,
}

impl std::fmt::Debug for TlsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsContext").finish_non_exhaustive()
    }
}

impl TlsContext {
    /// Build a server-side context with the supplied PEM
    /// materials.
    ///
    /// * `cert_chain_pem` — server certificate (leaf first; chain
    ///   bytes after if any).
    /// * `key_pem` — matching private key.
    /// * `client_ca_pem` — concatenated PEM of the root CAs allowed
    ///   to issue *client* certificates. Required: there is no
    ///   system-CA fallback. RadSec listeners must own their trust
    ///   anchors explicitly — a fallback to the platform store
    ///   would silently let any publicly-issued certificate pass
    ///   libssl's chain check, leaving cert-keyed authorization
    ///   relying entirely on the consumer's `lookup_radsec_by_cert`
    ///   to spot a spoofed Subject / SAN.
    ///
    /// Mutual TLS is mandatory (`SSL_VERIFY_PEER |
    /// SSL_VERIFY_FAIL_IF_NO_PEER_CERT`); chain validation is
    /// performed by libssl. Application-level authorization
    /// (cert-keyed lookups, SPKI pinning, etc.) runs *after* the
    /// handshake completes by inspecting
    /// [`TlsConnection::peer_certificate`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] for any libssl init / parse / mismatch
    /// failure, or [`TlsError::Pem`] if `client_ca_pem` decodes to
    /// no certificates.
    pub fn server(
        cert_chain_pem: &[u8],
        key_pem: &[u8],
        client_ca_pem: &[u8],
    ) -> Result<Self, TlsError> {
        // SAFETY: TLS_server_method returns a pointer to a static
        // SSL_METHOD, never NULL.
        let method = unsafe { TLS_server_method() };
        // SAFETY: SSL_CTX_new returns NULL on alloc failure; we
        // check.
        let raw_ctx = unsafe { SSL_CTX_new(method) };
        let ctx = SslCtx(NonNull::new(raw_ctx).ok_or(TlsError::Init("SSL_CTX_new"))?);

        // Pin a TLS 1.2 floor. RFC 6614 \u00a72.3 forbids TLS \u2264 1.0;
        // RFC 9325 / BCP 195 \u00a74.1 mandates TLS 1.2 (or 1.3) for any
        // new deployment, and aws-lc's TLS 1.2 cipher defaults
        // exclude RC4, 3DES, and non-AEAD suites. We accept the
        // current aws-lc maximum (TLS 1.3 today) so the listener
        // negotiates the strongest version both peers support.
        // SAFETY: ctx is valid; the version constant comes from
        // aws-lc's bindings. The function returns 1 on success.
        // The cast widens i32 to u16 \u2014 both TLS1_2_VERSION (771) and
        // TLS1_3_VERSION (772) fit in u16.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let r = unsafe { SSL_CTX_set_min_proto_version(ctx.0.as_ptr(), TLS1_2_VERSION as u16) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("SSL_CTX_set_min_proto_version")));
        }

        // Parse cert + key, install both, then verify the pair.
        let cert = X509Owned::from_pem(cert_chain_pem)?;
        let key = EvpPkeyOwned::from_pem(key_pem)?;
        // SAFETY: ctx and cert/key are valid; functions take an
        // additional reference internally so our owners stay valid.
        let r = unsafe { SSL_CTX_use_certificate(ctx.0.as_ptr(), cert.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("SSL_CTX_use_certificate")));
        }
        let r = unsafe { SSL_CTX_use_PrivateKey(ctx.0.as_ptr(), key.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("SSL_CTX_use_PrivateKey")));
        }
        // SAFETY: ctx valid; checks the most recently installed
        // cert against the most recently installed key.
        let r = unsafe { SSL_CTX_check_private_key(ctx.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::KeyMismatch);
        }
        // The X509 / EVP_PKEY can drop now; SSL_CTX bumped their refcounts.
        drop(cert);
        drop(key);

        // Trust anchors for the *client* certs. Required — see
        // the doc comment on `server()` for why we don't fall back
        // to the platform store.
        install_client_cas(&ctx, client_ca_pem)?;

        // Mandatory mTLS for RadSec: peer MUST present a cert and
        // its chain MUST validate against the configured trust
        // store. No application callback — passing libssl's check
        // *is* the gate.
        // SAFETY: ctx valid; passing `None` for the verify callback
        // tells libssl to use its built-in chain-validation result
        // verbatim.
        unsafe {
            SSL_CTX_set_verify(
                ctx.0.as_ptr(),
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                None,
            );
        }

        Ok(Self {
            inner: Arc::new(ctx),
        })
    }
}

/// Parse a chain of PEM-encoded CA certificates into a fresh
/// `X509_STORE`. Used for both listener-wide trust (installed on
/// the [`SslCtx`]) and per-connection trust narrowing (installed
/// on the [`SslHandle`] via [`ClientTrust`]).
fn parse_pem_to_store(pem: &[u8]) -> Result<X509StoreOwned, TlsError> {
    // SAFETY: X509_STORE_new allocates an empty store; NULL on OOM.
    let store_raw = unsafe { X509_STORE_new() };
    let store = X509StoreOwned(NonNull::new(store_raw).ok_or(TlsError::Init("X509_STORE_new"))?);

    let bio = new_mem_bio_readonly(pem)?;
    let mut found = false;
    loop {
        // SAFETY: bio valid; PEM_read_bio_X509 returns NULL when
        // there are no more cert blocks in the BIO (or on error).
        let raw = unsafe {
            PEM_read_bio_X509(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if raw.is_null() {
            break;
        }
        let cert = X509Owned(NonNull::new(raw).expect("checked above"));
        // SAFETY: store and cert valid; X509_STORE_add_cert bumps
        // the X509 refcount on success.
        let r = unsafe { X509_STORE_add_cert(store.0.as_ptr(), cert.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("X509_STORE_add_cert")));
        }
        found = true;
        drop(cert);
    }
    drop(bio);
    if !found {
        return Err(TlsError::Pem("no CA certificates"));
    }
    Ok(store)
}

/// Install a chain of PEM-encoded client CAs as the SSL_CTX's trust
/// store.
fn install_client_cas(ctx: &SslCtx, pem: &[u8]) -> Result<(), TlsError> {
    let store = parse_pem_to_store(pem)?;
    // Hand the store to the SSL_CTX. `set1_` bumps the refcount, so
    // we keep our ownership and Drop our copy.
    // SAFETY: ctx + store valid; SSL_CTX_set1_cert_store doesn't
    // take ownership.
    unsafe { SSL_CTX_set1_cert_store(ctx.0.as_ptr(), store.0.as_ptr()) };
    drop(store);
    Ok(())
}

// ============================================================================
// ClientTrust
// ============================================================================

/// Per-client trust material for narrowing a [`TlsConnection`] to
/// the CA(s) that *this specific* RadSec peer is allowed to chain
/// to.
///
/// Without this narrowing every connection accepted by a listener
/// is validated against the listener-wide trust store passed to
/// [`TlsContext::server`]. That store is the union of every
/// allowed peer's CA — fine for a homogeneous deployment, too loose
/// for the IP-gated mode described in the project README, where a
/// successful handshake should mean *"the peer at this IP presented
/// the cert it was supposed to"*.
///
/// With per-client trust installed, libssl's chain validation is
/// the gate: peer-A presenting a cert chained to peer-B's CA fails
/// the handshake and the connection is dropped. No application
/// callback required.
///
/// # Cost
///
/// Parsing is one-time (typically at `Client` construction). The
/// resulting store is reference-counted via `Arc`, so cloning a
/// `ClientTrust` is cheap and sharing it between many `Client`
/// records is fine.
#[derive(Clone)]
pub struct ClientTrust {
    store: Arc<X509StoreOwned>,
}

// SAFETY: After construction the X509_STORE is read-only;
// BoringSSL / aws-lc validates concurrent reads against the same
// store. We never mutate the store after handing it to libssl.
unsafe impl Send for ClientTrust {}
// SAFETY: see above.
unsafe impl Sync for ClientTrust {}

impl ClientTrust {
    /// Build a trust set from a PEM bundle of one or more CA
    /// certificates.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Pem`] if the input contains no
    /// `BEGIN CERTIFICATE` blocks, or [`TlsError::Ssl`] if libssl
    /// rejects an individual cert.
    pub fn from_pem(ca_pem: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            store: Arc::new(parse_pem_to_store(ca_pem)?),
        })
    }
}

impl std::fmt::Debug for ClientTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTrust").finish_non_exhaustive()
    }
}

// ============================================================================
// TlsConnection
// ============================================================================

/// Per-connection TLS state machine.
///
/// Drive the handshake (and subsequent record traffic) by:
///
/// 1. Pushing inbound network bytes via [`feed_input`](Self::feed_input).
/// 2. Calling [`process`](Self::process) to advance the state.
/// 3. Pulling outbound network bytes via [`take_output`](Self::take_output).
/// 4. Repeating until [`is_handshaking`](Self::is_handshaking) is `false`.
/// 5. After the handshake: [`read`](Self::read) for inbound plaintext and
///    [`write`](Self::write) for outbound plaintext.
///
/// `TlsConnection` is `Send` but not `Sync`; one task at a time may
/// drive it. Cloning is not supported.
pub struct TlsConnection {
    ssl: SslHandle,
    rbio: NonNull<BIO>, // input — we BIO_write here
    wbio: NonNull<BIO>, // output — we BIO_read here
    handshake_done: bool,
    _ctx: TlsContext, // keep the SSL_CTX alive
}

// SAFETY: SSL objects can be sent between threads as long as no two
// threads use them concurrently; `TlsConnection` does not impl Sync.
unsafe impl Send for TlsConnection {}

impl TlsConnection {
    /// Build a fresh server-side connection from `ctx`.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Init`] if `SSL_new` or either `BIO_new`
    /// returns NULL.
    pub fn accept(ctx: &TlsContext) -> Result<Self, TlsError> {
        // SAFETY: ctx valid.
        let raw_ssl = unsafe { SSL_new(ctx.inner.0.as_ptr()) };
        let ssl = SslHandle(NonNull::new(raw_ssl).ok_or(TlsError::Init("SSL_new"))?);

        // SAFETY: BIO_s_mem returns a static method pointer.
        let rbio_raw = unsafe { BIO_new(BIO_s_mem()) };
        let rbio = BioOwned(NonNull::new(rbio_raw).ok_or(TlsError::Init("BIO_new(rbio)"))?);
        let wbio_raw = unsafe { BIO_new(BIO_s_mem()) };
        let wbio = BioOwned(NonNull::new(wbio_raw).ok_or(TlsError::Init("BIO_new(wbio)"))?);

        // Hand the BIOs to libssl. After this call libssl owns the
        // free; we keep raw pointers for direct BIO_read / BIO_write
        // but must NOT call BIO_free on them.
        let rbio_ptr = rbio.forget_into_ssl();
        let wbio_ptr = wbio.forget_into_ssl();
        // SAFETY: ssl + bios all valid.
        unsafe { SSL_set_bio(ssl.0.as_ptr(), rbio_ptr, wbio_ptr) };

        Ok(Self {
            ssl,
            rbio: NonNull::new(rbio_ptr).expect("non-null above"),
            wbio: NonNull::new(wbio_ptr).expect("non-null above"),
            handshake_done: false,
            _ctx: ctx.clone(),
        })
    }

    /// Narrow this connection's chain validation to `trust`,
    /// overriding the listener-wide trust store from
    /// [`TlsContext::server`].
    ///
    /// Call **before** driving the handshake (i.e. before the first
    /// [`process`](Self::process)). Used by RadSec's IP-gated
    /// admission flow: once `admit_radsec` resolves the source IP
    /// to a `Client`, the client's per-connection trust is
    /// installed so a successful handshake means *"this peer
    /// presented the cert it was supposed to"*.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if libssl rejects the store
    /// (shouldn't happen for a well-formed [`ClientTrust`]).
    pub fn set_client_trust(&mut self, trust: &ClientTrust) -> Result<(), TlsError> {
        // SAFETY: ssl + store both valid; SSL_set1_verify_cert_store
        // bumps the store's refcount, so the `Arc<X509StoreOwned>`
        // in `trust` retains its own reference.
        let r = unsafe { SSL_set1_verify_cert_store(self.ssl.0.as_ptr(), trust.store.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("SSL_set1_verify_cert_store")));
        }
        Ok(())
    }

    /// Push ciphertext bytes from the network into the input BIO.
    ///
    /// # Errors
    ///
    /// Surfaces [`TlsError::Io`] if the BIO refuses the write
    /// (which shouldn't happen for a memory BIO — they grow as
    /// needed).
    pub fn feed_input(&mut self, bytes: &[u8]) -> Result<usize, TlsError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // SAFETY: rbio is the memory BIO libssl took ownership of;
        // pointer is still valid because the SSL hasn't been freed
        // yet (we still hold it).
        let n = unsafe {
            BIO_write(
                self.rbio.as_ptr(),
                bytes.as_ptr().cast::<c_void>(),
                c_int::try_from(bytes.len()).unwrap_or(c_int::MAX),
            )
        };
        if n < 0 {
            return Err(TlsError::Io(pop_err("BIO_write(rbio)")));
        }
        Ok(usize::try_from(n).expect("n >= 0"))
    }

    /// Pull ciphertext bytes out of the output BIO into `out`.
    ///
    /// Returns the number of bytes written. May be 0 if the output
    /// BIO is empty (caller should call [`process`](Self::process)
    /// first to drive the state machine forward).
    ///
    /// # Errors
    ///
    /// Surfaces [`TlsError::Io`] if `BIO_read` fails for a reason
    /// other than "no data available".
    pub fn take_output(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
        if out.is_empty() {
            return Ok(0);
        }
        // SAFETY: wbio valid for the same reason as rbio above.
        let n = unsafe {
            BIO_read(
                self.wbio.as_ptr(),
                out.as_mut_ptr().cast::<c_void>(),
                c_int::try_from(out.len()).unwrap_or(c_int::MAX),
            )
        };
        if n < 0 {
            // -1 from a memory BIO with no data available is the
            // "would block" sentinel, not a real error.
            return Ok(0);
        }
        Ok(usize::try_from(n).expect("n >= 0"))
    }

    /// Drive the handshake state machine forward as far as it can
    /// go without more network input.
    ///
    /// Returns the current state: see [`HandshakeState`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Handshake`] on any unrecoverable
    /// handshake failure — bad cert, protocol error, missing client
    /// cert, chain validation failure, …
    pub fn process(&mut self) -> Result<HandshakeState, TlsError> {
        if self.handshake_done {
            return Ok(HandshakeState::Established);
        }
        // SAFETY: ssl valid, not yet finished.
        let r = unsafe { SSL_accept(self.ssl.0.as_ptr()) };
        if r == 1 {
            self.handshake_done = true;
            return Ok(HandshakeState::Established);
        }
        // SAFETY: ssl valid; SSL_get_error inspects ssl + the
        // returned code from the previous SSL_* call.
        let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), r) };
        match err {
            SSL_ERROR_WANT_READ => Ok(HandshakeState::NeedsRead),
            SSL_ERROR_WANT_WRITE => Ok(HandshakeState::NeedsWrite),
            _ => Err(TlsError::Handshake(pop_err("SSL_accept"))),
        }
    }

    /// `true` iff the handshake hasn't yet completed successfully.
    #[must_use]
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_done
    }

    /// Read decrypted plaintext into `out`. Returns 0 on clean
    /// close-notify or when more network input is needed; returns
    /// [`TlsError::Io`] on a record-layer failure mid-session.
    ///
    /// # Errors
    ///
    /// Surfaces [`TlsError::Io`] for any non-recoverable record
    /// layer error.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
        if out.is_empty() {
            return Ok(0);
        }
        // SAFETY: ssl valid; SSL_read pulls from rbio.
        let n = unsafe {
            SSL_read(
                self.ssl.0.as_ptr(),
                out.as_mut_ptr().cast::<c_void>(),
                c_int::try_from(out.len()).unwrap_or(c_int::MAX),
            )
        };
        if n > 0 {
            return Ok(usize::try_from(n).expect("n > 0"));
        }
        // SAFETY: ssl valid.
        let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), n) };
        match err {
            SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => Ok(0),
            SSL_ERROR_ZERO_RETURN => Ok(0), // clean close-notify
            SSL_ERROR_NONE => Ok(0),
            _ => Err(TlsError::Io(pop_err("SSL_read"))),
        }
    }

    /// Encrypt `bytes` into the output BIO. Returns the number of
    /// plaintext bytes accepted; the caller must subsequently call
    /// [`take_output`](Self::take_output) to drain the produced
    /// ciphertext.
    ///
    /// # Errors
    ///
    /// Surfaces [`TlsError::Io`] for any non-recoverable record
    /// layer error.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, TlsError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // SAFETY: ssl valid.
        let n = unsafe {
            SSL_write(
                self.ssl.0.as_ptr(),
                bytes.as_ptr().cast::<c_void>(),
                c_int::try_from(bytes.len()).unwrap_or(c_int::MAX),
            )
        };
        if n > 0 {
            return Ok(usize::try_from(n).expect("n > 0"));
        }
        // SAFETY: ssl valid.
        let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), n) };
        match err {
            SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => Ok(0),
            _ => Err(TlsError::Io(pop_err("SSL_write"))),
        }
    }

    /// `true` iff the SSL has buffered plaintext ready for `read`
    /// without needing more network input.
    #[must_use]
    pub fn has_plaintext_pending(&self) -> bool {
        // SAFETY: ssl valid.
        unsafe { SSL_pending(self.ssl.0.as_ptr()) > 0 }
    }

    /// Take ownership of the peer's leaf certificate, if the
    /// handshake has completed. This is the entry point for
    /// post-handshake authorization (cert-keyed lookups, SPKI
    /// pinning, Subject / SAN matching).
    #[must_use]
    pub fn peer_certificate(&self) -> Option<PeerCertificate> {
        if !self.handshake_done {
            return None;
        }
        // SAFETY: ssl valid; SSL_get_peer_certificate returns an
        // X509 with bumped refcount (caller must free). We hand
        // ownership of that bumped reference straight to
        // PeerCertificate, whose Drop calls X509_free.
        let raw = unsafe { SSL_get_peer_certificate(self.ssl.0.as_ptr()) };
        NonNull::new(raw).map(PeerCertificate::from_owned)
    }
}

/// Where the handshake state machine is currently parked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Need more bytes from the peer; caller should read from the
    /// socket and [`feed_input`](TlsConnection::feed_input).
    NeedsRead,
    /// Need to send queued ciphertext to the peer; caller should
    /// [`take_output`](TlsConnection::take_output) and write to
    /// the socket.
    NeedsWrite,
    /// Handshake completed; subsequent record traffic is allowed.
    Established,
}

#[cfg(test)]
pub(crate) mod test_client;
#[cfg(test)]
mod tests;
