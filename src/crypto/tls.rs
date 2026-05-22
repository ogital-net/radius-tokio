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

use std::ffi::{c_char, c_int, c_void, CStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::NonNull;
use std::sync::Arc;

use aws_lc_sys::{
    i2d_ASN1_TYPE, ASN1_STRING_get0_data, ASN1_STRING_length, BIO_free, BIO_mem_contents, BIO_new,
    BIO_new_mem_buf, BIO_read, BIO_reset, BIO_s_mem, BIO_write, ERR_clear_error,
    ERR_error_string_n, ERR_get_error, EVP_PKEY_free, GENERAL_NAMES_free, NID_commonName,
    NID_subject_alt_name, OBJ_obj2txt, OPENSSL_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_push, OPENSSL_sk_value, PEM_read_bio_PrivateKey, PEM_read_bio_X509,
    SSL_CTX_check_private_key, SSL_CTX_free, SSL_CTX_new, SSL_CTX_set1_cert_store,
    SSL_CTX_set_client_CA_list, SSL_CTX_set_min_proto_version, SSL_CTX_set_num_tickets,
    SSL_CTX_set_options, SSL_CTX_set_verify, SSL_CTX_set_verify_depth, SSL_CTX_use_PrivateKey,
    SSL_CTX_use_certificate, SSL_accept, SSL_export_keying_material, SSL_free, SSL_get_error,
    SSL_get_key_update_type, SSL_get_peer_certificate, SSL_key_update, SSL_new, SSL_pending,
    SSL_read, SSL_set_bio, SSL_shutdown, SSL_version, SSL_write, TLS_server_method,
    X509_NAME_ENTRY_get_data, X509_NAME_dup, X509_NAME_free, X509_NAME_get_entry,
    X509_NAME_get_index_by_NID, X509_NAME_oneline, X509_STORE_add_cert, X509_STORE_new, X509_free,
    X509_get_ext_d2i, X509_get_subject_name, ASN1_OBJECT, ASN1_TYPE, BIO, EVP_PKEY, GENERAL_NAME,
    GEN_DNS, GEN_IPADD, GEN_OTHERNAME, GEN_RID, GEN_URI, OTHERNAME, SSL, SSL_CTX, SSL_ERROR_NONE,
    SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN, SSL_KEY_UPDATE_NONE,
    SSL_KEY_UPDATE_REQUESTED, SSL_OP_NO_TICKET, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, SSL_VERIFY_PEER,
    TLS1_2_VERSION, TLS1_3_VERSION, X509, X509_STORE,
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

/// Pop and format every entry currently on the libssl error queue.
///
/// libssl pushes errors onto a thread-local FIFO; a single failed
/// operation may push several. We drain the queue completely so
/// the next libssl call starts from a clean slate — leftover
/// entries would otherwise surface as spurious context in an
/// unrelated `pop_err` report. Joins the formatted entries with
/// `"; "` separators; returns just the prefix when the queue is
/// empty (which is itself a bug-detector, since `pop_err` is only
/// called on a failure path).
pub(super) fn pop_err(prefix: &str) -> String {
    let mut messages: Vec<String> = Vec::new();
    loop {
        // SAFETY: ERR_get_error has no preconditions; returns 0
        // when the queue is empty.
        let code = unsafe { ERR_get_error() };
        if code == 0 {
            break;
        }
        let mut buf = [0u8; 256];
        // SAFETY: buf is a valid 256-byte mutable slice.
        // ERR_error_string_n writes a NUL-terminated string up to
        // the supplied size. Cast to `c_char` because its
        // signedness is platform-dependent (i8 on x86_64-linux/glibc,
        // u8 on aarch64).
        unsafe {
            ERR_error_string_n(
                code,
                buf.as_mut_ptr().cast::<std::os::raw::c_char>(),
                buf.len(),
            );
        }
        let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        messages.push(String::from_utf8_lossy(&buf[..nul_pos]).into_owned());
    }
    // Belt-and-suspenders: clear in case ERR_get_error skipped
    // something on a future aws-lc revision (no-op today).
    // SAFETY: ERR_clear_error has no preconditions.
    unsafe { ERR_clear_error() };
    if messages.is_empty() {
        format!("{prefix}: (no libssl error in queue)")
    } else {
        format!("{prefix}: {}", messages.join("; "))
    }
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
        let written = unsafe { aws_lc_sys::i2d_X509(self.0.as_ptr(), &raw mut p) };
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
    ///
    /// The returned string is always the **complete** Subject DN.
    /// We pass `NULL`/`0` to `X509_NAME_oneline`, which causes
    /// libcrypto to allocate a buffer sized exactly to fit, so an
    /// oversize DN can't be silently truncated into something
    /// shorter that a careless `subject.contains(needle)` matcher
    /// would treat as legitimate.
    pub(super) fn subject_display(&self) -> String {
        // SAFETY: cert valid; X509_get_subject_name returns an
        // interior pointer owned by the X509.
        let name = unsafe { X509_get_subject_name(self.0.as_ptr()) };
        if name.is_null() {
            return String::new();
        }
        // SAFETY: passing buf=NULL, size=0 tells X509_NAME_oneline
        // to allocate a buffer with OPENSSL_malloc and return it;
        // the caller must release it with OPENSSL_free. Returns
        // NULL on allocation failure.
        let ptr = unsafe { X509_NAME_oneline(name, std::ptr::null_mut(), 0) };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: ptr was just produced by X509_NAME_oneline and is
        // guaranteed NUL-terminated.
        let owned = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: ptr came from OPENSSL_malloc inside libcrypto;
        // OPENSSL_free is the matching deallocator.
        unsafe { OPENSSL_free(ptr.cast::<c_void>()) };
        owned
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
        let written = unsafe { aws_lc_sys::i2d_X509_PUBKEY(pubkey, &raw mut p) };
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
    /// if the extension is absent. Recognises every GeneralName
    /// choice that RFC 5280 §4.2.1.6 defines and `radsecproxy`'s
    /// `MatchCertificateAttribute` policy supports — `dNSName`,
    /// `iPAddress`, `uniformResourceIdentifier`, `registeredID`,
    /// `otherName`. Other choices are silently skipped.
    pub(super) fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, TlsError> {
        let mut out = Vec::new();
        self.walk_sans(|san| {
            out.push(san);
            true
        })?;
        Ok(out)
    }

    /// Walk the SAN extension, invoking `f` for each decoded
    /// entry. Returning `false` from `f` short-circuits the walk.
    /// Used by the per-field accessors on [`PeerCertificate`] so
    /// each only allocates for the entries it cares about.
    pub(super) fn walk_sans<F>(&self, mut f: F) -> Result<(), TlsError>
    where
        F: FnMut(SubjectAltName) -> bool,
    {
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
            return Ok(());
        };
        let _guard = GeneralNamesGuard(stack);
        // SAFETY: stack is a valid `GENERAL_NAMES*`; the cast to
        // `OPENSSL_STACK*` matches BoringSSL's stack ABI.
        let count = unsafe { OPENSSL_sk_num(stack.as_ptr().cast()) };
        for i in 0..count {
            // SAFETY: 0 <= i < count; the returned `GENERAL_NAME*`
            // is borrowed from the stack and remains valid until
            // `GENERAL_NAMES_free` runs (via the guard).
            let gn = unsafe { OPENSSL_sk_value(stack.as_ptr().cast(), i) }.cast::<GENERAL_NAME>();
            let Some(gn) = NonNull::new(gn) else { continue };
            let Some(san) = decode_general_name(gn.as_ptr()) else {
                continue;
            };
            if !f(san) {
                break;
            }
        }
        Ok(())
    }

    /// Walk the Subject DN, invoking `f` for each value of the
    /// `commonName` (NID 13) RDN. Returning `false` short-
    /// circuits. Useful for `radsecproxy`-style `CN:/regex/`
    /// matching even though RFC 6125 §6.4.4 deprecates CN-based
    /// identity for new deployments.
    pub(super) fn walk_common_names<F>(&self, mut f: F)
    where
        F: FnMut(String) -> bool,
    {
        // SAFETY: cert valid; X509_get_subject_name returns an
        // interior pointer that lives as long as the X509.
        let name = unsafe { X509_get_subject_name(self.0.as_ptr()) };
        if name.is_null() {
            return;
        }
        let mut loc: c_int = -1;
        loop {
            // SAFETY: `name` valid; -1 starts the search; the
            // function returns -1 when no further entries match.
            loc = unsafe { X509_NAME_get_index_by_NID(name, NID_commonName, loc) };
            if loc < 0 {
                break;
            }
            // SAFETY: `loc >= 0`; returned entry is interior to
            // the X509_NAME and lives as long as it does.
            let entry = unsafe { X509_NAME_get_entry(name, loc) };
            if entry.is_null() {
                continue;
            }
            // SAFETY: `entry` valid; returned ASN1_STRING is
            // interior and lives with the entry.
            let s = unsafe { X509_NAME_ENTRY_get_data(entry) };
            let Some(value) = read_asn1_string_utf8(s) else {
                continue;
            };
            if !f(value) {
                break;
            }
        }
    }
}

/// Decode a single `GENERAL_NAME*` into a [`SubjectAltName`].
/// Returns `None` for choices we don't model or for malformed
/// entries.
fn decode_general_name(gn: *const GENERAL_NAME) -> Option<SubjectAltName> {
    // SAFETY: caller passes a valid `GENERAL_NAME*` borrowed from
    // a live `GENERAL_NAMES` stack; we read `type_` before
    // touching the matching union arm.
    let ty = unsafe { (*gn).type_ };
    if ty == GEN_DNS {
        // SAFETY: type_ == GEN_DNS ⇒ d.dNSName is active.
        let s = unsafe { (*gn).d.dNSName };
        read_asn1_string_utf8(s).map(SubjectAltName::Dns)
    } else if ty == GEN_IPADD {
        // SAFETY: type_ == GEN_IPADD ⇒ d.iPAddress is active.
        let s = unsafe { (*gn).d.iPAddress };
        read_asn1_ip(s).map(SubjectAltName::Ip)
    } else if ty == GEN_URI {
        // SAFETY: type_ == GEN_URI ⇒ d.uniformResourceIdentifier
        // is active and points at an ASN1_IA5STRING.
        let s = unsafe { (*gn).d.uniformResourceIdentifier };
        read_asn1_string_utf8(s).map(SubjectAltName::Uri)
    } else if ty == GEN_RID {
        // SAFETY: type_ == GEN_RID ⇒ d.registeredID is active.
        let oid = unsafe { (*gn).d.registeredID };
        oid_to_dotted(oid).map(SubjectAltName::RegisteredId)
    } else if ty == GEN_OTHERNAME {
        // SAFETY: type_ == GEN_OTHERNAME ⇒ d.otherName is
        // active and points at an OTHERNAME { type_id, value }.
        let on = unsafe { (*gn).d.otherName };
        decode_other_name(on).map(SubjectAltName::OtherName)
    } else {
        None
    }
}

/// Format an `ASN1_OBJECT*` as a dotted-decimal OID string.
fn oid_to_dotted(oid: *const ASN1_OBJECT) -> Option<String> {
    if oid.is_null() {
        return None;
    }
    // OIDs in the wild rarely exceed ~80 characters; size the
    // buffer generously and bail if aws-lc reports a longer
    // representation than fits.
    let mut buf = [0u8; 256];
    // SAFETY: `oid` non-null and valid; `buf` is writable for
    // 256 bytes; `always_return_oid = 1` forces the dotted form
    // (so OID lookup tables don't render shortnames).
    let n = unsafe {
        OBJ_obj2txt(
            buf.as_mut_ptr().cast::<c_char>(),
            c_int::try_from(buf.len()).unwrap_or(c_int::MAX),
            oid,
            1,
        )
    };
    if n <= 0 {
        return None;
    }
    let n = usize::try_from(n).ok()?;
    if n >= buf.len() {
        return None;
    }
    std::str::from_utf8(&buf[..n]).ok().map(str::to_owned)
}

/// Decode an `OTHERNAME*` into the corresponding [`OtherNameSan`].
fn decode_other_name(on: *const OTHERNAME) -> Option<OtherNameSan> {
    if on.is_null() {
        return None;
    }
    // SAFETY: `on` non-null and valid for the lifetime of the
    // owning GENERAL_NAMES stack.
    let type_id = unsafe { (*on).type_id };
    let value = unsafe { (*on).value };
    let oid = oid_to_dotted(type_id)?;
    let der = i2d_asn1_type(value)?;
    Some(OtherNameSan { oid, value: der })
}

/// DER-encode an `ASN1_TYPE*` into an owned `Vec<u8>`.
fn i2d_asn1_type(value: *const ASN1_TYPE) -> Option<Vec<u8>> {
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` non-null. Calling i2d with a NULL `outp`
    // returns the encoded length without writing.
    let len = unsafe { i2d_ASN1_TYPE(value, std::ptr::null_mut()) };
    if len <= 0 {
        return None;
    }
    let len_usize = usize::try_from(len).ok()?;
    let mut out = vec![0u8; len_usize];
    let mut p = out.as_mut_ptr();
    // SAFETY: `&raw mut p` points to a writable `*mut u8`; aws-lc
    // advances the pointer by `len` bytes which we sized exactly
    // from the previous call.
    let written = unsafe { i2d_ASN1_TYPE(value, &raw mut p) };
    if written != len {
        return None;
    }
    Some(out)
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
///
/// The variants mirror the [GeneralName] choices that
/// `radsecproxy`'s `MatchCertificateAttribute` policy supports
/// (`SubjectAltName:DNS|IP|URI|rID|otherName:…`); the `radius-
/// tokio` library exposes raw values and leaves the matching
/// strategy (regex, wildcard, exact, …) to consumer code.
///
/// [GeneralName]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAltName {
    /// `dNSName` SAN entry. The contained string is the literal
    /// IA5/UTF-8 value as it appears in the certificate (no
    /// case-folding, no IDNA processing).
    Dns(String),
    /// `iPAddress` SAN entry. RFC 5280 fixes the wire encoding at
    /// 4 octets (IPv4) or 16 octets (IPv6).
    Ip(IpAddr),
    /// `uniformResourceIdentifier` SAN entry. The contained
    /// string is the literal IA5 value; no URI parsing or
    /// normalisation is performed.
    Uri(String),
    /// `registeredID` SAN entry, formatted as a dotted-decimal
    /// OID (e.g. `"1.3.6.1.4.1.311.20.2.3"`).
    RegisteredId(String),
    /// `otherName` SAN entry. Carries the type-id OID together
    /// with the DER encoding of the wrapped `ANY` value. The
    /// most common shape in the wild is the Microsoft UPN
    /// (`1.3.6.1.4.1.311.20.2.3`) wrapping a `UTF8String`;
    /// consumers that need the inner value should DER-decode
    /// `value` themselves.
    OtherName(OtherNameSan),
}

/// Payload of a [`SubjectAltName::OtherName`] entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherNameSan {
    /// Dotted-decimal OID identifying the value's type
    /// (e.g. `"1.3.6.1.4.1.311.20.2.3"` for the Microsoft UPN).
    pub oid: String,
    /// DER encoding of the wrapped `ANY` value (an `ASN1_TYPE`).
    /// Lossless: consumers can decode whichever inner type the
    /// OID dictates without information loss.
    pub value: Vec<u8>,
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
    /// extension. Recognises every GeneralName choice
    /// `radsecproxy`'s `MatchCertificateAttribute` policy
    /// supports — `dNSName`, `iPAddress`,
    /// `uniformResourceIdentifier`, `registeredID`, `otherName`.
    /// Choices outside that set are silently skipped.
    ///
    /// Consumers that only care about a single SAN type can
    /// avoid allocating the rejected entries by calling the
    /// per-type accessor instead — [`dns_names`](Self::dns_names),
    /// [`ip_addresses`](Self::ip_addresses), [`uris`](Self::uris),
    /// [`registered_ids`](Self::registered_ids), or
    /// [`other_names`](Self::other_names).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if the underlying decode fails.
    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, TlsError> {
        self.cert.subject_alt_names()
    }

    /// Common Name (CN) values from the leaf's Subject DN.
    ///
    /// A DN may contain zero or more `commonName` RDNs; this
    /// returns them in the order they appear. RFC 6125 §6.4.4
    /// deprecates CN-based identity for new deployments, but
    /// `radsecproxy`'s `CN:/regex/` match-type still relies on
    /// it and many enterprise PKIs continue to issue leaves whose
    /// only stable identifier is the CN.
    ///
    /// Independent of [`subject_alt_names`](Self::subject_alt_names):
    /// reads the Subject DN, not the SAN extension.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`Result`] for forward
    /// compatibility.
    pub fn common_names(&self) -> Result<Vec<String>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_common_names(|cn| {
            out.push(cn);
            true
        });
        Ok(out)
    }

    /// `dNSName` SAN entries only. Equivalent to
    /// [`subject_alt_names`](Self::subject_alt_names) followed
    /// by a filter, but skips allocation for non-DNS entries.
    ///
    /// # Errors
    ///
    /// See [`subject_alt_names`](Self::subject_alt_names).
    pub fn dns_names(&self) -> Result<Vec<String>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_sans(|san| {
            if let SubjectAltName::Dns(d) = san {
                out.push(d);
            }
            true
        })?;
        Ok(out)
    }

    /// `iPAddress` SAN entries only.
    ///
    /// # Errors
    ///
    /// See [`subject_alt_names`](Self::subject_alt_names).
    pub fn ip_addresses(&self) -> Result<Vec<IpAddr>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_sans(|san| {
            if let SubjectAltName::Ip(ip) = san {
                out.push(ip);
            }
            true
        })?;
        Ok(out)
    }

    /// `uniformResourceIdentifier` SAN entries only.
    ///
    /// # Errors
    ///
    /// See [`subject_alt_names`](Self::subject_alt_names).
    pub fn uris(&self) -> Result<Vec<String>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_sans(|san| {
            if let SubjectAltName::Uri(u) = san {
                out.push(u);
            }
            true
        })?;
        Ok(out)
    }

    /// `registeredID` SAN entries (formatted as dotted-decimal
    /// OIDs).
    ///
    /// # Errors
    ///
    /// See [`subject_alt_names`](Self::subject_alt_names).
    pub fn registered_ids(&self) -> Result<Vec<String>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_sans(|san| {
            if let SubjectAltName::RegisteredId(o) = san {
                out.push(o);
            }
            true
        })?;
        Ok(out)
    }

    /// `otherName` SAN entries.
    ///
    /// # Errors
    ///
    /// See [`subject_alt_names`](Self::subject_alt_names).
    pub fn other_names(&self) -> Result<Vec<OtherNameSan>, TlsError> {
        let mut out = Vec::new();
        self.cert.walk_sans(|san| {
            if let SubjectAltName::OtherName(o) = san {
                out.push(o);
            }
            true
        })?;
        Ok(out)
    }

    /// Identity-match `expected` against the leaf certificate using
    /// the RFC 6125 §6 / RFC 6614 §2.3 rules `radsecproxy`'s
    /// `certnamecheck` enforces.
    ///
    /// `expected` is interpreted as either a literal IP address
    /// (matched against `iPAddress` SAN entries) or a DNS hostname
    /// (matched against `dNSName` SAN entries, including a single
    /// leftmost `*` wildcard label).
    ///
    /// **CN gating.** Per RFC 6125 §6.4.4, when *any* SAN of the
    /// matching type (DNS or IP) is present, the Common Name MUST
    /// NOT be considered. CN is consulted only as a fallback for
    /// DNS hostnames on certificates that carry no DNS SANs at
    /// all, and only when `allow_common_name` is `true`. New
    /// deployments should pass `false`; existing deployments that
    /// need radsecproxy's `certcncheck` legacy behaviour pass
    /// `true`.
    ///
    /// Comparisons are ASCII case-insensitive (DNS labels are
    /// case-insensitive per RFC 1035 §2.3.3); IDNA / Unicode
    /// normalisation is *not* performed. Wildcard rules:
    ///
    /// * Wildcard appears only as the leftmost label and only as
    ///   the entire label (`*.example.com`, not `*foo.example.com`).
    /// * Wildcard matches exactly one label (`*.example.com` matches
    ///   `host.example.com` but not `host.sub.example.com`).
    /// * No wildcard is allowed in CN-fallback matching.
    ///
    /// Returns `true` iff `expected` matches at least one acceptable
    /// identifier on the certificate.
    #[must_use]
    pub fn matches_hostname(&self, expected: &str, allow_common_name: bool) -> bool {
        // Literal IP form: match SAN iPAddress only, regardless of
        // CN. Both v4 and v6.
        if let Ok(ip) = expected.parse::<IpAddr>() {
            let mut hit = false;
            // walk_sans short-circuits when the closure returns
            // `false`; once we find a match we stop.
            let _ = self.cert.walk_sans(|san| {
                if let SubjectAltName::Ip(san_ip) = san {
                    if san_ip == ip {
                        hit = true;
                        return false;
                    }
                }
                true
            });
            return hit;
        }

        // DNS form: match SAN dNSName entries (case-insensitive,
        // wildcard-aware). If *any* dNSName is present and none
        // matched, fail closed — RFC 6125 §6.4.4 forbids the CN
        // fallback.
        let mut any_dns = false;
        let mut hit = false;
        let _ = self.cert.walk_sans(|san| {
            if let SubjectAltName::Dns(name) = san {
                any_dns = true;
                if dns_name_matches(&name, expected) {
                    hit = true;
                    return false;
                }
            }
            true
        });
        if hit {
            return true;
        }
        if any_dns || !allow_common_name {
            return false;
        }

        // Legacy CN fallback. Exact case-insensitive match only;
        // no wildcard support — radsecproxy's `certcncheck` does
        // not treat CN values as wildcard-bearing patterns.
        let mut cn_hit = false;
        self.cert.walk_common_names(|cn| {
            if cn.eq_ignore_ascii_case(expected) {
                cn_hit = true;
                return false;
            }
            true
        });
        cn_hit
    }
}

/// Match a `dNSName` SAN value `presented` against the requested
/// hostname `expected` per RFC 6125 §6.4.3. Both inputs are
/// compared label-wise, case-insensitive ASCII; IDNA / U-label
/// processing is the caller's responsibility (consumers that need
/// it should normalize both sides before calling
/// [`PeerCertificate::matches_hostname`]).
fn dns_name_matches(presented: &str, expected: &str) -> bool {
    // Reject empty inputs and any presented value containing an
    // embedded NUL — both indicate a malformed certificate (or
    // a cert smuggling extra labels past a naive parser) and the
    // RFC 6125 algorithm only defines behaviour for well-formed
    // DNS names.
    if presented.is_empty() || expected.is_empty() {
        return false;
    }
    if presented.as_bytes().contains(&0) {
        return false;
    }

    // Strip a single trailing dot from each so "host.example.com"
    // and "host.example.com." compare equal.
    let presented = presented.strip_suffix('.').unwrap_or(presented);
    let expected = expected.strip_suffix('.').unwrap_or(expected);

    let p_labels: Vec<&str> = presented.split('.').collect();
    let e_labels: Vec<&str> = expected.split('.').collect();
    if p_labels.len() != e_labels.len() {
        return false;
    }
    // No empty labels (catches leading dots and ".." sequences).
    if p_labels.iter().any(|l| l.is_empty()) || e_labels.iter().any(|l| l.is_empty()) {
        return false;
    }

    for (i, (p, e)) in p_labels.iter().zip(e_labels.iter()).enumerate() {
        if i == 0 && *p == "*" {
            // Leftmost-only, full-label wildcard. Per RFC 6125
            // §6.4.3 we additionally require the expected name
            // to have at least three labels — a wildcard cert for
            // `*.com` is rejected.
            if e_labels.len() < 3 {
                return false;
            }
            // `*` matches exactly one label of any value (the
            // length check already guaranteed there *is* a label).
            continue;
        }
        // Reject partial-label wildcards (`f*o`, `*foo`, `foo*`)
        // outright — RFC 6125 §6.4.3 deprecates them and
        // radsecproxy treats them as no-match.
        if p.contains('*') {
            return false;
        }
        if !p.eq_ignore_ascii_case(e) {
            return false;
        }
    }
    true
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
        Self::build_server(cert_chain_pem, key_pem, Some(client_ca_pem))
    }

    /// Build a server-side context that does **not** require the
    /// peer to present a certificate.
    ///
    /// Used by EAP methods that tunnel a separate authentication
    /// exchange inside a server-authenticated TLS session
    /// (EAP-PEAP, EAP-TTLS, EAP-FAST): the supplicant proves who
    /// it is via the inner method (MS-CHAPv2, PAP, …) and the TLS
    /// channel only protects that exchange. Mandating a client
    /// certificate here would defeat the whole point.
    ///
    /// Compared to [`Self::server`]:
    /// * `install_client_cas` is skipped (no `CertificateRequest`
    ///   is sent during the handshake).
    /// * Verify mode is left at libssl's default (`SSL_VERIFY_NONE`
    ///   from the application's standpoint), so peers that do *not*
    ///   present a certificate are accepted.
    ///
    /// All other hardening matches [`Self::server`] verbatim: TLS
    /// 1.2 floor, key/cert pairing check, chain-depth cap, session
    /// tickets disabled.
    ///
    /// # Security caveat
    ///
    /// **Do not use this constructor for RadSec listeners.** RadSec
    /// requires mutual TLS (RFC 6614 §2.3); use [`Self::server`].
    /// This constructor is exclusively for EAP-PEAP / EAP-TTLS /
    /// EAP-FAST TLS sessions where authorization happens in an
    /// inner method.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] for any libssl init / parse / mismatch
    /// failure.
    pub fn server_without_client_auth(
        cert_chain_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, TlsError> {
        Self::build_server(cert_chain_pem, key_pem, None)
    }

    /// Shared body for [`Self::server`] and
    /// [`Self::server_without_client_auth`]. `client_ca_pem ==
    /// None` switches off mandatory mTLS.
    fn build_server(
        cert_chain_pem: &[u8],
        key_pem: &[u8],
        client_ca_pem: Option<&[u8]>,
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

        if let Some(pem) = client_ca_pem {
            // Trust anchors for the *client* certs. Required for
            // RadSec — see the doc comment on `server()` for why we
            // don't fall back to the platform store.
            install_client_cas(&ctx, pem)?;

            // Mandatory mTLS for RadSec: peer MUST present a cert
            // and its chain MUST validate against the configured
            // trust store. No application callback — passing
            // libssl's check *is* the gate.
            // SAFETY: ctx valid; passing `None` for the verify
            // callback tells libssl to use its built-in chain-
            // validation result verbatim.
            unsafe {
                SSL_CTX_set_verify(
                    ctx.0.as_ptr(),
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                    None,
                );
            }
            // Cap the accepted chain depth. RFC 5280 doesn't fix a
            // ceiling; `radsecproxy` uses 5 + 1 (leaf + 5
            // intermediates), which covers every realistic RadSec
            // PKI and rejects pathologically long cross-signed
            // chains predictably.
            // SAFETY: ctx valid; depth fits trivially in c_int.
            unsafe { SSL_CTX_set_verify_depth(ctx.0.as_ptr(), MAX_CERT_DEPTH) };
        }
        // No `else` branch: libssl defaults to `SSL_VERIFY_NONE`
        // (no `CertificateRequest`, peer cert is optional and not
        // chain-validated when absent). That is exactly what
        // EAP-PEAP / TTLS / FAST want.

        // Disable session resumption. RadSec connections are
        // long-lived (one per NAS, kept open for the device's
        // lifetime), so neither TLS 1.2 session tickets nor TLS 1.3
        // PSK resumption tickets buy anything — they only widen the
        // attack surface (ticket-key compromise → offline
        // decryption of recorded sessions). Match `radsecproxy`'s
        // posture.
        // SAFETY: ctx valid; SSL_CTX_set_options OR-merges the new
        // flags with the existing option mask and returns the new
        // value. The cast widens i32 to u32 — `SSL_OP_NO_TICKET` is
        // a positive bitflag (16384 today) and stays in range.
        #[allow(clippy::cast_sign_loss)]
        unsafe {
            SSL_CTX_set_options(ctx.0.as_ptr(), SSL_OP_NO_TICKET as u32);
        }
        // TLS 1.3: zero NewSessionTicket messages. Has no effect
        // pre-1.3, where `SSL_OP_NO_TICKET` already wins.
        // SAFETY: ctx valid.
        let _ = unsafe { SSL_CTX_set_num_tickets(ctx.0.as_ptr(), 0) };

        Ok(Self {
            inner: Arc::new(ctx),
        })
    }
}

/// Maximum certificate-chain depth accepted by RadSec listeners
/// (counted as the number of intermediates between the leaf and the
/// trust anchor). 5 matches `radsecproxy` and is comfortably above
/// every realistic RadSec PKI.
const MAX_CERT_DEPTH: c_int = 5;

/// RAII wrapper around a `STACK_OF(X509_NAME)*` that owns each entry
/// (i.e. `sk_pop_free(stack, X509_NAME_free)` semantics on Drop).
///
/// Used to build the CA distinguished-name list advertised to peers
/// in the TLS `CertificateRequest`. `SSL_CTX_set_client_CA_list`
/// takes ownership of the stack on success; on the success path we
/// surrender ownership via [`forget_into_ssl`] to suppress this
/// Drop.
struct X509NameStack(NonNull<aws_lc_sys::stack_st_X509_NAME>);

impl X509NameStack {
    fn new() -> Result<Self, TlsError> {
        // SAFETY: OPENSSL_sk_new_null allocates an empty stack;
        // NULL on OOM.
        let raw = unsafe { OPENSSL_sk_new_null() };
        NonNull::new(raw.cast::<aws_lc_sys::stack_st_X509_NAME>())
            .map(X509NameStack)
            .ok_or(TlsError::Init("OPENSSL_sk_new_null(X509_NAME)"))
    }

    /// Push a duplicated `X509_NAME` (the stack takes ownership of
    /// the duplicate; the caller's original is unaffected).
    fn push_dup(&mut self, name: *mut aws_lc_sys::X509_NAME) -> Result<(), TlsError> {
        // SAFETY: name is borrowed from a live X509; X509_NAME_dup
        // returns a freshly-allocated copy or NULL on OOM.
        let dup = unsafe { X509_NAME_dup(name) };
        if dup.is_null() {
            return Err(TlsError::Ssl(pop_err("X509_NAME_dup")));
        }
        // SAFETY: stack and dup both valid; OPENSSL_sk_push returns
        // 0 on failure, in which case we own `dup` and must free.
        let pushed = unsafe { OPENSSL_sk_push(self.0.as_ptr().cast(), dup.cast()) };
        if pushed == 0 {
            // SAFETY: dup is a freshly-allocated X509_NAME we own.
            unsafe { X509_NAME_free(dup) };
            return Err(TlsError::Ssl(pop_err("OPENSSL_sk_push(X509_NAME)")));
        }
        Ok(())
    }

    /// Surrender ownership to libssl. Returns the raw pointer and
    /// suppresses Drop.
    fn forget_into_ssl(self) -> *mut aws_lc_sys::stack_st_X509_NAME {
        let p = self.0.as_ptr();
        std::mem::forget(self);
        p
    }
}

impl Drop for X509NameStack {
    fn drop(&mut self) {
        // SAFETY: free each X509_NAME in the stack and the stack
        // itself. `sk_pop_free` is the documented matching free for
        // a stack we built with `OPENSSL_sk_new_null` + `sk_push`
        // when each entry needs an element-specific free function.
        unsafe {
            aws_lc_sys::sk_pop_free(self.0.as_ptr().cast(), Some(name_free_thunk));
        }
    }
}

// SAFETY: A FFI thunk that adapts `X509_NAME_free`'s signature to
// the `OPENSSL_sk_free_func` ABI (raw `*mut c_void`). The pointer
// `p` was pushed by `X509NameStack::push_dup` as an `X509_NAME*`
// allocated by `X509_NAME_dup`, so casting it back and calling
// `X509_NAME_free` is sound.
unsafe extern "C" fn name_free_thunk(p: *mut c_void) {
    if !p.is_null() {
        // SAFETY: see thunk-level comment above.
        unsafe { X509_NAME_free(p.cast()) };
    }
}

/// Install a chain of PEM-encoded client CAs as the `SSL_CTX`'s
/// trust store **and** as the CA distinguished-name list advertised
/// in the TLS `CertificateRequest`.
///
/// The DN list lets a NAS holding multiple client certificates pick
/// the one that chains to a trusted CA without guessing — a soft
/// interop requirement for RadSec deployments where peers may have
/// certs from several issuers.
fn install_client_cas(ctx: &SslCtx, pem: &[u8]) -> Result<(), TlsError> {
    // SAFETY: X509_STORE_new allocates an empty store; NULL on OOM.
    let store_raw = unsafe { X509_STORE_new() };
    let store = X509StoreOwned(NonNull::new(store_raw).ok_or(TlsError::Init("X509_STORE_new"))?);
    let mut name_stack = X509NameStack::new()?;

    let bio = new_mem_bio_readonly(pem)?;
    let mut found = false;
    loop {
        // SAFETY: bio valid; PEM_read_bio_X509 returns NULL when
        // there are no more cert blocks.
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
        // SAFETY: store + cert valid; bumps cert refcount on success.
        let r = unsafe { X509_STORE_add_cert(store.0.as_ptr(), cert.0.as_ptr()) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("X509_STORE_add_cert")));
        }
        // SAFETY: cert valid; X509_get_subject_name returns an
        // interior pointer borrowed from cert. `push_dup` calls
        // X509_NAME_dup so the stack does not alias cert.
        let subject = unsafe { X509_get_subject_name(cert.0.as_ptr()) };
        if !subject.is_null() {
            name_stack.push_dup(subject)?;
        }
        found = true;
        drop(cert);
    }
    drop(bio);
    if !found {
        return Err(TlsError::Pem("no CA certificates"));
    }

    // Hand the trust store to the SSL_CTX. `set1_` bumps the
    // refcount so we keep our ownership and Drop our copy.
    // SAFETY: ctx + store valid.
    unsafe { SSL_CTX_set1_cert_store(ctx.0.as_ptr(), store.0.as_ptr()) };
    drop(store);

    // Hand the DN list to the SSL_CTX. This call **takes ownership**
    // of the stack on success, so we surrender via `forget_into_ssl`.
    let stack_ptr = name_stack.forget_into_ssl();
    // SAFETY: ctx + stack valid; ownership transfer documented above.
    unsafe { SSL_CTX_set_client_CA_list(ctx.0.as_ptr(), stack_ptr) };
    Ok(())
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

    /// Borrow the ciphertext currently queued in the output BIO,
    /// without copying. The returned slice points directly at the
    /// BIO's internal buffer; it is valid until the next mutating
    /// call on this connection (write / process / consume_output /
    /// drop), which the borrow checker enforces via `&mut self`.
    ///
    /// Returns an empty slice if the BIO is empty.
    ///
    /// Pair with [`consume_output`](Self::consume_output) once the
    /// bytes have been pushed to the network — otherwise the next
    /// call returns the same bytes again.
    ///
    /// This is the zero-copy alternative to
    /// [`take_output`](Self::take_output) and is what the async
    /// transport adapter uses to avoid an extra `memcpy` per
    /// outbound TLS record.
    #[must_use]
    pub fn pending_output(&mut self) -> &[u8] {
        let mut ptr: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        // SAFETY: wbio is the memory BIO created in `accept`; the
        // out-pointers are stack slots we own. BIO_mem_contents
        // returns 1 on success and populates them with the BIO's
        // internal buffer pointer + length without consuming.
        let r = unsafe { BIO_mem_contents(self.wbio.as_ptr(), &raw mut ptr, &raw mut len) };
        if r != 1 || ptr.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: BIO_mem_contents handed us a non-NULL pointer to
        // `len` initialized bytes inside the BIO's own buffer. The
        // buffer is owned by the BIO and lives until the next
        // mutating BIO call. We tie the slice's lifetime to
        // `&mut self`, so the borrow checker forbids any such call
        // while the slice is live.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Discard everything currently queued in the output BIO.
    /// Call after a successful `pending_output` + network write.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Io`] if `BIO_reset` fails (should not
    /// happen for a memory BIO).
    pub fn consume_output(&mut self) -> Result<(), TlsError> {
        // SAFETY: wbio valid for the lifetime of `self`.
        if unsafe { BIO_reset(self.wbio.as_ptr()) } != 1 {
            return Err(TlsError::Io(pop_err("BIO_reset(wbio)")));
        }
        Ok(())
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

    /// Export keying material from the completed TLS session
    /// (RFC 5705 / RFC 8446 §7.5), the primitive every EAP method
    /// layered over TLS uses to derive its MSK + EMSK.
    ///
    /// Typical labels:
    /// - `"client EAP encryption"` — EAP-TLS (RFC 5216 §2.3),
    ///   EAP-TTLS (RFC 5281 §11), PEAPv0.
    /// - `"client PEAP encryption"` — PEAPv1.
    /// - `"EXPORTER_EAP_TLS_Key_Material"` — EAP-TLS over TLS 1.3
    ///   (RFC 9190 §2.3).
    ///
    /// EAP methods customarily request 128 bytes (`out_len = 128`),
    /// split as `MSK = out[0..64]`, `EMSK = out[64..128]`. The
    /// authentication server then takes `MSK[0..32]` as the
    /// MS-MPPE-Recv-Key and `MSK[32..64]` as the MS-MPPE-Send-Key
    /// (note the RECV/SEND order — that's RFC 5216 §2.3).
    ///
    /// `context` is the optional TLS-Exporter context value. Most
    /// EAP labels pass `None`; PEAPv1 / EAP-FAST pass method-specific
    /// bytes. A `Some(&[])` (empty slice) is **semantically different**
    /// from `None` per RFC 5705 §4 and we propagate that distinction
    /// to libssl via the `use_context` flag.
    ///
    /// # Errors
    ///
    /// - [`TlsError::Handshake`] — the handshake has not yet
    ///   finished; no keying material is available.
    /// - [`TlsError::Ssl`] — `SSL_export_keying_material` failed
    ///   (e.g. label exceeded libssl's length cap, or the
    ///   negotiated cipher suite forbids exporters).
    pub fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), TlsError> {
        if !self.handshake_done {
            return Err(TlsError::Handshake(
                "export_keying_material called before handshake completion".to_owned(),
            ));
        }
        let (ctx_ptr, ctx_len, use_context) = match context {
            // RFC 5705 §4: `use_context = 1` with `context_len = 0`
            // is the documented way to request the "empty context"
            // derivation, which differs from the no-context case.
            Some(c) => (c.as_ptr(), c.len(), 1 as c_int),
            None => (std::ptr::null::<u8>(), 0usize, 0 as c_int),
        };
        // SAFETY: ssl valid (Drop has not run); out slice is
        // exclusively borrowed for the call duration; label is
        // borrowed for the call and passed with its byte length
        // (not nul-terminated — libssl uses `label_len`, not
        // `strlen`); context pointer is either null with len 0 or a
        // valid borrow with matching length; numeric casts are
        // checked below.
        let r = unsafe {
            SSL_export_keying_material(
                self.ssl.0.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr().cast::<c_char>(),
                label.len(),
                ctx_ptr,
                ctx_len,
                use_context,
            )
        };
        if r == 1 {
            Ok(())
        } else {
            Err(TlsError::Ssl(pop_err("SSL_export_keying_material")))
        }
    }

    /// Send a TLS `close_notify` alert.
    ///
    /// `SSL_shutdown` is the proper way to terminate a TLS session:
    /// without it the peer logs a truncation / abrupt-close and may
    /// (legitimately) treat the connection as suspect. We perform
    /// the *first half* of the bidirectional shutdown here — the
    /// caller is expected to drain any produced ciphertext via
    /// [`pending_output`](Self::pending_output) /
    /// [`take_output`](Self::take_output) and write it to the
    /// network, then close the socket. Waiting for the peer's
    /// reciprocal `close_notify` would block the connection task on
    /// teardown for no real benefit on RadSec, where the upper
    /// layer is already done.
    ///
    /// Returns `true` if the shutdown was initiated (or was already
    /// complete); `false` if libssl reported a non-recoverable
    /// error. Either way the caller should drop the connection
    /// after attempting to flush the output BIO.
    pub fn shutdown(&mut self) -> bool {
        // SAFETY: ssl valid. `SSL_shutdown` returns:
        //   1  — bidirectional shutdown complete
        //   0  — close_notify sent, peer's not yet received
        //  <0  — error (or WANT_READ/WANT_WRITE)
        let r = unsafe { SSL_shutdown(self.ssl.0.as_ptr()) };
        if r >= 0 {
            return true;
        }
        // SAFETY: ssl valid.
        let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), r) };
        matches!(err, SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE)
    }

    /// Request a TLS 1.3 traffic-key update (RFC 8446 §4.6.3).
    ///
    /// Used by the RadSec connection driver to bound the data
    /// volume protected by a single set of traffic keys on
    /// long-lived sessions. No-op (returns `Ok(false)`) if the
    /// negotiated protocol is below TLS 1.3 or if a key update is
    /// already in flight. The produced ciphertext is queued in the
    /// output BIO and must be drained by the caller in the usual
    /// way.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Ssl`] if libssl rejects the request
    /// (shouldn't happen for a healthy session).
    pub fn request_key_update(&mut self) -> Result<bool, TlsError> {
        // SAFETY: ssl valid; SSL_version returns the negotiated
        // protocol number once the handshake has completed.
        let version = unsafe { SSL_version(self.ssl.0.as_ptr()) };
        if version < TLS1_3_VERSION {
            return Ok(false);
        }
        // SAFETY: ssl valid; returns SSL_KEY_UPDATE_NONE if no
        // update is queued, otherwise the in-flight type.
        let pending = unsafe { SSL_get_key_update_type(self.ssl.0.as_ptr()) };
        if pending != SSL_KEY_UPDATE_NONE {
            return Ok(false);
        }
        // SAFETY: ssl valid; the constant comes from aws-lc's
        // bindings. Returns 1 on success, 0 on failure.
        let r = unsafe { SSL_key_update(self.ssl.0.as_ptr(), SSL_KEY_UPDATE_REQUESTED) };
        if r != 1 {
            return Err(TlsError::Ssl(pop_err("SSL_key_update")));
        }
        Ok(true)
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
