//! Shared test fixtures: PKI builder and a minimal in-process
//! TLS client used to drive the (server-only) wrapper from tests
//! without pulling in another TLS library.
//!
//! `cfg(test)` only — never compiled into release artefacts.

#![allow(
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::unnecessary_wraps,
    clippy::missing_panics_doc
)]

// -----------------------------------------------------------------
// Cert fixtures (built on the in-tree `pki` module; dev-only)
// -----------------------------------------------------------------

pub(crate) struct Pki {
    pub server_chain_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
    pub client_chain_pem: Vec<u8>,
    pub client_key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

pub(crate) fn build_pki() -> Pki {
    use crate::crypto::pki::{CertificateAuthority, SubjectAltName};

    let ca = CertificateAuthority::new("test-ca").unwrap();
    let server = ca
        .issue_server("radsec.test", &[SubjectAltName::Dns("radsec.test".into())])
        .unwrap();
    let client = ca
        .issue_client("nas-1", &[SubjectAltName::Dns("nas-1".into())])
        .unwrap();

    Pki {
        server_chain_pem: server.chain_pem,
        server_key_pem: server.key_pem,
        client_chain_pem: client.chain_pem,
        client_key_pem: client.key_pem,
        ca_pem: ca.cert_pem().to_vec(),
    }
}

// -----------------------------------------------------------------
// Test-only client-side TLS wrapper.
//
// Mirrors the server wrapper's memory-BIO architecture so callers
// can pump bytes between client and server (in-process or over a
// real TCP socket). Reuses the parent module's owned-handle
// newtypes so Drop cleanliness matches production.
// -----------------------------------------------------------------

pub(crate) mod client_side {
    use super::super::{pop_err, BioOwned, EvpPkeyOwned, SslCtx, SslHandle, TlsError, X509Owned};
    use std::ffi::c_void;
    use std::ptr::NonNull;

    use aws_lc_sys::{
        BIO_new, BIO_read, BIO_s_mem, BIO_write, PEM_read_bio_PrivateKey, PEM_read_bio_X509,
        SSL_CTX_check_private_key, SSL_CTX_new, SSL_CTX_set_verify, SSL_CTX_use_PrivateKey,
        SSL_CTX_use_certificate, SSL_connect, SSL_get_error, SSL_new, SSL_read, SSL_set_bio,
        SSL_write, TLS_client_method, X509_STORE_add_cert, X509_STORE_new, X509_free, BIO,
        SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN, SSL_VERIFY_PEER,
    };

    pub struct ClientSsl {
        ssl: SslHandle,
        rbio: NonNull<BIO>,
        wbio: NonNull<BIO>,
        _ctx: SslCtx,
        done: bool,
    }

    pub struct ClientBuilder {
        ctx: SslCtx,
    }

    pub fn builder(ca_pem: &[u8]) -> Result<ClientBuilder, TlsError> {
        // SAFETY: TLS_client_method returns a static pointer.
        let method = unsafe { TLS_client_method() };
        // SAFETY: NULL on OOM.
        let raw = unsafe { SSL_CTX_new(method) };
        let ctx = SslCtx(NonNull::new(raw).ok_or(TlsError::Init("SSL_CTX_new client"))?);
        // SAFETY: stores allocated empty.
        let store = unsafe { X509_STORE_new() };
        let store_nn = NonNull::new(store).ok_or(TlsError::Init("X509_STORE_new"))?;
        // SAFETY: BIO_new with positive length.
        let bio_raw = unsafe {
            aws_lc_sys::BIO_new_mem_buf(
                ca_pem.as_ptr().cast::<c_void>(),
                isize::try_from(ca_pem.len()).unwrap(),
            )
        };
        let bio = BioOwned(NonNull::new(bio_raw).ok_or(TlsError::Init("BIO_new_mem_buf"))?);
        loop {
            // SAFETY: bio valid; PEM_read_bio_X509 returns NULL when done.
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
            // SAFETY: store + cert valid.
            let r = unsafe { X509_STORE_add_cert(store_nn.as_ptr(), raw) };
            // SAFETY: refcount bumped by add_cert; we drop our copy.
            unsafe { X509_free(raw) };
            if r != 1 {
                return Err(TlsError::Ssl("X509_STORE_add_cert".into()));
            }
        }
        drop(bio);
        // SAFETY: ctx + store valid.
        unsafe { aws_lc_sys::SSL_CTX_set1_cert_store(ctx.0.as_ptr(), store_nn.as_ptr()) };
        // SAFETY: store still owned; free our copy.
        unsafe { aws_lc_sys::X509_STORE_free(store_nn.as_ptr()) };
        // SAFETY: ctx valid; passing NULL callback uses libssl's
        // default chain check.
        unsafe { SSL_CTX_set_verify(ctx.0.as_ptr(), SSL_VERIFY_PEER, None) };
        Ok(ClientBuilder { ctx })
    }

    impl ClientBuilder {
        pub fn with_client_cert(self, chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
            // SAFETY: BIO_new_mem_buf with positive length.
            let bio_raw = unsafe {
                aws_lc_sys::BIO_new_mem_buf(
                    chain_pem.as_ptr().cast::<c_void>(),
                    isize::try_from(chain_pem.len()).unwrap(),
                )
            };
            let bio = BioOwned(NonNull::new(bio_raw).ok_or(TlsError::Init("BIO_new_mem_buf"))?);
            // SAFETY: bio valid.
            let cert_raw = unsafe {
                PEM_read_bio_X509(
                    bio.0.as_ptr(),
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null_mut(),
                )
            };
            drop(bio);
            let cert = X509Owned(NonNull::new(cert_raw).ok_or(TlsError::Pem("client cert"))?);
            let bio_raw = unsafe {
                aws_lc_sys::BIO_new_mem_buf(
                    key_pem.as_ptr().cast::<c_void>(),
                    isize::try_from(key_pem.len()).unwrap(),
                )
            };
            let bio = BioOwned(NonNull::new(bio_raw).ok_or(TlsError::Init("BIO_new_mem_buf"))?);
            // SAFETY: bio valid.
            let key_raw = unsafe {
                PEM_read_bio_PrivateKey(
                    bio.0.as_ptr(),
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null_mut(),
                )
            };
            drop(bio);
            let key = EvpPkeyOwned(NonNull::new(key_raw).ok_or(TlsError::Pem("client key"))?);
            // SAFETY: ctx + cert valid.
            let r = unsafe { SSL_CTX_use_certificate(self.ctx.0.as_ptr(), cert.0.as_ptr()) };
            if r != 1 {
                return Err(TlsError::Ssl("SSL_CTX_use_certificate (client)".into()));
            }
            // SAFETY: ctx + key valid.
            let r = unsafe { SSL_CTX_use_PrivateKey(self.ctx.0.as_ptr(), key.0.as_ptr()) };
            if r != 1 {
                return Err(TlsError::Ssl("SSL_CTX_use_PrivateKey (client)".into()));
            }
            // SAFETY: ctx valid.
            let r = unsafe { SSL_CTX_check_private_key(self.ctx.0.as_ptr()) };
            if r != 1 {
                return Err(TlsError::KeyMismatch);
            }
            Ok(self)
        }

        pub fn build(self) -> Result<ClientSsl, TlsError> {
            // SAFETY: ctx valid.
            let raw = unsafe { SSL_new(self.ctx.0.as_ptr()) };
            let ssl = SslHandle(NonNull::new(raw).ok_or(TlsError::Init("SSL_new client"))?);
            // SAFETY: BIO_new with static method.
            let r_raw = unsafe { BIO_new(BIO_s_mem()) };
            let w_raw = unsafe { BIO_new(BIO_s_mem()) };
            let r_bio = BioOwned(NonNull::new(r_raw).ok_or(TlsError::Init("BIO_new(rbio)"))?);
            let w_bio = BioOwned(NonNull::new(w_raw).ok_or(TlsError::Init("BIO_new(wbio)"))?);
            let r_ptr = r_bio.forget_into_ssl();
            let w_ptr = w_bio.forget_into_ssl();
            // SAFETY: ssl + bios valid.
            unsafe { SSL_set_bio(ssl.0.as_ptr(), r_ptr, w_ptr) };
            Ok(ClientSsl {
                ssl,
                rbio: NonNull::new(r_ptr).unwrap(),
                wbio: NonNull::new(w_ptr).unwrap(),
                _ctx: self.ctx,
                done: false,
            })
        }
    }

    impl ClientSsl {
        pub fn process(&mut self) -> Result<super::super::HandshakeState, TlsError> {
            if self.done {
                return Ok(super::super::HandshakeState::Established);
            }
            // SAFETY: ssl valid.
            let r = unsafe { SSL_connect(self.ssl.0.as_ptr()) };
            if r == 1 {
                self.done = true;
                return Ok(super::super::HandshakeState::Established);
            }
            // SAFETY: ssl valid.
            let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), r) };
            match err {
                SSL_ERROR_WANT_READ => Ok(super::super::HandshakeState::NeedsRead),
                SSL_ERROR_WANT_WRITE => Ok(super::super::HandshakeState::NeedsWrite),
                _ => Err(TlsError::Handshake(pop_err("SSL_connect"))),
            }
        }

        pub fn feed_input(&mut self, bytes: &[u8]) -> Result<(), TlsError> {
            if bytes.is_empty() {
                return Ok(());
            }
            // SAFETY: rbio valid for the life of self.
            let n = unsafe {
                BIO_write(
                    self.rbio.as_ptr(),
                    bytes.as_ptr().cast::<c_void>(),
                    std::ffi::c_int::try_from(bytes.len()).unwrap_or(i32::MAX),
                )
            };
            if n < 0 {
                return Err(TlsError::Io("BIO_write client".into()));
            }
            Ok(())
        }

        pub fn take_output(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
            if out.is_empty() {
                return Ok(0);
            }
            // SAFETY: wbio valid for the life of self.
            let n = unsafe {
                BIO_read(
                    self.wbio.as_ptr(),
                    out.as_mut_ptr().cast::<c_void>(),
                    std::ffi::c_int::try_from(out.len()).unwrap_or(i32::MAX),
                )
            };
            if n < 0 {
                return Ok(0);
            }
            Ok(usize::try_from(n).unwrap())
        }

        /// Encrypt `bytes`. Returns plaintext bytes accepted; the
        /// caller drains ciphertext via `take_output`.
        pub fn write(&mut self, bytes: &[u8]) -> Result<usize, TlsError> {
            if bytes.is_empty() {
                return Ok(0);
            }
            // SAFETY: ssl valid.
            let n = unsafe {
                SSL_write(
                    self.ssl.0.as_ptr(),
                    bytes.as_ptr().cast::<c_void>(),
                    std::ffi::c_int::try_from(bytes.len()).unwrap_or(i32::MAX),
                )
            };
            if n > 0 {
                return Ok(usize::try_from(n).unwrap());
            }
            // SAFETY: ssl valid.
            let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), n) };
            match err {
                SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => Ok(0),
                _ => Err(TlsError::Io(pop_err("SSL_write client"))),
            }
        }

        /// Decrypt into `out`. Returns 0 if more ciphertext is
        /// needed or on clean close-notify.
        pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
            if out.is_empty() {
                return Ok(0);
            }
            // SAFETY: ssl valid.
            let n = unsafe {
                SSL_read(
                    self.ssl.0.as_ptr(),
                    out.as_mut_ptr().cast::<c_void>(),
                    std::ffi::c_int::try_from(out.len()).unwrap_or(i32::MAX),
                )
            };
            if n > 0 {
                return Ok(usize::try_from(n).unwrap());
            }
            // SAFETY: ssl valid.
            let err = unsafe { SSL_get_error(self.ssl.0.as_ptr(), n) };
            match err {
                SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE | SSL_ERROR_ZERO_RETURN => Ok(0),
                _ => Err(TlsError::Io(pop_err("SSL_read client"))),
            }
        }
    }
}
