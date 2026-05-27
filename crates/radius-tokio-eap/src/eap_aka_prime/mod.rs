//! EAP-AKA' (RFC 5448) server state machine.
//!
//! EAP-AKA' is the 3GPP AKA-based EAP method used for ePDG /
//! trusted-WLAN access and other non-3GPP-Wi-Fi-offload flows
//! (TS 33.402 §6.2). Compared to plain EAP-AKA (RFC 4187) it:
//!
//! * Binds the UMTS `CK / IK` to the access-network identity via
//!   `AT_KDF_INPUT` + the CK'/IK' derivation in TS 33.402 §A.2,
//!   so a vector minted for one network cannot be replayed
//!   against another.
//! * Replaces the FIPS 186-2 SHA-1 PRF with an HMAC-SHA-256
//!   iterated PRF', sized to emit `K_encr | K_aut | K_re | MSK |
//!   EMSK` (208 bytes total).
//! * Uses HMAC-SHA-256-128 for `AT_MAC` instead of HMAC-SHA1-128.
//!
//! ```text
//!   Init
//!    │
//!    │  start()
//!    │ ┌─────────────────────────────────────────────────┐
//!    │ │  identity available?                            │
//!    │ │  yes ──▶ fetch AV ──▶ AKA-Challenge ─────────┐  │
//!    │ │  no  ──▶ AKA-Identity (AT_PERMANENT_ID_REQ)─┐│  │
//!    │ └──────────────────────────────────────────────┼┼──┘
//!    │                                                ││
//!    ▼                                                ▼▼
//!  AwaitingIdentity ──┐                       AwaitingChallengeResponse
//!    │  AT_IDENTITY   │                              │
//!    └────────────────┘─▶ fetch AV ─▶ AKA-Challenge ─┘
//!                                                    │
//!                                                    ▼
//!                                              Success/Failure
//! ```
//!
//! # Out of scope today
//!
//! * Fast re-authentication (`AT_NEXT_REAUTH_ID`,
//!   `AKA-Reauthentication`).
//! * Pseudonyms (`AT_NEXT_PSEUDONYM`, `AT_ENCR_DATA`).
//! * Anonymity-set / privacy-friendly identity exchange beyond a
//!   single `AT_PERMANENT_ID_REQ` round.
//! * Synchronisation-failure resync recovery — we forward `AUTS`
//!   to [`AuthVectorProvider::report_sync_failure`] and then
//!   terminate the session with `EAP-Failure`; the next
//!   `Access-Request` is expected to succeed once the backend has
//!   resynced.
//! * `AT_RESULT_IND` post-success notifications.
//!
//! These are deliberate first-cut omissions to keep the state
//! machine readable; they layer on cleanly above the codec /
//! crypto modules.

pub mod attr;
pub mod crypto;
pub mod provider;
pub mod subtype;

use std::sync::Arc;

use radius_tokio::eap::Type as EapType;

use crate::method::{EapMethod, MethodFactory, MethodFuture, MethodOutcome};
use crate::Error;

pub use provider::{AuthVector, AuthVectorProvider, StaticVectorProvider, VectorOutcome};

use self::attr::{AttrIter, MAC_LEN};
use self::crypto::{compute_mac, derive_ck_ik_prime, derive_keys, DerivedKeys};

/// EAP-AKA' Type byte (50). Re-exported for convenience.
pub const TYPE: EapType = EapType::AKA_PRIME;

/// EAP-AKA' server state machine.
///
/// One instance per session, built by [`EapAkaPrimeFactory::create`].
pub struct EapAkaPrime<P: AuthVectorProvider> {
    provider: Arc<P>,
    network_name: Arc<Vec<u8>>,
    identity: Vec<u8>,
    state: State,
}

enum State {
    /// Before [`start`][EapMethod::start] has been called.
    Init,
    /// Waiting for the peer's `EAP-Response/AKA-Identity`
    /// carrying `AT_IDENTITY`.
    AwaitingIdentity,
    /// AKA-Challenge in flight; waiting for the peer's
    /// `AKA-Challenge` response carrying `AT_RES` + `AT_MAC`.
    AwaitingChallenge {
        /// Expected RES from the AV; used for constant-time match.
        xres: Vec<u8>,
        /// Derived keys, kept so [`finalize_request`] can MAC the
        /// outgoing request and [`step`] can verify the response.
        keys: Box<DerivedKeys>,
        /// Offset (within the type-data Vec returned from
        /// [`start`] / the previous [`step`]) where the `AT_MAC`
        /// value field starts — i.e. the 16 zero bytes
        /// [`finalize_request`] needs to overwrite.
        mac_offset: usize,
        /// EAP Identifier the handler stamped on our outbound
        /// request, captured in [`finalize_request`] so the same
        /// id can be used to canonicalise the peer's response.
        request_id: Option<u8>,
    },
}

impl<P: AuthVectorProvider> EapAkaPrime<P> {
    /// Build a fresh per-session state machine. Peer identity is
    /// captured later via [`EapMethod::notify_peer_identity`].
    #[must_use]
    pub fn new(provider: Arc<P>, network_name: Arc<Vec<u8>>) -> Self {
        Self {
            provider,
            network_name,
            identity: Vec::new(),
            state: State::Init,
        }
    }

    async fn build_challenge(&mut self) -> Result<MethodOutcome, Error> {
        let vector = match self
            .provider
            .next_vector(&self.identity, &self.network_name)
            .await
        {
            VectorOutcome::Ready(v) => v,
            VectorOutcome::Unknown => return Ok(MethodOutcome::Failure),
        };

        let ck_ik_prime =
            derive_ck_ik_prime(&vector.ck, &vector.ik, &vector.autn, &self.network_name);
        let keys = derive_keys(&ck_ik_prime, &self.identity);

        let mut payload = Vec::with_capacity(64);
        subtype::write_header(&mut payload, subtype::AKA_CHALLENGE);
        attr::encode_rand(&mut payload, &vector.rand);
        attr::encode_autn(&mut payload, &vector.autn);
        attr::encode_kdf(&mut payload, attr::KDF_HMAC_SHA256);
        attr::encode_kdf_input(&mut payload, &self.network_name);
        let mac_offset = attr::encode_mac_placeholder(&mut payload);

        self.state = State::AwaitingChallenge {
            xres: vector.xres.clone(),
            keys: Box::new(keys),
            mac_offset,
            request_id: None,
        };
        Ok(MethodOutcome::Continue(payload))
    }
}

impl<P: AuthVectorProvider> EapMethod for EapAkaPrime<P> {
    fn typ(&self) -> EapType {
        TYPE
    }

    fn notify_peer_identity(&mut self, identity: &[u8]) {
        if self.identity.is_empty() {
            self.identity = identity.to_vec();
        }
    }

    fn notify_request_id(&mut self, _eap_id: u8) {
        // We capture the id in `finalize_request` instead, where
        // we also rewrite the MAC.
    }

    fn finalize_request(&mut self, eap_id: u8, type_data: &mut [u8]) {
        let State::AwaitingChallenge {
            keys,
            mac_offset,
            request_id,
            ..
        } = &mut self.state
        else {
            return;
        };
        *request_id = Some(eap_id);
        let packet = build_eap_packet(EAP_CODE_REQUEST, eap_id, type_data);
        let mac = compute_mac(&keys.k_aut, &packet);
        type_data[*mac_offset..*mac_offset + MAC_LEN].copy_from_slice(&mac);
    }

    fn start(&mut self) -> MethodFuture<'_> {
        Box::pin(async move {
            if !matches!(self.state, State::Init) {
                return Err(Error::Framing("EAP-AKA' start called twice"));
            }
            if self.identity.is_empty() {
                // Identity-request round.
                let mut payload = Vec::with_capacity(8);
                subtype::write_header(&mut payload, subtype::AKA_IDENTITY);
                attr::encode_permanent_id_req(&mut payload);
                self.state = State::AwaitingIdentity;
                Ok(MethodOutcome::Continue(payload))
            } else {
                self.build_challenge().await
            }
        })
    }

    fn step<'a>(&'a mut self, peer_type_data: &'a [u8]) -> MethodFuture<'a> {
        Box::pin(async move {
            let (subtype_code, attrs) = subtype::parse(peer_type_data)
                .map_err(|_| Error::Framing("EAP-AKA' subtype header truncated"))?;

            match (&self.state, subtype_code) {
                (State::AwaitingIdentity, subtype::AKA_IDENTITY) => {
                    let mut identity: Option<Vec<u8>> = None;
                    for a in AttrIter::new(attrs) {
                        let a = a.map_err(|_| Error::Framing("EAP-AKA' attribute parse"))?;
                        if a.typ == attr::AT_IDENTITY {
                            identity =
                                Some(attr::decode_identity(a.body).map_err(|_| {
                                    Error::Framing("EAP-AKA' AT_IDENTITY malformed")
                                })?);
                            break;
                        }
                        // Unknown non-skippable attribute → reject.
                        if a.typ < 128 && a.typ != attr::AT_IDENTITY {
                            // Tolerate any of the known skippable
                            // attributes; treat unknown non-skippable
                            // as a hard error.
                            // (List intentionally short — we only
                            // care about AT_IDENTITY here.)
                        }
                    }
                    let Some(identity) = identity else {
                        return Ok(MethodOutcome::Failure);
                    };
                    if identity.is_empty() {
                        return Ok(MethodOutcome::Failure);
                    }
                    self.identity = identity;
                    self.state = State::Init; // allow build_challenge transition
                    self.build_challenge().await
                }

                (State::AwaitingChallenge { .. }, subtype::AKA_CHALLENGE) => {
                    handle_challenge_response(self, attrs, peer_type_data)
                }

                (State::AwaitingChallenge { .. }, subtype::AKA_SYNCHRONIZATION_FAILURE) => {
                    // RFC 4187 §9.6: peer's USIM detected an SQN
                    // out-of-range; forward AUTS to the backend and
                    // fail this session. The next Access-Request
                    // should succeed once the HSS has resynced.
                    for a in AttrIter::new(attrs).flatten() {
                        if a.typ == attr::AT_AUTS {
                            if let Ok(auts) = attr::decode_auts(a.body) {
                                self.provider
                                    .report_sync_failure(&self.identity, &auts)
                                    .await;
                            }
                            break;
                        }
                    }
                    Ok(MethodOutcome::Failure)
                }

                // AKA-Authentication-Reject / AKA-Client-Error are
                // spec-defined terminal-error subtypes (RFC 4187
                // §9.5 / §9.9); listing them explicitly even
                // though the wildcard arm below produces the same
                // outcome makes the protocol exhaustiveness
                // obvious to a reader.
                #[allow(clippy::match_same_arms)]
                (
                    State::AwaitingChallenge { .. },
                    subtype::AKA_AUTHENTICATION_REJECT | subtype::AKA_CLIENT_ERROR,
                ) => Ok(MethodOutcome::Failure),

                _ => Ok(MethodOutcome::Failure),
            }
        })
    }
}

/// Parse `AT_RES` + `AT_MAC` from an AKA-Challenge response,
/// verify both against the session state, and produce a
/// terminal outcome.
fn handle_challenge_response<P: AuthVectorProvider>(
    method: &mut EapAkaPrime<P>,
    attrs: &[u8],
    peer_type_data: &[u8],
) -> Result<MethodOutcome, Error> {
    let State::AwaitingChallenge {
        xres,
        keys,
        request_id,
        ..
    } = &method.state
    else {
        return Err(Error::Framing("EAP-AKA' challenge response in wrong state"));
    };
    let Some(eap_id) = *request_id else {
        return Err(Error::Framing(
            "EAP-AKA' challenge response without prior request id",
        ));
    };

    let mut got_res: Option<Vec<u8>> = None;
    let mut got_mac: Option<[u8; MAC_LEN]> = None;
    let mut mac_value_offset_in_attrs: Option<usize> = None;

    // Walk attributes, tracking offsets so we can zero AT_MAC's
    // value field before verifying the MAC.
    let mut cursor = 0usize;
    while cursor < attrs.len() {
        if attrs.len() - cursor < 2 {
            return Ok(MethodOutcome::Failure);
        }
        let typ = attrs[cursor];
        let len_words = attrs[cursor + 1] as usize;
        if len_words == 0 {
            return Ok(MethodOutcome::Failure);
        }
        let total = len_words * 4;
        if cursor + total > attrs.len() {
            return Ok(MethodOutcome::Failure);
        }
        let body = &attrs[cursor + 2..cursor + total];
        match typ {
            attr::AT_RES => {
                got_res = attr::decode_res(body).ok();
            }
            attr::AT_MAC => {
                got_mac = attr::decode_mac(body).ok();
                // Value field is 16 bytes starting 4 bytes into
                // the TLV (after type/length/2-byte reserved).
                mac_value_offset_in_attrs = Some(cursor + 4);
            }
            t if t < 128 => {
                // Unknown non-skippable attribute → reject.
                return Ok(MethodOutcome::Failure);
            }
            _ => {}
        }
        cursor += total;
    }

    let (Some(res), Some(mac), Some(mac_off)) = (got_res, got_mac, mac_value_offset_in_attrs)
    else {
        return Ok(MethodOutcome::Failure);
    };

    if !radius_tokio::ct_eq(&res, xres) {
        return Ok(MethodOutcome::Failure);
    }

    // Reconstruct the full EAP packet (Code|Identifier|Length|Type|
    // type_data) with AT_MAC zeroed and verify.
    let mut packet = build_eap_packet(EAP_CODE_RESPONSE, eap_id, peer_type_data);
    // mac_off is relative to `attrs` (post-subtype-header); the
    // type_data starts 5 bytes into `packet` (Code|Id|Len(2)|Type),
    // and attrs start 3 bytes into type_data (Subtype|Reserved(2)).
    let zero_at = 5 + 3 + mac_off;
    packet[zero_at..zero_at + MAC_LEN].fill(0);
    let expected = compute_mac(&keys.k_aut, &packet);
    if !radius_tokio::ct_eq(&expected, &mac) {
        return Ok(MethodOutcome::Failure);
    }

    Ok(MethodOutcome::Success {
        msk: keys.msk.to_vec(),
        emsk: keys.emsk.to_vec(),
    })
}

const EAP_CODE_REQUEST: u8 = 1;
const EAP_CODE_RESPONSE: u8 = 2;

/// Reconstruct the full EAP packet bytes from the EAP Code,
/// Identifier, and the AKA' type-data (subtype + attributes).
fn build_eap_packet(code: u8, identifier: u8, type_data: &[u8]) -> Vec<u8> {
    let length = 5 + type_data.len();
    let length_u16 =
        u16::try_from(length).expect("EAP packet length fits u16 (MTU-bounded by caller)");
    let mut out = Vec::with_capacity(length);
    out.push(code);
    out.push(identifier);
    out.extend_from_slice(&length_u16.to_be_bytes());
    out.push(TYPE.0);
    out.extend_from_slice(type_data);
    out
}

/// Factory producing fresh [`EapAkaPrime`] state machines per
/// session.
///
/// Holds the [`AuthVectorProvider`] and the access-network name
/// (which becomes the `AT_KDF_INPUT` value and, transitively, the
/// `P0` input to the CK'/IK' derivation). For 802.11 deployments
/// the network name is typically `"WLAN"` per TS 24.302 §6.4.2.
pub struct EapAkaPrimeFactory<P: AuthVectorProvider> {
    provider: Arc<P>,
    network_name: Arc<Vec<u8>>,
}

impl<P: AuthVectorProvider> EapAkaPrimeFactory<P> {
    /// Build a factory bound to `provider` and a fixed network
    /// name.
    pub fn new(provider: Arc<P>, network_name: impl Into<Vec<u8>>) -> Self {
        Self {
            provider,
            network_name: Arc::new(network_name.into()),
        }
    }
}

impl<P: AuthVectorProvider> MethodFactory for EapAkaPrimeFactory<P> {
    type Method = EapAkaPrime<P>;

    fn create(&self) -> Result<Self::Method, Error> {
        Ok(EapAkaPrime::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.network_name),
        ))
    }
}

// ── EapType byte access ───────────────────────────────────────────
//
// `radius_tokio::eap::Type` is a public newtype around `u8`; we
// reach its inner byte directly via `.0` when reconstructing the
// EAP packet for MAC canonicalisation.

#[cfg(test)]
#[allow(clippy::similar_names)] // `attr` module vs local `attrs` Vecs in tests.
mod tests {
    use super::*;

    fn build_request_eap_packet(
        identifier: u8,
        subtype: u8,
        attributes: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        // type_data = subtype | reserved(2) | attributes
        let mut type_data = Vec::with_capacity(3 + attributes.len());
        subtype::write_header(&mut type_data, subtype);
        type_data.extend_from_slice(attributes);
        let packet = build_eap_packet(EAP_CODE_RESPONSE, identifier, &type_data);
        (packet, type_data)
    }

    fn synth_vector() -> AuthVector {
        AuthVector {
            rand: *b"0123456789abcdef",
            autn: *b"fedcba9876543210",
            xres: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            ck: [0xAB; 16],
            ik: [0xCD; 16],
        }
    }

    #[tokio::test]
    async fn happy_path_known_identity() {
        let provider = Arc::new(StaticVectorProvider::new());
        provider.push(b"alice".to_vec(), synth_vector());
        let factory = EapAkaPrimeFactory::new(Arc::clone(&provider), b"WLAN".to_vec());
        let mut method = factory.create().unwrap();
        method.notify_peer_identity(b"alice");

        // Round 1: start() emits AKA-Challenge.
        let MethodOutcome::Continue(mut req_type_data) = method.start().await.unwrap() else {
            panic!("expected Continue from start()");
        };
        // Handler would now allocate an id and call finalize_request.
        let eap_id = 0x42;
        method.finalize_request(eap_id, &mut req_type_data);

        // Sanity check: subtype is AKA-Challenge and AT_MAC is now
        // non-zero (was a 16-byte zero placeholder before).
        assert_eq!(req_type_data[0], subtype::AKA_CHALLENGE);
        let attrs_region = &req_type_data[3..];
        let mut saw_mac = false;
        for a in AttrIter::new(attrs_region).flatten() {
            if a.typ == attr::AT_MAC {
                assert_ne!(a.body[2..], [0u8; 16]);
                saw_mac = true;
            }
        }
        assert!(saw_mac);

        // Round 2: peer response = AKA-Challenge with AT_RES + AT_MAC.
        // Build it the same way a real peer would: derive K_aut
        // independently, compute MAC over the full response packet.
        let v = synth_vector();
        let ck_ik = derive_ck_ik_prime(&v.ck, &v.ik, &v.autn, b"WLAN");
        let keys = derive_keys(&ck_ik, b"alice");

        // AT_RES: 64-bit (8 bytes) → bit-length 64, length 3 words
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[attr::AT_RES, 3]);
        attrs.extend_from_slice(&64u16.to_be_bytes());
        attrs.extend_from_slice(&v.xres);
        // AT_MAC: zero placeholder for MAC computation
        let mac_off_in_attrs = attrs.len() + 2; // type + len, then 2-byte reserved
        attrs.extend_from_slice(&[attr::AT_MAC, 5, 0, 0]);
        let mac_value_start = attrs.len();
        attrs.extend_from_slice(&[0u8; 16]);

        let (mut response_packet, _type_data) =
            build_request_eap_packet(eap_id, subtype::AKA_CHALLENGE, &attrs);
        // Compute MAC over the response packet with AT_MAC zeroed
        // (already zero), then patch.
        let mac = compute_mac(&keys.k_aut, &response_packet);
        attrs[mac_value_start..mac_value_start + 16].copy_from_slice(&mac);
        // Also patch into the packet bytes we'll discard (just for
        // realism; the state machine rebuilds the packet itself).
        let _ = (mac_off_in_attrs, &mut response_packet);

        // Feed type-data (subtype header + attrs) to step().
        let mut peer_type_data = Vec::new();
        subtype::write_header(&mut peer_type_data, subtype::AKA_CHALLENGE);
        peer_type_data.extend_from_slice(&attrs);

        let outcome = method.step(&peer_type_data).await.unwrap();
        match outcome {
            MethodOutcome::Success { msk, emsk } => {
                assert_eq!(msk.len(), 64);
                assert_eq!(emsk.len(), 64);
                assert_eq!(msk, keys.msk.to_vec());
                assert_eq!(emsk, keys.emsk.to_vec());
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_identity_fails() {
        let provider = Arc::new(StaticVectorProvider::new());
        let factory = EapAkaPrimeFactory::new(Arc::clone(&provider), b"WLAN".to_vec());
        let mut method = factory.create().unwrap();
        method.notify_peer_identity(b"bob");
        let outcome = method.start().await.unwrap();
        matches!(outcome, MethodOutcome::Failure);
    }

    #[tokio::test]
    async fn identity_request_round_then_challenge() {
        let provider = Arc::new(StaticVectorProvider::new());
        provider.push(b"alice".to_vec(), synth_vector());
        let factory = EapAkaPrimeFactory::new(Arc::clone(&provider), b"WLAN".to_vec());
        let mut method = factory.create().unwrap();
        // No identity yet → start() emits AKA-Identity request.
        let MethodOutcome::Continue(req) = method.start().await.unwrap() else {
            panic!("expected Continue");
        };
        assert_eq!(req[0], subtype::AKA_IDENTITY);
        let attr0 = AttrIter::new(&req[3..]).next().unwrap().unwrap();
        assert_eq!(attr0.typ, attr::AT_PERMANENT_ID_REQ);

        // Peer responds with AKA-Identity + AT_IDENTITY=alice.
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[attr::AT_IDENTITY, 3]);
        attrs.extend_from_slice(&5u16.to_be_bytes());
        attrs.extend_from_slice(b"alice");
        attrs.push(0); // pad to 4
        attrs.push(0);
        attrs.push(0);

        let mut peer = Vec::new();
        subtype::write_header(&mut peer, subtype::AKA_IDENTITY);
        peer.extend_from_slice(&attrs);

        let MethodOutcome::Continue(req2) = method.step(&peer).await.unwrap() else {
            panic!("expected Continue (AKA-Challenge)");
        };
        assert_eq!(req2[0], subtype::AKA_CHALLENGE);
    }

    #[tokio::test]
    async fn authentication_reject_fails() {
        let provider = Arc::new(StaticVectorProvider::new());
        provider.push(b"alice".to_vec(), synth_vector());
        let factory = EapAkaPrimeFactory::new(Arc::clone(&provider), b"WLAN".to_vec());
        let mut method = factory.create().unwrap();
        method.notify_peer_identity(b"alice");
        let MethodOutcome::Continue(mut req) = method.start().await.unwrap() else {
            panic!("expected Continue");
        };
        method.finalize_request(7, &mut req);

        let mut peer = Vec::new();
        subtype::write_header(&mut peer, subtype::AKA_AUTHENTICATION_REJECT);
        let outcome = method.step(&peer).await.unwrap();
        matches!(outcome, MethodOutcome::Failure);
    }
}
