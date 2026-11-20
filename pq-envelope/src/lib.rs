//! Layer 2: end-to-end post-quantum envelope for MQTT payloads.
//!
//! Confidentiality: hybrid KEM = ML-KEM-768 (FIPS 203) + X25519, combined as
//!   ikm  = ss_mlkem || ss_x25519            (same order as TLS X25519MLKEM768)
//!   info = LABEL || kem_ct || eph_pub || topic || sender || seq
//!   key  = HKDF-SHA256(salt = LABEL, ikm, info) -> AES-256-GCM
//! Authenticity: ML-DSA-65 (FIPS 204) over topic + every byte before the signature.
//! Replay: per-sender monotonic sequence number + timestamp skew window.
//!
//! The broker only ever sees ciphertext; the Lean4 spec (`lean/HybridCombiner.lean`)
//! states and proves the structural properties of the combiner used here.
//! The envelope is a self-contained binary payload, so it works over MQTT 3.1.1 and 5.

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    agreement::{self, PrivateKey, UnparsedPublicKey, X25519},
    encoding::AsDer,
    hkdf::{Salt, HKDF_SHA256},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768},
    rand::{SecureRandom, SystemRandom},
    signature::{self as sig, KeyPair, PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING},
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"PQE1";
pub const LABEL: &[u8] = b"pqmqtt/v1/X25519MLKEM768+MLDSA65";
pub const SIG_LABEL: &[u8] = b"pqmqtt/v1/sig";
pub const MAX_SKEW_SECS: u64 = 300;

/// Errors while generating keys or sealing.
#[derive(Debug, thiserror::Error)]
#[error("crypto error: {0}")]
pub struct Error(String);

type Result<T> = std::result::Result<T, Error>;

/// Why an incoming envelope was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Malformed,
    UnknownSender,
    BadSignature,
    Replay,
    Stale,
    Decrypt,
}

/// Recipient (subscriber) long-term keys: ML-KEM-768 + X25519.
pub struct RecipientKeys {
    kem: DecapsulationKey,
    x25519: PrivateKey,
}

/// Public half, distributed to publishers (e.g. provisioned at commissioning).
#[derive(Clone)]
pub struct RecipientPublic {
    pub kem_ek: Vec<u8>,
    pub x25519_pub: Vec<u8>,
}

impl RecipientKeys {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            kem: DecapsulationKey::generate(&ML_KEM_768).map_err(e)?,
            x25519: PrivateKey::generate(&X25519).map_err(e)?,
        })
    }
    pub fn public(&self) -> Result<RecipientPublic> {
        Ok(RecipientPublic {
            kem_ek: self
                .kem
                .encapsulation_key()
                .map_err(e)?
                .key_bytes()
                .map_err(e)?
                .as_ref()
                .to_vec(),
            x25519_pub: self
                .x25519
                .compute_public_key()
                .map_err(e)?
                .as_ref()
                .to_vec(),
        })
    }
}

/// Publisher identity: ML-DSA-65 signing key.
pub struct Sender {
    pub id: String,
    key: PqdsaKeyPair,
    seq: u64,
}

impl Sender {
    pub fn generate(id: &str) -> Result<Self> {
        Ok(Self {
            id: id.into(),
            key: PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(e)?,
            seq: 0,
        })
    }
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.key.public_key().as_der().map_err(e)?.as_ref().to_vec())
    }

    /// Seal `plaintext` for `to`, bound to `topic`.
    pub fn seal(&mut self, to: &RecipientPublic, topic: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seq += 1;
        let seq = self.seq;
        self.seal_with(to, topic, plaintext, seq, now())
    }

    /// Exposed for tests (replay / stale-timestamp cases).
    pub fn seal_with(
        &self,
        to: &RecipientPublic,
        topic: &str,
        pt: &[u8],
        seq: u64,
        ts: u64,
    ) -> Result<Vec<u8>> {
        // 1. ML-KEM-768 encapsulation to the recipient.
        let ek = EncapsulationKey::new(&ML_KEM_768, &to.kem_ek).map_err(e)?;
        let (kem_ct, ss_pq) = ek.encapsulate().map_err(e)?;
        // 2. Ephemeral X25519 against the recipient's static key.
        let eph = PrivateKey::generate(&X25519).map_err(e)?;
        let eph_pub = eph.compute_public_key().map_err(e)?.as_ref().to_vec();
        let peer = UnparsedPublicKey::new(&X25519, &to.x25519_pub);
        let ss_ec = agreement::agree(&eph, peer, Error("x25519".into()), |s| Ok(s.to_vec()))?;

        // Header (authenticated, not encrypted).
        let mut w = Vec::with_capacity(5000);
        w.extend_from_slice(MAGIC);
        put(&mut w, self.id.as_bytes());
        w.extend_from_slice(&seq.to_be_bytes());
        w.extend_from_slice(&ts.to_be_bytes());
        put(&mut w, kem_ct.as_ref());
        put(&mut w, &eph_pub);

        // 3. Combiner -> AEAD key.
        let key = derive_key(
            ss_pq.as_ref(),
            &ss_ec,
            kem_ct.as_ref(),
            &eph_pub,
            topic,
            &self.id,
            seq,
        )?;
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(e)?;
        let mut body = pt.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(topic, &w)),
            &mut body,
        )
        .map_err(e)?;
        w.extend_from_slice(&nonce);
        put(&mut w, &body);

        // 4. ML-DSA-65 signature over topic || everything so far.
        let mut s = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let n = self.key.sign(&sig_msg(topic, &w), &mut s).map_err(e)?;
        put(&mut w, &s[..n]);
        Ok(w)
    }
}

/// Subscriber-side verifier/decryptor with replay state.
pub struct Opener {
    keys: RecipientKeys,
    senders: HashMap<String, Vec<u8>>, // sender id -> ML-DSA-65 public key (DER SPKI)
    last_seq: HashMap<String, u64>,
}

impl Opener {
    pub fn new(keys: RecipientKeys) -> Self {
        Self {
            keys,
            senders: HashMap::new(),
            last_seq: HashMap::new(),
        }
    }
    pub fn trust(&mut self, id: &str, mldsa_pub_der: Vec<u8>) {
        self.senders.insert(id.into(), mldsa_pub_der);
    }

    /// Verify, freshness-check and decrypt an envelope received on `topic`.
    /// Returns `(sender, seq, plaintext)`.
    pub fn open(
        &mut self,
        topic: &str,
        env: &[u8],
    ) -> std::result::Result<(String, u64, Vec<u8>), Reject> {
        let mut r = Rd { b: env, i: 0 };
        if r.take(4)? != MAGIC {
            return Err(Reject::Malformed);
        }
        let sender = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Reject::Malformed)?;
        let seq = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let ts = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let kem_ct = r.lp()?.to_vec();
        let eph_pub = r.lp()?.to_vec();
        let header_end = r.i;
        let nonce: [u8; NONCE_LEN] = r.take(NONCE_LEN)?.try_into().unwrap();
        let body = r.lp()?.to_vec();
        let signed_end = r.i;
        let signature = r.lp()?;
        if r.i != env.len() {
            return Err(Reject::Malformed);
        }

        // Authenticate first (cheap reject of forgeries before any KEM work).
        let pk = self.senders.get(&sender).ok_or(Reject::UnknownSender)?;
        sig::UnparsedPublicKey::new(&ML_DSA_65, pk)
            .verify(&sig_msg(topic, &env[..signed_end]), signature)
            .map_err(|_| Reject::BadSignature)?;
        // Freshness.
        if seq <= *self.last_seq.get(&sender).unwrap_or(&0) {
            return Err(Reject::Replay);
        }
        if now().abs_diff(ts) > MAX_SKEW_SECS {
            return Err(Reject::Stale);
        }

        // Decapsulate + combine.
        let ss_pq = self
            .keys
            .kem
            .decapsulate(Ciphertext::from(kem_ct.as_slice()))
            .map_err(|_| Reject::Decrypt)?;
        let peer = UnparsedPublicKey::new(&X25519, &eph_pub);
        let ss_ec = agreement::agree(&self.keys.x25519, peer, Reject::Decrypt, |s| Ok(s.to_vec()))?;
        let key = derive_key(
            ss_pq.as_ref(),
            &ss_ec,
            &kem_ct,
            &eph_pub,
            topic,
            &sender,
            seq,
        )
        .map_err(|_| Reject::Decrypt)?;
        let mut buf = body;
        let pt = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(topic, &env[..header_end])),
                &mut buf,
            )
            .map_err(|_| Reject::Decrypt)?
            .to_vec();
        self.last_seq.insert(sender.clone(), seq);
        Ok((sender, seq, pt))
    }
}

/// The hybrid combiner (mirrors `combine` in lean/HybridCombiner.lean).
pub fn combiner_ikm(ss_pq: &[u8], ss_ec: &[u8]) -> Vec<u8> {
    assert_eq!(ss_pq.len(), 32);
    assert_eq!(ss_ec.len(), 32);
    [ss_pq, ss_ec].concat()
}

fn derive_key(
    ss_pq: &[u8],
    ss_ec: &[u8],
    kem_ct: &[u8],
    eph: &[u8],
    topic: &str,
    sender: &str,
    seq: u64,
) -> Result<LessSafeKey> {
    let ikm = combiner_ikm(ss_pq, ss_ec);
    let mut info = Vec::new();
    for part in [LABEL, kem_ct, eph, topic.as_bytes(), sender.as_bytes()] {
        put(&mut info, part);
    }
    info.extend_from_slice(&seq.to_be_bytes());
    let prk = Salt::new(HKDF_SHA256, LABEL).extract(&ikm);
    let info_parts: [&[u8]; 1] = [&info];
    let okm = prk.expand(&info_parts, &AES_256_GCM).map_err(e)?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn aad(topic: &str, header: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    put(&mut a, topic.as_bytes());
    a.extend_from_slice(header);
    a
}
fn sig_msg(topic: &str, signed: &[u8]) -> Vec<u8> {
    let mut m = SIG_LABEL.to_vec();
    put(&mut m, topic.as_bytes());
    m.extend_from_slice(signed);
    m
}
fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u16).to_be_bytes());
    w.extend_from_slice(b);
}
struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], Reject> {
        let s = self.b.get(self.i..self.i + n).ok_or(Reject::Malformed)?;
        self.i += n;
        Ok(s)
    }
    fn lp(&mut self) -> std::result::Result<&'a [u8], Reject> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        self.take(n)
    }
}
/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn e<E: std::fmt::Debug>(x: E) -> Error {
    Error(format!("{x:?}"))
}
