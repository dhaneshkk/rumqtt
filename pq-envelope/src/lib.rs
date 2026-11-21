//! Layer 2: end-to-end post-quantum protection for MQTT payloads.
//!
//! Public-key encryption is HPKE (RFC 9180) with the X-Wing hybrid KEM
//! (ML-KEM-768 + X25519), HKDF-SHA256 and AES-256-GCM: see [`suite`]. Senders sign with
//! ML-DSA-65 (FIPS 204). Two modes:
//!
//! * **Per-message envelope** ([`Sender::seal`] / [`Opener::open`]): every message is a
//!   self-contained HPKE ciphertext + ML-DSA-65 signature (~4.5 KB overhead).
//! * **Session mode** ([`session`]): one signed HPKE handshake per session, wrapping a
//!   group key for one or more recipients, then ~45-byte frames with bucket padding and
//!   optional zstd.
//!
//! Keys are bound to identities by the certificates in [`keys`]. The broker only ever
//! sees ciphertext. `lean/HybridCombiner.lean` states and proves the structural
//! properties relied on here. Both formats are self-contained binary payloads, so they
//! work over MQTT 3.1.1 and 5.

pub mod keys;
pub mod session;
pub mod suite;

use aws_lc_rs::{
    encoding::AsDer,
    signature::{self as sig, KeyPair, PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING},
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"PQE2";
pub const LABEL: &[u8] = b"pqmqtt/v2/envelope";
pub const SIG_LABEL: &[u8] = b"pqmqtt/v2/sig";
pub const MAX_SKEW_SECS: u64 = 300;
/// Default maximum envelope age accepted by [`Opener`] (7 days).
pub const DEFAULT_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
const STATE_MAGIC: &[u8; 4] = b"PQES";

/// Timestamp policy for [`Opener`].
///
/// Replay protection comes from per-sender sequence numbers (persist them with
/// [`Opener::export_state`] / [`Opener::import_state`]), not from timestamps, so the
/// default policy accepts delayed delivery: retained messages, offline-session queues and
/// store-and-forward links. Only clearly future-dated envelopes (clock skew) and
/// envelopes older than `max_age` are rejected as [`Reject::Stale`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// Reject envelopes timestamped more than this many seconds in the future.
    pub max_future_skew: u64,
    /// Reject envelopes older than this many seconds; `None` disables the age limit.
    /// If replay state is *not* persisted, this bounds how far back a replay after a
    /// subscriber restart can reach.
    pub max_age: Option<u64>,
}

impl Default for Freshness {
    fn default() -> Self {
        Self {
            max_future_skew: MAX_SKEW_SECS,
            max_age: Some(DEFAULT_MAX_AGE_SECS),
        }
    }
}

impl Freshness {
    /// The original ±300 s window: rejects any delayed delivery.
    pub const STRICT: Freshness = Freshness {
        max_future_skew: MAX_SKEW_SECS,
        max_age: Some(MAX_SKEW_SECS),
    };
    /// No age limit (future skew still checked). Use together with persisted state.
    pub const UNBOUNDED: Freshness = Freshness {
        max_future_skew: MAX_SKEW_SECS,
        max_age: None,
    };

    /// `true` if an envelope stamped `ts` is acceptable at time `now`.
    pub fn accepts(&self, ts: u64, now: u64) -> bool {
        ts <= now.saturating_add(self.max_future_skew)
            && self.max_age.is_none_or(|a| now.saturating_sub(ts) <= a)
    }
}

/// MQTT 5 user-property keys describing an envelope (see [`user_properties`]).
pub const PROP_ALG: &str = "pqe-alg";
pub const PROP_SENDER: &str = "pqe-sender";
pub const PROP_SEQ: &str = "pqe-seq";
/// Value of the [`PROP_ALG`] property for this envelope version.
pub const ALG: &str = "PQE2/HPKE-XWing-HKDFSHA256-A256GCM+MLDSA65";

/// Errors while generating keys or sealing.
#[derive(Debug, thiserror::Error)]
#[error("crypto error: {0}")]
pub struct Error(pub(crate) String);

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
    /// MQTT 5 user properties disagree with the (signed) envelope header.
    PropertyMismatch,
    /// Session mode: frame for a session this receiver has no key for.
    UnknownSession,
    /// Session mode: handshake older than (or conflicting with) the last accepted one.
    StaleSession,
    /// Session mode: handshake does not wrap the session key for this recipient.
    NotARecipient,
    /// Session mode: frame needs a zstd dictionary this receiver does not have.
    UnknownDictionary,
    /// Session mode: zstd decompression failed or exceeded `max_plaintext`.
    Decompress,
    /// Session mode: plaintext larger than `max_plaintext`.
    Oversize,
}

/// MQTT 5 user properties for an envelope: algorithm, sender and sequence number,
/// copied from its header so subscribers and bridges can route or filter without
/// parsing the payload.
///
/// These are routing hints and are not covered by the envelope's own MAC/signature.
/// [`Opener::open_with_properties`] rejects any `pqe-*` property that disagrees with the
/// signed header, so a property a subscriber accepts is as trustworthy as the envelope.
pub fn user_properties(env: &[u8]) -> std::result::Result<Vec<(String, String)>, Reject> {
    let (sender, seq) = header_ids(env)?;
    Ok(vec![
        (PROP_ALG.into(), ALG.into()),
        (PROP_SENDER.into(), sender),
        (PROP_SEQ.into(), seq.to_string()),
    ])
}

/// The `pqe-sender` routing hint, if present. Unauthenticated until the envelope is opened.
pub fn sender_hint(props: &[(String, String)]) -> Option<&str> {
    props
        .iter()
        .find(|(k, _)| k == PROP_SENDER)
        .map(|(_, v)| v.as_str())
}

fn header_ids(env: &[u8]) -> std::result::Result<(String, u64), Reject> {
    let mut r = Rd { b: env, i: 0 };
    if r.take(4)? != MAGIC {
        return Err(Reject::Malformed);
    }
    let sender = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Reject::Malformed)?;
    let seq = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
    Ok((sender, seq))
}

/// Recipient (subscriber) long-term keys: an X-Wing (ML-KEM-768 + X25519) HPKE key pair.
pub struct RecipientKeys {
    pub(crate) sk: suite::Sk,
    pub(crate) pk: suite::Pk,
}

/// Public half, distributed to publishers (ideally inside a [`keys::KeyCert`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientPublic {
    /// X-Wing public key, 1216 bytes.
    pub xwing_pub: Vec<u8>,
}

impl RecipientPublic {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        suite::pk_from(b).ok_or_else(|| Error("invalid X-Wing public key".into()))?;
        Ok(Self {
            xwing_pub: b.to_vec(),
        })
    }
}

impl RecipientKeys {
    pub fn generate() -> Result<Self> {
        let (sk, pk) = suite::gen();
        Ok(Self { sk, pk })
    }
    pub fn public(&self) -> Result<RecipientPublic> {
        Ok(RecipientPublic {
            xwing_pub: suite::pk_bytes(&self.pk),
        })
    }
    /// 32-byte private seed, for storage (protect it like any private key).
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        suite::sk_bytes(&self.sk)
    }
    /// Restore keys saved with [`to_secret_bytes`](Self::to_secret_bytes).
    pub fn from_secret_bytes(b: &[u8]) -> Result<Self> {
        let sk = suite::sk_from(b).ok_or_else(|| Error("invalid X-Wing private key".into()))?;
        let pk = suite::pk_of(&sk);
        Ok(Self { sk, pk })
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
    /// PKCS#8 encoding of the ML-DSA-65 signing key, for storage.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_pkcs8v1().map_err(e)?.as_ref().to_vec())
    }
    /// Restore a sender from [`to_pkcs8`](Self::to_pkcs8).
    pub fn from_pkcs8(id: &str, der: &[u8]) -> Result<Self> {
        Ok(Self {
            id: id.into(),
            key: PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, der).map_err(e)?,
            seq: 0,
        })
    }
    /// Start sequence numbers at `epoch << 32`. Persist `epoch` and increase it on every
    /// restart, so a rebooted publisher's messages are never mistaken for replays.
    pub fn with_epoch(mut self, epoch: u32) -> Self {
        self.seq = (epoch as u64) << 32;
        self
    }
    /// Last sequence number used.
    pub fn seq(&self) -> u64 {
        self.seq
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
        let pk =
            suite::pk_from(&to.xwing_pub).ok_or_else(|| Error("invalid recipient key".into()))?;
        // Header (authenticated, not encrypted).
        let mut w = Vec::with_capacity(5000);
        w.extend_from_slice(MAGIC);
        put(&mut w, self.id.as_bytes());
        w.extend_from_slice(&seq.to_be_bytes());
        w.extend_from_slice(&ts.to_be_bytes());
        // HPKE single-shot seal to the recipient; info binds topic, sender and seq.
        let (enc, ct) =
            suite::seal(&pk, &info(topic, &self.id, seq), &aad(topic, &w), pt).map_err(e)?;
        put(&mut w, &enc);
        put(&mut w, &ct);
        // ML-DSA-65 signature over topic || everything so far.
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
    freshness: Freshness,
}

impl Opener {
    pub fn new(keys: RecipientKeys) -> Self {
        Self {
            keys,
            senders: HashMap::new(),
            last_seq: HashMap::new(),
            freshness: Freshness::default(),
        }
    }
    /// Replace the timestamp policy (default: [`Freshness::default`]).
    pub fn set_freshness(&mut self, f: Freshness) {
        self.freshness = f;
    }
    pub fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// Per-sender highest accepted sequence numbers, to persist (e.g. on every write or
    /// periodically) so that a restarted subscriber keeps rejecting replays.
    pub fn export_state(&self) -> Vec<u8> {
        let mut w = STATE_MAGIC.to_vec();
        w.extend_from_slice(&(self.last_seq.len() as u32).to_be_bytes());
        for (id, seq) in &self.last_seq {
            put(&mut w, id.as_bytes());
            w.extend_from_slice(&seq.to_be_bytes());
        }
        w
    }

    /// Restore state saved by [`export_state`](Self::export_state). Existing entries are
    /// only ever raised, never lowered.
    pub fn import_state(&mut self, state: &[u8]) -> std::result::Result<(), Reject> {
        let mut r = Rd { b: state, i: 0 };
        if r.take(4)? != STATE_MAGIC {
            return Err(Reject::Malformed);
        }
        let n = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
        let mut parsed = Vec::new();
        for _ in 0..n {
            let id = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Reject::Malformed)?;
            let seq = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
            parsed.push((id, seq));
        }
        if r.i != state.len() {
            return Err(Reject::Malformed);
        }
        for (id, seq) in parsed {
            let e = self.last_seq.entry(id).or_insert(0);
            *e = (*e).max(seq);
        }
        Ok(())
    }
    pub fn trust(&mut self, id: &str, mldsa_pub_der: Vec<u8>) {
        self.senders.insert(id.into(), mldsa_pub_der);
    }

    /// Replace the trusted senders with the currently valid sender certificates of `dir`.
    /// Call again after installing certificates or revocation lists (or periodically, to
    /// drop expired keys).
    pub fn sync_trust(&mut self, dir: &keys::KeyDirectory) {
        self.senders = dir.senders().into_iter().collect();
    }

    /// Like [`open`](Self::open), for MQTT 5 messages: every `pqe-*` user property present
    /// must match the envelope header, otherwise [`Reject::PropertyMismatch`] is returned
    /// before any key or replay state is touched. Absent properties are allowed;
    /// other user properties are ignored.
    pub fn open_with_properties(
        &mut self,
        topic: &str,
        env: &[u8],
        props: &[(String, String)],
    ) -> std::result::Result<(String, u64, Vec<u8>), Reject> {
        let expected = user_properties(env)?;
        for (k, v) in props.iter().filter(|(k, _)| k.starts_with("pqe-")) {
            match expected.iter().find(|(ek, _)| ek == k) {
                Some((_, ev)) if ev == v => {}
                _ => return Err(Reject::PropertyMismatch),
            }
        }
        self.open(topic, env)
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
        let header_end = r.i;
        let enc = r.lp()?;
        let ct = r.lp()?;
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
        if !self.freshness.accepts(ts, now()) {
            return Err(Reject::Stale);
        }

        let pt = suite::open(
            &self.keys.sk,
            enc,
            &info(topic, &sender, seq),
            &aad(topic, &env[..header_end]),
            ct,
        )
        .ok_or(Reject::Decrypt)?;
        self.last_seq.insert(sender.clone(), seq);
        Ok((sender, seq, pt))
    }
}

fn info(topic: &str, sender: &str, seq: u64) -> Vec<u8> {
    let mut i = Vec::new();
    put(&mut i, LABEL);
    put(&mut i, topic.as_bytes());
    put(&mut i, sender.as_bytes());
    i.extend_from_slice(&seq.to_be_bytes());
    i
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
