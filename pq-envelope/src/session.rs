//! Session mode: one post-quantum handshake per session, then small symmetric frames.
//!
//! The per-message envelope (crate root) costs ~4.5 KB per message because every message
//! carries an ML-KEM ciphertext and an ML-DSA signature. Session mode pays that once:
//!
//! * **Handshake** (once per session, ~1.2 KB per recipient + 3.3 KB signature):
//!   the sender draws a random 32-byte session key and wraps it for every recipient with
//!   HPKE (RFC 9180; X-Wing / HKDF-SHA256 / AES-256-GCM, see [`crate::suite`]). The member
//!   list (recipient fingerprints), sender epoch and session number are signed with
//!   ML-DSA-65. A handshake can name many recipients, which
//!   gives a **group key**: one published frame is readable by the whole group.
//! * **Frames** (every message, 45 bytes + padding; 49 with a dictionary):
//!   `"PQS1" ‖ session_id(16) ‖ seq(8) ‖ codec(1) [‖ dict_id(4)] ‖ AES-256-GCM(block)`,
//!   nonce = `0u32 ‖ seq`, AAD = `lp(topic) ‖ header`. The block is
//!   `len(u32) ‖ zstd?(payload) ‖ zero padding` rounded up to a fixed size bucket, so the
//!   ciphertext length only reveals the bucket.
//!
//! Freshness and restarts:
//! * Each sender keeps a persisted, monotonically increasing **epoch** (e.g. a boot
//!   counter). Receivers only accept handshakes whose `(epoch, session_no)` is newer
//!   than the last one accepted from that sender, so a rebooted publisher simply sends a
//!   handshake with `epoch + 1`, and replayed old handshakes are rejected.
//! * Frames use a 64-message sliding replay window (out-of-order QoS 1 delivery is fine).
//! * Receivers can [`SessionOpener::export_state`] / [`SessionOpener::import_state`] the
//!   per-sender high-water marks (no keys), so a restarted subscriber rejects replays of
//!   frames it had already seen while still re-accepting the current (retained) handshake.
//! * The previous session stays valid next to the current one, so frames still in flight
//!   during a rekey are not lost.
//!
//! Group caveat: frames are authenticated with the shared group key, so any member can
//! forge frames that other members would accept as the sender's. The handshake itself is
//! signed; use the per-message envelope (or per-member sessions) where members must not
//! be able to impersonate the sender.

use crate::{
    e, now, put, suite, Error, Rd, RecipientKeys, RecipientPublic, Reject, Result, Sender,
};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN},
    digest::{digest, SHA256},
    hkdf::{Salt, HKDF_SHA256},
    rand::{SecureRandom, SystemRandom},
    signature::{self as sig, ML_DSA_65, ML_DSA_65_SIGNING},
};
use std::collections::HashMap;
use std::sync::Arc;

pub const HS_MAGIC: &[u8; 4] = b"PQH2";
pub const FRAME_MAGIC: &[u8; 4] = b"PQS1";
const STATE_MAGIC: &[u8; 4] = b"PQST";
const WRAP_LABEL: &[u8] = b"pqmqtt/v2/session/wrap";
const FRAME_LABEL: &[u8] = b"pqmqtt/v1/session/frame";
const SIG_HS_LABEL: &[u8] = b"pqmqtt/v1/session/hs-sig";
const FP_LABEL: &[u8] = b"pqmqtt/v1/recipient-fp";
const WRAPPED_LEN: usize = 32 + 16;
const WINDOW: u64 = 64;

/// Default padding buckets (bytes of the encrypted block, before the 16-byte tag).
pub const DEFAULT_BUCKETS: &[usize] = &[
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];

/// Payload compression applied before padding and encryption.
#[derive(Clone, Debug, Default)]
pub enum Compression {
    #[default]
    None,
    /// Plain zstd at the given level.
    Zstd { level: i32 },
    /// zstd with a pre-shared dictionary (see [`train_dictionary`]); receivers register the
    /// same dictionary under `id` with [`SessionOpener::add_dictionary`].
    ZstdDict {
        id: u32,
        dict: Arc<Vec<u8>>,
        level: i32,
    },
}

/// Session-mode settings.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Ascending padding bucket sizes. Blocks larger than the last bucket are padded to a
    /// multiple of it.
    pub buckets: Vec<usize>,
    pub compression: Compression,
    /// Largest accepted plaintext after decompression (decompression-bomb guard).
    pub max_plaintext: usize,
    /// Reject handshakes older than this many seconds. `None` (default) so that retained
    /// handshakes keep working for late subscribers; freshness then comes from epochs.
    pub max_handshake_age: Option<u64>,
    /// [`SessionSender::needs_handshake`] turns true after this many frames.
    pub rekey_after: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            buckets: DEFAULT_BUCKETS.to_vec(),
            compression: Compression::None,
            max_plaintext: 1 << 20,
            max_handshake_age: None,
            rekey_after: 1 << 24,
        }
    }
}

/// 16-byte recipient fingerprint: SHA-256 over the recipient's public keys.
pub fn fingerprint(p: &RecipientPublic) -> [u8; 16] {
    let mut m = FP_LABEL.to_vec();
    put(&mut m, &p.xwing_pub);
    digest(&SHA256, &m).as_ref()[..16].try_into().unwrap()
}

/// Train a zstd dictionary from representative payloads (e.g. a few thousand messages).
pub fn train_dictionary(samples: &[Vec<u8>], max_size: usize) -> Result<Vec<u8>> {
    zstd::dict::from_samples(samples, max_size).map_err(e)
}

/// Size of the padded block for a `n`-byte input (length prefix included).
/// Mirrors `bucketFor` in `lean/HybridCombiner.lean`.
pub fn bucket_for(buckets: &[usize], n: usize) -> usize {
    match buckets.iter().find(|b| n <= **b) {
        Some(b) => *b,
        None => {
            let m = *buckets.last().expect("non-empty buckets");
            n + (m - n % m) % m
        }
    }
}

fn pad(buckets: &[usize], data: &[u8]) -> Vec<u8> {
    let n = data.len() + 4;
    let mut b = Vec::with_capacity(bucket_for(buckets, n));
    b.extend_from_slice(&(data.len() as u32).to_be_bytes());
    b.extend_from_slice(data);
    b.resize(bucket_for(buckets, n), 0);
    b
}

fn unpad(block: &[u8]) -> std::result::Result<&[u8], Reject> {
    let len =
        u32::from_be_bytes(block.get(..4).ok_or(Reject::Malformed)?.try_into().unwrap()) as usize;
    let data = block.get(4..4 + len).ok_or(Reject::Malformed)?;
    if block[4 + len..].iter().any(|b| *b != 0) {
        return Err(Reject::Malformed);
    }
    Ok(data)
}

fn validate(cfg: &SessionConfig) -> Result<()> {
    let ok = !cfg.buckets.is_empty()
        && cfg.buckets[0] >= 8
        && cfg.buckets.windows(2).all(|w| w[0] < w[1]);
    if ok {
        Ok(())
    } else {
        Err(Error(
            "buckets must be non-empty, ascending and >= 8".into(),
        ))
    }
}

fn aead_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<LessSafeKey> {
    let parts: [&[u8]; 1] = [info];
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let okm = prk.expand(&parts, &AES_256_GCM).map_err(e)?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn session_info(sender: &str, epoch: u64, session_no: u32, sid: &[u8; 16]) -> Vec<u8> {
    let mut i = Vec::new();
    put(&mut i, FRAME_LABEL);
    put(&mut i, sender.as_bytes());
    i.extend_from_slice(&epoch.to_be_bytes());
    i.extend_from_slice(&session_no.to_be_bytes());
    i.extend_from_slice(sid);
    i
}

/// HPKE `info` for wrapping the session key to one recipient.
fn wrap_info(sender: &str, epoch: u64, session_no: u32, sid: &[u8; 16], fp: &[u8; 16]) -> Vec<u8> {
    let mut i = Vec::new();
    put(&mut i, WRAP_LABEL);
    put(&mut i, sender.as_bytes());
    i.extend_from_slice(&epoch.to_be_bytes());
    i.extend_from_slice(&session_no.to_be_bytes());
    i.extend_from_slice(sid);
    i.extend_from_slice(fp);
    i
}

fn frame_nonce(seq: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

struct Current {
    id: [u8; 16],
    key: LessSafeKey,
    seq: u64,
}

/// Publisher side of session mode (one sender, one or more recipients).
pub struct SessionSender {
    signer: Sender,
    recipients: Vec<(RecipientPublic, [u8; 16])>,
    epoch: u64,
    session_no: u32,
    current: Option<Current>,
    cfg: SessionConfig,
}

impl SessionSender {
    /// `epoch` must be persisted by the caller and increased on every restart.
    pub fn new(
        signer: Sender,
        recipients: &[RecipientPublic],
        epoch: u64,
        cfg: SessionConfig,
    ) -> Result<Self> {
        validate(&cfg)?;
        let mut s = Self {
            signer,
            recipients: Vec::new(),
            epoch,
            session_no: 0,
            current: None,
            cfg,
        };
        s.set_recipients(recipients)?;
        Ok(s)
    }

    /// Change group membership. The current session is dropped, so the next
    /// [`handshake`](Self::handshake) re-keys: removed members cannot read later frames.
    pub fn set_recipients(&mut self, recipients: &[RecipientPublic]) -> Result<()> {
        if recipients.is_empty() || recipients.len() > u16::MAX as usize {
            return Err(Error("1..=65535 recipients required".into()));
        }
        self.recipients = recipients
            .iter()
            .map(|r| (r.clone(), fingerprint(r)))
            .collect();
        self.current = None;
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn session_id(&self) -> Option<[u8; 16]> {
        self.current.as_ref().map(|c| c.id)
    }
    pub fn needs_handshake(&self) -> bool {
        self.current
            .as_ref()
            .is_none_or(|c| c.seq >= self.cfg.rekey_after)
    }

    /// Start a new session and return its signed handshake. Publish it (retained, so late
    /// subscribers get it) before the session's frames.
    pub fn handshake(&mut self) -> Result<Vec<u8>> {
        self.handshake_at(now())
    }

    /// [`handshake`](Self::handshake) with an explicit timestamp (tests).
    pub fn handshake_at(&mut self, ts: u64) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        self.session_no = self
            .session_no
            .checked_add(1)
            .ok_or_else(|| Error("session_no overflow; bump epoch".into()))?;
        let mut sid = [0u8; 16];
        let mut sk = [0u8; 32];
        rng.fill(&mut sid).map_err(e)?;
        rng.fill(&mut sk).map_err(e)?;
        let id = self.signer.id.clone();

        let mut w = Vec::with_capacity(4096 + 1300 * self.recipients.len());
        w.extend_from_slice(HS_MAGIC);
        put(&mut w, id.as_bytes());
        w.extend_from_slice(&self.epoch.to_be_bytes());
        w.extend_from_slice(&self.session_no.to_be_bytes());
        w.extend_from_slice(&sid);
        w.extend_from_slice(&ts.to_be_bytes());
        w.extend_from_slice(&(self.recipients.len() as u16).to_be_bytes());
        let header = w.clone();

        for (rp, fp) in &self.recipients {
            let pk = suite::pk_from(&rp.xwing_pub)
                .ok_or_else(|| Error("invalid recipient key".into()))?;
            let info = wrap_info(&id, self.epoch, self.session_no, &sid, fp);
            let (enc, wrapped) = suite::seal(&pk, &info, &header, &sk).map_err(e)?;
            debug_assert_eq!(wrapped.len(), WRAPPED_LEN);
            w.extend_from_slice(fp);
            put(&mut w, &enc);
            w.extend_from_slice(&wrapped);
        }
        let mut s = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let mut m = SIG_HS_LABEL.to_vec();
        m.extend_from_slice(&w);
        let n = self.signer.key.sign(&m, &mut s).map_err(e)?;
        put(&mut w, &s[..n]);

        let key = aead_key(
            FRAME_LABEL,
            &sk,
            &session_info(&id, self.epoch, self.session_no, &sid),
        )?;
        self.current = Some(Current {
            id: sid,
            key,
            seq: 0,
        });
        Ok(w)
    }

    /// Seal one message for the current session.
    pub fn seal(&mut self, topic: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cur = self
            .current
            .as_mut()
            .ok_or_else(|| Error("no session: call handshake() first".into()))?;
        cur.seq = cur
            .seq
            .checked_add(1)
            .ok_or_else(|| Error("seq overflow".into()))?;
        let (codec, dict_id, body) = match &self.cfg.compression {
            Compression::None => (0u8, None, plaintext.to_vec()),
            Compression::Zstd { level } => {
                (1, None, zstd::bulk::compress(plaintext, *level).map_err(e)?)
            }
            Compression::ZstdDict { id, dict, level } => {
                let mut c = zstd::bulk::Compressor::with_dictionary(*level, dict).map_err(e)?;
                (2, Some(*id), c.compress(plaintext).map_err(e)?)
            }
        };
        let mut w = Vec::with_capacity(64 + body.len());
        w.extend_from_slice(FRAME_MAGIC);
        w.extend_from_slice(&cur.id);
        w.extend_from_slice(&cur.seq.to_be_bytes());
        w.push(codec);
        if let Some(d) = dict_id {
            w.extend_from_slice(&d.to_be_bytes());
        }
        let mut aad = Vec::new();
        put(&mut aad, topic.as_bytes());
        aad.extend_from_slice(&w);
        let mut block = pad(&self.cfg.buckets, &body);
        cur.key
            .seal_in_place_append_tag(frame_nonce(cur.seq), Aad::from(aad), &mut block)
            .map_err(e)?;
        w.extend_from_slice(&block);
        Ok(w)
    }
}

/// What an accepted handshake established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    pub sender: String,
    pub epoch: u64,
    pub session_no: u32,
    pub session_id: [u8; 16],
    /// Number of recipients the session key was wrapped for (group size).
    pub members: usize,
    /// `true` if this exact session was already active (e.g. retained re-delivery).
    pub duplicate: bool,
}

/// A decrypted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub sender: String,
    pub epoch: u64,
    pub seq: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Default, Clone, Copy)]
struct Window {
    highest: u64,
    bitmap: u64, // bit i set => (highest - i) seen
}

impl Window {
    fn check(&self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.highest {
            return true;
        }
        let d = self.highest - seq;
        d < WINDOW && self.bitmap & (1 << d) == 0
    }
    fn mark(&mut self, seq: u64) {
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest = seq;
        } else {
            self.bitmap |= 1 << (self.highest - seq);
        }
    }
}

struct Sess {
    sender: String,
    epoch: u64,
    key: LessSafeKey,
    win: Window,
}

#[derive(Default)]
struct Peer {
    epoch: u64,
    session_no: u32,
    current: Option<[u8; 16]>,
    previous: Option<[u8; 16]>,
    /// From [`SessionOpener::import_state`]: (session id, highest seq seen) before restart.
    floor: Option<([u8; 16], u64)>,
}

/// Subscriber side of session mode.
pub struct SessionOpener {
    keys: RecipientKeys,
    fp: [u8; 16],
    cfg: SessionConfig,
    senders: HashMap<String, Vec<u8>>,
    dicts: HashMap<u32, Vec<u8>>,
    peers: HashMap<String, Peer>,
    sessions: HashMap<[u8; 16], Sess>,
}

impl SessionOpener {
    pub fn new(keys: RecipientKeys, cfg: SessionConfig) -> Result<Self> {
        validate(&cfg)?;
        let fp = fingerprint(&keys.public()?);
        Ok(Self {
            keys,
            fp,
            cfg,
            senders: HashMap::new(),
            dicts: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
        })
    }
    /// Trust a sender's ML-DSA-65 public key (DER SPKI).
    pub fn trust(&mut self, id: &str, mldsa_pub_der: Vec<u8>) {
        self.senders.insert(id.into(), mldsa_pub_der);
    }
    /// Replace the trusted senders with the currently valid sender certificates of `dir`.
    pub fn sync_trust(&mut self, dir: &crate::keys::KeyDirectory) {
        self.senders = dir.senders().into_iter().collect();
    }
    pub fn add_dictionary(&mut self, id: u32, dict: Vec<u8>) {
        self.dicts.insert(id, dict);
    }
    /// This recipient's fingerprint, as listed in handshakes.
    pub fn fingerprint(&self) -> [u8; 16] {
        self.fp
    }

    /// Verify a handshake and install its session key if this recipient is a member.
    pub fn accept_handshake(&mut self, hs: &[u8]) -> std::result::Result<HandshakeInfo, Reject> {
        let mut r = Rd { b: hs, i: 0 };
        if r.take(4)? != HS_MAGIC {
            return Err(Reject::Malformed);
        }
        let sender = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Reject::Malformed)?;
        let epoch = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let session_no = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
        let sid: [u8; 16] = r.take(16)?.try_into().unwrap();
        let ts = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        let header_end = r.i;
        let mut mine = None;
        for _ in 0..n {
            let fp: [u8; 16] = r.take(16)?.try_into().unwrap();
            let enc = r.lp()?;
            let wrapped = r.take(WRAPPED_LEN)?;
            if fp == self.fp {
                mine = Some((enc, wrapped));
            }
        }
        let signed_end = r.i;
        let signature = r.lp()?;
        if r.i != hs.len() || n == 0 {
            return Err(Reject::Malformed);
        }

        let pk = self.senders.get(&sender).ok_or(Reject::UnknownSender)?;
        let mut m = SIG_HS_LABEL.to_vec();
        m.extend_from_slice(&hs[..signed_end]);
        sig::UnparsedPublicKey::new(&ML_DSA_65, pk)
            .verify(&m, signature)
            .map_err(|_| Reject::BadSignature)?;
        if let Some(age) = self.cfg.max_handshake_age {
            if now().abs_diff(ts) > age {
                return Err(Reject::Stale);
            }
        }
        let (enc, wrapped) = mine.ok_or(Reject::NotARecipient)?;
        let info = HandshakeInfo {
            sender: sender.clone(),
            epoch,
            session_no,
            session_id: sid,
            members: n,
            duplicate: false,
        };

        let peer = self.peers.entry(sender.clone()).or_default();
        let mut floor_seq = None;
        match (epoch, session_no).cmp(&(peer.epoch, peer.session_no)) {
            std::cmp::Ordering::Less => return Err(Reject::StaleSession),
            std::cmp::Ordering::Equal if peer.epoch != 0 || peer.session_no != 0 => {
                if peer.current == Some(sid) {
                    return Ok(HandshakeInfo {
                        duplicate: true,
                        ..info
                    });
                }
                match peer.floor {
                    Some((fsid, fseq)) if fsid == sid && peer.current.is_none() => {
                        floor_seq = Some(fseq)
                    }
                    _ => return Err(Reject::StaleSession),
                }
            }
            _ => {}
        }

        // Unwrap the session key.
        let winfo = wrap_info(&sender, epoch, session_no, &sid, &self.fp);
        let sk = suite::open(&self.keys.sk, enc, &winfo, &hs[..header_end], wrapped)
            .ok_or(Reject::Decrypt)?;
        if sk.len() != 32 {
            return Err(Reject::Decrypt);
        }
        let key = aead_key(
            FRAME_LABEL,
            &sk,
            &session_info(&sender, epoch, session_no, &sid),
        )
        .map_err(|_| Reject::Decrypt)?;

        let mut win = Window::default();
        if let Some(fseq) = floor_seq {
            win = Window {
                highest: fseq,
                bitmap: u64::MAX,
            };
        }
        let peer = self.peers.get_mut(&sender).unwrap();
        if floor_seq.is_none() {
            if let Some(old) = peer.previous.take() {
                self.sessions.remove(&old);
            }
            peer.previous = peer.current;
        }
        peer.current = Some(sid);
        peer.epoch = epoch;
        peer.session_no = session_no;
        peer.floor = None;
        self.sessions.insert(
            sid,
            Sess {
                sender,
                epoch,
                key,
                win,
            },
        );
        Ok(info)
    }

    /// Verify, decrypt, unpad and decompress one frame received on `topic`.
    pub fn open(&mut self, topic: &str, frame: &[u8]) -> std::result::Result<Opened, Reject> {
        let mut r = Rd { b: frame, i: 0 };
        if r.take(4)? != FRAME_MAGIC {
            return Err(Reject::Malformed);
        }
        let sid: [u8; 16] = r.take(16)?.try_into().unwrap();
        let seq = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        let codec = r.take(1)?[0];
        let dict = match codec {
            0 | 1 => None,
            2 => {
                let id = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
                Some(self.dicts.get(&id).ok_or(Reject::UnknownDictionary)?)
            }
            _ => return Err(Reject::Malformed),
        };
        let header_end = r.i;
        if frame.len() < header_end + 16 + 8 {
            return Err(Reject::Malformed);
        }
        let sess = self.sessions.get_mut(&sid).ok_or(Reject::UnknownSession)?;
        if !sess.win.check(seq) {
            return Err(Reject::Replay);
        }
        let mut aad = Vec::new();
        put(&mut aad, topic.as_bytes());
        aad.extend_from_slice(&frame[..header_end]);
        let mut buf = frame[header_end..].to_vec();
        let block = sess
            .key
            .open_in_place(frame_nonce(seq), Aad::from(aad), &mut buf)
            .map_err(|_| Reject::Decrypt)?;
        let body = unpad(block)?;
        let cap = self.cfg.max_plaintext;
        let plaintext = match (codec, dict) {
            (0, _) => body.to_vec(),
            (1, _) => zstd::bulk::decompress(body, cap).map_err(|_| Reject::Decompress)?,
            (_, Some(d)) => zstd::bulk::Decompressor::with_dictionary(d)
                .and_then(|mut dc| dc.decompress(body, cap))
                .map_err(|_| Reject::Decompress)?,
            _ => return Err(Reject::Malformed),
        };
        if plaintext.len() > cap {
            return Err(Reject::Oversize);
        }
        sess.win.mark(seq);
        Ok(Opened {
            sender: sess.sender.clone(),
            epoch: sess.epoch,
            seq,
            plaintext,
        })
    }

    /// Per-sender high-water marks (no key material) to persist across restarts.
    pub fn export_state(&self) -> Vec<u8> {
        let mut w = STATE_MAGIC.to_vec();
        w.extend_from_slice(&(self.peers.len() as u32).to_be_bytes());
        for (id, p) in &self.peers {
            put(&mut w, id.as_bytes());
            w.extend_from_slice(&p.epoch.to_be_bytes());
            w.extend_from_slice(&p.session_no.to_be_bytes());
            let (sid, hi) = match p
                .current
                .and_then(|s| self.sessions.get(&s).map(|x| (s, x.win.highest)))
            {
                Some(v) => v,
                None => p.floor.unwrap_or(([0; 16], 0)),
            };
            w.extend_from_slice(&sid);
            w.extend_from_slice(&hi.to_be_bytes());
        }
        w
    }

    /// Restore state from [`export_state`](Self::export_state). The sender's current
    /// session must then be re-established by its (retained) handshake; frames at or
    /// below the saved high-water mark are rejected as replays.
    pub fn import_state(&mut self, state: &[u8]) -> std::result::Result<(), Reject> {
        let mut r = Rd { b: state, i: 0 };
        if r.take(4)? != STATE_MAGIC {
            return Err(Reject::Malformed);
        }
        let n = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
        for _ in 0..n {
            let id = String::from_utf8(r.lp()?.to_vec()).map_err(|_| Reject::Malformed)?;
            let epoch = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
            let session_no = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
            let sid: [u8; 16] = r.take(16)?.try_into().unwrap();
            let hi = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
            self.peers.insert(
                id,
                Peer {
                    epoch,
                    session_no,
                    current: None,
                    previous: None,
                    floor: Some((sid, hi)),
                },
            );
        }
        if r.i != state.len() {
            return Err(Reject::Malformed);
        }
        Ok(())
    }
}
