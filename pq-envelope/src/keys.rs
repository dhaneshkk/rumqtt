//! Key management: who owns which key, for how long, and what has been revoked.
//!
//! * A fleet **trust anchor** (an ML-DSA-65 key kept offline / in an HSM) signs
//!   [`KeyCert`]s that bind an identity (`subject`) and [`Role`] to a public key:
//!   a sender's ML-DSA-65 verification key, or a recipient's X-Wing HPKE key.
//! * Certificates carry a **version** (rotation: a higher version replaces the lower one,
//!   a lower version is refused as a downgrade) and a validity window.
//! * Signed **revocation lists** with a monotonically increasing number revoke
//!   certificates by serial; older lists are refused.
//! * A [`KeyDirectory`] verifies all of this and feeds [`crate::Opener`],
//!   [`crate::session::SessionOpener`] and senders with currently valid keys only.
//!
//! Certificates and revocation lists are signed, so they can be distributed over the
//! untrusted broker itself, e.g. as retained messages on `pq/keys/<role>/<subject>` and
//! `pq/keys/crl`.

use crate::{e, now, put, Error, Rd, RecipientPublic, Result};
use aws_lc_rs::{
    digest::{digest, SHA256},
    encoding::AsDer,
    rand::{SecureRandom, SystemRandom},
    signature::{self as sig, KeyPair, PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING},
};
use std::collections::{HashMap, HashSet};

const CERT_MAGIC: &[u8; 4] = b"PQKC";
const CRL_MAGIC: &[u8; 4] = b"PQRL";
const CERT_SIG_LABEL: &[u8] = b"pqmqtt/v2/key-cert";
const CRL_SIG_LABEL: &[u8] = b"pqmqtt/v2/revocation-list";
/// Allowed clock skew for `not_before`.
pub const CERT_SKEW_SECS: u64 = 300;

/// What a certified key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// ML-DSA-65 verification key of a publisher.
    Sender,
    /// X-Wing HPKE public key of a subscriber.
    Recipient,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Sender => 1,
            Role::Recipient => 2,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Role::Sender),
            2 => Some(Role::Recipient),
            _ => None,
        }
    }
}

/// Why a certificate or revocation list was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("malformed")]
    Malformed,
    #[error("signature does not verify against the trust anchor")]
    BadSignature,
    #[error("issued by a different trust anchor")]
    WrongIssuer,
    #[error("certificate expired")]
    Expired,
    #[error("certificate not yet valid")]
    NotYetValid,
    #[error("certificate revoked")]
    Revoked,
    #[error("lower version than the installed certificate")]
    Downgrade,
    #[error("same version as the installed certificate but a different key")]
    Conflict,
    #[error("revocation list is not newer than the installed one")]
    StaleRevocationList,
    #[error("key is not valid for this role")]
    InvalidKey,
}

/// 16-byte fingerprint of an ML-DSA-65 public key (DER SPKI).
pub fn key_fingerprint(der: &[u8]) -> [u8; 16] {
    digest(&SHA256, der).as_ref()[..16].try_into().unwrap()
}

/// A parsed, signature-checked key certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCert {
    pub subject: String,
    pub role: Role,
    pub version: u32,
    pub serial: [u8; 16],
    pub not_before: u64,
    pub not_after: u64,
    /// ML-DSA-65 DER SPKI (sender) or X-Wing public key (recipient).
    pub key: Vec<u8>,
    pub issuer: [u8; 16],
}

impl KeyCert {
    pub fn is_valid_at(&self, t: u64) -> std::result::Result<(), KeyError> {
        if t > self.not_after {
            return Err(KeyError::Expired);
        }
        if self.not_before > t.saturating_add(CERT_SKEW_SECS) {
            return Err(KeyError::NotYetValid);
        }
        Ok(())
    }
}

/// The fleet's signing authority. Keep its PKCS#8 offline; only its public key
/// ([`TrustAnchor::public_key_der`]) goes onto devices.
pub struct TrustAnchor {
    key: PqdsaKeyPair,
}

impl TrustAnchor {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            key: PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(e)?,
        })
    }
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        Ok(Self {
            key: PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, der).map_err(e)?,
        })
    }
    pub fn to_pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_pkcs8v1().map_err(e)?.as_ref().to_vec())
    }
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        Ok(self.key.public_key().as_der().map_err(e)?.as_ref().to_vec())
    }
    fn sign(&self, label: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        let mut m = label.to_vec();
        m.extend_from_slice(body);
        let mut s = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let n = self.key.sign(&m, &mut s).map_err(e)?;
        s.truncate(n);
        Ok(s)
    }

    /// Issue a certificate for `subject`'s `key` in `role`, valid `[not_before, not_after]`.
    pub fn issue(
        &self,
        subject: &str,
        role: Role,
        key: &[u8],
        version: u32,
        not_before: u64,
        not_after: u64,
    ) -> Result<Vec<u8>> {
        check_key(role, key).map_err(|k| Error(k.to_string()))?;
        let mut serial = [0u8; 16];
        SystemRandom::new().fill(&mut serial).map_err(e)?;
        let issuer = key_fingerprint(&self.public_key_der()?);
        let mut w = CERT_MAGIC.to_vec();
        put(&mut w, subject.as_bytes());
        w.push(role.byte());
        w.extend_from_slice(&version.to_be_bytes());
        w.extend_from_slice(&serial);
        w.extend_from_slice(&not_before.to_be_bytes());
        w.extend_from_slice(&not_after.to_be_bytes());
        put(&mut w, key);
        w.extend_from_slice(&issuer);
        let s = self.sign(CERT_SIG_LABEL, &w)?;
        put(&mut w, &s);
        Ok(w)
    }

    /// Sign revocation list number `number` revoking `serials` (cumulative: include every
    /// still-relevant revoked serial).
    pub fn revocation_list(&self, number: u64, serials: &[[u8; 16]]) -> Result<Vec<u8>> {
        let issuer = key_fingerprint(&self.public_key_der()?);
        let mut w = CRL_MAGIC.to_vec();
        w.extend_from_slice(&number.to_be_bytes());
        w.extend_from_slice(&now().to_be_bytes());
        w.extend_from_slice(&(serials.len() as u32).to_be_bytes());
        for s in serials {
            w.extend_from_slice(s);
        }
        w.extend_from_slice(&issuer);
        let s = self.sign(CRL_SIG_LABEL, &w)?;
        put(&mut w, &s);
        Ok(w)
    }
}

fn check_key(role: Role, key: &[u8]) -> std::result::Result<(), KeyError> {
    let ok = match role {
        Role::Sender => sig::ParsedPublicKey::new(&ML_DSA_65, key).is_ok(),
        Role::Recipient => RecipientPublic::from_bytes(key).is_ok(),
    };
    if ok {
        Ok(())
    } else {
        Err(KeyError::InvalidKey)
    }
}

/// Verified certificates and revocations under one trust anchor.
pub struct KeyDirectory {
    anchor: Vec<u8>,
    anchor_fp: [u8; 16],
    certs: HashMap<(String, Role), KeyCert>,
    revoked: HashSet<[u8; 16]>,
    crl_number: u64,
}

impl KeyDirectory {
    /// Create a directory that trusts only `anchor_der` (the anchor's ML-DSA-65 DER SPKI).
    pub fn new(anchor_der: Vec<u8>) -> std::result::Result<Self, KeyError> {
        check_key(Role::Sender, &anchor_der)?;
        let anchor_fp = key_fingerprint(&anchor_der);
        Ok(Self {
            anchor: anchor_der,
            anchor_fp,
            certs: HashMap::new(),
            revoked: HashSet::new(),
            crl_number: 0,
        })
    }

    fn verify(
        &self,
        label: &[u8],
        signed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), KeyError> {
        let mut m = label.to_vec();
        m.extend_from_slice(signed);
        sig::UnparsedPublicKey::new(&ML_DSA_65, &self.anchor)
            .verify(&m, signature)
            .map_err(|_| KeyError::BadSignature)
    }

    /// Parse and verify a certificate without installing it.
    pub fn verify_cert(&self, bytes: &[u8]) -> std::result::Result<KeyCert, KeyError> {
        let m = |_| KeyError::Malformed;
        let mut r = Rd { b: bytes, i: 0 };
        if r.take(4).map_err(m)? != CERT_MAGIC {
            return Err(KeyError::Malformed);
        }
        let subject =
            String::from_utf8(r.lp().map_err(m)?.to_vec()).map_err(|_| KeyError::Malformed)?;
        let role = Role::from_byte(r.take(1).map_err(m)?[0]).ok_or(KeyError::Malformed)?;
        let version = u32::from_be_bytes(r.take(4).map_err(m)?.try_into().unwrap());
        let serial: [u8; 16] = r.take(16).map_err(m)?.try_into().unwrap();
        let not_before = u64::from_be_bytes(r.take(8).map_err(m)?.try_into().unwrap());
        let not_after = u64::from_be_bytes(r.take(8).map_err(m)?.try_into().unwrap());
        let key = r.lp().map_err(m)?.to_vec();
        let issuer: [u8; 16] = r.take(16).map_err(m)?.try_into().unwrap();
        let signed_end = r.i;
        let signature = r.lp().map_err(m)?;
        if r.i != bytes.len() {
            return Err(KeyError::Malformed);
        }
        if issuer != self.anchor_fp {
            return Err(KeyError::WrongIssuer);
        }
        self.verify(CERT_SIG_LABEL, &bytes[..signed_end], signature)?;
        check_key(role, &key)?;
        Ok(KeyCert {
            subject,
            role,
            version,
            serial,
            not_before,
            not_after,
            key,
            issuer,
        })
    }

    /// Verify and install a certificate (new identity, or rotation to a higher version).
    pub fn add_cert(&mut self, bytes: &[u8]) -> std::result::Result<KeyCert, KeyError> {
        let c = self.verify_cert(bytes)?;
        c.is_valid_at(now())?;
        if self.revoked.contains(&c.serial) {
            return Err(KeyError::Revoked);
        }
        if let Some(old) = self.certs.get(&(c.subject.clone(), c.role)) {
            if c.version < old.version {
                return Err(KeyError::Downgrade);
            }
            if c.version == old.version && c.key != old.key {
                return Err(KeyError::Conflict);
            }
        }
        self.certs.insert((c.subject.clone(), c.role), c.clone());
        Ok(c)
    }

    /// Verify and apply a revocation list; returns how many installed certificates it
    /// removed.
    pub fn apply_revocations(&mut self, bytes: &[u8]) -> std::result::Result<usize, KeyError> {
        let m = |_| KeyError::Malformed;
        let mut r = Rd { b: bytes, i: 0 };
        if r.take(4).map_err(m)? != CRL_MAGIC {
            return Err(KeyError::Malformed);
        }
        let number = u64::from_be_bytes(r.take(8).map_err(m)?.try_into().unwrap());
        let _issued = r.take(8).map_err(m)?;
        let n = u32::from_be_bytes(r.take(4).map_err(m)?.try_into().unwrap()) as usize;
        let mut serials = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            serials.push(<[u8; 16]>::try_from(r.take(16).map_err(m)?).unwrap());
        }
        let issuer: [u8; 16] = r.take(16).map_err(m)?.try_into().unwrap();
        let signed_end = r.i;
        let signature = r.lp().map_err(m)?;
        if r.i != bytes.len() {
            return Err(KeyError::Malformed);
        }
        if issuer != self.anchor_fp {
            return Err(KeyError::WrongIssuer);
        }
        self.verify(CRL_SIG_LABEL, &bytes[..signed_end], signature)?;
        if number <= self.crl_number {
            return Err(KeyError::StaleRevocationList);
        }
        self.crl_number = number;
        self.revoked.extend(serials);
        let before = self.certs.len();
        let revoked = &self.revoked;
        self.certs.retain(|_, c| !revoked.contains(&c.serial));
        Ok(before - self.certs.len())
    }

    fn valid(&self, subject: &str, role: Role) -> Option<&KeyCert> {
        self.certs
            .get(&(subject.to_string(), role))
            .filter(|c| c.is_valid_at(now()).is_ok() && !self.revoked.contains(&c.serial))
    }

    /// Currently valid ML-DSA-65 key of sender `subject`.
    pub fn sender_key(&self, subject: &str) -> Option<Vec<u8>> {
        self.valid(subject, Role::Sender).map(|c| c.key.clone())
    }

    /// Currently valid HPKE key of recipient `subject`.
    pub fn recipient(&self, subject: &str) -> Option<RecipientPublic> {
        self.valid(subject, Role::Recipient)
            .and_then(|c| RecipientPublic::from_bytes(&c.key).ok())
    }

    /// All currently valid sender keys, `(subject, ML-DSA-65 DER)`.
    pub fn senders(&self) -> Vec<(String, Vec<u8>)> {
        let t = now();
        self.certs
            .values()
            .filter(|c| {
                c.role == Role::Sender
                    && c.is_valid_at(t).is_ok()
                    && !self.revoked.contains(&c.serial)
            })
            .map(|c| (c.subject.clone(), c.key.clone()))
            .collect()
    }

    /// Number of the last applied revocation list.
    pub fn crl_number(&self) -> u64 {
        self.crl_number
    }
}
