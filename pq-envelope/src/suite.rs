//! The HPKE (RFC 9180) cipher suite used for every public-key encryption in this crate:
//! KEM X-Wing (ML-KEM-768 + X25519, `0x647a`, draft-ietf-hpke-pq), KDF HKDF-SHA256,
//! AEAD AES-256-GCM, base mode, single-shot. Sender authentication is done separately
//! with ML-DSA-65 signatures, because HPKE auth mode is not defined for X-Wing.

use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::XWing, Deserializable, Kem as _, OpModeR, OpModeS,
    Serializable,
};

pub(crate) type KemT = XWing;
pub(crate) type Sk = <XWing as hpke::Kem>::PrivateKey;
pub(crate) type Pk = <XWing as hpke::Kem>::PublicKey;
type Enc = <XWing as hpke::Kem>::EncappedKey;

/// Suite description, e.g. for logs and MQTT 5 `pqe-alg`.
pub const SUITE: &str = "HPKE(XWing,HKDF-SHA256,AES-256-GCM)";
/// Length of an X-Wing public key, encapsulated key and private key seed.
pub const XWING_PK_LEN: usize = 1216;
pub const XWING_ENC_LEN: usize = 1120;
pub const XWING_SK_LEN: usize = 32;

pub(crate) fn gen() -> (Sk, Pk) {
    KemT::gen_keypair()
}
pub(crate) fn pk_of(sk: &Sk) -> Pk {
    KemT::sk_to_pk(sk)
}
pub(crate) fn pk_bytes(pk: &Pk) -> Vec<u8> {
    pk.to_bytes().to_vec()
}
pub(crate) fn sk_bytes(sk: &Sk) -> Vec<u8> {
    sk.to_bytes().to_vec()
}
pub(crate) fn pk_from(b: &[u8]) -> Option<Pk> {
    Pk::from_bytes(b).ok()
}
pub(crate) fn sk_from(b: &[u8]) -> Option<Sk> {
    Sk::from_bytes(b).ok()
}

/// HPKE single-shot seal: returns (enc, ciphertext||tag).
pub(crate) fn seal(
    pk: &Pk,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), hpke::HpkeError> {
    let (enc, ct) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha256, KemT>(&OpModeS::Base, pk, info, pt, aad)?;
    Ok((enc.to_bytes().to_vec(), ct))
}

/// HPKE single-shot open.
pub(crate) fn open(sk: &Sk, enc: &[u8], info: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let enc = Enc::from_bytes(enc).ok()?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, KemT>(&OpModeR::Base, sk, &enc, info, ct, aad)
        .ok()
}
