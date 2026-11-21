#![allow(dead_code)]
//! Shared test helpers: attack-case generator and Matthews Correlation Coefficient.

pub mod net;

use rumqtt_pq_envelope::{now, RecipientKeys, RecipientPublic, Sender};

pub const TOPIC: &str = "vg360/site1/telemetry";

/// Confusion counts for an accept/reject classifier ("accept" = positive class).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Confusion {
    pub tp: u64,
    pub tn: u64,
    pub fp: u64,
    pub fn_: u64,
}

impl Confusion {
    pub fn record(&mut self, genuine: bool, accepted: bool) {
        match (genuine, accepted) {
            (true, true) => self.tp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fp += 1,
            (true, false) => self.fn_ += 1,
        }
    }

    /// Matthews Correlation Coefficient in [-1, 1]; 0 when undefined.
    pub fn mcc(&self) -> f64 {
        let (tp, tn, fp, fn_) = (
            self.tp as f64,
            self.tn as f64,
            self.fp as f64,
            self.fn_ as f64,
        );
        let d = ((tp + fp) * (tp + fn_) * (tn + fp) * (tn + fn_)).sqrt();
        if d == 0.0 {
            0.0
        } else {
            (tp * tn - fp * fn_) / d
        }
    }
}

/// 30 genuine + 35 attack envelopes, in delivery order: (label, is_genuine, bytes).
pub fn test_matrix(
    cam: &mut Sender,
    ops_pub: &RecipientPublic,
) -> Vec<(&'static str, bool, Vec<u8>)> {
    let mut cases = Vec::new();
    let mut genuine_sent = Vec::new();
    for i in 0..25 {
        let pt = format!("{{\"cam\":1,\"frame\":{i},\"ppe_ok\":true}}");
        let env = cam.seal(ops_pub, TOPIC, pt.as_bytes()).unwrap();
        genuine_sent.push(env.clone());
        cases.push(("genuine", true, env));
    }
    for i in 0..5 {
        let mut env = cam.seal(ops_pub, TOPIC, b"tamper-me").unwrap();
        let n = env.len();
        env[n - 3400 - i] ^= 0x01; // flip a bit in the ML-KEM ciphertext
        cases.push(("bit-flip", false, env));
    }
    let attacker = Sender::generate("edge-cam-01").unwrap(); // same id, wrong ML-DSA key
    for _ in 0..5 {
        let env = attacker
            .seal_with(ops_pub, TOPIC, b"evil", 9_000_000, now())
            .unwrap();
        cases.push(("forged-signer", false, env));
    }
    for env in genuine_sent.iter().take(5) {
        cases.push(("replay", false, env.clone()));
    }
    for _ in 0..5 {
        let env = cam.seal(ops_pub, "vg360/site1/other", b"moved").unwrap();
        cases.push(("topic-swap", false, env));
    }
    for i in 0..5 {
        let env = cam
            .seal_with(
                ops_pub,
                TOPIC,
                b"old",
                1_000_000 + i,
                now() - 30 * 24 * 3600,
            )
            .unwrap();
        cases.push(("stale-ts", false, env));
    }
    let other = RecipientKeys::generate().unwrap().public().unwrap();
    for _ in 0..5 {
        let env = cam.seal(&other, TOPIC, b"not for you").unwrap();
        cases.push(("wrong-recipient", false, env));
    }
    let stranger = Sender::generate("unknown-cam").unwrap();
    for i in 0..5 {
        let env = stranger
            .seal_with(ops_pub, TOPIC, b"hi", i + 1, now())
            .unwrap();
        cases.push(("unknown-sender", false, env));
    }
    for i in 0..5 {
        let pt = format!("{{\"cam\":1,\"after_attacks\":{i}}}");
        cases.push((
            "genuine",
            true,
            cam.seal(ops_pub, TOPIC, pt.as_bytes()).unwrap(),
        ));
    }
    cases
}
