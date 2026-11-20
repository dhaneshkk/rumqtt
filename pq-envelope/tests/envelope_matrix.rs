//! Offline accept/reject matrix for the envelope verifier, scored with MCC.

mod common;

use common::{test_matrix, Confusion, TOPIC};
use rumqtt_pq_envelope::{combiner_ikm, Opener, RecipientKeys, Reject, Sender};

#[test]
fn verifier_matrix_mcc_is_one() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());

    let mut c = Confusion::default();
    for (label, genuine, env) in test_matrix(&mut cam, &ops_pub) {
        let res = opener.open(TOPIC, &env);
        let expected = match label {
            "genuine" => None,
            "bit-flip" | "forged-signer" | "topic-swap" => Some(Reject::BadSignature),
            "replay" => Some(Reject::Replay),
            "stale-ts" => Some(Reject::Stale),
            "wrong-recipient" => Some(Reject::Decrypt),
            "unknown-sender" => Some(Reject::UnknownSender),
            _ => unreachable!(),
        };
        assert_eq!(res.as_ref().err().copied(), expected, "case {label}");
        c.record(genuine, res.is_ok());
    }
    println!("confusion = {c:?}, MCC = {:.4}", c.mcc());
    assert_eq!(
        c,
        Confusion {
            tp: 30,
            tn: 35,
            fp: 0,
            fn_: 0
        }
    );
    assert!((c.mcc() - 1.0).abs() < 1e-12);
}

#[test]
fn roundtrip_preserves_plaintext_and_sender() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    let env = cam.seal(&ops_pub, TOPIC, b"hello").unwrap();
    let (sender, seq, pt) = opener.open(TOPIC, &env).unwrap();
    assert_eq!(
        (sender.as_str(), seq, pt.as_slice()),
        ("edge-cam-01", 1, &b"hello"[..])
    );
}

#[test]
fn truncated_envelopes_are_malformed_not_panics() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    let env = cam.seal(&ops_pub, TOPIC, b"x").unwrap();
    for cut in [0, 3, 4, 10, 100, env.len() - 1] {
        assert_eq!(
            opener.open(TOPIC, &env[..cut]).unwrap_err(),
            Reject::Malformed
        );
    }
}

#[test]
fn combiner_matches_lean_model() {
    // Lean: combine pq ec = pq ++ ec, length 64, split recovers both halves.
    let pq = [1u8; 32];
    let ec = [2u8; 32];
    let ikm = combiner_ikm(&pq, &ec);
    assert_eq!(ikm.len(), 64);
    assert_eq!((&ikm[..32], &ikm[32..]), (&pq[..], &ec[..]));
}
