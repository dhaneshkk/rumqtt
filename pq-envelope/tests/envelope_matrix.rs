//! Offline accept/reject matrix for the envelope verifier, scored with MCC.

mod common;

use common::{test_matrix, Confusion, TOPIC};
use rumqtt_pq_envelope::{suite, Freshness, Opener, RecipientKeys, Reject, Sender};

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
fn hpke_xwing_sizes_and_key_persistence() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    assert_eq!(ops_pub.xwing_pub.len(), suite::XWING_PK_LEN);
    // Keys survive a save/load round trip (publisher and subscriber restarts).
    let ops2 = RecipientKeys::from_secret_bytes(&ops.to_secret_bytes()).unwrap();
    assert_eq!(ops2.public().unwrap(), ops_pub);
    let cam = Sender::generate("edge-cam-01").unwrap();
    let mut cam2 = Sender::from_pkcs8("edge-cam-01", &cam.to_pkcs8().unwrap()).unwrap();
    assert_eq!(
        cam2.public_key_der().unwrap(),
        cam.public_key_der().unwrap()
    );

    let mut opener = Opener::new(ops2);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    let env = cam2.seal(&ops_pub, TOPIC, b"hello").unwrap();
    // magic 4 + id 2+11 + seq 8 + ts 8 + enc 2+1120 + ct 2+5+16 + sig 2+3309
    assert_eq!(
        env.len(),
        4 + 13 + 16 + 2 + suite::XWING_ENC_LEN + 2 + 21 + 2 + 3309
    );
    assert_eq!(opener.open(TOPIC, &env).unwrap().2, b"hello");
}

#[test]
fn delayed_delivery_is_accepted_but_future_and_ancient_are_not() {
    use rumqtt_pq_envelope::now;
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    // Retained / offline-queued for 2 hours and 6 days: accepted by default.
    let late = cam
        .seal_with(&ops_pub, TOPIC, b"2h", 1, now() - 7200)
        .unwrap();
    assert!(opener.open(TOPIC, &late).is_ok());
    let later = cam
        .seal_with(&ops_pub, TOPIC, b"6d", 2, now() - 6 * 86400)
        .unwrap();
    assert!(opener.open(TOPIC, &later).is_ok());
    // Older than max_age (7 days), or from the future beyond skew: rejected.
    let ancient = cam
        .seal_with(&ops_pub, TOPIC, b"8d", 3, now() - 8 * 86400)
        .unwrap();
    assert_eq!(opener.open(TOPIC, &ancient).unwrap_err(), Reject::Stale);
    let future = cam
        .seal_with(&ops_pub, TOPIC, b"f", 4, now() + 3600)
        .unwrap();
    assert_eq!(opener.open(TOPIC, &future).unwrap_err(), Reject::Stale);
    // STRICT restores the old +/-300 s behaviour; UNBOUNDED drops the age limit.
    opener.set_freshness(Freshness::STRICT);
    let late2 = cam
        .seal_with(&ops_pub, TOPIC, b"2h", 5, now() - 7200)
        .unwrap();
    assert_eq!(opener.open(TOPIC, &late2).unwrap_err(), Reject::Stale);
    opener.set_freshness(Freshness::UNBOUNDED);
    let ancient2 = cam
        .seal_with(&ops_pub, TOPIC, b"8d", 6, now() - 8 * 86400)
        .unwrap();
    assert!(opener.open(TOPIC, &ancient2).is_ok());
}

#[test]
fn restarts_keep_replay_protection() {
    let ops = RecipientKeys::generate().unwrap();
    let secret = ops.to_secret_bytes();
    let ops_pub = ops.public().unwrap();
    let pkcs8 = Sender::generate("edge-cam-01").unwrap().to_pkcs8().unwrap();
    let mut cam = Sender::from_pkcs8("edge-cam-01", &pkcs8)
        .unwrap()
        .with_epoch(1);
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    let m1 = cam.seal(&ops_pub, TOPIC, b"m1").unwrap();
    let m2 = cam.seal(&ops_pub, TOPIC, b"m2").unwrap();
    opener.open(TOPIC, &m1).unwrap();
    opener.open(TOPIC, &m2).unwrap();
    let saved = opener.export_state();

    // Subscriber restart: keys and replay state restored -> old messages are replays.
    let mut opener = Opener::new(RecipientKeys::from_secret_bytes(&secret).unwrap());
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());
    opener.import_state(&saved).unwrap();
    assert_eq!(opener.open(TOPIC, &m1).unwrap_err(), Reject::Replay);
    assert_eq!(opener.open(TOPIC, &m2).unwrap_err(), Reject::Replay);

    // Publisher restart with the next epoch: sequence numbers jump ahead, accepted.
    let mut cam = Sender::from_pkcs8("edge-cam-01", &pkcs8)
        .unwrap()
        .with_epoch(2);
    let m3 = cam.seal(&ops_pub, TOPIC, b"after reboot").unwrap();
    assert_eq!(opener.open(TOPIC, &m3).unwrap().2, b"after reboot");
    // A publisher that forgot its epoch is rejected rather than silently accepted.
    let mut forgetful = Sender::from_pkcs8("edge-cam-01", &pkcs8)
        .unwrap()
        .with_epoch(1);
    let m4 = forgetful.seal(&ops_pub, TOPIC, b"stale epoch").unwrap();
    assert_eq!(opener.open(TOPIC, &m4).unwrap_err(), Reject::Replay);
}

#[test]
fn property_mismatch_rejects_before_touching_replay_state() {
    use rumqtt_pq_envelope::{user_properties, PROP_SENDER};
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());

    let env = cam.seal(&ops_pub, TOPIC, b"m1").unwrap();
    let good = user_properties(&env).unwrap();
    let mut lie = good.clone();
    lie.iter_mut().find(|(k, _)| k == PROP_SENDER).unwrap().1 = "edge-cam-99".into();
    assert_eq!(
        opener.open_with_properties(TOPIC, &env, &lie).unwrap_err(),
        Reject::PropertyMismatch
    );
    // Same envelope still opens: the rejected attempt did not consume seq 1.
    let extra = [("app".to_string(), "ignored".to_string())];
    let props: Vec<_> = good.iter().cloned().chain(extra).collect();
    assert_eq!(
        opener.open_with_properties(TOPIC, &env, &props).unwrap().2,
        b"m1"
    );
    // No properties at all is allowed.
    let env2 = cam.seal(&ops_pub, TOPIC, b"m2").unwrap();
    assert_eq!(opener.open_with_properties(TOPIC, &env2, &[]).unwrap().1, 2);
}
