//! Key management: certificates under a fleet trust anchor, rotation, expiry and
//! revocation, and their effect on the openers. Scored with MCC.

mod common;

use common::{Confusion, TOPIC};
use rumqtt_pq_envelope::keys::{KeyDirectory, KeyError, Role, TrustAnchor};
use rumqtt_pq_envelope::session::{SessionConfig, SessionOpener, SessionSender};
use rumqtt_pq_envelope::{now, Opener, RecipientKeys, Reject, Sender};

const YEAR: u64 = 365 * 86400;

#[test]
fn certificate_matrix_mcc_is_one() {
    let anchor = TrustAnchor::generate().unwrap();
    let rogue = TrustAnchor::generate().unwrap();
    let mut dir = KeyDirectory::new(anchor.public_key_der().unwrap()).unwrap();
    let t = now();
    let mut c = Confusion::default();
    let mut check =
        |label: &str, genuine: bool, res: Result<(), KeyError>, expected: Option<KeyError>| {
            assert_eq!(res.err(), expected, "case {label}");
            c.record(genuine, res.is_ok());
        };

    let cams: Vec<Sender> = (0..10)
        .map(|i| Sender::generate(&format!("cam-{i}")).unwrap())
        .collect();
    for s in &cams {
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t,
                t + YEAR,
            )
            .unwrap();
        check("issue-sender", true, dir.add_cert(&cert).map(|_| ()), None);
    }
    let subs: Vec<RecipientKeys> = (0..5).map(|_| RecipientKeys::generate().unwrap()).collect();
    for (i, k) in subs.iter().enumerate() {
        let cert = anchor
            .issue(
                &format!("ops-{i}"),
                Role::Recipient,
                &k.public().unwrap().xwing_pub,
                1,
                t,
                t + YEAR,
            )
            .unwrap();
        check(
            "issue-recipient",
            true,
            dir.add_cert(&cert).map(|_| ()),
            None,
        );
    }
    // Rotation to a higher version.
    let mut serials = Vec::new();
    for s in cams.iter().take(5) {
        let new = Sender::generate(&s.id).unwrap();
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &new.public_key_der().unwrap(),
                2,
                t,
                t + YEAR,
            )
            .unwrap();
        let installed = dir.add_cert(&cert);
        check(
            "rotate",
            true,
            installed.as_ref().map(|_| ()).map_err(|e| *e),
            None,
        );
        serials.push(installed.unwrap().serial);
    }
    // Attacks / invalid certificates.
    for s in cams.iter().take(5) {
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t,
                t + YEAR,
            )
            .unwrap();
        check(
            "downgrade",
            false,
            dir.add_cert(&cert).map(|_| ()),
            Some(KeyError::Downgrade),
        );
    }
    for s in cams.iter().take(5) {
        let other = Sender::generate(&s.id).unwrap();
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &other.public_key_der().unwrap(),
                2,
                t,
                t + YEAR,
            )
            .unwrap();
        check(
            "same-version-conflict",
            false,
            dir.add_cert(&cert).map(|_| ()),
            Some(KeyError::Conflict),
        );
    }
    for i in 0..5 {
        let s = Sender::generate(&format!("rogue-{i}")).unwrap();
        let cert = rogue
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t,
                t + YEAR,
            )
            .unwrap();
        check(
            "wrong-issuer",
            false,
            dir.add_cert(&cert).map(|_| ()),
            Some(KeyError::WrongIssuer),
        );
    }
    for i in 0..5 {
        let s = Sender::generate(&format!("forged-{i}")).unwrap();
        let mut cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t,
                t + YEAR,
            )
            .unwrap();
        cert[10] ^= 1; // tamper with the signed body
        let r = dir.add_cert(&cert).map(|_| ());
        let r = if r == Err(KeyError::Malformed) {
            Err(KeyError::BadSignature)
        } else {
            r
        };
        check("tampered", false, r, Some(KeyError::BadSignature));
    }
    for i in 0..5 {
        let s = Sender::generate(&format!("expired-{i}")).unwrap();
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t - 2 * YEAR,
                t - YEAR,
            )
            .unwrap();
        check(
            "expired",
            false,
            dir.add_cert(&cert).map(|_| ()),
            Some(KeyError::Expired),
        );
    }
    for i in 0..5 {
        let s = Sender::generate(&format!("future-{i}")).unwrap();
        let cert = anchor
            .issue(
                &s.id,
                Role::Sender,
                &s.public_key_der().unwrap(),
                1,
                t + 86400,
                t + YEAR,
            )
            .unwrap();
        check(
            "not-yet-valid",
            false,
            dir.add_cert(&cert).map(|_| ()),
            Some(KeyError::NotYetValid),
        );
    }
    // Revocation of the 5 rotated certs; re-adding them is refused.
    let crl = anchor.revocation_list(1, &serials).unwrap();
    assert_eq!(dir.apply_revocations(&crl).unwrap(), 5);
    for s in cams.iter().take(5) {
        assert!(dir.sender_key(&s.id).is_none());
    }
    let crl_old = anchor.revocation_list(1, &[]).unwrap();
    check(
        "stale-crl",
        false,
        dir.apply_revocations(&crl_old).map(|_| ()),
        Some(KeyError::StaleRevocationList),
    );
    let crl_rogue = rogue.revocation_list(9, &[]).unwrap();
    check(
        "rogue-crl",
        false,
        dir.apply_revocations(&crl_rogue).map(|_| ()),
        Some(KeyError::WrongIssuer),
    );

    println!("certificate confusion = {c:?}, MCC = {:.4}", c.mcc());
    assert_eq!(
        c,
        Confusion {
            tp: 20,
            tn: 32,
            fp: 0,
            fn_: 0
        }
    );
    assert!((c.mcc() - 1.0).abs() < 1e-12);
    assert_eq!(dir.senders().len(), 5);
    assert!(dir.recipient("ops-0").is_some());
}

#[test]
fn directory_drives_openers_rotation_and_revocation() {
    let anchor = TrustAnchor::generate().unwrap();
    // Device provisioning: only the anchor's public key ships with the subscriber.
    let mut dir = KeyDirectory::new(anchor.public_key_der().unwrap()).unwrap();
    let t = now();
    let ops = RecipientKeys::generate().unwrap();
    let ops_cert = anchor
        .issue(
            "ops",
            Role::Recipient,
            &ops.public().unwrap().xwing_pub,
            1,
            t,
            t + YEAR,
        )
        .unwrap();
    let mut cam = Sender::generate("cam").unwrap();
    let cam_cert = anchor
        .issue(
            "cam",
            Role::Sender,
            &cam.public_key_der().unwrap(),
            1,
            t,
            t + YEAR,
        )
        .unwrap();
    dir.add_cert(&ops_cert).unwrap();
    let cam_serial = dir.add_cert(&cam_cert).unwrap().serial;

    // Publisher looks the recipient up by name instead of carrying raw keys around.
    let ops_pub = dir.recipient("ops").unwrap();
    let mut opener = Opener::new(ops);
    opener.sync_trust(&dir);
    let env = cam.seal(&ops_pub, TOPIC, b"v1").unwrap();
    assert!(opener.open(TOPIC, &env).is_ok());

    // Key rotation: new key, cert version 2; the old key stops verifying.
    // Same device, new key: it keeps counting (next epoch), so it is not a replay.
    let mut cam2 = Sender::generate("cam").unwrap().with_epoch(1);
    let cert2 = anchor
        .issue(
            "cam",
            Role::Sender,
            &cam2.public_key_der().unwrap(),
            2,
            t,
            t + YEAR,
        )
        .unwrap();
    let serial2 = dir.add_cert(&cert2).unwrap().serial;
    opener.sync_trust(&dir);
    let old_key = cam.seal(&ops_pub, TOPIC, b"old key").unwrap();
    assert_eq!(
        opener.open(TOPIC, &old_key).unwrap_err(),
        Reject::BadSignature
    );
    let new_key = cam2.seal(&ops_pub, TOPIC, b"new key").unwrap();
    assert!(opener.open(TOPIC, &new_key).is_ok());

    // Compromise: revoke both serials -> sender is no longer trusted at all.
    dir.apply_revocations(&anchor.revocation_list(1, &[cam_serial, serial2]).unwrap())
        .unwrap();
    opener.sync_trust(&dir);
    let after = cam2.seal(&ops_pub, TOPIC, b"revoked").unwrap();
    assert_eq!(
        opener.open(TOPIC, &after).unwrap_err(),
        Reject::UnknownSender
    );

    // Session mode uses the same directory.
    let cam3 = Sender::generate("cam").unwrap();
    let cert3 = anchor
        .issue(
            "cam",
            Role::Sender,
            &cam3.public_key_der().unwrap(),
            3,
            t,
            t + YEAR,
        )
        .unwrap();
    dir.add_cert(&cert3).unwrap();
    let ops2 = RecipientKeys::generate().unwrap();
    let ops2_cert = anchor
        .issue(
            "ops2",
            Role::Recipient,
            &ops2.public().unwrap().xwing_pub,
            1,
            t,
            t + YEAR,
        )
        .unwrap();
    dir.add_cert(&ops2_cert).unwrap();
    let mut so = SessionOpener::new(ops2, SessionConfig::default()).unwrap();
    so.sync_trust(&dir);
    let mut tx = SessionSender::new(
        cam3,
        &[dir.recipient("ops2").unwrap()],
        1,
        SessionConfig::default(),
    )
    .unwrap();
    so.accept_handshake(&tx.handshake().unwrap()).unwrap();
    assert!(so
        .open(TOPIC, &tx.seal(TOPIC, b"via directory").unwrap())
        .is_ok());
}

#[test]
fn anchor_and_keys_persist() {
    let anchor = TrustAnchor::generate().unwrap();
    let restored = TrustAnchor::from_pkcs8(&anchor.to_pkcs8().unwrap()).unwrap();
    assert_eq!(
        restored.public_key_der().unwrap(),
        anchor.public_key_der().unwrap()
    );
    let dir = KeyDirectory::new(anchor.public_key_der().unwrap()).unwrap();
    let s = Sender::generate("cam").unwrap();
    let cert = restored
        .issue(
            "cam",
            Role::Sender,
            &s.public_key_der().unwrap(),
            1,
            now(),
            now() + YEAR,
        )
        .unwrap();
    assert_eq!(dir.verify_cert(&cert).unwrap().subject, "cam");
    // A recipient key is not accepted as a sender key and vice versa.
    let r = RecipientKeys::generate().unwrap().public().unwrap();
    assert!(anchor
        .issue("x", Role::Sender, &r.xwing_pub, 1, now(), now() + YEAR)
        .is_err());
    assert!(anchor
        .issue(
            "x",
            Role::Recipient,
            &s.public_key_der().unwrap(),
            1,
            now(),
            now() + YEAR
        )
        .is_err());
}
