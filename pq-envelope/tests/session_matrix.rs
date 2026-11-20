//! Session mode (HPKE group handshake + small frames): attack matrix scored with MCC,
//! group membership, restarts, replay window, bucket padding and zstd sizing.

mod common;

use common::{Confusion, TOPIC};
use rumqtt_pq_envelope::session::{
    bucket_for, train_dictionary, Compression, SessionConfig, SessionOpener, SessionSender,
};
use rumqtt_pq_envelope::{RecipientKeys, RecipientPublic, Reject, Sender};
use std::sync::Arc;

fn cam() -> Sender {
    Sender::generate("edge-cam-01").unwrap()
}

fn opener_for(keys: RecipientKeys, cam: &Sender, cfg: SessionConfig) -> SessionOpener {
    let mut o = SessionOpener::new(keys, cfg).unwrap();
    o.trust("edge-cam-01", cam.public_key_der().unwrap());
    o
}

fn telemetry(i: usize) -> Vec<u8> {
    format!(
        "{{\"site\":\"rig-07\",\"cam\":\"edge-cam-01\",\"frame\":{i},\"ts\":{},\"ppe\":{{\"helmet\":{},\"vest\":true}},\"persons\":{},\"zone\":\"deck-{}\"}}",
        1_763_600_000 + i,
        !i.is_multiple_of(7),
        i % 4,
        i % 3
    )
    .into_bytes()
}

#[test]
fn session_matrix_mcc_is_one() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let signer = cam();
    let mut o = opener_for(ops, &signer, SessionConfig::default());
    let mut tx = SessionSender::new(
        signer,
        std::slice::from_ref(&ops_pub),
        1,
        SessionConfig::default(),
    )
    .unwrap();

    let hs1 = tx.handshake().unwrap();
    assert_eq!(o.accept_handshake(&hs1).unwrap().members, 1);

    let mut c = Confusion::default();
    let mut check =
        |label: &str, genuine: bool, res: Result<(), Reject>, expected: Option<Reject>| {
            assert_eq!(res.err(), expected, "case {label}");
            c.record(genuine, res.is_ok());
        };

    let mut sent = Vec::new();
    for i in 0..30 {
        let f = tx.seal(TOPIC, &telemetry(i)).unwrap();
        sent.push(f.clone());
        let r = o.open(TOPIC, &f).map(|_| ());
        check("genuine", true, r, None);
    }
    // Frame attacks.
    for i in 0..5 {
        let mut f = tx.seal(TOPIC, b"tamper").unwrap();
        let n = f.len();
        f[n - 1 - i] ^= 1;
        check(
            "bit-flip",
            false,
            o.open(TOPIC, &f).map(|_| ()),
            Some(Reject::Decrypt),
        );
    }
    for f in sent.iter().take(5) {
        check(
            "replay",
            false,
            o.open(TOPIC, f).map(|_| ()),
            Some(Reject::Replay),
        );
    }
    for _ in 0..5 {
        let f = tx.seal("vg360/site1/other", b"moved").unwrap();
        check(
            "topic-swap",
            false,
            o.open(TOPIC, &f).map(|_| ()),
            Some(Reject::Decrypt),
        );
    }
    for _ in 0..5 {
        let mut f = tx.seal(TOPIC, b"codec").unwrap();
        f[28] = 1; // claim zstd: header is in the AAD
        check(
            "header-tamper",
            false,
            o.open(TOPIC, &f).map(|_| ()),
            Some(Reject::Decrypt),
        );
    }
    for _ in 0..5 {
        let mut f = tx.seal(TOPIC, b"sid").unwrap();
        f[4] ^= 0xff; // unknown session id
        check(
            "unknown-session",
            false,
            o.open(TOPIC, &f).map(|_| ()),
            Some(Reject::UnknownSession),
        );
    }
    for cut in [0, 3, 20, 29, 44] {
        let f = tx.seal(TOPIC, b"short").unwrap();
        check(
            "truncated",
            false,
            o.open(TOPIC, &f[..cut]).map(|_| ()),
            Some(Reject::Malformed),
        );
    }
    // Handshake attacks.
    let attacker = Sender::generate("edge-cam-01").unwrap();
    let mut forged = SessionSender::new(
        attacker,
        std::slice::from_ref(&ops_pub),
        99,
        SessionConfig::default(),
    )
    .unwrap();
    for _ in 0..5 {
        let hs = forged.handshake().unwrap();
        check(
            "forged-handshake",
            false,
            o.accept_handshake(&hs).map(|_| ()),
            Some(Reject::BadSignature),
        );
    }
    // Validly signed, but the key is wrapped for someone else.
    let real = Sender::generate("edge-cam-01").unwrap();
    let mut o2 = opener_for(
        RecipientKeys::generate().unwrap(),
        &real,
        SessionConfig::default(),
    );
    let mut not_me = SessionSender::new(
        real,
        &[RecipientKeys::generate().unwrap().public().unwrap()],
        1,
        SessionConfig::default(),
    )
    .unwrap();
    for _ in 0..5 {
        let hs = not_me.handshake().unwrap();
        check(
            "not-a-recipient",
            false,
            o2.accept_handshake(&hs).map(|_| ()),
            Some(Reject::NotARecipient),
        );
    }
    // Rekey: hs2 newer -> accepted; replaying hs1 afterwards -> stale.
    let hs2 = tx.handshake().unwrap();
    o.accept_handshake(&hs2).unwrap();
    for _ in 0..5 {
        check(
            "stale-handshake",
            false,
            o.accept_handshake(&hs1).map(|_| ()),
            Some(Reject::StaleSession),
        );
    }
    for i in 0..5 {
        let f = tx.seal(TOPIC, &telemetry(100 + i)).unwrap();
        check(
            "genuine-after-rekey",
            true,
            o.open(TOPIC, &f).map(|_| ()),
            None,
        );
    }
    println!("session confusion = {c:?}, MCC = {:.4}", c.mcc());
    assert_eq!(
        c,
        Confusion {
            tp: 35,
            tn: 45,
            fp: 0,
            fn_: 0
        }
    );
    assert!((c.mcc() - 1.0).abs() < 1e-12);
}

#[test]
fn group_key_one_frame_many_readers_and_membership_change() {
    let members: Vec<RecipientKeys> = (0..5).map(|_| RecipientKeys::generate().unwrap()).collect();
    let pubs: Vec<RecipientPublic> = members.iter().map(|k| k.public().unwrap()).collect();
    let signer = cam();
    let pk = signer.public_key_der().unwrap();
    let mut openers: Vec<SessionOpener> = members
        .into_iter()
        .map(|k| {
            let mut o = SessionOpener::new(k, SessionConfig::default()).unwrap();
            o.trust("edge-cam-01", pk.clone());
            o
        })
        .collect();
    let mut tx = SessionSender::new(signer, &pubs, 1, SessionConfig::default()).unwrap();
    let hs = tx.handshake().unwrap();
    println!("group handshake for 5 members: {} bytes", hs.len());
    for o in &mut openers {
        assert_eq!(o.accept_handshake(&hs).unwrap().members, 5);
    }
    // One frame, five readers.
    let f = tx.seal(TOPIC, b"to everyone").unwrap();
    for o in &mut openers {
        assert_eq!(o.open(TOPIC, &f).unwrap().plaintext, b"to everyone");
    }
    // Remove member 4: re-key; member 4 cannot join the new session or read its frames.
    tx.set_recipients(&pubs[..4]).unwrap();
    assert!(tx.needs_handshake());
    let hs2 = tx.handshake().unwrap();
    for o in &mut openers[..4] {
        assert_eq!(o.accept_handshake(&hs2).unwrap().members, 4);
    }
    assert_eq!(
        openers[4].accept_handshake(&hs2).unwrap_err(),
        Reject::NotARecipient
    );
    let f2 = tx.seal(TOPIC, b"members only").unwrap();
    for o in &mut openers[..4] {
        assert_eq!(o.open(TOPIC, &f2).unwrap().plaintext, b"members only");
    }
    assert_eq!(
        openers[4].open(TOPIC, &f2).unwrap_err(),
        Reject::UnknownSession
    );
}

#[test]
fn delayed_frames_and_rekey_grace() {
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let signer = cam();
    let mut o = opener_for(ops, &signer, SessionConfig::default());
    let mut tx = SessionSender::new(signer, &[ops_pub], 1, SessionConfig::default()).unwrap();
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    let old: Vec<_> = (0..10)
        .map(|i| tx.seal(TOPIC, &telemetry(i)).unwrap())
        .collect();
    // Rekey while those 10 are still queued at the broker: they stay readable.
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    let new = tx.seal(TOPIC, b"new session").unwrap();
    assert!(o.open(TOPIC, &new).is_ok());
    // Delivered out of order (QoS 1 redelivery), within the 64-frame window.
    for f in old.iter().rev() {
        assert!(o.open(TOPIC, f).is_ok());
    }
    // ...but exactly once.
    assert_eq!(o.open(TOPIC, &old[3]).unwrap_err(), Reject::Replay);
    // Frames older than the window are rejected.
    let mut tx2 = tx;
    let first = tx2.seal(TOPIC, b"first").unwrap();
    for i in 0..70 {
        o.open(TOPIC, &tx2.seal(TOPIC, &telemetry(i)).unwrap())
            .unwrap();
    }
    assert_eq!(o.open(TOPIC, &first).unwrap_err(), Reject::Replay);
}

#[test]
fn restarts_publisher_epoch_and_subscriber_state() {
    let ops = RecipientKeys::generate().unwrap();
    let secret = ops.to_secret_bytes();
    let ops_pub = ops.public().unwrap();
    let pkcs8 = cam().to_pkcs8().unwrap();
    let signer = Sender::from_pkcs8("edge-cam-01", &pkcs8).unwrap();
    let pk = signer.public_key_der().unwrap();
    let mut o = SessionOpener::new(ops, SessionConfig::default()).unwrap();
    o.trust("edge-cam-01", pk.clone());
    let mut tx = SessionSender::new(
        signer,
        std::slice::from_ref(&ops_pub),
        1,
        SessionConfig::default(),
    )
    .unwrap();
    let hs = tx.handshake().unwrap(); // published retained
    o.accept_handshake(&hs).unwrap();
    let seen: Vec<_> = (0..5)
        .map(|i| tx.seal(TOPIC, &telemetry(i)).unwrap())
        .collect();
    for f in &seen {
        o.open(TOPIC, f).unwrap();
    }
    let saved = o.export_state();

    // Subscriber restart: keys + state restored; retained handshake re-delivered.
    let mut o = SessionOpener::new(
        RecipientKeys::from_secret_bytes(&secret).unwrap(),
        SessionConfig::default(),
    )
    .unwrap();
    o.trust("edge-cam-01", pk.clone());
    o.import_state(&saved).unwrap();
    assert!(!o.accept_handshake(&hs).unwrap().duplicate);
    for f in &seen {
        assert_eq!(
            o.open(TOPIC, f).unwrap_err(),
            Reject::Replay,
            "replay after restart"
        );
    }
    assert!(o.open(TOPIC, &tx.seal(TOPIC, b"fresh").unwrap()).is_ok());
    assert!(o.accept_handshake(&hs).unwrap().duplicate);

    // Publisher restart without persisted session: next epoch -> accepted.
    let signer = Sender::from_pkcs8("edge-cam-01", &pkcs8).unwrap();
    let mut tx = SessionSender::new(
        signer,
        std::slice::from_ref(&ops_pub),
        2,
        SessionConfig::default(),
    )
    .unwrap();
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    assert!(o
        .open(TOPIC, &tx.seal(TOPIC, b"after reboot").unwrap())
        .is_ok());
    // A publisher that reused an old epoch is refused.
    let signer = Sender::from_pkcs8("edge-cam-01", &pkcs8).unwrap();
    let mut stale = SessionSender::new(signer, &[ops_pub], 1, SessionConfig::default()).unwrap();
    assert_eq!(
        o.accept_handshake(&stale.handshake().unwrap()).unwrap_err(),
        Reject::StaleSession
    );
}

#[test]
fn bucket_padding_hides_length_within_bucket() {
    let b = SessionConfig::default().buckets;
    assert_eq!(bucket_for(&b, 1), 64);
    assert_eq!(bucket_for(&b, 64), 64);
    assert_eq!(bucket_for(&b, 65), 128);
    assert_eq!(bucket_for(&b, 65536), 65536);
    assert_eq!(bucket_for(&b, 65537), 131072);

    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let signer = cam();
    let mut o = opener_for(ops, &signer, SessionConfig::default());
    let mut tx = SessionSender::new(signer, &[ops_pub], 1, SessionConfig::default()).unwrap();
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    let lens: Vec<usize> = [0usize, 1, 10, 40, 60]
        .iter()
        .map(|n| {
            let f = tx.seal(TOPIC, &vec![b'x'; *n]).unwrap();
            assert_eq!(o.open(TOPIC, &f).unwrap().plaintext.len(), *n);
            f.len()
        })
        .collect();
    // header 29 + block 64 + tag 16
    assert!(lens.iter().all(|l| *l == 29 + 64 + 16), "{lens:?}");
    let big = tx.seal(TOPIC, &[b'x'; 61]).unwrap();
    assert_eq!(big.len(), 29 + 128 + 16);
}

#[test]
fn zstd_and_dictionary_sizes() {
    let samples: Vec<Vec<u8>> = (0..2000).map(telemetry).collect();
    let dict = Arc::new(train_dictionary(&samples, 4096).unwrap());
    let configs = [
        ("none", Compression::None),
        ("zstd", Compression::Zstd { level: 3 }),
        (
            "zstd+dict",
            Compression::ZstdDict {
                id: 7,
                dict: dict.clone(),
                level: 3,
            },
        ),
    ];
    let mut avg = Vec::new();
    for (name, comp) in configs {
        let cfg = SessionConfig {
            compression: comp,
            ..Default::default()
        };
        let ops = RecipientKeys::generate().unwrap();
        let ops_pub = ops.public().unwrap();
        let signer = cam();
        let mut o = opener_for(ops, &signer, cfg.clone());
        o.add_dictionary(7, dict.to_vec());
        let mut tx = SessionSender::new(signer, &[ops_pub], 1, cfg).unwrap();
        o.accept_handshake(&tx.handshake().unwrap()).unwrap();
        let mut total = 0usize;
        for i in 5000..5200 {
            let pt = telemetry(i);
            let f = tx.seal(TOPIC, &pt).unwrap();
            assert_eq!(o.open(TOPIC, &f).unwrap().plaintext, pt);
            total += f.len();
        }
        avg.push((name, total / 200));
    }
    let raw = telemetry(5000).len();
    println!("payload ~{raw} B JSON; per-message envelope ~4.7 KB; session frames: {avg:?}");
    assert!(
        avg[2].1 < avg[0].1,
        "dictionary should shrink frames: {avg:?}"
    );
    assert!(avg[2].1 <= 128, "{avg:?}");

    // Unknown dictionary and decompression bomb are rejected.
    let cfg = SessionConfig {
        compression: Compression::ZstdDict {
            id: 8,
            dict,
            level: 3,
        },
        ..Default::default()
    };
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let signer = cam();
    let small = SessionConfig {
        max_plaintext: 1024,
        ..Default::default()
    };
    let mut o = opener_for(ops, &signer, small);
    let mut tx = SessionSender::new(signer, &[ops_pub], 1, cfg).unwrap();
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    assert_eq!(
        o.open(TOPIC, &tx.seal(TOPIC, b"x").unwrap()).unwrap_err(),
        Reject::UnknownDictionary
    );
    let bomb_cfg = SessionConfig {
        compression: Compression::Zstd { level: 19 },
        ..Default::default()
    };
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let signer = cam();
    let mut o = opener_for(
        ops,
        &signer,
        SessionConfig {
            max_plaintext: 1024,
            ..Default::default()
        },
    );
    let mut tx = SessionSender::new(signer, &[ops_pub], 1, bomb_cfg).unwrap();
    o.accept_handshake(&tx.handshake().unwrap()).unwrap();
    let bomb = tx.seal(TOPIC, &vec![0u8; 1 << 20]).unwrap();
    println!("1 MiB of zeros -> {} byte frame", bomb.len());
    assert_eq!(o.open(TOPIC, &bomb).unwrap_err(), Reject::Decompress);
}
