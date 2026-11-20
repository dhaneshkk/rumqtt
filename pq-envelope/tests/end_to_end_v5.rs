//! MQTT 5 end-to-end: rumqttd `[v5]` listeners with native `key_exchange` policies, the
//! rumqttc v5 client over X25519MLKEM768-only mTLS, and the Layer-2 envelope with its
//! routing metadata carried in MQTT 5 user properties (`pqe-alg`, `pqe-sender`, `pqe-seq`).
//!
//! Checks:
//! * classical-only client refused by `post-quantum-only`, accepted by `prefer-post-quantum`;
//! * the broker forwards the envelope's user properties unchanged;
//! * the 65-case envelope matrix, plus 10 property-tampering cases and 5 genuine
//!   messages sent without properties, are all classified correctly (MCC = 1.0).
//!
//! Run with `cargo test -p rumqtt-pq-envelope --test end_to_end_v5 -- --nocapture`.

mod common;

use common::net::{client_tls, free_port, make_pki, start_broker, Pki};
use common::{test_matrix, Confusion, TOPIC};
use rumqtt_pq_envelope::{
    sender_hint, user_properties, Opener, RecipientKeys, Reject, Sender, PROP_SENDER, PROP_SEQ,
};
use rumqttc::v5::mqttbytes::v5::{Packet, PublishProperties};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::Transport;
use std::time::Duration;
use tokio::sync::mpsc;

type Props = Vec<(String, String)>;

fn client(pki: &Pki, idx: usize, port: u16, pq_only: bool) -> (AsyncClient, EventLoop) {
    let mut o = MqttOptions::new(format!("v5-client-{idx}-{port}"), "localhost", port);
    o.set_max_packet_size(Some(64 * 1024));
    o.set_transport(Transport::tls_with_config(
        client_tls(pki, idx, pq_only).into(),
    ));
    AsyncClient::new(o, 64)
}

/// Poll until CONNACK (Ok) or a connection error (Err).
async fn handshake(ev: &mut EventLoop) -> Result<(), String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ev.poll()).await {
            Ok(Ok(Event::Incoming(Packet::ConnAck(_)))) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("timeout".into()),
        }
    }
}

fn set(props: &Props, key: &str, value: &str) -> Props {
    props
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                if k == key {
                    value.to_string()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mqtt5_post_quantum_tls_and_envelope_end_to_end() {
    let pki = make_pki("v5", 4);
    let (pq_port, migrate_port) = (free_port(), free_port());
    start_broker(
        &pki,
        "v5",
        &[
            (pq_port, "post-quantum-only"),
            (migrate_port, "prefer-post-quantum"),
        ],
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Layer 1 checks over MQTT 5 ---
    let (_l, mut legacy) = client(&pki, 2, pq_port, false);
    let legacy_res = handshake(&mut legacy).await;
    println!("[v5] classical-only client -> post-quantum-only listener: {legacy_res:?}");
    assert!(legacy_res.is_err(), "classical-only client must be refused");

    let (_m, mut migrating) = client(&pki, 3, migrate_port, false);
    let migrate_res = handshake(&mut migrating).await;
    println!("[v5] classical-only client -> prefer-post-quantum listener: {migrate_res:?}");
    assert!(
        migrate_res.is_ok(),
        "prefer-post-quantum keeps a classical fallback"
    );

    // --- Layer 2 over the PQ-only MQTT 5 listener ---
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());

    let (sub, mut sub_ev) = client(&pki, 1, pq_port, true);
    handshake(&mut sub_ev)
        .await
        .expect("PQ v5 subscriber handshake");
    sub.subscribe(TOPIC, QoS::AtLeastOnce).await.unwrap();
    let (pubc, mut pub_ev) = client(&pki, 0, pq_port, true);
    handshake(&mut pub_ev)
        .await
        .expect("PQ v5 publisher handshake");
    println!("[v5] publisher + subscriber connected with X25519MLKEM768-only TLS 1.3");

    // Subscriber: open with the received user properties; report what arrived.
    type Opened = (Props, Result<(String, u64, Vec<u8>), Reject>);
    let (tx, mut rx) = mpsc::unbounded_channel::<Opened>();
    tokio::spawn(async move {
        while let Ok(ev) = sub_ev.poll().await {
            if let Event::Incoming(Packet::Publish(p)) = ev {
                let topic = std::str::from_utf8(&p.topic).unwrap().to_string();
                let props: Props = p
                    .properties
                    .map(|pp| pp.user_properties)
                    .unwrap_or_default();
                // Routing hint is available before any crypto work.
                let _route = sender_hint(&props).map(str::to_owned);
                let res = opener.open_with_properties(&topic, &p.payload, &props);
                let _ = tx.send((props, res));
            }
        }
    });
    tokio::spawn(async move { while pub_ev.poll().await.is_ok() {} });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Build the v5 matrix: (label, genuine, envelope, user properties sent).
    let mut cases: Vec<(&str, bool, Vec<u8>, Props)> = test_matrix(&mut cam, &ops_pub)
        .into_iter()
        .map(|(l, g, env)| {
            let props = user_properties(&env).unwrap();
            (l, g, env, props)
        })
        .collect();
    for _ in 0..5 {
        let env = cam.seal(&ops_pub, TOPIC, b"route-me").unwrap();
        let props = set(&user_properties(&env).unwrap(), PROP_SENDER, "edge-cam-99");
        cases.push(("prop-sender-lie", false, env, props));
    }
    for _ in 0..5 {
        let env = cam.seal(&ops_pub, TOPIC, b"seq-lie").unwrap();
        let props = set(&user_properties(&env).unwrap(), PROP_SEQ, "1");
        cases.push(("prop-seq-lie", false, env, props));
    }
    for i in 0..5 {
        let pt = format!("{{\"cam\":1,\"no_props\":{i}}}");
        let env = cam.seal(&ops_pub, TOPIC, pt.as_bytes()).unwrap();
        cases.push(("genuine-no-props", true, env, Vec::new()));
    }

    let mut c = Confusion::default();
    let mut forwarded_ok = 0;
    for (label, genuine, env, props) in cases {
        let properties = PublishProperties {
            user_properties: props.clone(),
            ..Default::default()
        };
        pubc.publish_with_properties(TOPIC, QoS::AtLeastOnce, false, env, properties)
            .await
            .unwrap();
        let (got_props, res) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery timeout")
            .expect("subscriber closed");
        assert_eq!(
            got_props, props,
            "broker must forward user properties ({label})"
        );
        forwarded_ok += 1;
        let expected = match label {
            "genuine" | "genuine-no-props" => None,
            "bit-flip" | "forged-signer" | "topic-swap" => Some(Reject::BadSignature),
            "replay" => Some(Reject::Replay),
            "stale-ts" => Some(Reject::Stale),
            "wrong-recipient" => Some(Reject::Decrypt),
            "unknown-sender" => Some(Reject::UnknownSender),
            "prop-sender-lie" | "prop-seq-lie" => Some(Reject::PropertyMismatch),
            _ => unreachable!(),
        };
        assert_eq!(res.as_ref().err().copied(), expected, "case {label}");
        if let Err(r) = &res {
            print!("{label}->{r:?}  ");
        }
        c.record(genuine, res.is_ok());
    }
    println!("\n[v5] user properties forwarded intact: {forwarded_ok}/80");
    println!("[v5] confusion = {c:?}, MCC = {:.4}", c.mcc());
    assert_eq!(forwarded_ok, 80);
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
    let _ = std::fs::remove_dir_all(&pki.dir);
}
