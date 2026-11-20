//! End-to-end: rumqttd with a native `key_exchange = "post-quantum-only"` mTLS listener,
//! rumqttc publisher/subscriber using an X25519MLKEM768-only rustls config, and the
//! Layer-2 envelope on every payload. Also checks that a classical-only client is refused,
//! and that a `prefer-post-quantum` listener still accepts it (migration mode).
//!
//! Run with `cargo test -p rumqtt-pq-envelope --test end_to_end -- --nocapture`.

mod common;

use common::net::{client_tls, free_port, make_pki, start_broker, Pki};
use common::{test_matrix, Confusion, TOPIC};
use rumqtt_pq_envelope::{Opener, RecipientKeys, Reject, Sender};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, Transport};
use std::time::Duration;
use tokio::sync::mpsc;

fn client(pki: &Pki, idx: usize, port: u16, pq_only: bool) -> (AsyncClient, EventLoop) {
    let mut o = MqttOptions::new(format!("client-{idx}-{port}"), "localhost", port);
    o.set_max_packet_size(64 * 1024, 64 * 1024);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_quantum_tls_and_envelope_end_to_end() {
    let pki = make_pki("v4", 4);
    let (pq_port, migrate_port) = (free_port(), free_port());
    start_broker(
        &pki,
        "v4",
        &[
            (pq_port, "post-quantum-only"),
            (migrate_port, "prefer-post-quantum"),
        ],
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    // --- Layer 1 checks ---
    let (_l, mut legacy) = client(&pki, 2, pq_port, false);
    let legacy_res = handshake(&mut legacy).await;
    println!("classical-only client -> post-quantum-only listener: {legacy_res:?}");
    assert!(legacy_res.is_err(), "classical-only client must be refused");

    let (_m, mut migrating) = client(&pki, 3, migrate_port, false);
    let migrate_res = handshake(&mut migrating).await;
    println!("classical-only client -> prefer-post-quantum listener: {migrate_res:?}");
    assert!(
        migrate_res.is_ok(),
        "prefer-post-quantum keeps a classical fallback"
    );

    // --- Layer 2 over the PQ-only listener ---
    let ops = RecipientKeys::generate().unwrap();
    let ops_pub = ops.public().unwrap();
    let mut cam = Sender::generate("edge-cam-01").unwrap();
    let mut opener = Opener::new(ops);
    opener.trust("edge-cam-01", cam.public_key_der().unwrap());

    let (sub, mut sub_ev) = client(&pki, 1, pq_port, true);
    handshake(&mut sub_ev)
        .await
        .expect("PQ subscriber handshake");
    sub.subscribe(TOPIC, QoS::AtLeastOnce).await.unwrap();
    let (pubc, mut pub_ev) = client(&pki, 0, pq_port, true);
    handshake(&mut pub_ev)
        .await
        .expect("PQ publisher handshake");
    println!("PQ publisher + subscriber connected with X25519MLKEM768-only TLS 1.3");

    type Opened = Result<(String, u64, Vec<u8>), Reject>;
    let (tx, mut rx) = mpsc::unbounded_channel::<Opened>();
    tokio::spawn(async move {
        while let Ok(ev) = sub_ev.poll().await {
            if let Event::Incoming(Packet::Publish(p)) = ev {
                let _ = tx.send(opener.open(&p.topic, &p.payload));
            }
        }
    });
    tokio::spawn(async move { while pub_ev.poll().await.is_ok() {} });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut c = Confusion::default();
    for (label, genuine, env) in test_matrix(&mut cam, &ops_pub) {
        pubc.publish(TOPIC, QoS::AtLeastOnce, false, env)
            .await
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery timeout")
            .expect("subscriber closed");
        if let Err(r) = &res {
            print!("{label}->{r:?}  ");
        }
        c.record(genuine, res.is_ok());
    }
    println!("\nconfusion = {c:?}, MCC = {:.4}", c.mcc());
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
    let _ = std::fs::remove_dir_all(&pki.dir);
}
