//! Session mode end-to-end over rumqttd (MQTT 5, post-quantum-only TLS):
//! * the publisher's HPKE group handshake is published **retained** on `pq/hs/<sender>`,
//! * three subscribers (one joins late, after the handshake was published) read every
//!   frame from a single publish,
//! * a retained data frame is readable by the late joiner,
//! * the publisher "reboots" with the next epoch; a replayed old handshake is refused.

mod common;

use common::net::{client_tls, free_port, make_pki, start_broker, Pki};
use common::TOPIC;
use rumqtt_pq_envelope::session::{Compression, SessionConfig, SessionOpener, SessionSender};
use rumqtt_pq_envelope::{RecipientKeys, Reject, Sender};
use rumqttc::v5::mqttbytes::v5::Packet;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, EventLoop, MqttOptions};
use rumqttc::Transport;
use std::time::Duration;
use tokio::sync::mpsc;

const HS_TOPIC: &str = "pq/hs/edge-cam-01";

fn client(pki: &Pki, idx: usize, port: u16) -> (AsyncClient, EventLoop) {
    let mut o = MqttOptions::new(format!("sess-{idx}-{port}"), "localhost", port);
    o.set_max_packet_size(Some(64 * 1024));
    o.set_transport(Transport::tls_with_config(
        client_tls(pki, idx, true).into(),
    ));
    AsyncClient::new(o, 64)
}

async fn connack(ev: &mut EventLoop) {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ev.poll())
            .await
            .expect("timeout")
        {
            Ok(Event::Incoming(Packet::ConnAck(_))) => return,
            Ok(_) => {}
            Err(e) => panic!("connect failed: {e}"),
        }
    }
}

/// Subscriber task: handshakes on HS_TOPIC, frames elsewhere. Reports (topic, result).
fn spawn_reader(
    mut opener: SessionOpener,
    mut ev: EventLoop,
) -> mpsc::UnboundedReceiver<(String, Result<Vec<u8>, Reject>)> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(e) = ev.poll().await {
            if let Event::Incoming(Packet::Publish(p)) = e {
                let topic = String::from_utf8(p.topic.to_vec()).unwrap();
                let res = if topic.starts_with("pq/hs/") {
                    opener
                        .accept_handshake(&p.payload)
                        .map(|i| format!("hs epoch={} n={}", i.epoch, i.members).into_bytes())
                } else {
                    opener.open(&topic, &p.payload).map(|o| o.plaintext)
                };
                let _ = tx.send((topic, res));
            }
        }
    });
    rx
}

async fn next(
    rx: &mut mpsc::UnboundedReceiver<(String, Result<Vec<u8>, Reject>)>,
) -> (String, Result<Vec<u8>, Reject>) {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("delivery timeout")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mqtt5_session_mode_group_retained_reboot() {
    let pki = make_pki("sess", 4);
    let port = free_port();
    start_broker(&pki, "v5", &[(port, "post-quantum-only")]);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let cfg = SessionConfig {
        compression: Compression::Zstd { level: 3 },
        ..Default::default()
    };
    let keys: Vec<RecipientKeys> = (0..3).map(|_| RecipientKeys::generate().unwrap()).collect();
    let pubs: Vec<_> = keys.iter().map(|k| k.public().unwrap()).collect();
    let pkcs8 = Sender::generate("edge-cam-01").unwrap().to_pkcs8().unwrap();
    let signer = Sender::from_pkcs8("edge-cam-01", &pkcs8).unwrap();
    let pk = signer.public_key_der().unwrap();
    let mut openers: Vec<SessionOpener> = keys
        .into_iter()
        .map(|k| {
            let mut o = SessionOpener::new(k, cfg.clone()).unwrap();
            o.trust("edge-cam-01", pk.clone());
            o
        })
        .collect();

    // Publisher: retained handshake first.
    let (pubc, mut pub_ev) = client(&pki, 0, port);
    connack(&mut pub_ev).await;
    tokio::spawn(async move { while pub_ev.poll().await.is_ok() {} });
    let mut tx = SessionSender::new(signer, &pubs, 1, cfg.clone()).unwrap();
    let hs1 = tx.handshake().unwrap();
    pubc.publish(HS_TOPIC, QoS::AtLeastOnce, true, hs1.clone())
        .await
        .unwrap();

    // Two subscribers join now; the third joins later.
    let late_opener = openers.pop().unwrap();
    let mut readers = Vec::new();
    for (i, o) in openers.into_iter().enumerate() {
        let (c, mut ev) = client(&pki, 1 + i, port);
        connack(&mut ev).await;
        c.subscribe("pq/hs/+", QoS::AtLeastOnce).await.unwrap();
        c.subscribe(TOPIC, QoS::AtLeastOnce).await.unwrap();
        let mut rx = spawn_reader(o, ev);
        let (t, r) = next(&mut rx).await; // retained handshake
        assert_eq!(t, HS_TOPIC);
        assert_eq!(r.unwrap(), b"hs epoch=1 n=3");
        readers.push((c, rx));
    }

    // Frames: one publish each, read by every member. The last one is retained.
    let mut sizes = Vec::new();
    for i in 0..20 {
        let msg = format!("{{\"cam\":1,\"frame\":{i},\"helmet\":true}}");
        let f = tx.seal(TOPIC, msg.as_bytes()).unwrap();
        sizes.push(f.len());
        pubc.publish(TOPIC, QoS::AtLeastOnce, i == 19, f)
            .await
            .unwrap();
        for (_, rx) in &mut readers {
            let (_, r) = next(rx).await;
            assert_eq!(r.unwrap(), msg.as_bytes());
        }
    }
    println!(
        "session frames on the wire: {:?} bytes (handshake {} bytes, 3 members)",
        sizes.iter().max(),
        hs1.len()
    );
    assert!(sizes.iter().all(|s| *s <= 29 + 64 + 16));

    // Late joiner: gets the retained handshake, then the retained last frame.
    let (late, mut late_ev) = client(&pki, 3, port);
    connack(&mut late_ev).await;
    late.subscribe("pq/hs/+", QoS::AtLeastOnce).await.unwrap();
    let mut late_rx = spawn_reader(late_opener, late_ev);
    assert_eq!(next(&mut late_rx).await.1.unwrap(), b"hs epoch=1 n=3");
    late.subscribe(TOPIC, QoS::AtLeastOnce).await.unwrap();
    assert_eq!(
        next(&mut late_rx).await.1.unwrap(),
        b"{\"cam\":1,\"frame\":19,\"helmet\":true}"
    );
    readers.push((late, late_rx));

    // Publisher reboot: next epoch, new retained handshake, frames keep flowing.
    let signer = Sender::from_pkcs8("edge-cam-01", &pkcs8).unwrap();
    let mut tx = SessionSender::new(signer, &pubs, 2, cfg).unwrap();
    pubc.publish(HS_TOPIC, QoS::AtLeastOnce, true, tx.handshake().unwrap())
        .await
        .unwrap();
    for (_, rx) in &mut readers {
        assert_eq!(next(rx).await.1.unwrap(), b"hs epoch=2 n=3");
    }
    let f = tx.seal(TOPIC, b"after reboot").unwrap();
    pubc.publish(TOPIC, QoS::AtLeastOnce, false, f)
        .await
        .unwrap();
    for (_, rx) in &mut readers {
        assert_eq!(next(rx).await.1.unwrap(), b"after reboot");
    }
    // Attacker re-publishes the captured epoch-1 handshake: everyone refuses it.
    pubc.publish(HS_TOPIC, QoS::AtLeastOnce, false, hs1)
        .await
        .unwrap();
    for (_, rx) in &mut readers {
        assert_eq!(next(rx).await.1.unwrap_err(), Reject::StaleSession);
    }
    let _ = std::fs::remove_dir_all(&pki.dir);
}
