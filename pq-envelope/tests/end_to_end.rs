//! End-to-end: rumqttd with a native `key_exchange = "post-quantum-only"` mTLS listener,
//! rumqttc publisher/subscriber using an X25519MLKEM768-only rustls config, and the
//! Layer-2 envelope on every payload. Also checks that a classical-only client is refused,
//! and that a `prefer-post-quantum` listener still accepts it (migration mode).
//!
//! Run with `cargo test -p rumqtt-pq-envelope --test end_to_end -- --nocapture`.

mod common;

use common::{test_matrix, Confusion, TOPIC};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rumqtt_pq_envelope::{Opener, RecipientKeys, Reject, Sender};
use rumqttc::tokio_rustls::rustls::{
    self,
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, RootCertStore,
};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, Transport};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::mpsc;

struct Pki {
    dir: PathBuf,
    ca: CertificateDer<'static>,
    clients: Vec<(Vec<CertificateDer<'static>>, Vec<u8>)>,
}

fn make_pki(n_clients: usize) -> Pki {
    let dir = std::env::temp_dir().join(format!("rumqtt-pq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rumqtt pq test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let srv_key = KeyPair::generate().unwrap();
    let mut sp = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv = sp.signed_by(&srv_key, &issuer).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("server.pem"), srv.pem() + &ca.pem()).unwrap();
    std::fs::write(dir.join("server.key"), srv_key.serialize_pem()).unwrap();

    let clients = (0..n_clients)
        .map(|i| {
            let k = KeyPair::generate().unwrap();
            let mut cp = CertificateParams::new(Vec::<String>::new()).unwrap();
            cp.distinguished_name
                .push(DnType::CommonName, format!("client-{i}"));
            cp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let c = cp.signed_by(&k, &issuer).unwrap();
            (vec![c.der().clone(), ca.der().clone()], k.serialize_der())
        })
        .collect();
    Pki {
        dir,
        ca: ca.der().clone(),
        clients,
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start rumqttd with one TLS listener per (port, key_exchange) pair.
fn start_broker(pki: &Pki, listeners: &[(u16, &str)]) {
    let d = pki.dir.display();
    let mut toml = String::from(
        "id = 0\n[router]\nid = 0\nmax_connections = 100\nmax_outgoing_packet_count = 200\n\
         max_segment_size = 104857600\nmax_segment_count = 10\n",
    );
    for (i, (port, kx)) in listeners.iter().enumerate() {
        toml += &format!(
            "[v4.{i}]\nname = \"pq-{i}\"\nlisten = \"127.0.0.1:{port}\"\nnext_connection_delay_ms = 1\n\
             [v4.{i}.tls]\ncapath = \"{d}/ca.pem\"\ncertpath = \"{d}/server.pem\"\n\
             keypath = \"{d}/server.key\"\nkey_exchange = \"{kx}\"\n\
             [v4.{i}.connections]\nconnection_timeout_ms = 60000\nmax_payload_size = 65536\n\
             max_inflight_count = 100\ndynamic_filters = true\n"
        );
    }
    let cfg: rumqttd::Config = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    std::thread::spawn(move || rumqttd::Broker::new(cfg).start().unwrap());
}

fn provider(pq_only: bool) -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = if pq_only {
        vec![aws_lc_rs::kx_group::X25519MLKEM768]
    } else {
        vec![aws_lc_rs::kx_group::X25519] // legacy device
    };
    Arc::new(p)
}

fn client(pki: &Pki, idx: usize, port: u16, pq_only: bool) -> (AsyncClient, EventLoop) {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let (chain, key) = &pki.clients[idx];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()));
    let cfg = ClientConfig::builder_with_provider(provider(pq_only))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain.clone(), key)
        .unwrap();
    let mut o = MqttOptions::new(format!("client-{idx}-{port}"), "localhost", port);
    o.set_max_packet_size(64 * 1024, 64 * 1024);
    o.set_transport(Transport::tls_with_config(cfg.into()));
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
    let pki = make_pki(4);
    let (pq_port, migrate_port) = (free_port(), free_port());
    start_broker(
        &pki,
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
