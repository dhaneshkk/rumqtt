//! Post-quantum policies on the two remaining TLS paths of rumqttd:
//!
//! * **Bridge** (rumqttd as a TLS *client* to a remote broker):
//!   `[bridge.transport.tls] key_exchange / signatures`.
//!   - end to end: broker A bridges `remote/#` from broker B over X25519MLKEM768-only,
//!     ML-DSA-65 mutual TLS; a message published on B arrives at A's subscriber;
//!   - policy checks against probe TLS servers that record each handshake:
//!     classical-only key exchange and an ECDSA server certificate are refused under
//!     `post-quantum-only` and accepted under `default`; an ECDSA bridge client key is
//!     refused before any handshake.
//! * **Secure websockets** (`[ws.x]` with `tls`): the same listener policy applies.

mod common;

use common::net::free_port;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ML_DSA_65,
};
use rumqttc::tokio_rustls::{
    rustls::{
        self,
        crypto::{aws_lc_rs, CryptoProvider},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor,
};
use rumqttc::{
    AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, TlsConfiguration, Transport,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc};

struct Pki {
    dir: PathBuf,
    ca: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

impl Pki {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rumqtt-pq-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_key = KeyPair::generate_for(&PKCS_ML_DSA_65).unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(DnType::CommonName, "fleet ML-DSA-65 CA");
        let ca = p.self_signed(&ca_key).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
        Self {
            dir,
            ca,
            issuer: Issuer::new(p, ca_key),
        }
    }
    fn path(&self, f: &str) -> String {
        self.dir.join(f).display().to_string()
    }
    /// Issue a leaf and write `<name>.pem` (chain) and `<name>.key`.
    fn leaf(&self, name: &str, alg: &'static SignatureAlgorithm, server: bool) -> Leaf {
        let k = KeyPair::generate_for(alg).unwrap();
        let sans = if server {
            vec!["localhost".to_string()]
        } else {
            vec![]
        };
        let mut p = CertificateParams::new(sans).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.extended_key_usages = vec![if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        let c = p.signed_by(&k, &self.issuer).unwrap();
        std::fs::write(
            self.dir.join(format!("{name}.pem")),
            c.pem() + &self.ca.pem(),
        )
        .unwrap();
        std::fs::write(self.dir.join(format!("{name}.key")), k.serialize_pem()).unwrap();
        Leaf {
            chain: vec![c.der().clone(), self.ca.der().clone()],
            key: k.serialize_der(),
        }
    }
}

const ROUTER: &str =
    "id = 0\n[router]\nid = 0\nmax_connections = 100\nmax_outgoing_packet_count = 200\n\
                      max_segment_size = 104857600\nmax_segment_count = 10\n";

fn listener(section: &str, port: u16, tls: Option<(&Pki, &str, &str, &str)>) -> String {
    let mut s = format!(
        "[{section}]\nname = \"{section}\"\nlisten = \"127.0.0.1:{port}\"\nnext_connection_delay_ms = 1\n\
         [{section}.connections]\nconnection_timeout_ms = 60000\nmax_payload_size = 65536\n\
         max_inflight_count = 100\ndynamic_filters = true\n"
    );
    if let Some((pki, server, kx, sigs)) = tls {
        s += &format!(
            "[{section}.tls]\ncapath = '{}'\ncertpath = '{}'\nkeypath = '{}'\n\
             key_exchange = \"{kx}\"\nsignatures = \"{sigs}\"\n",
            pki.path("ca.pem"),
            pki.path(&format!("{server}.pem")),
            pki.path(&format!("{server}.key")),
        );
    }
    s
}

fn bridge(pki: &Pki, remote_port: u16, client: Option<&str>, kx: &str, sigs: &str) -> String {
    let mut s = format!(
        "[bridge]\nname = \"bridge-{remote_port}\"\naddr = \"localhost:{remote_port}\"\nqos = 1\n\
         sub_path = \"remote/#\"\nreconnection_delay = 1\nping_delay = 10\n\
         [bridge.connections]\nconnection_timeout_ms = 60000\nmax_payload_size = 65536\n\
         max_inflight_count = 100\ndynamic_filters = true\n\
         [bridge.transport.tls]\nca = '{}'\nkey_exchange = \"{kx}\"\nsignatures = \"{sigs}\"\n",
        pki.path("ca.pem")
    );
    if let Some(name) = client {
        s += &format!(
            "[bridge.transport.tls.client_auth]\ncerts = '{}'\nkey = '{}'\n",
            pki.path(&format!("{name}.pem")),
            pki.path(&format!("{name}.key"))
        );
    }
    s
}

fn start(toml: String) {
    let cfg: rumqttd::Config = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    std::thread::spawn(move || rumqttd::Broker::new(cfg).start().unwrap());
}

/// A TLS server that only performs handshakes and reports each outcome.
async fn probe_server(
    cert: &Leaf,
    kx_classical_only: bool,
) -> (u16, mpsc::UnboundedReceiver<Result<String, String>>) {
    let mut p: CryptoProvider = aws_lc_rs::default_provider();
    if kx_classical_only {
        p.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key.clone()));
    let cfg = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert.chain.clone(), key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let r = acceptor.accept(tcp).await;
            let _ = tx.send(
                r.map(|s| {
                    format!(
                        "{:?}",
                        s.get_ref()
                            .1
                            .negotiated_key_exchange_group()
                            .map(|g| g.name())
                    )
                })
                .map_err(|e| e.to_string()),
            );
        }
    });
    (port, rx)
}

async fn first(rx: &mut mpsc::UnboundedReceiver<Result<String, String>>) -> Result<String, String> {
    tokio::time::timeout(Duration::from_secs(8), rx.recv())
        .await
        .expect("bridge never connected")
        .unwrap()
}

fn client_cfg(pki: &Pki, me: &Leaf, pq_kx: bool) -> ClientConfig {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = if pq_kx {
        vec![aws_lc_rs::kx_group::X25519MLKEM768]
    } else {
        vec![aws_lc_rs::kx_group::X25519]
    };
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.der().clone()).unwrap();
    ClientConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            me.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(me.key.clone())),
        )
        .unwrap()
}

async fn connack(ev: &mut EventLoop) -> Result<(), String> {
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
async fn bridge_end_to_end_over_post_quantum_mtls() {
    let pki = Pki::new("bridge-e2e");
    let _srv = pki.leaf("server-pq", &PKCS_ML_DSA_65, true);
    let _br = pki.leaf("bridge-pq", &PKCS_ML_DSA_65, false);
    let publisher = pki.leaf("publisher-pq", &PKCS_ML_DSA_65, false);

    // Broker B (remote): PQ-only key exchange + ML-DSA-only mutual TLS.
    let b_port = free_port();
    start(format!(
        "{ROUTER}{}",
        listener(
            "v4.0",
            b_port,
            Some((&pki, "server-pq", "post-quantum-only", "post-quantum-only"))
        )
    ));
    // Broker A (local): plain listener for the local subscriber + PQ bridge to B.
    let a_port = free_port();
    start(format!(
        "{ROUTER}{}{}",
        listener("v4.0", a_port, None),
        bridge(
            &pki,
            b_port,
            Some("bridge-pq"),
            "post-quantum-only",
            "post-quantum-only"
        )
    ));
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let (local, mut local_ev) =
        AsyncClient::new(MqttOptions::new("local-sub", "127.0.0.1", a_port), 10);
    connack(&mut local_ev).await.unwrap();
    local.subscribe("remote/#", QoS::AtLeastOnce).await.unwrap();

    let mut o = MqttOptions::new("remote-pub", "localhost", b_port);
    o.set_transport(Transport::tls_with_config(
        client_cfg(&pki, &publisher, true).into(),
    ));
    let (remote, mut remote_ev) = AsyncClient::new(o, 10);
    connack(&mut remote_ev)
        .await
        .expect("PQ publisher -> broker B");
    tokio::spawn(async move { while remote_ev.poll().await.is_ok() {} });

    // Publish until the bridge's subscription on B is in place, then expect delivery on A.
    let got = tokio::time::timeout(Duration::from_secs(15), async {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    remote.publish("remote/rig-07/alarm", QoS::AtLeastOnce, false, "gas-high").await.unwrap();
                }
                ev = local_ev.poll() => {
                    if let Ok(Event::Incoming(Packet::Publish(p))) = ev {
                        return (p.topic, p.payload);
                    }
                }
            }
        }
    })
    .await
    .expect("message never crossed the PQ bridge");
    println!(
        "bridged over X25519MLKEM768 + ML-DSA-65 mTLS: {:?} = {:?}",
        got.0, got.1
    );
    assert_eq!(got.0, "remote/rig-07/alarm");
    assert_eq!(&got.1[..], b"gas-high");
    let _ = std::fs::remove_dir_all(&pki.dir);
}

/// (label, probe cert, classical-only kx?, bridge client cert, bridge kx, bridge sigs, expect ok)
type Case<'a> = (
    &'a str,
    &'a Leaf,
    bool,
    Option<&'a str>,
    &'a str,
    &'a str,
    bool,
);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_policies_against_probe_servers() {
    let pki = Pki::new("bridge-probe");
    let srv_pq = pki.leaf("probe-pq", &PKCS_ML_DSA_65, true);
    let srv_ec = pki.leaf("probe-ec", &PKCS_ECDSA_P256_SHA256, true);
    let _ec_client = pki.leaf("bridge-ec", &PKCS_ECDSA_P256_SHA256, false);

    let cases: [Case; 5] = [
        (
            "classical-only server, bridge kx post-quantum-only",
            &srv_pq,
            true,
            None,
            "post-quantum-only",
            "default",
            false,
        ),
        (
            "classical-only server, bridge kx default",
            &srv_pq,
            true,
            None,
            "default",
            "default",
            true,
        ),
        (
            "ECDSA server cert, bridge signatures post-quantum-only",
            &srv_ec,
            false,
            None,
            "default",
            "post-quantum-only",
            false,
        ),
        (
            "ECDSA server cert, bridge signatures default",
            &srv_ec,
            false,
            None,
            "default",
            "default",
            true,
        ),
        (
            "ECDSA bridge client key, signatures post-quantum-only",
            &srv_pq,
            false,
            Some("bridge-ec"),
            "default",
            "post-quantum-only",
            false,
        ),
    ];
    for (label, cert, classical, client, kx, sigs, expect_ok) in cases {
        let (port, mut rx) = probe_server(cert, classical).await;
        start(format!(
            "{ROUTER}{}{}",
            listener("v4.0", free_port(), None),
            bridge(&pki, port, client, kx, sigs)
        ));
        let r = first(&mut rx).await;
        println!("{label}: {r:?}");
        assert_eq!(r.is_ok(), expect_ok, "{label}: {r:?}");
        if expect_ok && classical {
            assert_eq!(r.unwrap(), "Some(X25519)");
        }
    }
    let _ = std::fs::remove_dir_all(&pki.dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secure_websocket_listener_enforces_post_quantum_policies() {
    let pki = Pki::new("wss");
    let _srv = pki.leaf("server-pq", &PKCS_ML_DSA_65, true);
    let cli_pq = pki.leaf("client-pq", &PKCS_ML_DSA_65, false);
    let cli_ec = pki.leaf("client-ec", &PKCS_ECDSA_P256_SHA256, false);
    let port = free_port();
    start(format!(
        "{ROUTER}{}",
        listener(
            "ws.0",
            port,
            Some((&pki, "server-pq", "post-quantum-only", "post-quantum-only"))
        )
    ));
    tokio::time::sleep(Duration::from_millis(700)).await;

    let wss = |me: &Leaf, pq_kx: bool, id: &str| {
        let mut o = MqttOptions::new(id, format!("wss://localhost:{port}/mqtt"), port);
        o.set_transport(Transport::wss_with_config(TlsConfiguration::Rustls(
            Arc::new(client_cfg(&pki, me, pq_kx)),
        )));
        AsyncClient::new(o, 10)
    };
    let (_a, mut a) = wss(&cli_pq, true, "wss-pq");
    let ok = connack(&mut a).await;
    println!("wss ML-DSA client, X25519MLKEM768: {ok:?}");
    assert!(ok.is_ok());
    let (_b, mut b) = wss(&cli_pq, false, "wss-classical-kx");
    let r = connack(&mut b).await;
    println!("wss classical-only key exchange: {r:?}");
    assert!(r.is_err());
    let (_c, mut c) = wss(&cli_ec, true, "wss-ecdsa");
    let r = connack(&mut c).await;
    println!("wss ECDSA client certificate: {r:?}");
    assert!(r.is_err());
    let _ = std::fs::remove_dir_all(&pki.dir);
}
