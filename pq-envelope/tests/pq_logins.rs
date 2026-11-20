//! Post-quantum logins: TLS 1.3 mutual authentication with ML-DSA-65 certificates.
//!
//! One ML-DSA-65 CA issues ML-DSA-65 *and* ECDSA leaf certificates, so every refusal
//! below is caused by the signature-algorithm policy, not by an unknown CA.
//!
//! * listener A: `key_exchange = "post-quantum-only"`, `signatures = "post-quantum-only"`
//! * listener B: `key_exchange = "post-quantum-only"`, `signatures = "default"`
//! * listener C: ECDSA server key with `signatures = "post-quantum-only"` (must not start)
//! * listener D: ECDSA server key, `signatures = "default"`

mod common;

use common::net::free_port;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ML_DSA_65,
};
use rumqttc::tokio_rustls::rustls::{
    self,
    crypto::{aws_lc_rs, WebPkiSupportedAlgorithms},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SignatureVerificationAlgorithm,
    },
    ClientConfig, RootCertStore, SignatureScheme,
};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, Transport};
use std::{path::PathBuf, sync::Arc, time::Duration};

const PQ: &[SignatureScheme] = &[
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
    cert_pem: String,
    key_pem: String,
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
    ca_der: &CertificateDer<'static>,
    alg: &'static SignatureAlgorithm,
    server: bool,
    name: &str,
) -> Leaf {
    let k = KeyPair::generate_for(alg).unwrap();
    let mut p = CertificateParams::new(if server {
        vec!["localhost".to_string()]
    } else {
        vec![]
    })
    .unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.extended_key_usages = vec![if server {
        ExtendedKeyUsagePurpose::ServerAuth
    } else {
        ExtendedKeyUsagePurpose::ClientAuth
    }];
    let c = p.signed_by(&k, issuer).unwrap();
    Leaf {
        chain: vec![c.der().clone(), ca_der.clone()],
        key: k.serialize_der(),
        cert_pem: c.pem(),
        key_pem: k.serialize_pem(),
    }
}

/// rustls verification algorithms restricted to ML-DSA (client side of the same policy).
fn pq_verification() -> WebPkiSupportedAlgorithms {
    type Mapping = (
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    );
    let base = aws_lc_rs::default_provider().signature_verification_algorithms;
    let mapping: Vec<Mapping> = base
        .mapping
        .iter()
        .filter(|(s, _)| PQ.contains(s))
        .copied()
        .collect();
    let all: Vec<&'static dyn SignatureVerificationAlgorithm> = mapping
        .iter()
        .flat_map(|(_, a)| a.iter().copied())
        .collect();
    WebPkiSupportedAlgorithms {
        all: Box::leak(all.into_boxed_slice()),
        mapping: Box::leak(mapping.into_boxed_slice()),
    }
}

fn client(
    ca: &CertificateDer<'static>,
    me: &Leaf,
    port: u16,
    pq_auth: bool,
    id: &str,
) -> (AsyncClient, EventLoop) {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    if pq_auth {
        p.signature_verification_algorithms = pq_verification();
    }
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let cfg = ClientConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            me.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(me.key.clone())),
        )
        .unwrap();
    let mut o = MqttOptions::new(id, "localhost", port);
    o.set_transport(Transport::tls_with_config(cfg.into()));
    AsyncClient::new(o, 10)
}

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
async fn ml_dsa_mutual_tls_logins() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("rumqtt-pq-logins-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = KeyPair::generate_for(&PKCS_ML_DSA_65).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "fleet ML-DSA-65 CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca.der().clone();
    let issuer = Issuer::new(ca_params, ca_key);

    let srv_pq = leaf(&issuer, &ca_der, &PKCS_ML_DSA_65, true, "broker-pq");
    let srv_ec = leaf(&issuer, &ca_der, &PKCS_ECDSA_P256_SHA256, true, "broker-ec");
    let cli_pq = leaf(&issuer, &ca_der, &PKCS_ML_DSA_65, false, "cam-pq");
    let cli_ec = leaf(&issuer, &ca_der, &PKCS_ECDSA_P256_SHA256, false, "cam-ec");
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    for (name, l) in [("pq", &srv_pq), ("ec", &srv_ec)] {
        std::fs::write(
            dir.join(format!("server-{name}.pem")),
            l.cert_pem.clone() + &ca.pem(),
        )
        .unwrap();
        std::fs::write(dir.join(format!("server-{name}.key")), &l.key_pem).unwrap();
    }

    let (a, b, c, d) = (free_port(), free_port(), free_port(), free_port());
    let path = |f: &str| dir.join(f).display().to_string();
    let mut toml = String::from(
        "id = 0\n[router]\nid = 0\nmax_connections = 100\nmax_outgoing_packet_count = 200\n\
         max_segment_size = 104857600\nmax_segment_count = 10\n",
    );
    for (i, (port, srv, sigs)) in [
        (a, "pq", "post-quantum-only"),
        (b, "pq", "default"),
        (c, "ec", "post-quantum-only"),
        (d, "ec", "default"),
    ]
    .iter()
    .enumerate()
    {
        toml += &format!(
            "[v4.{i}]\nname = \"login-{i}\"\nlisten = \"127.0.0.1:{port}\"\nnext_connection_delay_ms = 1\n\
             [v4.{i}.tls]\ncapath = '{}'\ncertpath = '{}'\nkeypath = '{}'\n\
             key_exchange = \"post-quantum-only\"\nsignatures = \"{sigs}\"\n\
             [v4.{i}.connections]\nconnection_timeout_ms = 60000\nmax_payload_size = 65536\n\
             max_inflight_count = 100\ndynamic_filters = true\n",
            path("ca.pem"),
            path(&format!("server-{srv}.pem")),
            path(&format!("server-{srv}.key")),
        );
    }
    let cfg: rumqttd::Config = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    std::thread::spawn(move || rumqttd::Broker::new(cfg).start().unwrap());
    tokio::time::sleep(Duration::from_millis(700)).await;

    let mut results = Vec::new();
    let mut run = |name: &'static str, r: Result<(), String>, expect_ok: bool| {
        println!("{name}: {r:?}");
        results.push((name, r.is_ok() == expect_ok));
    };
    // A: fully post-quantum login.
    let (_c1, mut e1) = client(&ca_der, &cli_pq, a, true, "c1");
    run(
        "A ML-DSA client, PQ-only verification",
        handshake(&mut e1).await,
        true,
    );
    // A: ECDSA client certificate (chain is ML-DSA, CertificateVerify is ECDSA) refused.
    let (_c2, mut e2) = client(&ca_der, &cli_ec, a, false, "c2");
    run("A ECDSA client cert", handshake(&mut e2).await, false);
    // B: same ECDSA client accepted when the listener allows classical signatures.
    let (_c3, mut e3) = client(&ca_der, &cli_ec, b, false, "c3");
    run(
        "B ECDSA client cert, default policy",
        handshake(&mut e3).await,
        true,
    );
    // C: listener with ECDSA server key + PQ-only policy refuses to start (never binds).
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", c)).is_err(),
        "listener C must not bind"
    );
    let (_c4, mut e4) = client(&ca_der, &cli_pq, c, false, "c4");
    run(
        "C ECDSA server key with PQ-only policy (listener not started)",
        handshake(&mut e4).await,
        false,
    );
    // D: a PQ-auth client refuses a classical (ECDSA) server certificate.
    let (_c5, mut e5) = client(&ca_der, &cli_pq, d, true, "c5");
    run(
        "D PQ-auth client vs ECDSA server",
        handshake(&mut e5).await,
        false,
    );
    let (_c6, mut e6) = client(&ca_der, &cli_pq, d, false, "c6");
    run(
        "D classical-verification client vs ECDSA server",
        handshake(&mut e6).await,
        true,
    );

    let _ = std::fs::remove_dir_all(&dir);
    for (name, ok) in &results {
        assert!(ok, "unexpected result: {name}");
    }
}
