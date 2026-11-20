//! TLS/PKI and broker helpers shared by the end-to-end tests.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
};
use rumqttc::tokio_rustls::rustls::{
    self,
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, RootCertStore,
};
use std::{path::PathBuf, sync::Arc};

pub struct Pki {
    pub dir: PathBuf,
    pub ca: CertificateDer<'static>,
    pub clients: Vec<(Vec<CertificateDer<'static>>, Vec<u8>)>,
}

pub fn make_pki(tag: &str, n_clients: usize) -> Pki {
    let dir = std::env::temp_dir().join(format!("rumqtt-pq-{tag}-{}", std::process::id()));
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

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start rumqttd with one TLS listener per (port, key_exchange) pair.
/// `proto` is `"v4"` (MQTT 3.1.1) or `"v5"` (MQTT 5).
pub fn start_broker(pki: &Pki, proto: &str, listeners: &[(u16, &str)]) {
    let d = pki.dir.display();
    let mut toml = String::from(
        "id = 0\n[router]\nid = 0\nmax_connections = 100\nmax_outgoing_packet_count = 200\n\
         max_segment_size = 104857600\nmax_segment_count = 10\n",
    );
    for (i, (port, kx)) in listeners.iter().enumerate() {
        toml += &format!(
            "[{proto}.{i}]\nname = \"pq-{i}\"\nlisten = \"127.0.0.1:{port}\"\nnext_connection_delay_ms = 1\n\
             [{proto}.{i}.tls]\ncapath = \"{d}/ca.pem\"\ncertpath = \"{d}/server.pem\"\n\
             keypath = \"{d}/server.key\"\nkey_exchange = \"{kx}\"\n\
             [{proto}.{i}.connections]\nconnection_timeout_ms = 60000\nmax_payload_size = 65536\n\
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

/// TLS 1.3 mTLS client config: `pq_only` = X25519MLKEM768 only, else classical X25519 only.
pub fn client_tls(pki: &Pki, idx: usize, pq_only: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let (chain, key) = &pki.clients[idx];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()));
    ClientConfig::builder_with_provider(provider(pq_only))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain.clone(), key)
        .unwrap()
}
