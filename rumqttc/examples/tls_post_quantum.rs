//! Connect over TLS 1.3 using ONLY the hybrid post-quantum key exchange
//! `X25519MLKEM768` (ML-KEM-768 + X25519, RFC 10024), with no classical fallback.
//!
//! Pair it with a rumqttd listener configured with `key_exchange = "post-quantum-only"`,
//! or any broker whose TLS stack offers X25519MLKEM768 (e.g. OpenSSL >= 3.5).
//!
//! Run: `cargo run -p rumqttc --example tls_post_quantum -- <host> <port> <ca.pem>`
use std::{error::Error, sync::Arc};

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, Transport};
use tokio_rustls::rustls::{crypto::aws_lc_rs, version::TLS13, ClientConfig, RootCertStore};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "localhost".into());
    let port: u16 = args.next().map(|p| p.parse()).transpose()?.unwrap_or(8883);
    let ca = args.next().unwrap_or_else(|| "ca.cert.pem".into());

    // aws-lc-rs provider restricted to X25519MLKEM768.
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];

    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&ca)?)) {
        roots.add(cert?)?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth(); // use .with_client_auth_cert(..) for mTLS

    let mut options = MqttOptions::new("pq-client", host, port);
    options.set_transport(Transport::tls_with_config(config.into()));

    let (client, mut eventloop) = AsyncClient::new(options, 10);
    client.subscribe("hello/pq", QoS::AtLeastOnce).await?;
    client
        .publish("hello/pq", QoS::AtLeastOnce, false, "quantum-safe hello")
        .await?;

    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Incoming::Publish(p))) => {
                println!("Topic: {}, Payload: {:?}", p.topic, p.payload);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                println!("Error = {e:?}");
                return Ok(());
            }
        }
    }
}
