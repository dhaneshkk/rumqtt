# rumqtt-pq-envelope

Post-quantum protection for MQTT, in two layers.

| Layer | What | Where |
|---|---|---|
| 1. Transport | TLS 1.3 with the hybrid key exchange `X25519MLKEM768` (ML-KEM-768 + X25519, RFC 10024) | `rumqttd` listener option `key_exchange`, `rumqttc` example `tls_post_quantum` |
| 2. Payload | End-to-end envelope: ML-KEM-768 + X25519 → HKDF-SHA256 → AES-256-GCM, signed with ML-DSA-65 | this crate |

Layer 1 defeats "harvest now, decrypt later" on every hop. Layer 2 keeps payloads confidential
and authenticated even from the broker (shared or third-party brokers, bridges, retained
messages at rest).

## Layer 1: broker and client

```toml
# rumqttd.toml
[v4.2.tls]
capath   = "/etc/tls/ca.cert.pem"   # with feature verify-client-cert -> mTLS
certpath = "/etc/tls/server.cert.pem"
keypath  = "/etc/tls/server.key.pem"
key_exchange = "post-quantum-only"   # or "prefer-post-quantum" during migration
```

| `key_exchange` | Behaviour |
|---|---|
| `default` | rustls/aws-lc-rs defaults (`X25519MLKEM768` offered) |
| `prefer-post-quantum` | `X25519MLKEM768` first, classical fallback kept for legacy devices |
| `post-quantum-only` | TLS 1.3 + `X25519MLKEM768` only; classical-only clients get `HandshakeFailure` |

Client side: see `rumqttc/examples/tls_post_quantum.rs`.

For Mosquitto (OpenSSL ≥ 3.5) see `broker/mosquitto.conf` + `broker/openssl-pq.cnf`.

## Layer 2: envelope

```rust
use rumqtt_pq_envelope::{Opener, RecipientKeys, Sender};

let ops = RecipientKeys::generate()?;          // subscriber: ML-KEM-768 + X25519
let ops_pub = ops.public()?;                    // provision to publishers
let mut cam = Sender::generate("edge-cam-01")?; // publisher: ML-DSA-65

let env = cam.seal(&ops_pub, "site1/telemetry", b"{...}")?; // MQTT payload

let mut opener = Opener::new(ops);
opener.trust("edge-cam-01", cam.public_key_der()?);
let (sender, seq, plaintext) = opener.open("site1/telemetry", &env)?;
```

Wire format (all authenticated, binary, works over MQTT 3.1.1 and 5):
`"PQE1" ‖ lp(sender) ‖ seq:u64 ‖ ts:u64 ‖ lp(kem_ct) ‖ lp(eph_x25519) ‖ nonce ‖ lp(aead_ct) ‖ lp(mldsa_sig)`.

**MQTT 5:** attach the envelope's routing metadata as user properties and open with them:

```rust
use rumqtt_pq_envelope::{sender_hint, user_properties};
let props = user_properties(&env)?; // pqe-alg, pqe-sender, pqe-seq
// publisher: PublishProperties { user_properties: props, ..Default::default() }
// subscriber/bridge: route on sender_hint(&props) without parsing the payload, then
let (sender, seq, pt) = opener.open_with_properties(topic, &payload, &received_props)?;
```

The properties are not authenticated on their own; `open_with_properties` rejects any
`pqe-*` property that disagrees with the signed header (`Reject::PropertyMismatch`)
before touching replay state. Absent properties are allowed, and non-`pqe-*` ones are
ignored.

Checks on `open`, in order: structure → known sender → ML-DSA-65 signature over
topic + header + ciphertext → monotonic `seq` (replay) → timestamp within ±300 s →
decapsulate + combine → AES-GCM open. Overhead ≈ 4.5 KB per message (mostly the
signature), so raise `max_payload_size` accordingly.

## Verification

* `cargo test -p rumqtt-pq-envelope`:
  * `envelope_matrix`: 30 genuine + 35 attacks (bit flip, forged signer, replay, topic
    swap, stale timestamp, wrong recipient, unknown sender). Asserts the exact rejection
    reason per case and MCC = 1.0.
  * `end_to_end` (MQTT 3.1.1) and `end_to_end_v5` (MQTT 5): rumqttd with native
    `post-quantum-only` mTLS, rumqttc PQ clients, same matrix over the wire;
    classical-only client refused; `prefer-post-quantum` still accepts it.
    The v5 test also checks that the broker forwards user properties intact (80/80)
    and adds 10 property-tampering cases plus 5 genuine messages without properties:
    TP=35 TN=45, MCC = 1.0.
* `lean lean/HybridCombiner.lean` (Lean 4 core, no Mathlib): proves the combiner
  `ss_mlkem ‖ ss_x25519` is uniquely decodable, injective in each half, robust under any
  injective KDF model, binds the KDF `info`, and loses no PQ entropy, and that the MQTT 5 property check only accepts properties
  the signed header produced. No `sorry`; the
  axioms used are printed. The computational IND-CCA argument (ML-KEM, X25519 gap-DH,
  HKDF as PRF) is assumed, not proven, as the file header states.
* `notebooks/pq_mqtt_rumqtt.ipynb`: single-cell Colab notebook that clones this repo
  and runs all of the above.

## Not covered yet

* Certificates are still ECDSA/RSA; ML-DSA certificates need peer TLS support.
* The rumqttd bridge client and websocket listeners don't take `key_exchange` yet.
