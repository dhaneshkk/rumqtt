# rumqtt-pq-envelope

Post-quantum protection for MQTT, in two layers.

| Layer | What | Where |
|---|---|---|
| 1. Transport | TLS 1.3, key exchange `X25519MLKEM768` (RFC 10024), ML-DSA-65 certificates for logins | rumqttd `key_exchange` / `signatures`, rumqttc example `tls_post_quantum` |
| 2. Payload | HPKE (RFC 9180) with X-Wing (ML-KEM-768 + X25519) + ML-DSA-65 signatures; per-message or session mode with group keys | this crate |

Layer 1 defeats "harvest now, decrypt later" and impersonation on every hop. Layer 2 keeps
payloads confidential and authenticated even from the broker (shared or third-party
brokers, bridges, retained messages at rest).

## Layer 1: broker and client

```toml
# rumqttd.toml
[v4.2.tls]
capath   = "/etc/tls/ca.cert.pem"   # with feature verify-client-cert -> mTLS
certpath = "/etc/tls/server.cert.pem"
keypath  = "/etc/tls/server.key.pem"
key_exchange = "post-quantum-only"   # or "prefer-post-quantum" during migration
signatures   = "post-quantum-only"   # ML-DSA certificates only (post-quantum logins)
```

| Option | Value | Behaviour |
|---|---|---|
| `key_exchange` | `default` | rustls/aws-lc-rs defaults (`X25519MLKEM768` offered) |
| | `prefer-post-quantum` | `X25519MLKEM768` first, classical fallback kept for legacy devices |
| | `post-quantum-only` | TLS 1.3 + `X25519MLKEM768` only; classical-only clients get `HandshakeFailure` |
| `signatures` | `default` | ECDSA, Ed25519, RSA and ML-DSA |
| | `post-quantum-only` | ML-DSA only for certificate chains and CertificateVerify; the listener refuses to start without an ML-DSA server key |

ML-DSA certificates can be issued with rcgen (`PKCS_ML_DSA_65`, `aws_lc_rs` feature) or
OpenSSL >= 3.5 (`openssl req -newkey mldsa65 ...`). Client side:
`rumqttc/examples/tls_post_quantum.rs` (`PQ_AUTH=1` for ML-DSA-only verification).
For Mosquitto (OpenSSL >= 3.5) see `broker/mosquitto.conf` + `broker/openssl-pq.cnf`.

## Layer 2

All public-key encryption is HPKE base mode, suite `X-Wing (0x647a) / HKDF-SHA256 /
AES-256-GCM` (`suite.rs`); senders sign with ML-DSA-65.

### Session mode (recommended): small frames, group keys

```rust
use rumqtt_pq_envelope::session::{Compression, SessionConfig, SessionOpener, SessionSender};

let cfg = SessionConfig { compression: Compression::Zstd { level: 3 }, ..Default::default() };
// Publisher: one handshake wraps a fresh group key for every recipient.
let mut tx = SessionSender::new(signer, &[ops_a, ops_b, ops_c], epoch, cfg.clone())?;
client.publish("pq/hs/edge-cam-01", QoS::AtLeastOnce, true, tx.handshake()?).await?; // retained
client.publish(topic, QoS::AtLeastOnce, false, tx.seal(topic, payload)?).await?;      // ~45 B + bucket

// Subscriber
let mut rx = SessionOpener::new(my_keys, cfg)?;
rx.sync_trust(&directory);                     // or rx.trust(id, mldsa_der)
rx.accept_handshake(&handshake_payload)?;      // from pq/hs/+
let msg = rx.open(topic, &frame)?;             // msg.sender, msg.epoch, msg.seq, msg.plaintext
```

| | Per-message envelope | Session frame |
|---|---|---|
| Overhead per message | ~4.5 KB (X-Wing enc 1120 B + ML-DSA sig 3309 B) | 45 B + padding (49 B with a dictionary) |
| 128 B JSON telemetry (measured) | ~4.6 KB | 301 B none / 173 B zstd / 113 B zstd+dictionary |
| Handshake | none | once per session: ~3.4 KB + ~1.2 KB per recipient |

* **Group keys.** One handshake lists every recipient (signed fingerprints), so one
  published frame is readable by the whole group. `set_recipients` + `handshake` re-keys;
  removed members cannot read later frames. Members share the frame key, so a member
  could forge frames to other members: use the per-message envelope or per-member
  sessions where that matters.
* **Padding.** The encrypted block (`len ‖ payload ‖ zeros`) is rounded up to a bucket
  (64, 128, ... 65536, then multiples of 65536), so frame length only reveals the bucket.
  Compression happens before padding; avoid mixing attacker-controlled data with secrets
  in one compressed message (CRIME/BREACH).
* **zstd.** `Compression::Zstd` or `ZstdDict` with a dictionary trained by
  `train_dictionary(samples, 4096)` and registered on receivers with `add_dictionary`.
  Decompression is capped by `max_plaintext` (bomb guard).
* **Delayed delivery.** Frames carry no timestamp: retained messages, offline-session
  queues and store-and-forward links all work. A 64-frame sliding window tolerates QoS 1
  reordering; the previous session stays valid during a rekey.
* **Restarts.** Publishers keep a persisted `epoch` (boot counter) and start each boot
  with `epoch + 1`; handshakes with an older `(epoch, session_no)` are refused
  (`StaleSession`). Subscribers persist `export_state()` and restore it with
  `import_state()`; frames already seen before the restart stay rejected.

### Per-message envelope

```rust
let mut cam = Sender::from_pkcs8("edge-cam-01", &stored_pkcs8)?.with_epoch(boot_counter);
let env = cam.seal(&ops_pub, "site1/telemetry", b"{...}")?;
let mut opener = Opener::new(RecipientKeys::from_secret_bytes(&stored_seed)?);
opener.sync_trust(&directory);
opener.import_state(&saved_state)?;            // replay high-water marks
let (sender, seq, plaintext) = opener.open("site1/telemetry", &env)?;
```

Wire format: `"PQE2" ‖ lp(sender) ‖ seq ‖ ts ‖ lp(hpke_enc) ‖ lp(hpke_ct) ‖ lp(mldsa_sig)`.
Timestamps are a policy (`Freshness`), not the replay defence: by default envelopes up to
7 days old (and at most 5 min in the future) are accepted; `Freshness::STRICT` restores
+/-300 s, `Freshness::UNBOUNDED` removes the age limit. MQTT 5: `user_properties(env)` /
`open_with_properties` carry `pqe-alg`, `pqe-sender`, `pqe-seq` for routing.

## Key management (`keys`)

```rust
let anchor = TrustAnchor::generate()?;                        // offline / HSM
let cert = anchor.issue("edge-cam-01", Role::Sender, &cam.public_key_der()?, 1, now, now + YEAR)?;
let crl  = anchor.revocation_list(7, &[compromised_serial])?;

let mut dir = KeyDirectory::new(anchor_public_der)?;            // shipped on devices
dir.add_cert(&cert)?;          // verifies issuer, signature, validity, version
dir.apply_revocations(&crl)?;  // monotonic list number
opener.sync_trust(&dir);       // only currently valid sender keys
let ops = dir.recipient("ops-dashboard").unwrap();           // look up recipients by name
```

* Rotation: issue the same subject with a higher `version`; lower versions are refused
  (`Downgrade`), same version with a different key is refused (`Conflict`).
* Expiry via `not_before` / `not_after`; revocation by certificate serial.
* Certificates and lists are signed, so they can travel over the broker itself
  (e.g. retained on `pq/keys/<role>/<subject>` and `pq/keys/crl`).
* Private keys persist with `Sender::to_pkcs8` / `from_pkcs8`,
  `RecipientKeys::to_secret_bytes` / `from_secret_bytes`, `TrustAnchor::to_pkcs8`.

## Verification

`cargo test -p rumqtt-pq-envelope` (all asserted, MCC with "accept" as positive class):

| Test | Covers | Result |
|---|---|---|
| `envelope_matrix` | 65 cases: genuine, bit flip, forged signer, replay, topic swap, stale, wrong recipient, unknown sender; HPKE sizes; delayed delivery; restarts | MCC 1.0 |
| `session_matrix` | 80 cases (frames + handshakes); group membership; rekey grace; out-of-order window; restarts; padding; zstd/dictionary sizes; decompression bomb | MCC 1.0 |
| `keys` | 52 certificate cases: issue, rotate, downgrade, conflict, wrong issuer, tampered, expired, not-yet-valid, stale/rogue CRL; directory-driven openers | MCC 1.0 |
| `end_to_end` / `end_to_end_v5` | rumqttd PQ-only mTLS + envelope over MQTT 3.1.1 / 5 (user properties) | MCC 1.0 |
| `session_e2e_v5` | retained group handshake, 3 readers incl. late joiner, retained frame, publisher reboot, replayed handshake | pass |
| `pq_logins` | ML-DSA-65 mutual TLS; ECDSA client/server refused under `signatures = "post-quantum-only"`; misconfigured listener refuses to start | pass |

`lean lean/HybridCombiner.lean` (Lean 4 core, no Mathlib, no `sorry`, axioms printed):
combiner injectivity in each secret (TLS hybrid and X-Wing's context), KDF binding,
no entropy loss, MQTT 5 property-check soundness, bucket padding (never shorter, exact
bucket length, payload recovered, same bucket => same length) and replay-window
no-double-accept. Computational security (ML-KEM, X25519, HKDF, AES-GCM, ML-DSA) is
assumed, not proven.

`notebooks/pq_mqtt_rumqtt.ipynb` is a single-cell Colab notebook that clones the repo and
runs all of the above.

## Not covered

* The rumqttd bridge client and websocket listeners don't take `key_exchange` /
  `signatures` yet.
* HPKE comes from the pure-Rust `hpke` / `x-wing` crates (not FIPS-validated); TLS and
  ML-DSA use aws-lc-rs.
* Group members can impersonate the sender to each other in session mode (see above).
