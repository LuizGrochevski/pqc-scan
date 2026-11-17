# pqc-scan

**English** | [Português (BR)](README.pt-BR.md)

Audit TLS endpoints and X.509 certificates for **quantum-vulnerable cryptography** and report what to migrate to the NIST post-quantum standards (ML-KEM, ML-DSA, SLH-DSA).

Written in Rust. One binary, JSON output, and a `--fail-on` flag so it can gate a CI pipeline.

## Why

A large quantum computer running Shor's algorithm breaks RSA, ECDSA, EdDSA, ECDH and X25519, no matter how long the keys are. The two halves of the problem are not equally urgent:

- **Key exchange** is urgent. An attacker can record encrypted traffic today and decrypt it later ("harvest now, decrypt later"). The fix is a hybrid post-quantum key exchange such as `X25519MLKEM768`, already available in TLS 1.3 stacks.
- **Signatures / certificates** matter at handshake time, so the risk is the day a quantum computer can forge them. Migration is slower because it depends on CAs and PKI tooling, but long-lived keys (roots, intermediates, code signing) need a plan now.

`pqc-scan` checks both and tells you which is which.

## Install

```bash
cargo install --path .
```

Requires a recent stable Rust toolchain. The TLS stack (`rustls` with the `aws-lc-rs` provider) needs a C compiler, and CMake on some platforms.

## Usage

```text
pqc-scan host <TARGET> [--timeout SECS] [--json] [--fail-on vulnerable|critical]
pqc-scan cert <FILE>... [--json] [--fail-on vulnerable|critical]
```

`TARGET` is `host`, `host:port` or `https://host[:port]` (default port 443).

### Scan a live endpoint

Handshakes with the server, offering the hybrid `X25519MLKEM768` group, then audits the negotiated key exchange and every certificate in the chain. This is a scan of a local OpenSSL test server:

```text
$ pqc-scan host 127.0.0.1:14443
pqc-scan · 127.0.0.1:14443
TLSv1.3 · TLS13_AES_256_GCM_SHA384 · key exchange: X25519

Connection
  [QUANTUM-VULNERABLE] key exchange: X25519
      Classical key exchange: traffic recorded today can be decrypted once a quantum computer exists ("harvest now, decrypt later"). The client offered X25519MLKEM768 and the server did not select it.
      → Enable the hybrid X25519MLKEM768 group (TLS 1.3) on the server or TLS terminator.

Certificate #0 (root) — CN=localhost
  issuer:  CN=localhost
  expires: Nov 19 12:27:39 2026 +00:00
  [QUANTUM-VULNERABLE] public key: ECDSA/EC P-256
      Broken by Shor's algorithm on a cryptographically relevant quantum computer, regardless of key size.
      → Plan a migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid/composite certificates during the transition.
  [INFO] signature: ECDSA with SHA-256
      Self-signature on a trust anchor is not verified by relying parties, so it has no practical effect.

Summary: 0 critical · 2 quantum-vulnerable · 1 info · 0 quantum-safe
```

### Scan certificate files

PEM (including multi-certificate bundles) and raw DER are supported:

```text
$ pqc-scan cert tests/fixtures/rsa2048.pem
pqc-scan · tests/fixtures/rsa2048.pem

Certificate #0 (root) — CN=rsa2048.test
  issuer:  CN=rsa2048.test
  expires: Nov 14 12:27:16 2036 +00:00
  [QUANTUM-VULNERABLE] public key: RSA-2048
      Broken by Shor's algorithm on a cryptographically relevant quantum computer, regardless of key size.
      → Plan a migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid/composite certificates during the transition.
  [INFO] signature: RSA with SHA-256
      Self-signature on a trust anchor is not verified by relying parties, so it has no practical effect.

Summary: 0 critical · 1 quantum-vulnerable · 1 info · 0 quantum-safe
```

### Use it in CI

```bash
pqc-scan host api.example.com --json --fail-on critical > pqc-report.json
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Scan finished and nothing reached the `--fail-on` threshold (or no threshold was set) |
| `1` | At least one finding reached the `--fail-on` threshold |
| `2` | Error: unreachable host, unreadable file, no certificates found |

`--json` always prints an array of reports, even for a single target, so the schema is stable for scripts.

## Severity model

| Severity | Meaning | Examples |
|----------|---------|----------|
| `critical` | Weak even against classical attackers | RSA < 2048 bits, SHA-1 or MD5 signatures, DSA, P-192 |
| `vulnerable` | Sound today, broken by Shor's algorithm | RSA ≥ 2048, ECDSA P-256/384/521, Ed25519, X25519 key exchange |
| `info` | Unrecognised algorithm, or no practical effect | Self-signature on a root CA |
| `safe` | NIST post-quantum standard | ML-KEM, ML-DSA, SLH-DSA, hybrid `X25519MLKEM768` key exchange |

## How it works

1. `host` opens a TCP connection and performs a TLS handshake with [rustls](https://github.com/rustls/rustls). The client offers `X25519MLKEM768`, so the negotiated group shows whether the **server** will use post-quantum key exchange. A unit test guards that assumption.
2. The certificate chain is parsed with [x509-parser](https://github.com/rusticata/x509-parser). Public-key and signature algorithms are identified by OID and classified (`src/classify.rs`).
3. Self-signed CA signatures are reported as `info`: relying parties never verify them, so a SHA-1 self-signature on a root is not a real finding. The root's *key* is still reported.

## Limitations

- **Certificate validation is disabled on purpose.** This is an audit tool: it inspects whatever the server presents, including expired, self-signed or untrusted certificates. Do not reuse that connection code for anything that needs authenticated TLS.
- One handshake per scan. It reports what *this* handshake negotiated, not every group or version the server supports.
- Only TLS 1.2 and 1.3 are probed, and TLS 1.2 never negotiates ML-KEM.
- No STARTTLS, SSH, or source-code scanning yet (see roadmap).
- The OID tables cover common algorithms; anything else is reported as `info` for manual review.
- Tested against local OpenSSL servers and certificate fixtures. Results against production endpoints depend on the server's TLS stack.

## Roadmap

- [ ] SSH host-key and key-exchange audit
- [ ] STARTTLS (SMTP, IMAP)
- [ ] Probe several key-exchange groups separately to list everything a server accepts
- [ ] Scan source trees and lockfiles for quantum-vulnerable crypto usage
- [ ] SARIF and CycloneDX CBOM output
- [ ] Batch mode for a list of hosts

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Test fixtures in `tests/fixtures/` are self-signed certificates generated with OpenSSL; their private keys were discarded.

## References

- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*

## License

MIT
