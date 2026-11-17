//! Classification of cryptographic algorithms by quantum-readiness.
//!
//! Severity model:
//! - `Critical`: weak even against classical attackers (RSA < 2048, SHA-1/MD5, DSA, tiny curves).
//! - `Vulnerable`: sound today, but broken by Shor's algorithm on a large quantum computer
//!   (RSA, ECDSA, ECDH, EdDSA, X25519, finite-field DH).
//! - `Info`: unrecognised algorithm or a finding with limited practical impact.
//! - `Safe`: NIST post-quantum standard (ML-KEM, ML-DSA, SLH-DSA).

use clap::ValueEnum;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Safe,
    Info,
    Vulnerable,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Safe => "QUANTUM-SAFE",
            Severity::Info => "INFO",
            Severity::Vulnerable => "QUANTUM-VULNERABLE",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// What was inspected: "public key", "signature", "key exchange".
    pub what: String,
    pub algorithm: String,
    pub detail: String,
    pub recommendation: Option<String>,
}

fn finding(
    severity: Severity,
    what: &str,
    algorithm: impl Into<String>,
    detail: &str,
    recommendation: Option<&str>,
) -> Finding {
    Finding {
        severity,
        what: what.to_string(),
        algorithm: algorithm.into(),
        detail: detail.to_string(),
        recommendation: recommendation.map(str::to_string),
    }
}

const MIGRATE_SIG: &str = "Plan a migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid/composite certificates during the transition.";
const SHOR: &str = "Broken by Shor's algorithm on a cryptographically relevant quantum computer, regardless of key size.";

fn curve(oid: Option<&str>) -> (String, Option<u32>) {
    match oid {
        Some("1.2.840.10045.3.1.1") => ("P-192".into(), Some(192)),
        Some("1.3.132.0.33") => ("P-224".into(), Some(224)),
        Some("1.2.840.10045.3.1.7") => ("P-256".into(), Some(256)),
        Some("1.3.132.0.10") => ("secp256k1".into(), Some(256)),
        Some("1.3.132.0.34") => ("P-384".into(), Some(384)),
        Some("1.3.132.0.35") => ("P-521".into(), Some(521)),
        Some("1.3.36.3.3.2.8.1.1.7") => ("brainpoolP256r1".into(), Some(256)),
        Some("1.3.36.3.3.2.8.1.1.11") => ("brainpoolP384r1".into(), Some(384)),
        Some("1.3.36.3.3.2.8.1.1.13") => ("brainpoolP512r1".into(), Some(512)),
        Some(other) => (format!("unknown curve ({other})"), None),
        None => ("unknown curve".into(), None),
    }
}

fn pq_sig_name(oid: &str) -> Option<String> {
    let arc = oid
        .strip_prefix("2.16.840.1.101.3.4.3.")?
        .parse::<u32>()
        .ok()?;
    match arc {
        17 => Some("ML-DSA-44".into()),
        18 => Some("ML-DSA-65".into()),
        19 => Some("ML-DSA-87".into()),
        20..=31 => Some("SLH-DSA".into()),
        _ => None,
    }
}

fn pq_kem_name(oid: &str) -> Option<&'static str> {
    match oid {
        "2.16.840.1.101.3.4.4.1" => Some("ML-KEM-512"),
        "2.16.840.1.101.3.4.4.2" => Some("ML-KEM-768"),
        "2.16.840.1.101.3.4.4.3" => Some("ML-KEM-1024"),
        _ => None,
    }
}

/// Classify a certificate's subject public key.
///
/// `rsa_bits` is the modulus size when the key is RSA; `curve_oid` is the named-curve OID for EC keys.
pub fn classify_public_key(oid: &str, rsa_bits: Option<usize>, curve_oid: Option<&str>) -> Finding {
    if let Some(name) = pq_sig_name(oid) {
        return finding(
            Severity::Safe,
            "public key",
            name,
            "NIST post-quantum signature algorithm.",
            None,
        );
    }
    if let Some(name) = pq_kem_name(oid) {
        return finding(
            Severity::Safe,
            "public key",
            name,
            "NIST post-quantum key-encapsulation mechanism.",
            None,
        );
    }
    match oid {
        "1.2.840.113549.1.1.1" => {
            let bits = rsa_bits.unwrap_or(0);
            let alg = if bits > 0 {
                format!("RSA-{bits}")
            } else {
                "RSA".to_string()
            };
            if bits > 0 && bits < 2048 {
                finding(
                    Severity::Critical,
                    "public key",
                    alg,
                    "Key is shorter than 2048 bits, which is weak against classical attackers. It also falls to Shor's algorithm.",
                    Some(
                        "Replace immediately with at least RSA-3072 or ECDSA P-256, then plan the PQC migration.",
                    ),
                )
            } else {
                finding(
                    Severity::Vulnerable,
                    "public key",
                    alg,
                    SHOR,
                    Some(MIGRATE_SIG),
                )
            }
        }
        "1.2.840.10045.2.1" => {
            let (name, bits) = curve(curve_oid);
            let alg = format!("ECDSA/EC {name}");
            if bits.is_some_and(|b| b < 224) {
                finding(
                    Severity::Critical,
                    "public key",
                    alg,
                    "Curve is too small to be considered secure against classical attackers.",
                    Some("Replace with P-256 or stronger, then plan the PQC migration."),
                )
            } else {
                finding(
                    Severity::Vulnerable,
                    "public key",
                    alg,
                    SHOR,
                    Some(MIGRATE_SIG),
                )
            }
        }
        "1.3.101.112" => finding(
            Severity::Vulnerable,
            "public key",
            "Ed25519",
            SHOR,
            Some(MIGRATE_SIG),
        ),
        "1.3.101.113" => finding(
            Severity::Vulnerable,
            "public key",
            "Ed448",
            SHOR,
            Some(MIGRATE_SIG),
        ),
        "1.3.101.110" => finding(
            Severity::Vulnerable,
            "public key",
            "X25519",
            SHOR,
            Some(MIGRATE_SIG),
        ),
        "1.3.101.111" => finding(
            Severity::Vulnerable,
            "public key",
            "X448",
            SHOR,
            Some(MIGRATE_SIG),
        ),
        "1.2.840.10040.4.1" => finding(
            Severity::Critical,
            "public key",
            "DSA",
            "DSA is deprecated and no longer approved for new signatures; it also falls to Shor's algorithm.",
            Some(MIGRATE_SIG),
        ),
        other => finding(
            Severity::Info,
            "public key",
            format!("unrecognised ({other})"),
            "Algorithm OID is not in pqc-scan's table; review manually.",
            None,
        ),
    }
}

/// Classify the signature algorithm on a certificate.
///
/// `trust_anchor` is true for self-signed CA certificates: their self-signature is never
/// verified by relying parties, so weak hashes or quantum-vulnerable signatures there have
/// no practical effect (the root's *key* is still reported separately).
pub fn classify_signature(oid: &str, trust_anchor: bool) -> Finding {
    if let Some(name) = pq_sig_name(oid) {
        return finding(
            Severity::Safe,
            "signature",
            name,
            "NIST post-quantum signature algorithm.",
            None,
        );
    }

    let (name, weak_hash): (&str, bool) = match oid {
        "1.2.840.113549.1.1.4" => ("RSA with MD5", true),
        "1.2.840.113549.1.1.5" => ("RSA with SHA-1", true),
        "1.2.840.10045.4.1" => ("ECDSA with SHA-1", true),
        "1.2.840.113549.1.1.14" => ("RSA with SHA-224", false),
        "1.2.840.113549.1.1.11" => ("RSA with SHA-256", false),
        "1.2.840.113549.1.1.12" => ("RSA with SHA-384", false),
        "1.2.840.113549.1.1.13" => ("RSA with SHA-512", false),
        "1.2.840.113549.1.1.10" => ("RSASSA-PSS", false),
        "1.2.840.10045.4.3.1" => ("ECDSA with SHA-224", false),
        "1.2.840.10045.4.3.2" => ("ECDSA with SHA-256", false),
        "1.2.840.10045.4.3.3" => ("ECDSA with SHA-384", false),
        "1.2.840.10045.4.3.4" => ("ECDSA with SHA-512", false),
        "1.3.101.112" => ("Ed25519", false),
        "1.3.101.113" => ("Ed448", false),
        other => {
            return finding(
                Severity::Info,
                "signature",
                format!("unrecognised ({other})"),
                "Signature algorithm OID is not in pqc-scan's table; review manually.",
                None,
            );
        }
    };

    if trust_anchor {
        return finding(
            Severity::Info,
            "signature",
            name,
            "Self-signature on a trust anchor is not verified by relying parties, so it has no practical effect.",
            None,
        );
    }
    if weak_hash {
        return finding(
            Severity::Critical,
            "signature",
            name,
            "Hash function is broken for signatures (collision attacks); it is also quantum-vulnerable.",
            Some("Re-issue the certificate with SHA-256 or stronger, then plan the PQC migration."),
        );
    }
    finding(
        Severity::Vulnerable,
        "signature",
        name,
        SHOR,
        Some(MIGRATE_SIG),
    )
}

/// Classify the TLS key-exchange group that was negotiated.
///
/// This is the most urgent item: recorded traffic can be decrypted later
/// ("harvest now, decrypt later"), whereas certificate signatures only matter at handshake time.
pub fn classify_kx_group(name: &str) -> Finding {
    if name.contains("MLKEM") {
        finding(
            Severity::Safe,
            "key exchange",
            name,
            "Hybrid post-quantum key exchange: recorded traffic stays protected against future quantum decryption.",
            None,
        )
    } else if name.starts_with("Unknown") {
        finding(
            Severity::Info,
            "key exchange",
            name,
            "Negotiated group is not in pqc-scan's table; review manually.",
            None,
        )
    } else {
        finding(
            Severity::Vulnerable,
            "key exchange",
            name,
            "Classical key exchange: traffic recorded today can be decrypted once a quantum computer exists (\"harvest now, decrypt later\"). The client offered X25519MLKEM768 and the server did not select it.",
            Some(
                "Enable the hybrid X25519MLKEM768 group (TLS 1.3) on the server or TLS terminator.",
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_1024_is_critical() {
        let f = classify_public_key("1.2.840.113549.1.1.1", Some(1024), None);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.algorithm, "RSA-1024");
    }

    #[test]
    fn rsa_2048_is_quantum_vulnerable() {
        let f = classify_public_key("1.2.840.113549.1.1.1", Some(2048), None);
        assert_eq!(f.severity, Severity::Vulnerable);
    }

    #[test]
    fn p256_is_quantum_vulnerable() {
        let f = classify_public_key("1.2.840.10045.2.1", None, Some("1.2.840.10045.3.1.7"));
        assert_eq!(f.severity, Severity::Vulnerable);
        assert!(f.algorithm.contains("P-256"));
    }

    #[test]
    fn p192_is_critical() {
        let f = classify_public_key("1.2.840.10045.2.1", None, Some("1.2.840.10045.3.1.1"));
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ml_dsa_is_safe() {
        let f = classify_public_key("2.16.840.1.101.3.4.3.18", None, None);
        assert_eq!(f.severity, Severity::Safe);
        assert_eq!(f.algorithm, "ML-DSA-65");
    }

    #[test]
    fn sha1_signature_is_critical_unless_trust_anchor() {
        assert_eq!(
            classify_signature("1.2.840.113549.1.1.5", false).severity,
            Severity::Critical
        );
        assert_eq!(
            classify_signature("1.2.840.113549.1.1.5", true).severity,
            Severity::Info
        );
    }

    #[test]
    fn ecdsa_sha256_signature_is_vulnerable() {
        assert_eq!(
            classify_signature("1.2.840.10045.4.3.2", false).severity,
            Severity::Vulnerable
        );
    }

    #[test]
    fn unknown_oid_is_info() {
        assert_eq!(
            classify_signature("1.2.3.4", false).severity,
            Severity::Info
        );
        assert_eq!(
            classify_public_key("1.2.3.4", None, None).severity,
            Severity::Info
        );
    }

    #[test]
    fn kx_groups() {
        assert_eq!(classify_kx_group("X25519MLKEM768").severity, Severity::Safe);
        assert_eq!(classify_kx_group("X25519").severity, Severity::Vulnerable);
        assert_eq!(
            classify_kx_group("secp256r1").severity,
            Severity::Vulnerable
        );
        assert_eq!(classify_kx_group("Unknown(65535)").severity, Severity::Info);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::Vulnerable);
        assert!(Severity::Vulnerable > Severity::Info);
        assert!(Severity::Info > Severity::Safe);
    }
}
