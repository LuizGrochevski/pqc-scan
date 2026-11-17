//! X.509 certificate parsing and analysis.

use anyhow::{Result, anyhow};
use serde::Serialize;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::classify::{Finding, classify_public_key, classify_signature};

#[derive(Debug, Serialize)]
pub struct CertReport {
    pub index: usize,
    /// "leaf", "intermediate" or "root".
    pub role: &'static str,
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    pub findings: Vec<Finding>,
}

/// Extract DER certificates from PEM text (all `CERTIFICATE` blocks) or a single raw DER blob.
pub fn certs_from_bytes(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for pem in Pem::iter_from_buffer(data) {
        match pem {
            Ok(p) if p.label == "CERTIFICATE" => out.push(p.contents),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if out.is_empty() && X509Certificate::from_der(data).is_ok() {
        out.push(data.to_vec());
    }
    out
}

pub fn analyze_der(der: &[u8], index: usize) -> Result<CertReport> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow!("certificate #{index} is not valid X.509: {e}"))?;

    let spki = cert.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let rsa_bits = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => Some(rsa.key_size()),
        _ => None,
    };
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|o| o.to_id_string());

    let is_ca = cert.is_ca();
    let self_signed = cert.subject() == cert.issuer();
    let trust_anchor = is_ca && self_signed;
    let role = if trust_anchor {
        "root"
    } else if is_ca {
        "intermediate"
    } else {
        "leaf"
    };

    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();

    let findings = vec![
        classify_public_key(&key_oid, rsa_bits, curve_oid.as_deref()),
        classify_signature(&sig_oid, trust_anchor),
    ];

    Ok(CertReport {
        index,
        role,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_after: cert.validity().not_after.to_string(),
        findings,
    })
}
