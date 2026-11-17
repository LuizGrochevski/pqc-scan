//! TLS probing: perform a handshake and collect what the server negotiated.
//!
//! The client offers the hybrid `X25519MLKEM768` group (rustls' default provider does), so the
//! negotiated group tells us whether the *server* is willing to use post-quantum key exchange.
//! Certificate validation is intentionally disabled: this is an audit tool that inspects
//! whatever the server presents, including expired or self-signed certificates.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

pub struct TlsInfo {
    pub version: String,
    pub cipher_suite: String,
    pub key_exchange: Option<String>,
    /// DER-encoded certificates, leaf first.
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn probe(host: &str, port: u16, timeout: Duration) -> Result<TlsInfo> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow!("'{host}' is not a valid DNS name or IP address"))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;

    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {host}"))?
        .next()
        .ok_or_else(|| anyhow!("no address found for {host}"))?;
    let mut sock = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("cannot connect to {addr}"))?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }

    Ok(TlsInfo {
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}").replace('_', "."))
            .unwrap_or_else(|| "unknown".into()),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_else(|| "unknown".into()),
        key_exchange: conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name())),
        chain: conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use rustls::crypto::aws_lc_rs;

    /// The report wording "the server did not select X25519MLKEM768" relies on the client
    /// actually offering that group, so guard the assumption.
    #[test]
    fn client_offers_hybrid_pq_group() {
        let provider = aws_lc_rs::default_provider();
        assert!(
            provider
                .kx_groups
                .iter()
                .any(|g| format!("{:?}", g.name()).contains("MLKEM"))
        );
    }
}
