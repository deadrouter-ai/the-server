//! TLS cryptographic configuration and ephemeral certificate generation.
//!
//! Defines the hardened TLS 1.3 crypto policy (AES-256-GCM only, PQ key exchange)
//! and provides runtime self-signed certificate generation using ECDSA P-384.

use rustls::crypto::aws_lc_rs;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// ======================================================================
// TLS crypto policy — AES-256 only, FIPS-grade key exchange
// ======================================================================

/// Returns a hardened `CryptoProvider` for TLS 1.3.
///
/// Restricts the cipher suite to AES-256-GCM-SHA384 only and prioritizes
/// post-quantum key exchange algorithms (ML-KEM-768 hybrids) followed by
/// classical ECDH curves.
pub fn hardened_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
            rustls::crypto::aws_lc_rs::kx_group::MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

// ======================================================================
// Self-signed certificate generation (runtime, ephemeral)
// ======================================================================

/// A self-signed TLS certificate with both PEM and DER representations.
pub struct SelfSignedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
    pub key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

/// Generates an ephemeral self-signed ECDSA P-384 certificate for the given domains.
pub fn generate_self_signed(domains: Vec<String>) -> SelfSignedCert {
    let params = CertificateParams::new(domains)
        .expect("Failed to initialize certificate parameters");

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .expect("Failed to generate P-384 key pair");

    let cert = params.self_signed(&key_pair)
        .expect("Failed to sign the certificate");

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );

    SelfSignedCert {
        cert_pem,
        key_pem,
        cert_der,
        key_der,
    }
}
