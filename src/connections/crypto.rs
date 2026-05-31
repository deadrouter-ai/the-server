use rustls::crypto::aws_lc_rs;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// ======================================================================
// TLS crypto policy — AES-256 only, FIPS-grade key exchange
// ======================================================================

pub fn hardened_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            aws_lc_rs::kx_group::SECP256R1MLKEM768,
            // Note - per NIST SP 800-56C Rev. 2, the X25519MLKEM768 is compliant.
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::MLKEM1024,
            aws_lc_rs::kx_group::MLKEM768,
            aws_lc_rs::kx_group::SECP384R1,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

// ======================================================================
// Self-signed certificate generation (runtime, ephemeral)
// ======================================================================

pub struct SelfSignedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
    pub key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

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
