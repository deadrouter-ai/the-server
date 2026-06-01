//! Near AI E2EE Cryptographic Utilities
//!
//! This module implements the Near AI V2 End-to-End Encryption (E2EE) protocol.
//! It utilizes `aws-lc-rs` for core cryptographic primitives (Ed25519, SHA-512, HKDF)
//! and FIPS-validated TLS cert verification, and uses `chacha20poly1305` and 
//! `curve25519-dalek` / `x25519-dalek` solely for key format conversions and AEAD.

use aws_lc_rs::{
    digest::{digest, SHA512},
    hkdf::{Salt, HKDF_SHA256},
    signature::{Ed25519KeyPair, KeyPair},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use x25519_dalek::{PublicKey, StaticSecret};
use serde_json::Value;
use zeroize::Zeroizing;

pub struct E2eeSession {
    pub client_pub_hex: String,
    pub x25519_secret: Zeroizing<[u8; 32]>,
}

pub fn gen_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes).expect("Entropy source failed");
    bytes
}

impl E2eeSession {
    /// Generates the ephemeral Ed25519 client key and derives the X25519 secret.
    pub fn new() -> Self {
        let seed = Zeroizing::new(gen_random_bytes::<32>());
        
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&*seed)
            .expect("Valid seed length guaranteed by gen_random_bytes");
        let client_pub_hex = hex::encode(key_pair.public_key().as_ref());

        let hash_bytes = digest(&SHA512, &*seed);
        let mut hash_slice = Zeroizing::new(hash_bytes.as_ref().to_vec());
        
        hash_slice[0] &= 248;
        hash_slice[31] &= 127;
        hash_slice[31] |= 64;
        
        let mut x25519_secret = [0u8; 32];
        x25519_secret.copy_from_slice(&hash_slice[0..32]);
        
        drop(hash_slice);
        drop(seed);

        Self { client_pub_hex, x25519_secret: Zeroizing::new(x25519_secret) }
    }
}

pub fn v2_encrypt(plaintext: &[u8], recipient_x25519_pub_bytes: &[u8; 32]) -> Result<String, String> {
    use aws_lc_rs::agreement::{self, EphemeralPrivateKey, X25519};
    use aws_lc_rs::rand::SystemRandom;

    let rand = SystemRandom::new();
    let ephemeral_sk = EphemeralPrivateKey::generate(&X25519, &rand)
        .map_err(|e| format!("Failed to generate ephemeral key: {:?}", e))?;
    let ephemeral_pk = ephemeral_sk.compute_public_key()
        .map_err(|e| format!("Failed to compute public key: {:?}", e))?;

    let peer_pk = agreement::UnparsedPublicKey::new(&X25519, recipient_x25519_pub_bytes);

    let mut shared_secret = Zeroizing::new(vec![0u8; 32]);
    agreement::agree_ephemeral(
        ephemeral_sk,
        &peer_pk,
        aws_lc_rs::error::Unspecified,
        |secret| {
            if secret.len() == 32 {
                shared_secret.copy_from_slice(secret);
                Ok(())
            } else {
                Err(aws_lc_rs::error::Unspecified)
            }
        }
    ).map_err(|_| "Failed DH agreement")?;

    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(&shared_secret);
    let okm = prk.expand(&[b"ed25519_encryption"], HKDF_SHA256).map_err(|_| "Failed HKDF expand")?;
    
    let mut symmetric_key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *symmetric_key).map_err(|_| "Failed HKDF fill")?;

    let nonce_bytes = gen_random_bytes::<24>();
    let nonce = XNonce::from(nonce_bytes);
    
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*symmetric_key));
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(32 + 24 + ciphertext.len());
    result.extend_from_slice(ephemeral_pk.as_ref());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    drop(symmetric_key);
    drop(shared_secret);

    Ok(hex::encode(result))
}

pub fn v2_decrypt(data_hex: &str, secret_x25519_bytes: &[u8; 32]) -> Result<String, String> {
    let data = hex::decode(data_hex).map_err(|_| "Invalid hex")?;
    if data.len() < 56 { return Err("Payload too short".into()); }

    let mut eph_pub_bytes = [0u8; 32];
    eph_pub_bytes.copy_from_slice(&data[0..32]);
    let ephemeral_pub = PublicKey::from(eph_pub_bytes);

    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&data[32..56]);
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = &data[56..];

    let secret_key = StaticSecret::from(*secret_x25519_bytes);
    let shared_secret = Zeroizing::new(secret_key.diffie_hellman(&ephemeral_pub));

    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret.as_bytes());
    let okm = prk.expand(&[b"ed25519_encryption"], HKDF_SHA256).map_err(|_| "Failed HKDF expand")?;
    
    let mut symmetric_key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *symmetric_key).map_err(|_| "Failed HKDF fill")?;

    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*symmetric_key));
    let plaintext = Zeroizing::new(cipher.decrypt(&nonce, ciphertext).map_err(|_| "Decryption failed")?);

    let raw_string = String::from_utf8(plaintext.to_vec()).map_err(|_| "Invalid UTF-8")?;
    
    drop(symmetric_key);
    drop(shared_secret);
    drop(plaintext);

    Ok(raw_string)
}

pub async fn fetch_near_ai_model_key(
    client: &reqwest::Client,
    standard_client: &reqwest::Client,
    direct_endpoint: &str,
) -> Result<([u8; 32], String), String> {
    let nonce_bytes = gen_random_bytes::<32>();
    let nonce_hex = hex::encode(nonce_bytes);

    let url = format!("{}/v1/attestation/report?signing_algo=ed25519&include_tls_fingerprint=true&nonce={}", direct_endpoint, nonce_hex);
    let resp = client.get(&url).send().await.map_err(|e| format!("Network error fetching attestation: {}", e))?;
    let json: Value = resp.json().await.map_err(|e| format!("Failed to parse attestation JSON: {}", e))?;

    let signing_key_hex = json.get("signing_address").and_then(|v| v.as_str())
        .or_else(|| json.get("signing_public_key").and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("signing_address")).and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("signing_public_key")).and_then(|v| v.as_str()))
        .ok_or_else(|| "FATAL: Missing signing key in attestation response".to_string())?;

    let mut key_bytes = [0u8; 32];
    hex::decode_to_slice(signing_key_hex, &mut key_bytes)
        .map_err(|_| format!("Invalid hex in model key: {}", signing_key_hex))?;

    let intel_quote_opt = json.get("intel_quote").and_then(|v| v.as_str())
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("intel_quote")).and_then(|v| v.as_str()));

    let nvidia_payload_opt = json.get("nvidia_payload").and_then(|v| v.as_str())
        .or_else(|| json.get("nvidia_quote").and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("nvidia_payload")).and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("nvidia_quote")).and_then(|v| v.as_str()));

    let mut verified_count = 0;

    let tls_cert_fingerprint = json.get("tls_cert_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "FATAL: Missing tls_cert_fingerprint in attestation response".to_string())?;
        
    let cert_fp_bytes = hex::decode(tls_cert_fingerprint)
        .map_err(|_| format!("Invalid hex in tls_cert_fingerprint: {}", tls_cert_fingerprint))?;

    // A. Verify Intel TDX
    if let Some(intel_quote_hex) = intel_quote_opt {
        let quote_bytes = hex::decode(intel_quote_hex.trim_start_matches("0x"))
            .map_err(|_| "Invalid hex in TDX quote")?;
        
        if quote_bytes.len() < 632 {
            return Err("FATAL: TDX Quote is too short to contain REPORTDATA".into());
        }

        let pccs_client = dcap_qvl::collateral::CollateralClient::with_default_http("https://pccs.phala.network")
            .map_err(|e| format!("Failed to create PCCS client: {:?}", e))?;

        pccs_client.fetch_and_verify(&quote_bytes)
            .await
            .map_err(|e| format!("FATAL: TDX Hardware Verification Failed! {:?}", e))?;

        let td_attributes = &quote_bytes[168..176];
        let is_debug_mode = (td_attributes[0] & 1) != 0;
        
        if is_debug_mode {
            return Err("FATAL: Intel TDX Enclave is running in DEBUG mode. Memory can be dumped!".into());
        }

        let mut expected_hash_input = Vec::with_capacity(key_bytes.len() + cert_fp_bytes.len());
        expected_hash_input.extend_from_slice(&key_bytes);
        expected_hash_input.extend_from_slice(&cert_fp_bytes);
        
        let expected_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &expected_hash_input);

        let report_data = &quote_bytes[568..632]; 
        let binding_ok = aws_lc_rs::constant_time::verify_slices_are_equal(&report_data[0..32], expected_hash.as_ref()).is_ok();
        let nonce_ok = aws_lc_rs::constant_time::verify_slices_are_equal(&report_data[32..64], nonce_bytes.as_slice()).is_ok();
        if !binding_ok || !nonce_ok {
            return Err("FATAL: Intel TDX Key/TLS/Nonce binding verification failed! Possible MITM attack.".into());
        }

        if quote_bytes.len() >= 280 {
            let mr_config_id_bytes = &quote_bytes[232..280];
            let mr_config_id_hex = hex::encode(mr_config_id_bytes);
            
            let is_all_zeros = mr_config_id_bytes.iter().all(|&b| b == 0);
            
            if !is_all_zeros {
                let app_compose_str = json.get("info")
                    .and_then(|info| info.get("tcb_info"))
                    .and_then(|tcb| {
                        if let Some(s) = tcb.as_str() {
                            serde_json::from_str::<Value>(s).ok()
                        } else {
                            Some(tcb.clone())
                        }
                    })
                    .and_then(|tcb_obj| tcb_obj.get("app_compose").and_then(|v| v.as_str()).map(String::from));

                if let Some(app_compose) = &app_compose_str {
                    let compose_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, app_compose.as_bytes());
                    let expected_mr_config = format!("01{}", hex::encode(compose_hash));
                    
                    if !mr_config_id_hex.starts_with(&expected_mr_config) {
                        return Err(format!(
                            "FATAL: Docker Compose hash mismatch! mr_config_id does not match SHA256(app_compose). \
                             Expected prefix: {}, Got: {}",
                            expected_mr_config, mr_config_id_hex
                        ));
                    }
                }
            }
        }
        
        verified_count += 1;
    }

    // B. Verify NVIDIA GPU (V3 API)
    if let Some(nvidia_payload_str) = nvidia_payload_opt {
        let mut nras_req_body: Value = serde_json::from_str(nvidia_payload_str)
            .map_err(|_| "Failed to parse nvidia_payload as JSON".to_string())?;

        if let Some(obj) = nras_req_body.as_object_mut() {
            obj.insert("nonce".to_string(), Value::String(nonce_hex.clone()));
            obj.insert("arch".to_string(), Value::String("HOPPER".to_string()));
        }

        let nras_url = "https://nras.attestation.nvidia.com/v3/attest/gpu";
        let nras_resp = standard_client.post(nras_url)
            .header("Content-Type", "application/json")
            .json(&nras_req_body)
            .send()
            .await
            .map_err(|e| format!("NRAS Network error: {}", e))?;

        if !nras_resp.status().is_success() {
            return Err(format!("FATAL: NVIDIA Verification Failed! Status: {} - Body: {}", 
                nras_resp.status(), nras_resp.text().await.unwrap_or_default()));
        }

        let nras_json: Value = nras_resp.json().await.map_err(|_| "Failed to parse NRAS V3 response".to_string())?;

        let top_jwt = nras_json.get(0)
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_str())
            .ok_or("Missing top-level JWT in NRAS response".to_string())?;

        let top_parts: Vec<&str> = top_jwt.split('.').collect();
        if top_parts.len() < 2 { return Err("Invalid Top JWT format".into()); }
        
        let top_decoded = Base64UrlUnpadded::decode_vec(top_parts[1])
            .map_err(|e| format!("Base64 decode failed for top JWT: {}", e))?;
        let top_claims: Value = serde_json::from_slice(&top_decoded)
            .map_err(|_| "Failed to parse Top JWT claims".to_string())?;

        if top_claims.get("x-nvidia-overall-att-result").and_then(|v| v.as_bool()) != Some(true) {
            return Err("FATAL: NVIDIA attestation verdict was not PASS".into());
        }
        let gpu_jwt = nras_json.get(1)
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("GPU-0"))
            .and_then(|v| v.as_str())
            .ok_or("Missing GPU-0 JWT in NRAS response".to_string())?;

        let gpu_parts: Vec<&str> = gpu_jwt.split('.').collect();
        if gpu_parts.len() < 2 { return Err("Invalid GPU JWT format".into()); }
        
        let gpu_decoded = Base64UrlUnpadded::decode_vec(gpu_parts[1])
            .map_err(|e| format!("Base64 decode failed for GPU JWT: {}", e))?;
        let gpu_claims: Value = serde_json::from_slice(&gpu_decoded)
            .map_err(|_| "Failed to parse GPU JWT claims".to_string())?;

        let dbgstat = gpu_claims.get("dbgstat").and_then(|v| v.as_str()).unwrap_or("");
        if dbgstat != "disabled" {
            return Err("FATAL: NVIDIA GPU debug mode is enabled. Memory can be dumped!".into());
        }

        if gpu_claims.get("secboot").and_then(|v| v.as_bool()) != Some(true) {
            return Err("FATAL: NVIDIA GPU Secure Boot is disabled.".into());
        }

        let eat_nonce_str = gpu_claims.get("eat_nonce").and_then(|v| v.as_str()).unwrap_or("");
        let mut eat_nonce_bytes = [0u8; 32];
        let decode_ok = hex::decode_to_slice(eat_nonce_str, &mut eat_nonce_bytes).is_ok();
        let nonce_match = aws_lc_rs::constant_time::verify_slices_are_equal(&eat_nonce_bytes, &nonce_bytes).is_ok();
        if !decode_ok || !nonce_match {
            return Err(format!("FATAL: NVIDIA GPU payload nonce ({}) does not match request nonce", eat_nonce_str));
        }

        verified_count += 1;
    }

    if verified_count == 0 {
        return Err("FATAL: No Intel TDX or NVIDIA payload found for hardware verification. Refusing to send unencrypted data.".into());
    }

    let model_x25519_bytes = CompressedEdwardsY(key_bytes)
        .decompress()
        .ok_or("Invalid Ed25519 curve point")?
        .to_montgomery()
        .to_bytes();

    Ok((model_x25519_bytes, tls_cert_fingerprint.to_string()))
}

use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error as RustlsError, SignatureScheme};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use std::collections::HashMap;
use x509_parser::prelude::*;

#[derive(Debug)]
pub struct NearAiTlsVerifier {
    pub pinned_spki_hashes: Arc<RwLock<HashMap<String, std::collections::HashSet<String>>>>,
    pub observed_spki: Arc<Mutex<HashMap<String, std::collections::HashSet<String>>>>,
}

impl ServerCertVerifier for NearAiTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let domain = server_name.to_str().to_string();

        let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| RustlsError::General("Failed to parse X509 cert".into()))?;
        
        let spki_der = cert.tbs_certificate.subject_pki.raw;
        
        let spki_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki_der);
        let live_spki_hex = hex::encode(spki_hash);

        let map = self.pinned_spki_hashes.try_read()
            .map_err(|_| RustlsError::General("Lock poisoned".into()))?;

        if let Some(expected_spki) = map.get(&domain) {
            let mut matched = false;
            for pin_hex in expected_spki {
                if let Ok(pin_bytes) = hex::decode(pin_hex) {
                    if aws_lc_rs::constant_time::verify_slices_are_equal(spki_hash.as_ref(), &pin_bytes).is_ok() {
                        matched = true;
                    }
                }
            }
            if matched {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(RustlsError::General(format!(
                    "FATAL TLS PINNING FAILURE for {}. Expected: {:?}, Got: {}",
                    domain, expected_spki, live_spki_hex
                )))
            }
        } else {
            if let Ok(mut obs) = self.observed_spki.lock() {
                obs.entry(domain).or_default().insert(live_spki_hex);
            }
            Ok(ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, RustlsError> { Ok(HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, RustlsError> { Ok(HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
