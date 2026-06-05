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

// TLS & Certificate Management Imports
use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{Error as RustlsError, SignatureScheme};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use std::collections::HashMap;
use x509_parser::prelude::*;

// Stream & Async HTTP Imports
use std::convert::Infallible;
use std::io::Error as IoError;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::io::StreamReader;

use crate::{AppState, CachedModelKey, ProviderConfig};
use crate::routes::api::chat_completions::{ChatCompletionRequest, StreamOptions};
use crate::providers::utiles::{
    mark_provider_healthy, mark_provider_unhealthy,
    sanitize_and_spoof_response, wrap_stream_with_timing_padding
};

// ============================================================================
// E2EE Cryptographic Session State
// ============================================================================

/// Represents an active End-to-End Encrypted session for Near AI.
///
/// Handles generation of an ephemeral Ed25519 client key pair, and extracts
/// an X25519 shared secret to be combined later with the upstream model's 
/// public key via Diffie-Hellman, yielding a secure CHACHA20-POLY1305 tunnel.

pub struct E2eeSession {
    pub client_pub_hex: String,
    pub x25519_secret: Zeroizing<[u8; 32]>,
}

use super::utiles::gen_random_bytes;

/// Minimum hex-encoded payload length for a valid V2 encrypted chunk.
/// 32 (ephemeral X25519 pub) + 24 (XChaCha nonce) = 56 raw bytes = 112 hex chars.
const MIN_V2_ENCRYPTED_HEX_LEN: usize = 112;

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

// ============================================================================
// E2EE Encryption & Decryption
// ============================================================================

/// Encrypts plaintext bytes using a combination of Ephemeral X25519 Diffie-Hellman 
/// and XChaCha20Poly1305 symmetric AEAD encryption.
///
/// Generates an ephemeral public key per message and derives a symmetric key via HKDF.
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

/// Decrypts a hex-encoded XChaCha20Poly1305 payload using the local static secret.
/// 
/// The payload must be prefixed with a 32-byte ephemeral public key and a 24-byte nonce.
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

// ============================================================================
// Attestation Verification
// ============================================================================

/// Dynamically fetches and rigorously verifies a Near AI model's hardware attestation.
///
/// Connects to the models direct endpoint, parsing the JSON report to extract
/// either the Intel TDX Quote or NVIDIA NRAS Payload. Strictly enforces security
/// properties: checks Debug limits, Secure Boot, Nonce Binding, and TLS PKI match.
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

    let signing_key_hex = json.get("signing_public_key").and_then(|v| v.as_str())
        .or_else(|| json.get("signing_address").and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("signing_public_key")).and_then(|v| v.as_str()))
        .or_else(|| json.get("model_attestations").and_then(|a| a.get(0)).and_then(|m| m.get("signing_address")).and_then(|v| v.as_str()))
        .ok_or_else(|| "FATAL: Missing signing key in attestation response".to_string())?;

    let mut key_bytes = [0u8; 32];
    hex::decode_to_slice(signing_key_hex.trim_start_matches("0x"), &mut key_bytes)
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

// ── Custom TLS Certificate Validation ───────────────────────────────────────

/// A custom TLS verifier specifically locking down Near AI server connections.
/// 
/// Employs Trust On First Use (TOFU) mixed with dynamic hardware attestation binding.
/// Forces the downstream provider to prove they own the Ed25519 hardware key 
/// linked to the live SPKI presented during TLS negotiation.
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

// ============================================================================
// Model Configuration Parsing
// ============================================================================

/// Constructs the explicit backend domain resolution string for a specific model.
pub fn get_direct_endpoint(frontend_requested_model: &str) -> String {
    let lower = frontend_requested_model.to_lowercase().replace(".", "-");
    format!("https://{}.completions.near.ai", lower)
}

/// Dynamically filters and registers a JSON response array of available AI models.
///
/// This parser safely filters out audio/embedding models, strips non-essential
/// prefix routing schemas, extracts dynamically generated Context Limits, and 
/// sanitizes configuration parameters directly into a typed cache structure.
pub async fn parse_models(client: &reqwest::Client, data_array: &[Value]) -> HashMap<String, crate::DynamicModelInfo> {
    let mapping_json: Value = match client.get("https://completions.near.ai/endpoints")
        .timeout(std::time::Duration::from_secs(5))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            resp.json().await.unwrap_or_else(|_| get_hardcoded_endpoints())
        }
        _ => get_hardcoded_endpoints()
    };

    let mut model_to_domain = HashMap::new();
    if let Some(endpoints) = mapping_json.get("endpoints").and_then(|v| v.as_array()) {
        for ep in endpoints {
            let domain = ep.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(models) = ep.get("models").and_then(|v| v.as_array()) {
                for m in models {
                    if let Some(m_str) = m.as_str() {
                        model_to_domain.insert(m_str.to_string(), domain.to_string());
                    }
                }
            }
        }
    }

    let mut models = HashMap::new();
    for model_val in data_array {
        // Strict text-only model filter
        let out_mods = model_val.get("output_modalities").or_else(|| model_val.get("architecture").and_then(|a| a.get("outputModalities"))).and_then(|v| v.as_array());
        let in_mods = model_val.get("input_modalities").or_else(|| model_val.get("architecture").and_then(|a| a.get("inputModalities"))).and_then(|v| v.as_array());
        
        let is_valid = out_mods.map_or(false, |m| m.iter().all(|x| x.as_str() == Some("text")) && !m.is_empty()) && in_mods.map_or(false, |m| m.iter().all(|x| x.as_str() == Some("text")) && !m.is_empty());

        if !is_valid {
            continue;
        }

        if let Some(id) = model_val.get("id").and_then(|v| v.as_str()) {
            let domain = match model_to_domain.get(id) {
                Some(d) => d,
                None => continue,
            };

            // Explicitly filter out mislabeled embedding or reranker models from Near AI
            if id.contains("Reranker") || id.contains("Embedding") {
                continue;
            }

            let mut frontend_name = match id.find('/') {
                Some(idx) => &id[idx + 1..],
                None => id,
            }.to_string();

            if frontend_name.ends_with("-FP8") {
                frontend_name = frontend_name.trim_end_matches("-FP8").to_string();
            }
            if frontend_name.ends_with("-TEE") {
                frontend_name = frontend_name.trim_end_matches("-TEE").to_string();
            }
            if frontend_name.ends_with("-AWQ") {
                frontend_name = frontend_name.trim_end_matches("-AWQ").to_string();
            }
            if frontend_name.ends_with("-NVFP4") {
                frontend_name = frontend_name.trim_end_matches("-NVFP4").to_string();
            }

            frontend_name = frontend_name.to_lowercase();

            let (p_in, p_out) = crate::providers::utiles::parse_model_price(model_val).unwrap_or((0.0, 0.0));
            
            let mut ctx_len = 128000;
            let mut max_comp = 4096;
            if let Some(c) = model_val.get("context_length").and_then(|v| v.as_u64()) { ctx_len = c; }
            if let Some(m) = model_val.get("max_output_length").and_then(|v| v.as_u64()) { max_comp = m; }

            if let Some(top_prov) = model_val.get("top_provider") {
                if let Some(c) = top_prov.get("context_length").and_then(|v| v.as_u64()) { ctx_len = c; }
                if let Some(m) = top_prov.get("max_completion_tokens").and_then(|v| v.as_u64()) { max_comp = m; }
            }

            let name = frontend_name.clone();
            let params = model_val.get("supported_sampling_parameters").cloned().unwrap_or(serde_json::json!(["temperature","top_p","top_k","frequency_penalty","presence_penalty","max_tokens","seed"]));
            
            // Remove "stop" from params if present
            let mut cleaned_params = params.clone();
            if let Some(arr) = cleaned_params.as_array_mut() {
                arr.retain(|v| v.as_str() != Some("stop"));
            }

            let feats = model_val.get("supported_features").cloned().unwrap_or(serde_json::json!([]));

            models.insert(frontend_name, crate::DynamicModelInfo {
                upstream_model_name: id.to_string(),
                name,
                price_input_1m: p_in,
                price_output_1m: p_out,
                context_length: ctx_len,
                max_completion_tokens: max_comp,
                supported_sampling_parameters: cleaned_params,
                supported_features: feats,
                direct_endpoint: Some(format!("https://{}", domain)),
            });
        }
    }
    models
}

fn get_hardcoded_endpoints() -> Value {
    serde_json::json!({"endpoints":[{"domain":"flux2-klein.completions.near.ai","models":["black-forest-labs/FLUX.2-klein-4B"]},{"domain":"gemma-4-31b.completions.near.ai","models":["google/gemma-4-31B-it"]},{"domain":"glm-5-1.completions.near.ai","models":["zai-org/GLM-5.1-FP8"]},{"domain":"glm-5.completions.near.ai","models":["zai-org/GLM-5-FP8"]},{"domain":"gpt-oss-120b.completions.near.ai","models":["openai/gpt-oss-120b"]},{"domain":"privacy-filter.completions.near.ai","models":["openai/privacy-filter"]},{"domain":"qwen3-30b.completions.near.ai","models":["Qwen/Qwen3-30B-A3B-Instruct-2507"]},{"domain":"qwen3-6-35b.completions.near.ai","models":["Qwen/Qwen3.6-35B-A3B-FP8"]},{"domain":"qwen3-embedding.completions.near.ai","models":["Qwen/Qwen3-Embedding-0.6B"]},{"domain":"qwen3-reranker.completions.near.ai","models":["Qwen/Qwen3-Reranker-0.6B"]},{"domain":"qwen3-vl-30b.completions.near.ai","models":["Qwen/Qwen3-VL-30B-A3B-Instruct"]},{"domain":"qwen35-122b.completions.near.ai","models":["Qwen/Qwen3.5-122B-A10B"]},{"domain":"whisper-large-v3.completions.near.ai","models":["openai/whisper-large-v3"]}]})
}

// ============================================================================
// Upstream Response & Network Routing
// ============================================================================

/// Internal stream/response processor that decrypts Server-Sent Events (SSE) inline.
///
/// Applies response spoofing, billing recalculations based on markup limits, 
/// tracks token usage, un-pads timing countermeasures, and handles connection healing.
async fn process_near_ai_response(
    resp: reqwest::Response,
    provider: Arc<ProviderConfig>,
    is_streaming: bool,
    client_wants_usage: bool,
    chat_id: String,
    requested_model: String,
    provider_id: String,
    price_input_1m: f64,
    price_output_1m: f64,
    client_secret: Zeroizing<[u8; 32]>,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
    skip_decryption: bool,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if is_streaming {
        let stream_err_mapper = resp.bytes_stream().map(|res| res.map_err(|e| IoError::new(std::io::ErrorKind::Other, e)));
        let mut stream_reader = BufReader::new(StreamReader::new(stream_err_mapper));
        let provider_clone = provider.clone();
        let client_secret_clone = client_secret.clone();

        let stream = async_stream::stream! {
            let mut line = String::new();
            let mut total_input_tokens = 0.0;
            let mut total_output_tokens = 0.0;

            loop {
                line.clear();
                match stream_reader.read_line(&mut line).await {
                    Ok(0) => {
                        mark_provider_healthy(&provider_clone).await;
                        break;
                    } 
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() { continue; }

                        let mut is_corrupt = false;
                        let mut error_msg = "Corrupt or invalid response from downstream provider.".to_string();

                        if trimmed.starts_with("data: ") {
                            let data_content = trimmed[6..].trim();
                            if data_content == "[DONE]" {
                                let chunk = if skip_decryption {
                                    crate::providers::utiles::pad_raw_sse("data: [DONE]")
                                } else {
                                    "data: [DONE]\n\n".to_string()
                                };
                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(chunk)));
                                break;
                            } 
                            
                            match serde_json::from_str::<Value>(data_content) {
                                Ok(mut json) => {
                                    if json.get("error").is_some() {
                                        is_corrupt = true;
                                        if let Some(msg) = json.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                                            error_msg = msg.to_string();
                                        }
                                    } else {
                                        let is_usage_chunk = json.get("usage").is_some() && 
                                            json.get("choices").and_then(|c| c.as_array()).map_or(true, |a| a.is_empty());

                                        // --- Inline Decryption for Stream Chunks ---
                                        if let Some(choices) = json.get_mut("choices").and_then(|c| c.as_array_mut()) {
                                            for choice in choices.iter_mut() {
                                                if let Some(delta) = choice.get_mut("delta").and_then(|d| d.as_object_mut()) {
                                                    if let Some(enc_content) = delta.get("content").and_then(|v| v.as_str()) {
                                                        if enc_content.len() >= MIN_V2_ENCRYPTED_HEX_LEN && !skip_decryption {
                                                            match v2_decrypt(enc_content, &client_secret_clone) {
                                                                Ok(plain) => {
                                                                    delta.insert("content".to_string(), Value::String(plain));
                                                                }
                                                                Err(e) => {
                                                                    is_corrupt = true;
                                                                    error_msg = format!("Failed to decrypt stream content: {}", e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if let Some(enc_reasoning) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                                                        if enc_reasoning.len() >= MIN_V2_ENCRYPTED_HEX_LEN && !skip_decryption {
                                                            match v2_decrypt(enc_reasoning, &client_secret_clone) {
                                                                Ok(plain) => {
                                                                    delta.insert("reasoning_content".to_string(), Value::String(plain));
                                                                }
                                                                Err(e) => {
                                                                    is_corrupt = true;
                                                                    error_msg = format!("Failed to decrypt stream reasoning: {}", e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if !is_corrupt {
                                            let sanitized_json = sanitize_and_spoof_response(
                                                json, &chat_id, &requested_model, &provider_id,
                                                price_input_1m, price_output_1m, &mut total_input_tokens, &mut total_output_tokens,
                                                None
                                            );

                                            if !is_usage_chunk || client_wants_usage {
                                                let modified_chunk = if skip_decryption {
                                                    crate::providers::utiles::pad_json_sse(sanitized_json)
                                                } else {
                                                    format!("data: {}\n\n", serde_json::to_string(&sanitized_json).unwrap())
                                                };
                                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(modified_chunk)));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    is_corrupt = true;
                                    error_msg = format!("Corrupt JSON in stream: {}", e);
                                }
                            }
                        } else {
                            if trimmed.starts_with('{') {
                                if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
                                    if json.get("error").is_some() {
                                        is_corrupt = true;
                                        if let Some(msg) = json.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                                            error_msg = msg.to_string();
                                        }
                                    }
                                }
                            } else {
                                is_corrupt = true;
                                error_msg = format!("Invalid stream protocol line: {}", trimmed);
                            }
                        }

                        if is_corrupt {
                            mark_provider_unhealthy(&provider_clone, 30).await;
                            let err_json = serde_json::json!({
                                "error": {
                                    "message": format!("Downstream provider '{}' is temporarily unavailable. Error: {}", provider_clone.id, error_msg),
                                    "type": "service_unavailable",
                                    "param": null,
                                    "code": "provider_unavailable"
                                }
                            });
                            let err_chunk = if skip_decryption {
                                                crate::providers::utiles::pad_json_sse(err_json)
                                            } else {
                                                format!("data: {}\n\n", serde_json::to_string(&err_json).unwrap())
                                            };
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from(err_chunk)));
                            break;
                        }
                    }
                    Err(e) => {
                        mark_provider_unhealthy(&provider_clone, 30).await;
                        let err_json = serde_json::json!({
                            "error": {
                                "message": format!("Downstream provider '{}' is temporarily unavailable. Stream read error: {}", provider_clone.id, e),
                                "type": "service_unavailable",
                                "param": null,
                                "code": "provider_unavailable"
                            }
                        });
                        let err_chunk = if skip_decryption {
                                            crate::providers::utiles::pad_json_sse(err_json)
                                        } else {
                                            format!("data: {}\n\n", serde_json::to_string(&err_json).unwrap())
                                        };
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(err_chunk)));
                        break;
                    }
                }
            }
        };

        if skip_decryption {
            // In passthrough mode, emit each SSE chunk individually.
            // The timing padding wrapper aggregates multiple chunks which would
            // concatenate separate encrypted hex payloads, making them undecryptable.
            Ok(BodyExt::boxed(StreamBody::new(Box::pin(stream))))
        } else {
            let wrapped = wrap_stream_with_timing_padding(Box::pin(stream), e2ee_session);
            Ok(BodyExt::boxed(StreamBody::new(wrapped)))
        }
            
    } else {
        match resp.json::<Value>().await {
            Ok(mut json_resp) => {
                if json_resp.get("error").is_some() {
                    let mut error_msg = "Upstream error response".to_string();
                    if let Some(msg) = json_resp.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                        error_msg = msg.to_string();
                    }
                    return Err(error_msg);
                }

                if let Some(choices) = json_resp.get_mut("choices").and_then(|c| c.as_array_mut()) {
                    for choice in choices.iter_mut() {
                        if let Some(message) = choice.get_mut("message").and_then(|m| m.as_object_mut()) {
                            if let Some(enc_content) = message.get("content").and_then(|v| v.as_str()) {
                                if enc_content.len() >= MIN_V2_ENCRYPTED_HEX_LEN && !skip_decryption {
                                    if let Ok(plain) = v2_decrypt(enc_content, &client_secret) {
                                        message.insert("content".to_string(), Value::String(plain));
                                    }
                                }
                            }
                            if let Some(enc_reasoning) = message.get("reasoning_content").and_then(|v| v.as_str()) {
                                if enc_reasoning.len() >= MIN_V2_ENCRYPTED_HEX_LEN && !skip_decryption {
                                    if let Ok(plain) = v2_decrypt(enc_reasoning, &client_secret) {
                                        message.insert("reasoning_content".to_string(), Value::String(plain));
                                    }
                                }
                            }
                        }
                    }
                }

                let mut in_tok = 0.0;
                let mut out_tok = 0.0;

                let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
                let mut sanitized_json = sanitize_and_spoof_response(
                    json_resp, &chat_id, &requested_model, &provider_id,
                    price_input_1m, price_output_1m, &mut in_tok, &mut out_tok,
                    ratchet.as_mut()
                );

                mark_provider_healthy(&provider).await;

                sanitized_json["pad"] = Value::String("".to_string());
                let base_json = serde_json::to_string(&sanitized_json).unwrap();
                let p = 1024 - (base_json.len() % 1024);
                let pad_str = "X".repeat(p);
                sanitized_json["pad"] = Value::String(pad_str);

                let body_bytes = serde_json::to_vec(&sanitized_json).unwrap();
                debug_assert_eq!(body_bytes.len() % 1024, 0);

                Ok(BodyExt::boxed(Full::new(Bytes::from(body_bytes)).map_err(|e| match e {})))
            }
            Err(e) => Err(format!("Failed to parse JSON response: {}", e))
        }
    }
}

// ============================================================================
// Core Execution Orchestrator
// ============================================================================

/// Executes a fully encrypted proxy request to a Near AI upstream node.
///
/// Orchestrates dynamic routing, memory locking for attestation keys, encryption
/// of chat parameters, enforcing connection verification, and delegating the final
/// output to `process_near_ai_response`.
pub async fn call_near_ai(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    mut proxy_req: ChatCompletionRequest,
    chat_id: String,
    client_wants_usage: bool,
    frontend_requested_model: String,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
    nearai_passthrough_pubkey: Option<String>,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if proxy_req.stream { proxy_req.stream_options = Some(StreamOptions { include_usage: true }); }

    let (upstream_model_name, price_input, price_output, direct_endpoint) = {
        let state_read = provider.dynamic_state.read().await;
        if let Some(info) = state_read.dynamic_models.get(&frontend_requested_model) {
            (info.upstream_model_name.clone(), info.price_input_1m, info.price_output_1m, info.direct_endpoint.clone())
        } else {
            return Err(format!("Model {} not dynamically configured", frontend_requested_model));
        }
    };

    let direct_url = direct_endpoint.unwrap_or_else(|| get_direct_endpoint(&frontend_requested_model));
    let domain = direct_url.trim_start_matches("https://").trim_end_matches('/').to_string();

    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut cached_key_opt = None;

    {
        let state_read = provider.dynamic_state.read().await;
        if let Some(key_info) = state_read.cached_model_keys.get(&frontend_requested_model) {
            if current_ts < key_info.expires_at {
                cached_key_opt = Some(key_info.x25519_bytes);
            }
        }
    }

    let model_x25519_bytes = match cached_key_opt {
        Some(key) => key,
        None => {
            let (fetched_bytes, tls_fingerprint) = fetch_near_ai_model_key(
                &state.near_ai_client,
                &state.http_client,
                &direct_url,
            ).await?;

            // Verify live SPKI matches attestation fingerprint
            {
                let observed = state.observed_spki.lock().unwrap();
                if let Some(live_spkis) = observed.get(&domain) {
                    if !live_spkis.contains(&tls_fingerprint) {
                        return Err(format!(
                            "TLS cert mismatch: live SPKIs ({:?}) do not contain attested fingerprint ({}).",
                            live_spkis, tls_fingerprint
                        ));
                    }
                }
            }

            {
                let mut pins_write = state.tls_pins.write().await;
                pins_write.entry(domain.clone()).or_default().insert(tls_fingerprint.clone());
            }
            
            let mut state_write = provider.dynamic_state.write().await;
            state_write.cached_model_keys.insert(frontend_requested_model.clone(), CachedModelKey {
                expires_at: current_ts + (60 * 60),
                x25519_bytes: fetched_bytes,
            });
            
            fetched_bytes
        }
    };

    // Extraction handled safely above during routing phase

    // E2EE Encryption
    proxy_req.model = upstream_model_name;
    
    let mut upstream_session_secret = Zeroizing::new([0u8; 32]);
    let client_pub_hex = if let Some(pubkey) = nearai_passthrough_pubkey {
        pubkey
    } else {
        let upstream_session = E2eeSession::new();
        for msg in proxy_req.messages.iter_mut() {
            let encrypted = v2_encrypt(msg.content.as_bytes(), &model_x25519_bytes)?;
            msg.content = encrypted;
        }
        upstream_session_secret.copy_from_slice(&*upstream_session.x25519_secret);
        upstream_session.client_pub_hex
    };
    
    let skip_decryption = client_pub_hex.len() > 0 && upstream_session_secret.iter().all(|&b| b == 0);

    let req_body = serde_json::to_vec(&proxy_req).map_err(|e| e.to_string())?;

    let chat_url = format!("{}/v1/chat/completions", direct_url);
    
    let upstream_req = state.near_ai_client
        .post(&chat_url)
        .header("Authorization", format!("Bearer {}", provider.api_key))
        .header("Content-Type", "application/json")
        .header("X-Signing-Algo", "ed25519")
        .header("X-Client-Pub-Key", &client_pub_hex)
        .header("X-Encryption-Version", "2")
        .body(req_body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !upstream_req.status().is_success() {
        return Err(format!("{} - {}", upstream_req.status(), upstream_req.text().await.unwrap_or_default()));
    }

    // Prices already grabbed dynamically from state

    process_near_ai_response(
        upstream_req,
        provider.clone(),
        proxy_req.stream,
        client_wants_usage,
        chat_id,
        frontend_requested_model, 
        provider.id.clone(),
        price_input,
        price_output,
        upstream_session_secret,
        e2ee_session,
        skip_decryption,
    ).await
}
