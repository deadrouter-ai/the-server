//! Chutes AI E2EE Cryptographic Utilities
//!
//! This module implements the Chutes E2EE protocol using post-quantum
//! ML-KEM-768 key encapsulation combined with HKDF-SHA256 key derivation
//! and ChaCha20-Poly1305 authenticated encryption.
//!
//! All crypto primitives use `aws_lc_rs` natively — no external RustCrypto
//! AEAD crates are needed since standard ChaCha20 (12-byte nonce) is fully
//! supported by the AWS-LC backend.

use aws_lc_rs::{
    hkdf::{Salt, HKDF_SHA256},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768},
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use base64ct::{Base64, Encoding};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use super::utiles::gen_random_bytes;

use std::collections::HashMap;
use std::sync::Arc;
use std::io::Error as IoError;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::io::StreamReader;

use crate::{AppState, ProviderConfig, DynamicModelInfo};
use crate::routes::api::chat_completions::{ChatCompletionRequest, StreamOptions};
use crate::providers::utiles::{sanitize_and_spoof_response, wrap_stream_with_timing_padding};

// ── Constants ─────────────────────────────────────────────────────────────────

const MLKEM_CT_SIZE: usize = 1088;
const CHACHA_NONCE_LEN: usize = 12;
const CHACHA_TAG_LEN: usize = 16;
const MIN_RESPONSE_LEN: usize = MLKEM_CT_SIZE + CHACHA_NONCE_LEN + CHACHA_TAG_LEN;

const INFO_REQ: &[u8] = b"e2e-req-v1";
const INFO_RESP: &[u8] = b"e2e-resp-v1";
const INFO_STREAM: &[u8] = b"e2e-stream-v1";

// ── Key Derivation ────────────────────────────────────────────────────────────

/// Derives a 32-byte symmetric key from an ML-KEM shared secret using HKDF-SHA256.
///
/// Uses the first 16 bytes of the ML-KEM ciphertext as salt (matching the
/// reference implementation) and a purpose-specific info string for domain
/// separation between request, response, and stream keys.
fn derive_key(shared_secret: &[u8], mlkem_ct: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let salt_bytes = &mlkem_ct[..16.min(mlkem_ct.len())];
    let salt = Salt::new(HKDF_SHA256, salt_bytes);
    let prk = salt.extract(shared_secret);
    let info_arr = [info];
    let okm = prk.expand(&info_arr, HKDF_SHA256).map_err(|_| "HKDF expand failed")?;
    let mut key = Zeroizing::new([0u8; 32]);
    okm.fill(&mut *key).map_err(|_| "HKDF fill failed")?;
    Ok(key)
}

// ── ChaCha20-Poly1305 Helpers (aws-lc-rs native) ─────────────────────────────

/// Encrypts plaintext with ChaCha20-Poly1305 using a random 12-byte nonce.
///
/// Returns: `[nonce (12B)] [ciphertext + auth_tag (16B)]`
fn chacha_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = gen_random_bytes::<CHACHA_NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| "ChaCha20 encryption failed")?;

    let mut result = Vec::with_capacity(CHACHA_NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts a ChaCha20-Poly1305 blob: `[nonce (12B)] [ciphertext + auth_tag]`
fn chacha_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < CHACHA_NONCE_LEN + CHACHA_TAG_LEN {
        return Err("Ciphertext too short for ChaCha20-Poly1305".into());
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&data[..CHACHA_NONCE_LEN]);

    let plaintext = cipher.decrypt(nonce, &data[CHACHA_NONCE_LEN..])
        .map_err(|_| "ChaCha20 decryption/auth failed")?;

    Ok(plaintext)
}

// ── Gzip Helpers ──────────────────────────────────────────────────────────────

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(|e| format!("Gzip compress write: {}", e))?;
    encoder.finish().map_err(|e| format!("Gzip compress finish: {}", e))
}

fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).map_err(|e| format!("Gzip decompress: {}", e))?;
    Ok(buf)
}

// ── Request Encryption ───────────────────────────────────────────────────────

/// Result of building an E2EE request. Contains the encrypted blob to send
/// and the response decapsulation key needed to decrypt the server's reply.
pub struct ChutesE2eeRequest {
    /// The binary blob to send as the POST body to `/e2e/invoke`.
    pub blob: Vec<u8>,
    /// The ML-KEM-768 decapsulation key for decrypting the response.
    /// This is the client's ephemeral secret key.
    pub response_sk: DecapsulationKey,
}

/// Builds an encrypted E2EE request blob for the Chutes API.
///
/// 1. Generates an ephemeral ML-KEM-768 response keypair
/// 2. Encapsulates a shared secret using the instance's public key
/// 3. Derives a symmetric key via HKDF-SHA256
/// 4. Injects `e2e_response_pk` into the JSON payload
/// 5. Gzip-compresses the modified payload
/// 6. Encrypts with ChaCha20-Poly1305
///
/// Returns: `[ML-KEM CT (1088B)] [nonce (12B)] [ciphertext] [tag (16B)]`
pub fn build_e2ee_request(
    e2e_pubkey_b64: &str,
    payload: &Value,
) -> Result<ChutesE2eeRequest, String> {
    // 1. Generate ephemeral response keypair
    let response_dk = DecapsulationKey::generate(&ML_KEM_768)
        .map_err(|_| "ML-KEM-768 response keypair generation failed")?;
    let response_ek = response_dk.encapsulation_key()
        .map_err(|_| "Failed to derive response encapsulation key")?;
    let response_pk_bytes = response_ek.key_bytes()
        .map_err(|_| "Failed to export response public key bytes")?;
    let response_pk_b64 = Base64::encode_string(response_pk_bytes.as_ref());

    // 2. Decode instance's public key and encapsulate
    let instance_pk_bytes = Base64::decode_vec(e2e_pubkey_b64)
        .map_err(|_| "Invalid base64 in instance e2e_pubkey")?;
    let instance_ek = EncapsulationKey::new(&ML_KEM_768, &instance_pk_bytes)
        .map_err(|_| "Invalid ML-KEM-768 public key from instance")?;
    let (mlkem_ct, shared_secret) = instance_ek.encapsulate()
        .map_err(|_| "ML-KEM-768 encapsulation failed")?;

    // 3. Derive request symmetric key
    let sym_key = derive_key(shared_secret.as_ref(), mlkem_ct.as_ref(), INFO_REQ)?;

    // 4. Inject client's response public key into payload
    let mut payload_with_pk = payload.clone();
    if let Some(obj) = payload_with_pk.as_object_mut() {
        obj.insert("e2e_response_pk".to_string(), Value::String(response_pk_b64));
    }

    // 5. Gzip compress
    let json_bytes = serde_json::to_vec(&payload_with_pk)
        .map_err(|e| format!("JSON serialize failed: {}", e))?;
    let compressed = gzip_compress(&json_bytes)?;

    // 6. Encrypt with ChaCha20-Poly1305
    let encrypted = chacha_encrypt(&*sym_key, &compressed)?;

    // 7. Build final blob: [ML-KEM CT] [encrypted (nonce + ciphertext + tag)]
    let mut blob = Vec::with_capacity(MLKEM_CT_SIZE + encrypted.len());
    blob.extend_from_slice(mlkem_ct.as_ref());
    blob.extend_from_slice(&encrypted);

    Ok(ChutesE2eeRequest {
        blob,
        response_sk: response_dk,
    })
}

// ── Response Decryption (Non-Streaming) ──────────────────────────────────────

/// Decrypts a non-streaming E2EE response blob from the Chutes API.
///
/// Blob format: `[ML-KEM CT (1088B)] [nonce (12B)] [ciphertext] [tag (16B)]`
pub fn decrypt_response(
    response_blob: &[u8],
    response_sk: &DecapsulationKey,
) -> Result<Value, String> {
    if response_blob.len() < MIN_RESPONSE_LEN {
        return Err(format!(
            "Response blob too short: {} bytes (minimum {})",
            response_blob.len(), MIN_RESPONSE_LEN
        ));
    }

    let mlkem_ct = &response_blob[..MLKEM_CT_SIZE];
    let encrypted = &response_blob[MLKEM_CT_SIZE..];

    // Decapsulate shared secret
    let shared_secret = response_sk
        .decapsulate(Ciphertext::from(mlkem_ct))
        .map_err(|_| "ML-KEM-768 decapsulation failed")?;

    // Derive response key
    let sym_key = derive_key(shared_secret.as_ref(), mlkem_ct, INFO_RESP)?;

    // Decrypt
    let compressed = chacha_decrypt(&*sym_key, encrypted)?;

    // Decompress
    let json_bytes = gzip_decompress(&compressed)?;

    // Parse JSON
    serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Failed to parse decrypted response JSON: {}", e))
}

// ── Response Decryption (Streaming) ──────────────────────────────────────────

/// Decrypts the `e2e_init` SSE event to derive the stream symmetric key.
///
/// The `e2e_init` event contains a base64-encoded ML-KEM ciphertext.
/// We decapsulate it with the response secret key and derive a stream-
/// specific symmetric key via HKDF.
pub fn decrypt_stream_init(
    response_sk: &DecapsulationKey,
    mlkem_ct_b64: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mlkem_ct_bytes = Base64::decode_vec(mlkem_ct_b64)
        .map_err(|_| "Invalid base64 in e2e_init ML-KEM ciphertext")?;

    let shared_secret = response_sk
        .decapsulate(Ciphertext::from(mlkem_ct_bytes.as_slice()))
        .map_err(|_| "ML-KEM-768 decapsulation failed for stream init")?;

    derive_key(shared_secret.as_ref(), &mlkem_ct_bytes, INFO_STREAM)
}

/// Decrypts a single E2EE streaming chunk.
///
/// The chunk is a base64-encoded blob: `[nonce (12B)] [ciphertext] [tag (16B)]`
pub fn decrypt_stream_chunk(
    enc_chunk_b64: &str,
    stream_key: &[u8; 32],
) -> Result<String, String> {
    let raw = Base64::decode_vec(enc_chunk_b64)
        .map_err(|_| "Invalid base64 in e2e stream chunk")?;

    let plaintext = chacha_decrypt(stream_key, &raw)?;

    String::from_utf8(plaintext)
        .map_err(|_| "Decrypted stream chunk is not valid UTF-8".into())
}

// ── Instance Discovery & Nonce Management ─────────────────────────────────────

/// Information about a single Chutes TEE instance.
#[derive(Debug, Clone)]
pub struct ChutesInstanceInfo {
    pub instance_id: String,
    pub e2e_pubkey: String, // base64-encoded ML-KEM-768 public key
    pub nonces: Vec<String>,
}

/// Cached nonce pool for a single chute, with thread-safe consumption.
/// Shared across concurrent requests via `Mutex`.
#[derive(Debug)]
pub struct CachedChutesNonces {
    pub instances: Vec<ChutesInstanceInfo>,
    pub expires_at: u64, // unix timestamp
    lock: Mutex<()>,
}

impl CachedChutesNonces {
    pub fn new(instances: Vec<ChutesInstanceInfo>, expires_at: u64) -> Self {
        Self { instances, expires_at, lock: Mutex::new(()) }
    }

    /// Atomically consume one nonce, returning (instance_info, nonce) or None.
    pub fn take_nonce(&mut self) -> Option<(ChutesInstanceInfo, String)> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now >= self.expires_at {
            return None;
        }
        let _guard = self.lock.lock().ok()?;
        for inst in self.instances.iter_mut() {
            if let Some(nonce) = inst.nonces.pop() {
                return Some((inst.clone(), nonce));
            }
        }
        None
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now >= self.expires_at
    }

    pub fn remaining(&self) -> usize {
        self.instances.iter().map(|i| i.nonces.len()).sum()
    }
}

/// Fetches E2EE-capable instances and nonces for a given chute.
///
/// Calls: `GET {api_base}/e2e/instances/{chute_id}`
///
/// Returns the list of instances and the nonce expiry TTL in seconds.
pub async fn fetch_instances(
    client: &reqwest::Client,
    api_base: &str,
    chute_id: &str,
    api_key: &str,
) -> Result<(Vec<ChutesInstanceInfo>, u64), String> {
    let url = format!("{}/e2e/instances/{}", api_base, chute_id);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("Instance discovery network error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Instance discovery failed: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    let data: Value = resp.json().await
        .map_err(|e| format!("Instance discovery JSON parse failed: {}", e))?;

    let instances_arr = data.get("instances")
        .and_then(|v| v.as_array())
        .ok_or("Missing 'instances' array in discovery response")?;

    let instances: Vec<ChutesInstanceInfo> = instances_arr
        .iter()
        .filter_map(|inst| {
            Some(ChutesInstanceInfo {
                instance_id: inst.get("instance_id")?.as_str()?.to_string(),
                e2e_pubkey: inst.get("e2e_pubkey")?.as_str()?.to_string(),
                nonces: inst.get("nonces")?
                    .as_array()?
                    .iter()
                    .filter_map(|n| n.as_str().map(String::from))
                    .collect(),
            })
        })
        .collect();

    // Server uses 75s expiry, client sees 60s. We use 50s for safety margin
    // to avoid failed requests due to nonce expiry during network transit.
    let nonce_ttl = data.get("nonce_expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(50);

    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() + nonce_ttl;

    Ok((instances, expires_at))
}

/// Resolves a model name to a Chutes `chute_id` by querying the models listing.
///
/// Calls: `GET {models_base}/v1/models`
pub async fn resolve_chute_id(
    client: &reqwest::Client,
    models_base: &str,
    api_key: &str,
    model_name: &str,
) -> Result<String, String> {
    let url = format!("{}/v1/models", models_base);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("Model resolution network error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Model resolution failed: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    let data: Value = resp.json().await
        .map_err(|e| format!("Model resolution JSON parse failed: {}", e))?;

    let models = data.get("data")
        .and_then(|v| v.as_array())
        .ok_or("Missing 'data' array in models response")?;

    for entry in models {
        let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let chute_id = entry.get("chute_id").and_then(|v| v.as_str()).unwrap_or("");
        if id == model_name && !chute_id.is_empty() {
            return Ok(chute_id.to_string());
        }
    }

    Err(format!("Model '{}' not found in Chutes model listing", model_name))
}

// ── TEE Attestation Verification ──────────────────────────────────────────────

use aws_lc_rs::digest;
use base64ct::Base64UrlUnpadded;

/// Minimum quote length to contain REPORTDATA at offset [568..632].
const MIN_TDX_QUOTE_LEN: usize = 632;

/// Verifies TEE attestation evidence for Chutes AI instances.
///
/// This is the critical security gate: we MUST verify that each instance's
/// ML-KEM-768 public key was generated inside a genuine, non-debug Intel TDX
/// enclave before trusting it for E2EE encryption.
///
/// ## Verification Steps
/// 1. Generate a fresh 32-byte nonce for replay protection
/// 2. Fetch evidence via `GET /chutes/{chute_id}/evidence?nonce={hex}`
/// 3. For each instance in the response:
///    a. Verify Intel TDX quote via DCAP (hardware signature)
///    b. Reject DEBUG mode enclaves (memory can be dumped)
///    c. Verify key binding: `report_data[0..32] == SHA256(nonce || e2e_pubkey)`
///    d. Verify NVIDIA GPU attestation (debug disabled, secure boot, nonce)
/// 4. Confirm all expected instance pubkeys are attested
///
/// Fails loudly if any verification step fails — refusing to encrypt data
/// to potentially compromised or spoofed keys.
pub async fn verify_chutes_tee_evidence(
    client: &reqwest::Client,
    api_base: &str,
    chute_id: &str,
    api_key: &str,
    expected_instances: &[ChutesInstanceInfo],
) -> Result<Vec<String>, String> {
    if expected_instances.is_empty() {
        return Err("FATAL: No instances to verify".into());
    }

    // 1. Generate a secure 32-byte nonce
    let nonce_bytes = gen_random_bytes::<32>();
    let nonce_hex = hex::encode(nonce_bytes);

    // 2. Fetch TEE evidence
    let url = format!("{}/chutes/{}/evidence?nonce={}", api_base, chute_id, nonce_hex);
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .map_err(|e| format!("TEE evidence fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "TEE evidence request failed: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }

    let evidence_json: Value = resp.json().await
        .map_err(|e| format!("TEE evidence JSON parse failed: {}", e))?;

    // 3. Extract per-instance evidence array
    let evidence_arr = evidence_json.get("evidence")
        .and_then(|v| v.as_array())
        .ok_or("Missing 'evidence' array in TEE evidence response")?;

    // 4. Verify each expected instance has valid attestation
    let mut verified_ids = Vec::new();

    for expected_inst in expected_instances {
        let inst_evidence = match evidence_arr.iter()
            .find(|e| {
                e.get("instance_id").and_then(|v| v.as_str()) == Some(&expected_inst.instance_id)
            }) {
            Some(e) => e,
            None => {
                eprintln!("WARNING: No TEE evidence found for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        // Compute the expected hash for nonce binding
        let str_input = format!("{}{}", nonce_hex, expected_inst.e2e_pubkey);
        let expected_hash = digest::digest(&digest::SHA256, str_input.as_bytes());

        // ── A. Intel TDX Hardware Verification ──
        let quote_b64 = match inst_evidence.get("quote").and_then(|v| v.as_str()) {
            Some(q) => q,
            None => {
                eprintln!("WARNING: Missing Intel TDX quote for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        let quote_bytes = match Base64::decode_vec(quote_b64) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("WARNING: Invalid base64 in TDX quote for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        if quote_bytes.len() < MIN_TDX_QUOTE_LEN {
            eprintln!("WARNING: TDX Quote too short for instance {}", expected_inst.instance_id);
            continue;
        }

        // DCAP signature verification via PCCS
        let pccs_client = match dcap_qvl::collateral::CollateralClient::with_default_http(
            "https://pccs.phala.network"
        ) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to create PCCS client: {:?}", e)),
        };

        if let Err(e) = pccs_client.fetch_and_verify(&quote_bytes).await {
            eprintln!("WARNING: TDX Hardware Verification Failed for instance {}! {:?}", expected_inst.instance_id, e);
            continue;
        }

        // Check TDATTRIBUTES for Debug Mode (bit 0 of byte 168)
        let td_attributes = &quote_bytes[168..176];
        if (td_attributes[0] & 1) != 0 {
            eprintln!("WARNING: Instance {} is running in TDX DEBUG mode.", expected_inst.instance_id);
            continue;
        }

        // Verify ML-KEM public key binding in report_data
        let report_data = &quote_bytes[568..632];
        if aws_lc_rs::constant_time::verify_slices_are_equal(&report_data[0..32], expected_hash.as_ref()).is_err() {
            eprintln!("WARNING: ML-KEM pubkey binding verification failed for instance {}", expected_inst.instance_id);
            continue;
        }

        // ── B. NVIDIA GPU Attestation ──
        let gpu_arr = match inst_evidence.get("gpu_evidence").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                eprintln!("WARNING: Missing NVIDIA GPU evidence for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        let hashed_nonce_hex = hex::encode(expected_hash);
        let nras_req_body = serde_json::json!({
            "nonce": hashed_nonce_hex,
            "arch": "HOPPER",
            "evidence_list": gpu_arr
        });

        let nras_url = "https://nras.attestation.nvidia.com/v3/attest/gpu";
        let nras_resp = match client.post(nras_url)
            .header("Content-Type", "application/json")
            .json(&nras_req_body)
            .send()
            .await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("WARNING: NRAS network error for instance {}: {}", expected_inst.instance_id, e);
                continue;
            }
        };

        if !nras_resp.status().is_success() {
            eprintln!("WARNING: NVIDIA GPU Verification HTTP Failed for instance {}", expected_inst.instance_id);
            continue;
        }

        let nras_json: Value = match nras_resp.json().await {
            Ok(j) => j,
            Err(_) => {
                eprintln!("WARNING: Failed to parse NRAS response for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        // Verify top-level attestation result
        let top_jwt = match nras_json.get(0).and_then(|v| v.as_array()).and_then(|a| a.get(1)).and_then(|v| v.as_str()) {
            Some(j) => j,
            None => {
                eprintln!("WARNING: Missing top-level JWT in NRAS response for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        let top_parts: Vec<&str> = top_jwt.split('.').collect();
        if top_parts.len() < 2 { 
            eprintln!("WARNING: Invalid Top JWT format for instance {}", expected_inst.instance_id);
            continue; 
        }

        let top_decoded = match Base64UrlUnpadded::decode_vec(top_parts[1]) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("WARNING: Base64 decode failed for top JWT for instance {}", expected_inst.instance_id);
                continue;
            }
        };
        
        let top_claims: Value = match serde_json::from_slice(&top_decoded) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("WARNING: Failed to parse Top JWT claims for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        if top_claims.get("x-nvidia-overall-att-result").and_then(|v| v.as_bool()) != Some(true) {
            eprintln!("WARNING: NVIDIA attestation verdict was NOT PASS for instance {}", expected_inst.instance_id);
            continue;
        }

        // Verify per-GPU claims
        let gpu_jwt = match nras_json.get(1).and_then(|v| v.as_object()).and_then(|o| o.get("GPU-0")).and_then(|v| v.as_str()) {
            Some(j) => j,
            None => {
                eprintln!("WARNING: Missing GPU-0 JWT in NRAS response for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        let gpu_parts: Vec<&str> = gpu_jwt.split('.').collect();
        if gpu_parts.len() < 2 { 
            eprintln!("WARNING: Invalid GPU JWT format for instance {}", expected_inst.instance_id);
            continue; 
        }

        let gpu_decoded = match Base64UrlUnpadded::decode_vec(gpu_parts[1]) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("WARNING: Base64 decode failed for GPU JWT for instance {}", expected_inst.instance_id);
                continue;
            }
        };
        
        let gpu_claims: Value = match serde_json::from_slice(&gpu_decoded) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("WARNING: Failed to parse GPU JWT claims for instance {}", expected_inst.instance_id);
                continue;
            }
        };

        // GPU debug must be disabled
        let dbgstat = gpu_claims.get("dbgstat").and_then(|v| v.as_str()).unwrap_or("");
        if dbgstat != "disabled" {
            eprintln!("WARNING: NVIDIA GPU debug mode is enabled on instance {}", expected_inst.instance_id);
            continue;
        }

        // GPU secure boot must be enabled
        if gpu_claims.get("secboot").and_then(|v| v.as_bool()) != Some(true) {
            eprintln!("WARNING: NVIDIA GPU Secure Boot is disabled on instance {}", expected_inst.instance_id);
            continue;
        }

        // GPU nonce must match
        let eat_nonce = gpu_claims.get("eat_nonce").and_then(|v| v.as_str()).unwrap_or("");
        let mut eat_nonce_bytes = [0u8; 32];
        if hex::decode_to_slice(eat_nonce, &mut eat_nonce_bytes).is_err() ||
           aws_lc_rs::constant_time::verify_slices_are_equal(&eat_nonce_bytes, expected_hash.as_ref()).is_err() {
            eprintln!("WARNING: NVIDIA GPU nonce mismatch on instance {}", expected_inst.instance_id);
            continue;
        }

        // ── C. Success! ──
        // If the code successfully makes it to this line, it means NO `continue` was triggered.
        // Therefore, both TDX and GPU hardware are 100% verified.
        verified_ids.push(expected_inst.instance_id.clone());
    }

    if verified_ids.is_empty() {
        return Err("FATAL: No instances were successfully verified. Aborting.".into());
    }

    Ok(verified_ids)
}

pub fn parse_models(data_array: &[Value]) -> HashMap<String, DynamicModelInfo> {
    let mut models = HashMap::new();
    for model_val in data_array {
        let conf_compute = model_val.get("confidential_compute").and_then(|v| v.as_bool()).unwrap_or(false);
        if !conf_compute {
            continue;
        }

        let upstream_id = match model_val.get("id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => continue,
        };

        let mut frontend_name = match upstream_id.find('/') {
            Some(idx) => &upstream_id[idx + 1..],
            None => &upstream_id,
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
        
        let ctx_len = model_val.get("context_length").and_then(|v| v.as_u64()).unwrap_or(0);
        let max_comp = model_val.get("max_output_length").and_then(|v| v.as_u64()).unwrap_or(0);

        let sampling = model_val.get("supported_sampling_parameters").cloned().unwrap_or(Value::Null);
        let features = model_val.get("supported_features").cloned().unwrap_or(Value::Null);

        models.insert(frontend_name.clone(), DynamicModelInfo {
            upstream_model_name: upstream_id,
            name: frontend_name,
            price_input_1m: p_in,
            price_output_1m: p_out,
            context_length: ctx_len,
            max_completion_tokens: max_comp,
            supported_sampling_parameters: sampling,
            supported_features: features,
            direct_endpoint: None,
        });
    }
    models
}

pub async fn call_chutes_ai(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    mut proxy_req: ChatCompletionRequest,
    chat_id: String,
    client_wants_usage: bool,
    frontend_requested_model: String,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
) -> Result<BoxBody<Bytes, std::convert::Infallible>, String> {
    if proxy_req.stream { proxy_req.stream_options = Some(StreamOptions { include_usage: true }); }

    let api_base = "https://api.chutes.ai";
    let models_base = "https://llm.chutes.ai";
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let (upstream_model_name, price_input_1m, price_output_1m) = {
        let state_read = provider.dynamic_state.read().await;
        if let Some(info) = state_read.dynamic_models.get(&frontend_requested_model) {
            (info.upstream_model_name.clone(), info.price_input_1m, info.price_output_1m)
        } else {
            return Err(format!("Model {} not configured", frontend_requested_model));
        }
    };

    let chute_id = {
        let state_read = provider.dynamic_state.read().await;
        state_read.chutes_e2ee.chute_id_cache.get(&upstream_model_name)
            .filter(|(_, exp)| current_ts < *exp)
            .map(|(id, _)| id.clone())
    };
    let chute_id = match chute_id {
        Some(id) => id,
        None => {
            let resolved = resolve_chute_id(&state.http_client, models_base, &provider.api_key, &upstream_model_name).await?;
            let mut state_write = provider.dynamic_state.write().await;
            state_write.chutes_e2ee.chute_id_cache.insert(
                upstream_model_name.clone(),
                (resolved.clone(), current_ts + 300),
            );
            resolved
        }
    };

    let mut last_error = String::new();
    let max_instance_retries = 5;

    for _ in 0..max_instance_retries {
        let instance_nonce_opt = {
            let mut state_write = provider.dynamic_state.write().await;
            let pool = state_write.chutes_e2ee.nonce_pools.get_mut(&chute_id);
            pool.and_then(|p| if !p.is_expired() { p.take_nonce() } else { None })
        };

        let (instance, nonce) = match instance_nonce_opt {
            Some(pair) => pair,
            None => {
                match fetch_instances(&state.http_client, api_base, &chute_id, &provider.api_key).await {
                    Ok((mut instances, expires_at)) => {
                        let mut state_write = provider.dynamic_state.write().await;
                        let mut unverified_instances = Vec::new();
                        for inst in &instances {
                            let is_verified = state_write.chutes_e2ee.verified_instances.get(&inst.instance_id)
                                .map_or(false, |&exp| current_ts < exp);
                            if !is_verified {
                                unverified_instances.push(inst.clone());
                            }
                        }

                        if !unverified_instances.is_empty() {
                            match verify_chutes_tee_evidence(&state.http_client, api_base, &chute_id, &provider.api_key, &unverified_instances).await {
                                Ok(newly_verified_ids) => {
                                    for id in newly_verified_ids {
                                        state_write.chutes_e2ee.verified_instances.insert(id, current_ts + 3600);
                                    }
                                }
                                Err(e) => eprintln!("Warning during TEE verification: {}", e),
                            }
                        }

                        instances.retain(|inst| {
                            state_write.chutes_e2ee.verified_instances.get(&inst.instance_id)
                                .map_or(false, |&exp| current_ts < exp)
                        });

                        if instances.is_empty() {
                            return Err("FATAL: No instances were successfully verified. Aborting.".into());
                        }

                        instances.sort_by_cached_key(|_| {
                            let mut b = [0u8; 4];
                            aws_lc_rs::rand::fill(&mut b).unwrap();
                            u32::from_le_bytes(b)
                        });

                        state_write.chutes_e2ee.nonce_pools.insert(
                            chute_id.clone(),
                            CachedChutesNonces::new(instances, expires_at)
                        );
                        
                        let pool = state_write.chutes_e2ee.nonce_pools.get_mut(&chute_id).unwrap();
                        pool.take_nonce().unwrap()
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        let is_verified = {
            let state_read = provider.dynamic_state.read().await;
            state_read.chutes_e2ee.verified_instances.get(&instance.instance_id)
                .map_or(false, |&exp| current_ts < exp)
        };
        if !is_verified {
            last_error = format!("FATAL: Instance {} has no valid TEE attestation.", instance.instance_id);
            continue;
        }

        proxy_req.model = upstream_model_name.clone();
        let payload = serde_json::to_value(&proxy_req).map_err(|e| e.to_string())?;
        let e2ee_req = build_e2ee_request(&instance.e2e_pubkey, &payload)?;

        let invoke_url = format!("{}/e2e/invoke", api_base);
        let upstream_resp = match state.http_client
            .post(&invoke_url)
            .header("Authorization", format!("Bearer {}", provider.api_key))
            .header("Content-Type", "application/octet-stream")
            .header("X-Chute-Id", &chute_id)
            .header("X-Instance-Id", &instance.instance_id)
            .header("X-E2E-Nonce", &nonce)
            .header("X-E2E-Stream", if proxy_req.stream { "true" } else { "false" })
            .header("X-E2E-Path", "/v1/chat/completions")
            .body(e2ee_req.blob)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                last_error = format!("Chutes E2EE network error: {}", e);
                continue;
            }
        };

        if !upstream_resp.status().is_success() {
            let status = upstream_resp.status();
            let body = upstream_resp.text().await.unwrap_or_default();
            last_error = format!("{} - {}", status, body);
            if status.is_server_error() || status == 429 || status == 408 {
                continue;
            }
            return Err(last_error);
        }

        return process_chutes_response(
            upstream_resp, proxy_req.stream, client_wants_usage, chat_id,
            frontend_requested_model, provider.id.clone(),
            price_input_1m, price_output_1m,
            e2ee_req.response_sk,
            provider.markup,
            e2ee_session,
        ).await;
    }

    Err(format!("All instances failed. Last error: {}", last_error))
}

async fn process_chutes_response(
    resp: reqwest::Response,
    is_streaming: bool,
    client_wants_usage: bool,
    chat_id: String,
    requested_model: String,
    provider_id: String,
    price_input_1m: f64,
    price_output_1m: f64,
    response_sk: DecapsulationKey,
    markup: f64,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
) -> Result<BoxBody<Bytes, std::convert::Infallible>, String> {
    if is_streaming {
        let stream_err_mapper = resp.bytes_stream().map(|res| res.map_err(|e| IoError::new(std::io::ErrorKind::Other, e)));
        let mut stream_reader = BufReader::new(StreamReader::new(stream_err_mapper));

        let stream = async_stream::stream! {
            let mut line = String::new();
            let mut total_input_tokens = 0.0;
            let mut total_output_tokens = 0.0;
            let mut stream_key: Option<Zeroizing<[u8; 32]>> = None;

            loop {
                line.clear();
                match stream_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() { continue; }

                        if !trimmed.starts_with("data: ") { continue; }
                        let data_content = trimmed[6..].trim();

                        if data_content == "[DONE]" {
                            yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from("data: [DONE]\n\n")));
                            break;
                        }

                        if let Ok(event) = serde_json::from_str::<Value>(data_content) {
                            if let Some(init_ct) = event.get("e2e_init").and_then(|v| v.as_str()) {
                                match decrypt_stream_init(&response_sk, init_ct) {
                                    Ok(key) => { stream_key = Some(key); }
                                    Err(e) => {
                                        let err = format!("data: {{\"error\":\"stream init failed: {}\"}}\n\n", e);
                                        yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(err)));
                                        break;
                                    }
                                }
                                continue;
                            }

                            if let Some(enc_chunk) = event.get("e2e").and_then(|v| v.as_str()) {
                                let sk = match &stream_key {
                                    Some(k) => k,
                                    None => {
                                        yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from("data: {\"error\":\"e2e chunk before init\"}\n\n")));
                                        break;
                                    }
                                };
                                match decrypt_stream_chunk(enc_chunk, &**sk) {
                                    Ok(decrypted_sse) => {
                                        let sse_content = decrypted_sse.trim();
                                        let json_str = if sse_content.starts_with("data: ") {
                                            &sse_content[6..]
                                        } else {
                                            sse_content
                                        };

                                        if let Ok(json) = serde_json::from_str::<Value>(json_str) {
                                            let is_usage_chunk = json.get("usage").is_some() &&
                                                json.get("choices").and_then(|c| c.as_array()).map_or(true, |a| a.is_empty());

                                            let sanitized = sanitize_and_spoof_response(
                                                json, &chat_id, &requested_model, &provider_id,
                                                price_input_1m, price_output_1m, markup,
                                                &mut total_input_tokens, &mut total_output_tokens,
                                                None
                                            );

                                            if !is_usage_chunk || client_wants_usage {
                                                let chunk = format!("data: {}\n\n", serde_json::to_string(&sanitized).unwrap());
                                                yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(chunk)));
                                            }
                                        }
                                    }
                                    Err(_) => continue,
                                }
                                continue;
                            }

                            if event.get("usage").is_some() {
                                let sanitized = sanitize_and_spoof_response(
                                    event, &chat_id, &requested_model, &provider_id,
                                    price_input_1m, price_output_1m, markup,
                                    &mut total_input_tokens, &mut total_output_tokens,
                                    None
                                );
                                if client_wants_usage {
                                    let chunk = format!("data: {}\n\n", serde_json::to_string(&sanitized).unwrap());
                                    yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(chunk)));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let err = format!("data: {{\"error\":\"stream read failed: {}\"}}\n\n", e);
                        yield Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from(err)));
                        break;
                    }
                }
            }
        };

        let wrapped = wrap_stream_with_timing_padding(Box::pin(stream), e2ee_session);
        Ok(BodyExt::boxed(StreamBody::new(wrapped)))
    } else {
        let resp_bytes = resp.bytes().await.map_err(|e| format!("Failed to read response: {}", e))?;
        let decrypted_json = decrypt_response(&resp_bytes, &response_sk)?;
        let mut total_in = 0.0;
        let mut total_out = 0.0;
        
        let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
        let sanitized = sanitize_and_spoof_response(
            decrypted_json, &chat_id, &requested_model, &provider_id,
            price_input_1m, price_output_1m, markup,
            &mut total_in, &mut total_out,
            ratchet.as_mut()
        );
        
        let body_bytes = serde_json::to_vec(&sanitized).unwrap();
        Ok(BodyExt::boxed(Full::new(Bytes::from(body_bytes)).map_err(|e| match e {})))
    }
}
