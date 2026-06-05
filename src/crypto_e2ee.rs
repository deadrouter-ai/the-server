//! Client ↔ Proxy E2EE Ticket and Session Management
//!
//! Implements the proxy-layer End-to-End Encryption protocol:
//!   - **Ticket system**: AES-256-GCM encrypted ephemeral X25519 key pairs
//!     with automatic 5-minute rotation of master secrets.
//!   - **Session decryption**: Per-message HKDF-derived AES-256-GCM keys
//!     bound to message index, role, and client toggles via AAD.
//!   - **Stream ratchet**: Forward-secret symmetric key chain for encrypting
//!     streamed SSE response chunks back to the client.

use aws_lc_rs::{
    aead::{AES_256_GCM, Nonce, UnboundKey, LessSafeKey, Aad},
    rand::fill,
    hkdf::{HKDF_SHA256, Salt},
};
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use base64ct::{Base64, Encoding};

/// Rotating master secrets used to encrypt/decrypt E2EE ephemeral tickets.
///
/// The server maintains two 32-byte AES-256-GCM keys: `current` for new tickets
/// and `previous` for graceful rotation. On each 5-minute rotation cycle,
/// `current` becomes `previous` and a fresh key is generated. Both are
/// automatically zeroized when the struct is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TicketSecrets {
    pub current: [u8; 32],
    pub previous: [u8; 32],
}

impl TicketSecrets {
    /// Generates a fresh pair of cryptographically random master secrets.
    pub fn new() -> Self {
        let mut current = [0u8; 32];
        let mut previous = [0u8; 32];
        fill(&mut current).expect("RNG failure");
        fill(&mut previous).expect("RNG failure");
        Self { current, previous }
    }

    /// Rotates the master secret: current → previous, then generates a new current.
    pub fn rotate(&mut self) {
        self.previous = self.current;
        fill(&mut self.current).expect("RNG failure");
    }
}

/// JSON-serializable E2EE ticket returned to clients.
///
/// Contains the X25519 public key and the AES-256-GCM encrypted private key.
/// The client uses `public_key` for its DH exchange and sends back
/// `encrypted_private_key` in subsequent requests so the server can
/// recover the shared secret.
#[derive(serde::Serialize)]
pub struct E2eeTicketResponse {
    pub public_key: String,
    pub encrypted_private_key: String,
}

/// Generates a fresh E2EE ticket: an ephemeral X25519 keypair where the
/// private key is encrypted under the current master secret.
pub fn generate_ticket(secrets: &TicketSecrets) -> E2eeTicketResponse {
    let mut x25519_secret_bytes = [0u8; 32];
    fill(&mut x25519_secret_bytes).expect("RNG failure");
    
    let static_secret = StaticSecret::from(x25519_secret_bytes);
    let public_key = PublicKey::from(&static_secret);

    let key = UnboundKey::new(&AES_256_GCM, &secrets.current).expect("Invalid key");
    let less_safe_key = LessSafeKey::new(key);
    
    let mut nonce_bytes = [0u8; 12];
    fill(&mut nonce_bytes).expect("RNG failure");
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).expect("Invalid nonce");
    
    let mut in_out = x25519_secret_bytes.to_vec();
    less_safe_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).expect("Encryption failed");

    let mut final_payload = Vec::with_capacity(12 + in_out.len());
    final_payload.extend_from_slice(&nonce_bytes);
    final_payload.extend_from_slice(&in_out);

    x25519_secret_bytes.zeroize();

    E2eeTicketResponse {
        public_key: Base64::encode_string(public_key.as_bytes()),
        encrypted_private_key: Base64::encode_string(&final_payload),
    }
}

/// Decrypts a client-submitted E2EE ticket to recover the ephemeral X25519 secret.
///
/// Tries the `current` master key first, then falls back to `previous` to handle
/// tickets issued just before a rotation boundary. All intermediate buffers are
/// zeroized regardless of success or failure.
pub fn decrypt_ticket(secrets: &TicketSecrets, encrypted_base64: &str) -> Result<StaticSecret, String> {
    let payload = Base64::decode_vec(encrypted_base64).map_err(|_| "Invalid base64")?;
    if payload.len() != 12 + 32 + 16 {
        return Err("Invalid ticket length".to_string());
    }

    let nonce_bytes = &payload[0..12];
    let ciphertext = &payload[12..];

    // Try current master key first
    let mut in_out = ciphertext.to_vec();
    let current_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &secrets.current).unwrap());
    let nonce1 = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
    
    if current_key.open_in_place(nonce1, Aad::empty(), &mut in_out).is_ok() {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&in_out[0..32]);
        in_out.zeroize();
        let result = StaticSecret::from(secret);
        secret.zeroize();
        return Ok(result);
    }
    in_out.zeroize();

    // Fall back to previous master key (covers rotation boundary)
    let mut in_out2 = ciphertext.to_vec();
    let prev_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &secrets.previous).unwrap());
    let nonce2 = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
    
    if prev_key.open_in_place(nonce2, Aad::empty(), &mut in_out2).is_ok() {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&in_out2[0..32]);
        in_out2.zeroize();
        let result = StaticSecret::from(secret);
        secret.zeroize();
        return Ok(result);
    }
    in_out2.zeroize();

    Err("Ticket decryption failed (expired or invalid)".to_string())
}

/// An active E2EE session between a client and the proxy.
///
/// Created from a decrypted ticket secret and the client's ephemeral public key.
/// Provides per-message decryption and a forward-secret stream ratchet for
/// re-encrypting response chunks.
pub struct E2eeSession {
    shared_secret: SharedSecret,
    pub client_pub_key: PublicKey,
    pub model_name: String,
}

impl E2eeSession {
    /// Establishes a session by performing X25519 Diffie-Hellman between the
    /// server's ticket-derived static secret and the client's ephemeral public key.
    pub fn new(server_static: StaticSecret, client_pub_bytes: &[u8; 32], model_name: String) -> Self {
        let client_pub = PublicKey::from(*client_pub_bytes);
        let shared_secret = server_static.diffie_hellman(&client_pub);
        Self {
            shared_secret,
            client_pub_key: client_pub,
            model_name,
        }
    }

    /// Decrypts a single client message using an HKDF-derived per-message key.
    ///
    /// The key is derived from `shared_secret` with info = `"message_{index}_{role}"`.
    /// AAD binds the client's public key, model name, message role, and toggles.
    pub fn decrypt_message(&self, index: usize, role: &str, encrypted_base64: &str, toggles_aad: &str) -> Result<String, String> {
        let payload = Base64::decode_vec(encrypted_base64).map_err(|_| "Invalid message base64")?;
        if payload.len() < 12 + 16 {
            return Err("Invalid encrypted message length".to_string());
        }

        let info = format!("message_{}_{}", index, role);
        let salt = Salt::new(HKDF_SHA256, &[]);
        let prk = salt.extract(self.shared_secret.as_bytes());
        let info_bytes = info.as_bytes();
        let binding = [info_bytes];
        let okm = prk.expand(&binding, HKDF_SHA256).map_err(|_| "HKDF expand failed")?;
        
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        okm.fill(&mut *key_bytes).map_err(|_| "HKDF fill failed")?;

        let key = UnboundKey::new(&AES_256_GCM, &*key_bytes).map_err(|_| "AES key init failed")?;
        let less_safe_key = LessSafeKey::new(key);
        
        let nonce_bytes = &payload[0..12];
        let mut in_out = payload[12..].to_vec();
        
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
        
        // AAD = EPK (32 bytes) + Model Name + Role + Toggles
        let mut aad_bytes = Vec::new();
        aad_bytes.extend_from_slice(self.client_pub_key.as_bytes());
        aad_bytes.extend_from_slice(self.model_name.as_bytes());
        aad_bytes.extend_from_slice(role.as_bytes());
        aad_bytes.extend_from_slice(toggles_aad.as_bytes());
        let aad = Aad::from(&aad_bytes);

        less_safe_key.open_in_place(nonce, aad, &mut in_out).map_err(|_| "AES-GCM decryption failed")?;
        
        let plaintext_len = in_out.len() - 16;
        in_out.truncate(plaintext_len);

        let decoded = String::from_utf8(in_out).map_err(|_| "Invalid UTF-8 in decrypted message")?;
        Ok(decoded)
    }

    /// Creates a forward-secret stream ratchet for encrypting SSE response chunks.
    pub fn get_stream_ratchet(&self) -> StreamRatchet {
        StreamRatchet::new(self.shared_secret.as_bytes(), &self.client_pub_key, &self.model_name)
    }
}

/// Forward-secret key ratchet for encrypting streamed SSE response chunks.
///
/// After each chunk, the current key is consumed via HKDF to produce the next key.
/// Old keys are automatically zeroized by the `Zeroizing` wrapper, ensuring that
/// compromise of a later key cannot decrypt earlier chunks.
pub struct StreamRatchet {
    current_key: Zeroizing<[u8; 32]>,
    chunk_counter: u64,
    aad_bytes: Vec<u8>,
}

impl StreamRatchet {
    pub fn new(shared_secret: &[u8; 32], client_pub: &PublicKey, model_name: &str) -> Self {
        let salt = Salt::new(HKDF_SHA256, &[]);
        let prk = salt.extract(shared_secret);
        let okm = prk.expand(&[b"stream_init"], HKDF_SHA256).unwrap();
        
        let mut current_key = Zeroizing::new([0u8; 32]);
        okm.fill(&mut *current_key).unwrap();

        let mut aad_bytes = Vec::new();
        aad_bytes.extend_from_slice(client_pub.as_bytes());
        aad_bytes.extend_from_slice(model_name.as_bytes());
        aad_bytes.extend_from_slice(b"stream_response");

        Self {
            current_key,
            chunk_counter: 0,
            aad_bytes,
        }
    }

    /// Encrypts a single chunk with the current key, then ratchets forward.
    ///
    /// Returns the base64-encoded `[nonce (12B)] [ciphertext + tag (16B)]` payload.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> String {
        // Encrypt with current_key
        let key = UnboundKey::new(&AES_256_GCM, &*self.current_key).unwrap();
        let less_safe_key = LessSafeKey::new(key);
        
        let mut nonce_bytes = [0u8; 12];
        fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();

        let mut in_out = plaintext.to_vec();
        less_safe_key.seal_in_place_append_tag(nonce, Aad::from(&self.aad_bytes), &mut in_out).unwrap();

        let mut final_payload = Vec::with_capacity(12 + in_out.len());
        final_payload.extend_from_slice(&nonce_bytes);
        final_payload.extend_from_slice(&in_out);

        // Ratchet to next key IMMEDIATELY
        self.chunk_counter += 1;
        let info = format!("stream_chunk_{}", self.chunk_counter);
        
        let salt = Salt::new(HKDF_SHA256, &[]);
        let prk = salt.extract(&*self.current_key);
        let info_bytes = info.as_bytes();
        let binding = [info_bytes];
        let okm = prk.expand(&binding, HKDF_SHA256).unwrap();
        
        let mut next_key = Zeroizing::new([0u8; 32]);
        okm.fill(&mut *next_key).unwrap();
        
        self.current_key = next_key; // Overwrites and Zeroizes old key due to Zeroizing drop

        Base64::encode_string(&final_payload)
    }
}
