use aws_lc_rs::{
    aead::{AES_256_GCM, Nonce, UnboundKey, LessSafeKey, Aad},
    rand::fill,
    hkdf::{HKDF_SHA256, Salt},
};
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};
use zeroize::{Zeroize, Zeroizing};
use base64ct::{Base64, Encoding};

#[derive(Clone)]
pub struct TicketSecrets {
    pub current: [u8; 32],
    pub previous: [u8; 32],
}

impl TicketSecrets {
    pub fn new() -> Self {
        let mut current = [0u8; 32];
        let mut previous = [0u8; 32];
        fill(&mut current).expect("RNG failure");
        fill(&mut previous).expect("RNG failure");
        Self { current, previous }
    }

    pub fn rotate(&mut self) {
        self.previous = self.current;
        fill(&mut self.current).expect("RNG failure");
    }
}

#[derive(serde::Serialize)]
pub struct E2eeTicketResponse {
    pub public_key: String,
    pub encrypted_private_key: String,
}

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

pub fn decrypt_ticket(secrets: &TicketSecrets, encrypted_base64: &str) -> Result<StaticSecret, String> {
    let payload = Base64::decode_vec(encrypted_base64).map_err(|_| "Invalid base64")?;
    if payload.len() != 12 + 32 + 16 {
        return Err("Invalid ticket length".to_string());
    }

    let nonce_bytes = &payload[0..12];
    let ciphertext = &payload[12..];

    // Try current first
    let mut in_out = ciphertext.to_vec();
    let current_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &secrets.current).unwrap());
    let nonce1 = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
    
    if current_key.open_in_place(nonce1, Aad::empty(), &mut in_out).is_ok() {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&in_out[0..32]);
        in_out.zeroize();
        return Ok(StaticSecret::from(secret));
    }

    // Try previous
    let mut in_out2 = ciphertext.to_vec();
    let prev_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &secrets.previous).unwrap());
    let nonce2 = Nonce::try_assume_unique_for_key(nonce_bytes).unwrap();
    
    if prev_key.open_in_place(nonce2, Aad::empty(), &mut in_out2).is_ok() {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&in_out2[0..32]);
        in_out2.zeroize();
        return Ok(StaticSecret::from(secret));
    }

    Err("Ticket decryption failed (expired or invalid)".to_string())
}

pub struct E2eeSession {
    shared_secret: SharedSecret,
    pub client_pub_key: PublicKey,
    pub model_name: String,
}

impl E2eeSession {
    pub fn new(server_static: StaticSecret, client_pub_bytes: &[u8; 32], model_name: String) -> Self {
        let client_pub = PublicKey::from(*client_pub_bytes);
        let shared_secret = server_static.diffie_hellman(&client_pub);
        Self {
            shared_secret,
            client_pub_key: client_pub,
            model_name,
        }
    }

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

    pub fn get_stream_ratchet(&self) -> StreamRatchet {
        StreamRatchet::new(self.shared_secret.as_bytes(), &self.client_pub_key, &self.model_name)
    }
}

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
