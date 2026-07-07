# Near AI Zero-Trust E2EE

The Near AI E2EE layer provides absolute zero-trust cryptography directly to the hardware Trusted Execution Environment (TEE) hosting the inference engine. 

When this protocol is used, the proxy acts purely as a blind network router. The proxy cannot decrypt the prompts, cannot view the generated text, and cannot tamper with the stream without invalidating the cryptographic MACs.

## Cryptographic Primitives

The Near AI protocol relies on libsodium and specific elliptic curve transformations:
- **Attestation:** Ed25519 (Edwards Curve)
- **Key Exchange:** X25519 (Montgomery Curve)
- **Symmetric Encryption:** XChaCha20Poly1305
- **Key Derivation:** HKDF-SHA256

## Protocol Flow

1. **Hardware Attestation Verification**
   - Client requests the enclave attestation: `GET /v1/models/nearai/{model}/key?nonce={random}`
   - The response includes the AMD SEV-SNP or Intel TDX attestation report containing a `signing_public_key` (an Ed25519 public key bound to the hardware).
   - The client converts the `signing_public_key` from Ed25519 to X25519.

2. **Client Session Generation**
   - The client generates a random 32-byte `seed`.
   - Derives an Ed25519 keypair from the `seed`. The Ed25519 public key is sent to the enclave via headers.
   - Derives an X25519 secret key from the `seed` using SHA-512 and standard Curve25519 bit-clamping. This matches the enclave's internal key derivation path.

3. **Request Encryption (V2 Protocol)**
   - The client generates an ephemeral X25519 keypair.
   - Performs a DH exchange against the enclave's X25519 key (from Step 1) to get a `shared_secret`.
   - Derives a symmetric key via `HKDF(shared_secret, info="ed25519_encryption")`.
   - Encrypts the prompt payload using `XChaCha20Poly1305` with a random 24-byte nonce.
   - **Wire Format:** A hex-encoded string of: `ephemeral_pub_bytes (32) || nonce (24) || ciphertext`

4. **Request Submission**
   - The client submits the request to the proxy with headers:
     - `X-NearAI-E2EE-Enabled: true`
     - `X-NearAI-Client-Pub-Key: <client_ed25519_pub_hex>`
   - The proxy detects these headers and enables **Passthrough Mode**. 

## Response Decryption

Because Passthrough Mode is active, the proxy does not touch the payload. The client receives a response encrypted with the V2 protocol.

- The enclave generates a new ephemeral X25519 keypair for every response chunk.
- It performs a DH exchange against the client's X25519 key (derived in Step 2).
- The client receives the hex wire format, extracts the enclave's ephemeral public key, computes the DH shared secret using its X25519 secret, and decrypts the `XChaCha20Poly1305` payload.

## Traffic Obfuscation Limitations

In Passthrough Mode, the proxy implements **Length Padding** but bypasses **Timing Padding** for streaming responses.

- **Length Padding (Obfuscation Padding):** The proxy injects a `pad` string into every JSON chunk to reach a strict 256-byte boundary. This successfully masks the size of the generated tokens and prevents packet-length fingerprinting.
- **Timing Protection (Inactive):** The proxy cannot buffer and aggregate multiple SSE chunks into a 50ms interval because concatenating Near AI's stateful `XChaCha20Poly1305` hex strings would corrupt the ciphertexts and break the MAC validation. Consequently, streaming chunks are delivered with raw, un-buffered inter-packet timing, which could theoretically be vulnerable to traffic timing analysis.

## Code Example

Reference the Python implementation in `examples/nearai_direct_e2ee.py` for a complete, working example of Ed25519-to-X25519 conversions, V2 payload construction, and libsodium wrappers.
