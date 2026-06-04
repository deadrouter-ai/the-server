# Near AI True Client-to-Enclave End-to-End Encryption

The proxy supports "True" End-to-End Encryption (E2EE) with Near AI enclave models. This means the encryption happens directly between the end-user (client) and the Near AI TEE enclave. The proxy (`the-server`) operates in passthrough mode, entirely blinded to the payload contents, handling only routing and billing.

## Core Concepts

Unlike the standard proxy E2EE (where the proxy terminates the client connection and establishes a new encrypted connection to the provider), true Client-to-Enclave E2EE bypasses proxy decryption. The client encrypts messages directly using the Near AI model's hardware-attested public key.

**Important**: When `X-NearAI-E2EE-Enabled` is set, the proxy will **only** route to the `near-ai` provider. Other providers (chutes, redpill, etc.) cannot decrypt Near AI-encrypted payloads.

## 1. Fetching the Model Key (Attestation Proxy)

To encrypt data for the enclave, the client must first fetch the Near AI hardware attestation. The proxy provides a dummy endpoint that forwards requests directly to Near AI:

`GET /v1/models/nearai/{model_id}/key?nonce=<hex>&signing_algo=ed25519&include_tls_fingerprint=true`

**Headers Required**:
- `Authorization: Bearer <your_api_token>`

**Response**:
The proxy returns the *raw, unmodified* JSON response from Near AI's `/v1/attestation/report` endpoint. The proxy resolves the enclave's URL through the same dynamic model mapping used for chat requests, ensuring key consistency. The client is responsible for parsing the response and optionally verifying the attestation.

**Key extraction**:
The signing key is in `signing_public_key` (or `signing_address`). This is an **Ed25519** public key (32 bytes, hex-encoded, possibly `0x`-prefixed). It must be **converted to X25519** (Edwards→Montgomery) before use in encryption.

## 2. Client-Side Cryptography

### Key Generation (Client Session)

The protocol uses **Ed25519 keypairs** for identity, with X25519 derived for encryption:

1. Generate a random 32-byte `seed`.
2. Create an Ed25519 keypair from the seed.
3. The **Ed25519 public key** (hex) is sent to the enclave as `X-NearAI-Client-Pub-Key`.
4. Derive the **X25519 private key** from the seed: `SHA-512(seed)`, take first 32 bytes, clamp (`[0] &= 248, [31] &= 127, [31] |= 64`).

The Near AI enclave converts the received Ed25519 public key to X25519 internally before encrypting response chunks.

### Message Encryption (v2_encrypt)

For each message:
1. Generate an ephemeral X25519 keypair.
2. `DH(ephemeral_secret, model_x25519_pub)` → `shared_secret`.
3. `HKDF-SHA256(shared_secret, salt=b"", info=b"ed25519_encryption")` → 32-byte symmetric key.
4. `XChaCha20Poly1305(symmetric_key, random_24_byte_nonce, plaintext)` → ciphertext.
5. Wire format: `hex(ephemeral_pub_32 || nonce_24 || ciphertext)`.

### Response Decryption (v2_decrypt)

For each SSE chunk:
1. Parse `hex(ephemeral_pub_32 || nonce_24 || ciphertext)`.
2. `DH(client_x25519_secret, ephemeral_pub)` → `shared_secret`.
3. `HKDF-SHA256(shared_secret, salt=b"", info=b"ed25519_encryption")` → symmetric key.
4. `XChaCha20Poly1305_decrypt(symmetric_key, nonce, ciphertext)` → plaintext.

## 3. Sending the Request

Send the standard Chat Completions request to the proxy with passthrough headers:

**Headers**:
- `X-NearAI-E2EE-Enabled: true`
- `X-NearAI-Client-Pub-Key: <ed25519_public_key_hex>`

The proxy detects these headers, skips its own E2EE layer for the Near AI upstream, and forwards the client's key directly.

## 4. Double Encryption (Optional)

It is possible to stack E2EE layers. If you provide both proxy E2EE headers (`X-E2EE-Enabled: true`, `X-KX-Algo`, etc.) AND Near AI E2EE headers (`X-NearAI-E2EE-Enabled: true`), the proxy will:
1. Decrypt the outer layer (using the proxy E2EE session).
2. Find the inner layer (the Near AI encrypted hex strings).
3. Forward the inner layer directly to Near AI without further processing.

This guarantees encryption in transit to the proxy *and* absolute privacy from the proxy itself.

## 5. Example

See `examples/nearai_direct_e2ee.py` for a complete, working implementation.
