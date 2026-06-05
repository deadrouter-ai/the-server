# Proxy E2EE (Standard Encryption)

The Proxy E2EE layer ensures that all chat completion requests and responses are encrypted between the client and our proxy server. This prevents any intermediate network actor from reading the request or response payloads. 

Furthermore, streaming responses are wrapped in a **timing padding wrapper** to mitigate traffic analysis and side-channel attacks that attempt to infer generated tokens based on TCP packet timing.

## Protocol Flow

1. **Ticket Fetching**
   - Client sends a `GET /v1/keys/ephemeral` request.
   - The proxy responds with a `public_key` (X25519) and an `encrypted_private_key` (an AES-256-GCM encrypted blob that only the proxy can decrypt). This stateless design means the proxy does not need to store thousands of ephemeral keypairs in memory.

2. **Key Exchange (DH)**
   - The client generates its own ephemeral X25519 keypair.
   - The client performs a Diffie-Hellman (DH) exchange against the proxy's `public_key` to derive a `shared_secret`.

3. **Request Encryption**
   - The client derives a symmetric key via HKDF-SHA256: `HKDF(shared_secret, info="message_{index}_{role}")`.
   - The client encrypts the message content using AES-256-GCM. 
   - **AAD (Additional Authenticated Data):** `client_pub_bytes + model_name + role + toggles_string` (e.g. `zdr=true;zds=true;tee=true;`). This ensures the ciphertext is cryptographically bound to the request metadata.

4. **Request Submission**
   - Client sends the request to `/v1/chat/completions` with headers:
     - `X-E2EE-Enabled: true`
     - `X-Server-Ticket: <encrypted_private_key>`
     - `X-Client-Pub-Key: <client_pub_base64>`

## Response Decryption (Non-Streaming)

If `stream=false` is requested, the proxy processes the upstream response, encrypts the fields, and returns a standard JSON structure.

- **Important Encryption Order:** The proxy encrypts `reasoning_content` **BEFORE** `content`. 
- Because the proxy uses a forward-secret stream ratchet, the client MUST decrypt the fields in the exact same order to maintain synchronization.
- **Ratchet Init:** `HKDF(shared_secret, info="stream_init")`
- **Ratchet Step:** `HKDF(current_key, info="stream_chunk_{N}")`

## Response Decryption (Streaming)

If `stream=true` is requested, the proxy aggregates upstream Server-Sent Events (SSE) into fixed 50ms intervals. 
- The proxy pads every SSE payload with a dummy `pad` string of `X`s to reach a 256-byte boundary, masking the actual token sizes.
- The proxy wraps the encrypted JSON chunk inside an `e2e` property: `{"e2e": "<base64_ciphertext>"}`
- **Important Encryption Order:** In streaming mode, the proxy encrypts `content` **BEFORE** `reasoning_content` within each chunk.
- The client decrypts the `e2e` base64 payload to retrieve the actual SSE JSON chunk containing the `delta`.

## Code Example

Reference the Python implementation in `examples/e2ee_client.py` for a complete, working example of ticket management, AES-GCM encryption, and stream ratcheting.
