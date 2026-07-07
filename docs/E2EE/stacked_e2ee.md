# Stacked E2EE (Double Encryption)

Stacked Encryption provides the highest level of security by combining both Layer 1 (Near AI Zero-Trust) and Layer 2 (Proxy AES-GCM). 

By double-encrypting the payload, the client achieves end-to-end zero-trust with the hardware enclave, while simultaneously protecting routing metadata and preventing network timing analysis against the proxy infrastructure.

## Protocol Flow

1. **Layer 1 Encryption (Near AI V2 Protocol)**
   - The client fetches the Near AI hardware attestation.
   - The client encrypts the raw message text into a hex string using the `XChaCha20Poly1305` V2 protocol.

2. **Layer 2 Encryption (Proxy AES-GCM)**
   - The client fetches a Proxy Ephemeral Ticket.
   - The client treats the Layer 1 hex string as the "plaintext" content.
   - The client encrypts this hex string using AES-256-GCM to produce a base64 string.

3. **Request Submission**
   - The client submits the request with both sets of E2EE headers:
     - `X-E2EE-Enabled: true`
     - `X-Server-Ticket: ...`
     - `X-Client-Pub-Key: <proxy_client_pub>`
     - `X-NearAI-E2EE-Enabled: true`
     - `X-NearAI-Client-Pub-Key: <nearai_client_pub>`
   - The payload `content` field contains the base64 double-encrypted string.

4. **Proxy Routing**
   - The proxy intercepts the request and decrypts Layer 2 (AES-GCM).
   - The resulting JSON now contains the Near AI V2 hex strings.
   - The proxy forwards this request to the Near AI Enclave, passing along the `X-NearAI-*` headers.

## Response Decryption (Non-Streaming)

In a non-streaming configuration, the proxy re-encrypts the response before sending it to the client.

- The Near AI enclave responds with a JSON containing Layer 1 encrypted hex strings.
- Because `stream=false`, the proxy's `sanitize_and_spoof_response` interceptor executes.
- The interceptor encrypts the Layer 1 hex strings using the Proxy's stream ratchet, producing base64 strings.
- **Client Decryption:** 
  1. Decrypt the base64 string using the Proxy Ratchet to retrieve the Layer 1 hex string. *(Remember to decrypt `reasoning_content` before `content`!)*
  2. Decrypt the Layer 1 hex string using the Near AI V2 Protocol to retrieve the plaintext.

## Response Decryption (Streaming)

Streaming behavior differs significantly to prevent stream corruption.

- When the proxy detects `X-NearAI-Client-Pub-Key`, it enables **Passthrough Mode**.
- In Passthrough Mode, the proxy deliberately **bypasses** its stream timing padding (`wrap_stream_with_timing_padding`) and its Layer 2 stream ratchet.
- This is because aggregating multiple hardware-encrypted hex chunks into a single proxy event would break the chunk boundaries required for V2 decryption.
- **Obfuscation Padding:** To mitigate packet-size fingerprinting, the proxy injects a `"pad"` field to pad each chunk to a 256-byte boundary. However, timing padding remains inactive.
- **Client Decryption:** 
  - The client receives the length-padded Server-Sent Events from Near AI.
  - The client parses the JSON, ignoring the `pad` field, and directly decrypts the `content` and `reasoning_content` hex strings using the Near AI V2 protocol. 
  - *No Proxy Layer 2 decryption is required for the streaming response.*

## Code Example

Reference the Python implementation in `examples/stacked_e2ee_client.py` for a complete, working example of Double Encryption, illustrating the differences between streaming and non-streaming decryption pipelines.
