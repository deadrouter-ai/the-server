"""
Stacked E2EE Client Example (Setup 3)

Demonstrates "Stacked Encryption" where the client encrypts the payload for the Near AI
enclave (zero-trust), and then encrypts THAT ciphertext for the Proxy (transport security).

- Request: Double Encrypted (Near AI V2 Hex -> Proxy AES-GCM Base64)
- Response (Non-Streaming): Double Encrypted (Near AI V2 Hex -> Proxy AES-GCM Base64)
- Response (Streaming): Single Encrypted (Near AI V2 Hex passthrough)
  *(The proxy bypasses stream padding/ratcheting for passthrough streams to prevent corruption)*

Dependencies: requests, cryptography, pynacl
"""
import requests
import json
import base64
import os
import hashlib
import urllib3
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import nacl.bindings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://localhost:5443"
BEARER = "test_token"
MODEL = "gpt-oss-120b"
STREAMING = False


# ── Near AI Cryptography (Layer 1) ──────────────────────────────────────────

def xchacha_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)

def xchacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)

def ed25519_pub_to_x25519(ed25519_pub_bytes: bytes) -> bytes:
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pub_bytes)

def ed25519_seed_to_x25519_secret(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    secret = bytearray(h[:32])
    secret[0] &= 248
    secret[31] &= 127
    secret[31] |= 64
    return bytes(secret)

def get_nearai_attestation() -> dict:
    nonce = os.urandom(32).hex()
    resp = requests.get(
        f"{BASE_URL}/v1/models/nearai/{MODEL}/key?nonce={nonce}&signing_algo=ed25519&include_tls_fingerprint=true",
        headers={"Authorization": f"Bearer {BEARER}"},
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()

def extract_model_x25519_key(attestation: dict) -> bytes:
    signing_key_hex = attestation.get("signing_public_key") or attestation.get("signing_address")
    if not signing_key_hex:
        if "model_attestations" in attestation and len(attestation["model_attestations"]) > 0:
            ma = attestation["model_attestations"][0]
            signing_key_hex = ma.get("signing_public_key") or ma.get("signing_address")
    signing_key_hex = signing_key_hex.removeprefix("0x")
    ed25519_bytes = bytes.fromhex(signing_key_hex)
    return ed25519_pub_to_x25519(ed25519_bytes)

def v2_encrypt(plaintext: bytes, model_x25519_bytes: bytes) -> str:
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    model_pub = X25519PublicKey.from_public_bytes(model_x25519_bytes)
    shared_secret = eph_priv.exchange(model_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"ed25519_encryption")
    symmetric_key = hkdf.derive(shared_secret)
    nonce = os.urandom(24)
    ciphertext = xchacha_encrypt(symmetric_key, nonce, plaintext)
    return (eph_pub_bytes + nonce + ciphertext).hex()

def v2_decrypt(data_hex: str, x25519_secret_bytes: bytes) -> str:
    data = bytes.fromhex(data_hex)
    eph_pub_bytes, nonce, ciphertext = data[0:32], data[32:56], data[56:]
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    secret_key = X25519PrivateKey.from_private_bytes(x25519_secret_bytes)
    shared_secret = secret_key.exchange(eph_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"ed25519_encryption")
    symmetric_key = hkdf.derive(shared_secret)
    return xchacha_decrypt(symmetric_key, nonce, ciphertext).decode("utf-8")

def generate_nearai_client_session() -> tuple[str, bytes]:
    seed = os.urandom(32)
    ed_priv = Ed25519PrivateKey.from_private_bytes(seed)
    ed_pub_hex = ed_priv.public_key().public_bytes_raw().hex()
    x25519_secret = ed25519_seed_to_x25519_secret(seed)
    return ed_pub_hex, x25519_secret


# ── Proxy Cryptography (Layer 2) ────────────────────────────────────────────

def get_ephemeral_ticket() -> dict:
    resp = requests.get(f"{BASE_URL}/v1/keys/ephemeral", headers={"Authorization": f"Bearer {BEARER}"}, verify=False)
    resp.raise_for_status()
    return resp.json()

def derive_proxy_message_key(shared_secret: bytes, index: int, role: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=f"message_{index}_{role}".encode())
    return hkdf.derive(shared_secret)

def proxy_encrypt_message(content: str, key: bytes, client_pub: bytes, model: str, role: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = client_pub + model.encode() + role.encode() + b"zdr=true;zds=true;tee=true;"
    ciphertext = aesgcm.encrypt(nonce, content.encode(), aad)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def proxy_decrypt_stream_chunk(encrypted_b64: str, key: bytes, client_pub: bytes, model: str) -> str:
    raw = base64.b64decode(encrypted_b64)
    nonce, ciphertext = raw[:12], raw[12:]
    aad = client_pub + model.encode() + b"stream_response"
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad).decode('utf-8')

def get_proxy_stream_ratchet(shared_secret: bytes, client_pub: bytes, model: str):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"stream_init")
    current_key = hkdf.derive(shared_secret)
    chunk_counter = 0

    def decrypt_next(chunk_b64: str) -> str:
        nonlocal current_key, chunk_counter
        plaintext = proxy_decrypt_stream_chunk(chunk_b64, current_key, client_pub, model)
        chunk_counter += 1
        hkdf_next = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=f"stream_chunk_{chunk_counter}".encode())
        current_key = hkdf_next.derive(current_key)
        return plaintext
        
    return decrypt_next


# ── Main ─────────────────────────────────────────────────────────────────────

def send_stacked_e2ee_request():
    print("[1] Fetching Near AI attestation...")
    attestation = get_nearai_attestation()
    model_x25519_bytes = extract_model_x25519_key(attestation)
    
    print("[2] Generating Near AI client session...")
    nearai_pub_hex, nearai_secret = generate_nearai_client_session()

    print("[3] Fetching Proxy Ephemeral ticket...")
    ticket = get_ephemeral_ticket()
    proxy_server_pub_bytes = base64.b64decode(ticket["public_key"])
    
    print("[4] Generating Proxy client session...")
    proxy_client_priv = X25519PrivateKey.generate()
    proxy_client_pub_bytes = proxy_client_priv.public_key().public_bytes_raw()
    proxy_server_pub = X25519PublicKey.from_public_bytes(proxy_server_pub_bytes)
    proxy_shared_secret = proxy_client_priv.exchange(proxy_server_pub)

    # Message Encryption Pipeline
    role = "user"
    content = "What is the capital of Chile?"
    
    # Layer 1: Encrypt for Near AI Enclave (produces hex string)
    layer1_content = v2_encrypt(content.encode(), model_x25519_bytes)
    print(f"[5] Near AI Encrypted Payload: {layer1_content[:40]}... ({len(layer1_content)} chars)")
    
    # Layer 2: Encrypt the hex string for the Proxy (produces b64 string)
    msg_key = derive_proxy_message_key(proxy_shared_secret, 0, role)
    layer2_content = proxy_encrypt_message(layer1_content, msg_key, proxy_client_pub_bytes, MODEL, role)
    print(f"[6] Proxy Encrypted Payload: {layer2_content[:40]}... ({len(layer2_content)} chars)")

    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json",
        
        # Proxy E2EE Headers
        "X-KX-Algo": "X25519",
        "X-E2EE-Enabled": "true",
        "X-Server-Ticket": ticket["encrypted_private_key"],
        "X-Client-Pub-Key": base64.b64encode(proxy_client_pub_bytes).decode('utf-8'),
        
        # Near AI E2EE Headers
        "X-NearAI-E2EE-Enabled": "true",
        "X-NearAI-Client-Pub-Key": nearai_pub_hex,
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": role, "content": layer2_content}],
        "stream": STREAMING,
        "tee": True,
        "zdr": True,
        "zds": True
    }

    print("\n[7] Sending STACKED E2EE Request...")
    resp = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload, verify=False, stream=STREAMING)
    print(f"    Status: {resp.status_code}")

    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return

    proxy_decryptor = get_proxy_stream_ratchet(proxy_shared_secret, proxy_client_pub_bytes, MODEL)

    if not STREAMING:
        print("Response JSON (Encrypted):")
        resp_json = resp.json()
        print(json.dumps(resp_json, indent=2))

        print("\n--- DECRYPTING FULL CHAIN ---\n")
        # In non-streaming mode, the proxy re-encrypts the Near AI hex response
        resp_json = resp.json()
        for choice in resp_json.get("choices", []):
            msg = choice.get("message", {})
            
            # Note: For non-streaming, the proxy encrypts reasoning_content BEFORE content.
            # Thus, the decryptor must be called in that exact order to maintain ratchet sync!
            enc_reasoning = msg.get("reasoning_content")
            enc_content = msg.get("content")
            
            if enc_reasoning:
                # 1. Decrypt Proxy Layer -> hex string
                nearai_hex = proxy_decryptor(enc_reasoning)
                # 2. Decrypt Near AI Layer -> plaintext
                try:
                    dec = v2_decrypt(nearai_hex, nearai_secret)
                    print(f"[Decrypted Reasoning]: {dec}")
                except Exception as e:
                    print(f"[Decrypted Reasoning Failed]: {e}")
                    
            if enc_content:
                # 1. Decrypt Proxy Layer -> hex string
                nearai_hex = proxy_decryptor(enc_content)
                # 2. Decrypt Near AI Layer -> plaintext
                try:
                    dec = v2_decrypt(nearai_hex, nearai_secret)
                    print(f"[Decrypted Content]: {dec}")
                except Exception as e:
                    print(f"[Decrypted Content Failed]: {e}")

    else:
        print("\n--- DECRYPTING FULL CHAIN ---\n")
        # In streaming mode, the proxy skips timing padding and ratcheting 
        # to preserve the raw Near AI SSE chunks.
        reasoning_started = False
        
        chunk_intervals = []
        has_padding = False
        last_time = time.time()

        for line in resp.iter_lines():
            if not line: continue
            
            current_time = time.time()
            chunk_intervals.append(current_time - last_time)
            last_time = current_time
            
            line_str = line.decode("utf-8")
            if not line_str.startswith("data: "): continue

            data_str = line_str[6:]
            if data_str.strip() == "[DONE]":
                print("\n\n[DONE]")
                break

            try:
                chunk = json.loads(data_str)
                if "pad" in chunk:
                    has_padding = True
            except json.JSONDecodeError:
                continue

            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {})

                # Streaming bypasses Proxy encryption, so we only do Near AI decryption (Layer 1)
                enc_reasoning = delta.get("reasoning_content")
                if enc_reasoning:
                    if not reasoning_started:
                        print("<think>", end="", flush=True)
                        reasoning_started = True
                    try:
                        dec = v2_decrypt(enc_reasoning, nearai_secret)
                        print(dec, end="", flush=True)
                    except Exception: pass

                enc_content = delta.get("content")
                if enc_content:
                    if reasoning_started:
                        print("</think>\n", end="", flush=True)
                        reasoning_started = False
                    try:
                        dec = v2_decrypt(enc_content, nearai_secret)
                        print(dec, end="", flush=True)
                    except Exception: pass

        # --- Stream Analysis ---
        if chunk_intervals:
            valid_intervals = chunk_intervals[1:] if len(chunk_intervals) > 1 else chunk_intervals
            avg_interval = sum(valid_intervals) / len(valid_intervals) * 1000
            
            print("\n\n--- STREAM ANALYSIS ---")
            print(f"Total Chunks:        {len(chunk_intervals)}")
            print(f"Obfuscation Padding: {'ENABLED (pad field found)' if has_padding else 'DISABLED'}")
            
            is_timing_protected = 45 < avg_interval < 75
            print(f"Average Interval:    {avg_interval:.2f} ms")
            print(f"Timing Protection:   {'ACTIVE (Proxy is buffering/ratcheting at ~50ms ticks)' if is_timing_protected else 'INACTIVE (Streaming raw chunks)'}")

if __name__ == "__main__":
    send_stacked_e2ee_request()
