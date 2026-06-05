"""
Proxy E2EE Client Example (Setup 1)

Demonstrates End-to-End Encryption between the client and the proxy.
The proxy encrypts the stream with a forward-secret stream ratchet.

Dependencies: requests, cryptography
"""
import requests
import json
import base64
import os
import urllib3
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://localhost:5443"
BEARER = "test_token"
MODEL = "gpt-oss-120b"
STREAMING = True

def get_ephemeral_ticket():
    resp = requests.get(f"{BASE_URL}/v1/keys/ephemeral", headers={"Authorization": f"Bearer {BEARER}"}, verify=False)
    resp.raise_for_status()
    return resp.json()

def derive_message_key(shared_secret: bytes, index: int, role: str) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=f"message_{index}_{role}".encode())
    return hkdf.derive(shared_secret)

def encrypt_message(content: str, key: bytes, client_pub: bytes, model: str, role: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    # Toggles AAD
    aad = client_pub + model.encode() + role.encode() + b"zdr=true;zds=true;tee=true;"
    ciphertext = aesgcm.encrypt(nonce, content.encode(), aad)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_stream_chunk(encrypted_b64: str, key: bytes, client_pub: bytes, model: str) -> str:
    raw = base64.b64decode(encrypted_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aad = client_pub + model.encode() + b"stream_response"
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad).decode('utf-8')

def get_stream_ratchet(shared_secret: bytes, client_pub: bytes, model: str):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"stream_init")
    current_key = hkdf.derive(shared_secret)
    chunk_counter = 0

    def decrypt_next(chunk_b64: str) -> str:
        nonlocal current_key, chunk_counter
        plaintext = decrypt_stream_chunk(chunk_b64, current_key, client_pub, model)
        
        # Ratchet
        chunk_counter += 1
        hkdf_next = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=f"stream_chunk_{chunk_counter}".encode())
        current_key = hkdf_next.derive(current_key)
        
        return plaintext
        
    return decrypt_next

def send_chat_completion():
    ticket = get_ephemeral_ticket()
    server_pub_bytes = base64.b64decode(ticket["public_key"])
    
    # Generate Client Ephemeral Key
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes_raw()
    
    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = client_priv.exchange(server_pub)

    role = "user"
    content = "What is the capital of Chile?"
    
    msg_key = derive_message_key(shared_secret, 0, role)
    encrypted_content = encrypt_message(content, msg_key, client_pub_bytes, MODEL, role)

    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json",
        "X-KX-Algo": "X25519",
        "X-E2EE-Enabled": "true",
        "X-Server-Ticket": ticket["encrypted_private_key"],
        "X-Client-Pub-Key": base64.b64encode(client_pub_bytes).decode('utf-8')
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": role, "content": encrypted_content}],
        "stream": STREAMING,
        "tee": True,
        "zdr": True,
        "zds": True
    }

    print("Sending encrypted proxy request...")
    resp = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload, verify=False, stream=STREAMING)
    print(f"Status Code: {resp.status_code}")
    if resp.status_code != 200:
        print(resp.text)
        return
        
    
    decryptor = get_stream_ratchet(shared_secret, client_pub_bytes, MODEL)
    
    if not STREAMING:
        print("Response JSON (Encrypted):")
        resp_json = resp.json()
        print(json.dumps(resp_json, indent=2))
        
        print("\n--- DECRYPTING FULL CHAIN ---")
        for choice in resp_json.get("choices", []):
            msg = choice.get("message", {})
            
            # Note: For non-streaming, the proxy encrypts reasoning_content BEFORE content.
            # Thus, the decryptor must be called in that exact order to maintain ratchet sync!
            enc_reasoning = msg.get("reasoning_content")
            enc_content = msg.get("content")
            
            if enc_reasoning:
                try:
                    dec_reasoning = decryptor(enc_reasoning)
                    print(f"[Decrypted Reasoning]: {dec_reasoning}")
                except Exception as e:
                    print(f"[Decrypted Reasoning Failed]: {e}")
                    
            if enc_content:
                try:
                    dec_content = decryptor(enc_content)
                    print(f"[Decrypted Content]: {dec_content}")
                except Exception as e:
                    print(f"[Decrypted Content Failed]: {e}")

    else:
        print("\n--- STREAMING DECRYPTED RESPONSE ---")
        reasoning_started = False
        
        chunk_intervals = []
        has_padding = False
        last_time = time.time()

        for line in resp.iter_lines():
            if not line: continue
            
            # Record timing
            current_time = time.time()
            chunk_intervals.append(current_time - last_time)
            last_time = current_time
            
            line_str = line.decode('utf-8')
            if not line_str.startswith("data: "): continue
            
            data_str = line_str[6:].strip()
            if data_str == "[DONE]":
                print("\n[DONE]")
                break
                
            try:
                chunk = json.loads(data_str)
                if "pad" in chunk:
                    has_padding = True
            except json.JSONDecodeError:
                continue
                
            if "e2e" in chunk:
                # E2EE Padding wrapper encapsulates the JSON SSE payload in 'e2e'
                try:
                    decrypted_json_str = decryptor(chunk["e2e"])
                    decrypted_chunk = json.loads(decrypted_json_str)
                    
                    for choice in decrypted_chunk.get("choices", []):
                        delta = choice.get("delta", {})
                        
                        r_content = delta.get("reasoning_content")
                        if r_content:
                            if not reasoning_started:
                                print("<think>", end="", flush=True)
                                reasoning_started = True
                            print(r_content, end="", flush=True)
                            
                        content = delta.get("content")
                        if content:
                            if reasoning_started:
                                print("</think>\n", end="", flush=True)
                                reasoning_started = False
                            print(content, end="", flush=True)
                            
                except Exception as e:
                    print(f"\n[Decryption Error]: {e}")
            else:
                # Fallback if not wrapped in e2e
                for choice in chunk.get("choices", []):
                    delta = choice.get("delta", {})
                    enc_content = delta.get("content")
                    enc_reasoning = delta.get("reasoning_content")
                    
                    if enc_content:
                        dec = decryptor(enc_content)
                        print(dec, end="", flush=True)
                    if enc_reasoning:
                        dec = decryptor(enc_reasoning)
                        print(dec, end="", flush=True)

        # --- Stream Analysis ---
        if chunk_intervals:
            # Ignore the first chunk as it includes initial TTFB network latency
            valid_intervals = chunk_intervals[1:] if len(chunk_intervals) > 1 else chunk_intervals
            avg_interval = sum(valid_intervals) / len(valid_intervals) * 1000
            
            print("\n\n--- STREAM ANALYSIS ---")
            print(f"Total Chunks:        {len(chunk_intervals)}")
            print(f"Obfuscation Padding: {'ENABLED (pad field found)' if has_padding else 'DISABLED'}")
            
            # The proxy implements timing padding at exactly 50ms
            is_timing_protected = 45 < avg_interval < 75
            print(f"Average Interval:    {avg_interval:.2f} ms")
            print(f"Timing Protection:   {'ACTIVE (Proxy is buffering/ratcheting at ~50ms ticks)' if is_timing_protected else 'INACTIVE (Streaming raw chunks)'}")

if __name__ == "__main__":
    send_chat_completion()
