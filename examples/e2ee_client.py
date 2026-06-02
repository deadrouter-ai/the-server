import requests
import json
import base64
import os
import urllib3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://localhost:5443"
BEARER = "test_token"

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
    aad = client_pub + model.encode() + role.encode() + b"tee=false;"
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

    model = "gpt-oss-120b"
    role = "user"
    content = "What is the capital of Chile?"
    
    msg_key = derive_message_key(shared_secret, 0, role)
    encrypted_content = encrypt_message(content, msg_key, client_pub_bytes, model, role)

    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json",
        "X-KX-Algo": "X25519",
        "X-E2EE-Enabled": "true",
        "X-Server-Ticket": ticket["encrypted_private_key"],
        "X-Client-Pub-Key": base64.b64encode(client_pub_bytes).decode('utf-8')
    }

    payload = {
        "model": model,
        "messages": [{"role": role, "content": encrypted_content}],
        "stream": False,
        "tee": False
    }

    print("Sending encrypted proxy request...")
    resp = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload, verify=False)
    print(f"Status Code: {resp.status_code}")
    print("Response JSON (Encrypted):")
    resp_json = resp.json()
    print(json.dumps(resp_json, indent=2))
    
    print("\n--- DECRYPTING FULL CHAIN ---")
    decryptor = get_stream_ratchet(shared_secret, client_pub_bytes, model)
    
    for choice in resp_json.get("choices", []):
        msg = choice.get("message", {})
        
        enc_reasoning = msg.get("reasoning_content")
        if enc_reasoning:
            try:
                dec_reasoning = decryptor(enc_reasoning)
                print(f"[Decrypted Reasoning]: {dec_reasoning}")
            except Exception as e:
                print(f"[Decrypted Reasoning Failed]: {e}")
                
        enc_content = msg.get("content")
        if enc_content:
            try:
                dec_content = decryptor(enc_content)
                print(f"[Decrypted Content]: {dec_content}")
            except Exception as e:
                print(f"[Decrypted Content Failed]: {e}")

if __name__ == "__main__":
    send_chat_completion()
