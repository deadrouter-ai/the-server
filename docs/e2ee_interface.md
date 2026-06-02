# End-to-End Encryption (E2EE) Interface Guide

Our system implements an "Absolute Hell" hardened E2EE framework to ensure that your prompts and generations are cryptographically secured from the hypervisor and proxy memory. We utilize an **Encrypted Ticket Pattern** with Perfect Forward Secrecy (PFS).

## Protocol Overview

1. **Obtain Encrypted Ticket (GET /v1/keys/ephemeral)**
   The server issues an ephemeral AES-GCM encrypted ticket containing a freshly minted X25519 private key, accompanied by the public key. This offloads state from the server RAM while allowing 1-RTT connectivity.
   The keys are valid for a maximum of 10 minutes.

2. **Send Request (POST /v1/chat/completions)**
   When you send a request to the proxy, include the following headers:
   - `X-KX-Algo: X25519`
   - `X-E2EE-Enabled: true`
   - `X-Server-Ticket: <encrypted_private_key_from_step_1>`
   - `X-Client-Pub-Key: <your_x25519_public_key_base64>`

   **Message-level Encryption**: Every message `content` must be AES-GCM-256 encrypted using an HKDF-SHA256 derived key.
   - HKDF Info: `message_{index}_{role}`
   - AAD: `Client_Pub_Key (32B) + Model_Name + Role + Toggles`
   
   **AAD Toggles Rule**: To prevent downgrade attacks, the AAD must include any explicitly defined privacy toggles (`zdr`, `zds`, `tee`) exactly as they are sent in the JSON body. If you specify `"zdr": false`, append `zdr=false;` to the AAD. If you omit them entirely from the JSON body, the proxy will strictly default them to `true` (enforcing Zero Data Retention, Zero Data Sharing, and TEE), and you do *not* append them to the AAD.
   
   **Stream Chunk Ratcheting**: Stream chunks use an HKDF streaming ratchet initialized with `stream_init`, and ratcheting for each chunk using `stream_chunk_{counter}`.

---

## Prototype Python Client Example

This prototype script demonstrates how to interact with the hardened E2EE interface.

```python
import requests
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

def send_chat_completion():
    ticket = get_ephemeral_ticket()
    server_pub_bytes = base64.b64decode(ticket["public_key"])
    
    # Generate Client Ephemeral Key
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes = client_priv.public_key().public_bytes_raw()
    
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = client_priv.exchange(server_pub)

    model = "glm-5.1"
    role = "user"
    content = "What is the capital of France?"
    
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
    print(json.dumps(resp.json(), indent=2))

if __name__ == "__main__":
    send_chat_completion()
```
