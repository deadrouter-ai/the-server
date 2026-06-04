"""
Near AI Direct E2EE Example

Demonstrates true end-to-end encryption between the client and
the Near AI hardware enclave, bypassing the proxy's cryptographic layer.

The proxy acts as a blind router — it cannot read the payload.

Dependencies: requests, cryptography, pynacl
"""
import requests
import json
import os
import hashlib
import urllib3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import nacl.bindings

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://localhost:5443"
BEARER = "test_token"
MODEL = "gpt-oss-120b"


# ── XChaCha20Poly1305 wrappers (via libsodium) ──────────────────────────────

def xchacha_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """XChaCha20Poly1305 AEAD encrypt (no AAD)."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, None, nonce, key
    )

def xchacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """XChaCha20Poly1305 AEAD decrypt (no AAD)."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, None, nonce, key
    )


# ── Ed25519 → X25519 conversion ─────────────────────────────────────────────

def ed25519_pub_to_x25519(ed25519_pub_bytes: bytes) -> bytes:
    """
    Convert an Ed25519 public key (Edwards form) to X25519 (Montgomery form).
    This matches the Rust: CompressedEdwardsY(key).decompress().to_montgomery().to_bytes()
    """
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed25519_pub_bytes)


def ed25519_seed_to_x25519_secret(seed: bytes) -> bytes:
    """
    Convert an Ed25519 seed to an X25519 private key.
    This matches the Rust E2eeSession::new():
      1. SHA-512 hash the seed
      2. Clamp the lower 32 bytes: [0] &= 248, [31] &= 127, [31] |= 64
    """
    h = hashlib.sha512(seed).digest()
    secret = bytearray(h[:32])
    secret[0] &= 248
    secret[31] &= 127
    secret[31] |= 64
    return bytes(secret)


# ── Attestation & Key Extraction ─────────────────────────────────────────────

def get_nearai_attestation() -> dict:
    """Fetch the raw attestation report from Near AI via the proxy."""
    print("[1] Fetching Near AI attestation report...")
    nonce = os.urandom(32).hex()
    resp = requests.get(
        f"{BASE_URL}/v1/models/nearai/{MODEL}/key?nonce={nonce}&signing_algo=ed25519&include_tls_fingerprint=true",
        headers={"Authorization": f"Bearer {BEARER}"},
        verify=False,
    )
    resp.raise_for_status()
    print(f"    Attestation received ({len(resp.content)} bytes)")
    return resp.json()


def extract_model_x25519_key(attestation: dict) -> bytes:
    """Extract Ed25519 signing key from attestation and convert to X25519."""
    signing_key_hex = attestation.get("signing_public_key") or attestation.get("signing_address")
    if not signing_key_hex:
        if "model_attestations" in attestation and len(attestation["model_attestations"]) > 0:
            ma = attestation["model_attestations"][0]
            signing_key_hex = ma.get("signing_public_key") or ma.get("signing_address")

    if not signing_key_hex:
        raise ValueError("Could not find signing key in attestation response")

    signing_key_hex = signing_key_hex.removeprefix("0x")
    ed25519_bytes = bytes.fromhex(signing_key_hex)
    assert len(ed25519_bytes) == 32, f"Expected 32-byte Ed25519 key, got {len(ed25519_bytes)}"

    x25519_bytes = ed25519_pub_to_x25519(ed25519_bytes)
    print(f"[2] Ed25519 key (attestation): {ed25519_bytes.hex()}")
    print(f"    X25519  key (converted):   {x25519_bytes.hex()}")
    return x25519_bytes


# ── V2 Encrypt / Decrypt (matches Rust v2_encrypt / v2_decrypt) ─────────────

def v2_encrypt(plaintext: bytes, model_x25519_bytes: bytes) -> str:
    """
    Encrypt using Near AI's v2 protocol:
      1. Generate ephemeral X25519 keypair
      2. DH(ephemeral_secret, model_pub) → shared_secret
      3. HKDF(shared_secret, salt=b"", info=b"ed25519_encryption") → 32-byte symmetric key
      4. XChaCha20Poly1305(symmetric_key, random_nonce, plaintext)
      5. Return hex(ephemeral_pub ∥ nonce ∥ ciphertext)
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()

    model_pub = X25519PublicKey.from_public_bytes(model_x25519_bytes)
    shared_secret = eph_priv.exchange(model_pub)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"ed25519_encryption")
    symmetric_key = hkdf.derive(shared_secret)

    nonce = os.urandom(24)
    ciphertext = xchacha_encrypt(symmetric_key, nonce, plaintext)

    # Wire format: eph_pub (32) || nonce (24) || ciphertext
    result = eph_pub_bytes + nonce + ciphertext
    return result.hex()


def v2_decrypt(data_hex: str, x25519_secret_bytes: bytes) -> str:
    """
    Decrypt using Near AI's v2 protocol:
      1. Parse ephemeral_pub (32) || nonce (24) || ciphertext from hex
      2. DH(our_x25519_secret, ephemeral_pub) → shared_secret
      3. HKDF → symmetric key
      4. XChaCha20Poly1305 decrypt
    """
    data = bytes.fromhex(data_hex)
    if len(data) < 56:
        raise ValueError(f"Payload too short: {len(data)} bytes")

    eph_pub_bytes = data[0:32]
    nonce = data[32:56]
    ciphertext = data[56:]

    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    secret_key = X25519PrivateKey.from_private_bytes(x25519_secret_bytes)
    shared_secret = secret_key.exchange(eph_pub)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=b"ed25519_encryption")
    symmetric_key = hkdf.derive(shared_secret)

    plaintext = xchacha_decrypt(symmetric_key, nonce, ciphertext)
    return plaintext.decode("utf-8")


def is_valid_hex(s: str) -> bool:
    """Check if a string is valid hex (even length, only hex chars)."""
    if len(s) % 2 != 0 or len(s) < 112:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def try_decrypt(data: str, secret: bytes) -> tuple[bool, str]:
    """Attempt to decrypt, returning (success, result_or_raw)."""
    if not is_valid_hex(data):
        return False, data
    try:
        return True, v2_decrypt(data, secret)
    except Exception:
        return False, data


# ── Client Session (mirrors Rust E2eeSession::new()) ────────────────────────

def generate_client_session() -> tuple[str, bytes]:
    """
    Generate a client E2EE session matching the Rust E2eeSession::new().

    The Rust code:
      1. Generates a random 32-byte seed
      2. Creates an Ed25519 keypair from that seed
      3. Sends the Ed25519 PUBLIC KEY (hex) as X-Client-Pub-Key
      4. Derives the X25519 SECRET via SHA-512(seed) + clamping

    The Near AI enclave then:
      1. Receives the Ed25519 public key
      2. Converts it to X25519 (Edwards→Montgomery)
      3. Uses it as the DH recipient for encrypting response chunks

    Returns: (ed25519_pub_hex, x25519_secret_bytes)
    """
    seed = os.urandom(32)

    # Generate Ed25519 public key from seed
    ed_priv = Ed25519PrivateKey.from_private_bytes(seed)
    ed_pub_bytes = ed_priv.public_key().public_bytes_raw()
    ed_pub_hex = ed_pub_bytes.hex()

    # Derive X25519 secret key (SHA-512 of seed, clamped)
    x25519_secret = ed25519_seed_to_x25519_secret(seed)

    # Verify: our derived X25519 public key matches the Ed25519→X25519 conversion
    x25519_pub_from_secret = X25519PrivateKey.from_private_bytes(x25519_secret).public_key().public_bytes_raw()
    x25519_pub_from_ed = ed25519_pub_to_x25519(ed_pub_bytes)
    assert x25519_pub_from_secret == x25519_pub_from_ed, \
        f"Key mismatch! Secret-derived: {x25519_pub_from_secret.hex()}, Ed-converted: {x25519_pub_from_ed.hex()}"

    return ed_pub_hex, x25519_secret


# ── Main ─────────────────────────────────────────────────────────────────────

def send_direct_e2ee_request():
    attestation = get_nearai_attestation()
    model_x25519_bytes = extract_model_x25519_key(attestation)

    # Generate client session (Ed25519 pub + X25519 secret)
    client_ed_pub_hex, client_x25519_secret = generate_client_session()
    print(f"[3] Client Ed25519 pub (sent to enclave): {client_ed_pub_hex}")

    # Encrypt the user message using the model's X25519 key
    role = "user"
    content = "What is the capital of Chile?"
    encrypted_content = v2_encrypt(content.encode(), model_x25519_bytes)
    print(f"[4] Encrypted content ({len(encrypted_content)} hex chars)")

    # Send through the proxy with X-NearAI-* passthrough headers
    headers = {
        "Authorization": f"Bearer {BEARER}",
        "Content-Type": "application/json",
        "X-NearAI-E2EE-Enabled": "true",
        "X-NearAI-Client-Pub-Key": client_ed_pub_hex,
    }

    payload = {
        "model": MODEL,
        "messages": [{"role": role, "content": encrypted_content}],
        "stream": True,
        "tee": True,
    }

    print("\n[5] Sending encrypted passthrough request...")
    resp = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers=headers,
        json=payload,
        verify=False,
        stream=True,
    )
    print(f"    Status: {resp.status_code}")

    if resp.status_code != 200:
        print(f"    Error: {resp.text}")
        return

    print("\n--- STREAMING DECRYPTED RESPONSE ---\n")
    reasoning_started = False

    for line in resp.iter_lines():
        if not line:
            continue
        line_str = line.decode("utf-8")
        if not line_str.startswith("data: "):
            continue

        data_str = line_str[6:]
        if data_str.strip() == "[DONE]":
            print("\n\n[DONE]")
            break

        try:
            chunk = json.loads(data_str)
        except json.JSONDecodeError:
            continue

        for choice in chunk.get("choices", []):
            delta = choice.get("delta", {})

            # Handle reasoning_content
            enc_reasoning = delta.get("reasoning_content")
            if enc_reasoning:
                if not reasoning_started:
                    print("<think>", end="", flush=True)
                    reasoning_started = True
                ok, text = try_decrypt(enc_reasoning, client_x25519_secret)
                print(text, end="", flush=True)

            # Handle content (reasoning is finished when content starts)
            enc_content = delta.get("content")
            if enc_content:
                if reasoning_started:
                    print("</think>\n", end="", flush=True)
                    reasoning_started = False
                ok, text = try_decrypt(enc_content, client_x25519_secret)
                print(text, end="", flush=True)

    print()


if __name__ == "__main__":
    send_direct_e2ee_request()
