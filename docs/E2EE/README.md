# End-to-End Encryption (E2EE) Architecture

The server supports a robust, multi-layered End-to-End Encryption architecture designed to protect user data against passive surveillance, active MITM, and compromised hardware. 

We offer three distinct E2EE configurations, allowing clients to scale their security posture based on their threat model and the downstream provider.

## Routing Directory

1. **[Proxy E2EE (Standard)](proxy_e2ee.md)**
   Standard transport-layer security between the client and our proxy router. Protects against MITM attacks and ensures forward secrecy via stream ratcheting and timing side-channel padding.

2. **[Near AI Zero-Trust E2EE](nearai_e2ee.md)**
   Hardware-enforced encryption directly to a Near AI Trusted Execution Environment (TEE). The proxy acts as a blind passthrough, providing absolute cryptographic zero-trust even if the proxy itself is compromised.

3. **[Stacked E2EE (Double Encryption)](stacked_e2ee.md)**
   Combines both layers. Protects against proxy surveillance via Near AI's TEE encryption (Layer 1), whilst shielding the proxy's upstream routing metadata and preventing stream traffic analysis via the Proxy E2EE stream padding (Layer 2).

---

### Comparison of Modes

| Feature | Proxy E2EE | Near AI E2EE | Stacked E2EE |
|---------|------------|--------------|--------------|
| **Protects against Network MITM** | Yes | Yes | Yes |
| **Protects against Proxy Compromise** | No | Yes | Yes |
| **Protects against Length Fingerprinting** | Yes | Yes | Yes |
| **Protects against Timing Side-Channels** | Yes | No | No |
| **Supported Models** | All | Near AI Hardware | Near AI Hardware |
| **Cryptography** | AES-256-GCM | XChaCha20Poly1305 | Both |
| **Key Exchange** | Ephemeral X25519 | Attested Ed25519 -> X25519 | Both |

*See individual documentation files for protocol specifics, sequence diagrams, and code implementation guidelines.*
