//! E2EE key exchange API endpoints.
//!
//! Provides two endpoints:
//!   - `GET /v1/keys/ephemeral`: Generate a fresh X25519 E2EE ticket (no auth required)
//!   - `GET /v1/models/nearai/{model}/key`: Proxy an attestation report from a Near AI enclave

use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use crate::AppState;
use crate::crypto_e2ee::generate_ticket;

/// Generates and returns a fresh E2EE ephemeral ticket.
///
/// No authentication is required — tickets are lightweight and self-protecting.
/// The client receives an X25519 public key and an AES-256-GCM encrypted private
/// key that only this server can decrypt. This bootstraps the E2EE key exchange
/// without requiring any pre-shared secrets.

pub async fn handle_keys_ephemeral(
    state: &AppState,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let secrets = state.ticket_secrets.read().await;
    let ticket = generate_ticket(&secrets);
    
    let body_bytes = serde_json::to_vec(&ticket).unwrap();
    (
        StatusCode::OK,
        vec![("Content-Type", "application/json".to_string())],
        Full::new(Bytes::from(body_bytes)).map_err(|e| match e {}).boxed(),
    )
}

/// Proxies an attestation report request from a Near AI hardware enclave.
///
/// Resolves the model's direct endpoint from dynamic state, then forwards the
/// attestation request through the custom Near AI TLS client (which enforces
/// SPKI certificate pinning against attested fingerprints).
pub async fn handle_nearai_model_key(
    state: &AppState,
    req: &crate::IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    // 1. Enforce Auth
    let auth_header = req.headers.get("authorization").cloned().unwrap_or_default();
    if !auth_header.starts_with("Bearer ") {
        let err = serde_json::to_vec(&serde_json::json!({"error": "Missing or invalid Authorization header"})).unwrap();
        return (
            StatusCode::UNAUTHORIZED,
            vec![("Content-Type", "application/json".to_string())],
            Full::new(Bytes::from(err)).map_err(|e| match e {}).boxed(),
        );
    }

    let path = req.uri.path();
    let model_id = path.trim_start_matches("/v1/models/nearai/").trim_end_matches("/key");

    // Resolve the direct endpoint through the dynamic model info first,
    // falling back to the static URL construction. This ensures the attestation
    // is fetched from the exact same enclave that will serve the chat request.
    let direct_url = {
        let near_ai_provider = state.providers.get("near-ai");
        let mut resolved: Option<String> = None;

        if let Some(provider) = near_ai_provider {
            let dyn_state = provider.dynamic_state.read().await;
            // Try the frontend model name as-is first (lowercase)
            let lower_model = model_id.to_lowercase();
            if let Some(info) = dyn_state.dynamic_models.get(&lower_model) {
                if let Some(ref ep) = info.direct_endpoint {
                    resolved = Some(ep.clone());
                }
            }
        }

        resolved.unwrap_or_else(|| crate::providers::nearai::get_direct_endpoint(model_id))
    };

    let query = req.uri.query().unwrap_or("");
    let upstream_url = if query.is_empty() {
        format!("{}/v1/attestation/report?signing_algo=ed25519", direct_url)
    } else {
        format!("{}/v1/attestation/report?{}", direct_url, query)
    };

    // Use near_ai_client (which has the custom TLS verifier) to hit the enclave
    match state.near_ai_client.get(&upstream_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            (
                status,
                vec![("Content-Type", "application/json".to_string())],
                Full::new(body_bytes).map_err(|e| match e {}).boxed(),
            )
        }
        Err(e) => {
            let err = serde_json::to_vec(&serde_json::json!({"error": format!("Upstream network error: {}", e)})).unwrap();
            (
                StatusCode::BAD_GATEWAY,
                vec![("Content-Type", "application/json".to_string())],
                Full::new(Bytes::from(err)).map_err(|e| match e {}).boxed(),
            )
        }
    }
}
