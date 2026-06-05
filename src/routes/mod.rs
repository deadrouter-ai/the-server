pub mod api;

mod landing_page;
mod models_page;

pub use landing_page::handle_landing_page;
pub use models_page::handle_models_page;

use bytes::Bytes;
use hyper::{Method, Uri, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use crate::AppState;

/// Protocol-agnostic request representation.
/// This normalizes the different request sources into a common type so the
/// router logic is identical for HTTP/1.1, HTTP/2, HTTP/3, and Onion.
pub struct IncomingRequest {
    pub method: Method,
    pub uri: Uri,
    pub protocol: &'static str,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Bytes,
}

/// Helper function to create a hyper response body from a String.
pub fn full_body(chunk: String) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(chunk)).map_err(|e| match e {}).boxed()
}

/// Route an incoming request through the unified handler.
/// Returns (status, headers, body) regardless of transport protocol.
pub async fn router(
    state: &AppState,
    req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let path = req.uri.path();

    match (req.method.clone(), path) {
        // ---- Health / readiness probe ----
        (Method::GET, "/health") => {
            let uptime = state.started_at.elapsed();
            let body = format!(
                "{{\"status\":\"ok\",\"uptime_secs\":{}}}\n",
                uptime.as_secs(),
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "application/json; charset=utf-8".into())],
                full_body(body),
            )
        }

        // ---- Logos ----
        (Method::GET, path) if path.starts_with("/logos/") => {
            let filename = path.trim_start_matches("/logos/");
            let bytes: Option<&'static [u8]> = match filename {
                "zai.svg" => Some(include_bytes!("../../static/logos/zai.svg").as_slice()),
                "kimi.svg" => Some(include_bytes!("../../static/logos/kimi.svg").as_slice()),
                "openai.svg" => Some(include_bytes!("../../static/logos/openai.svg").as_slice()),
                "mistral.svg" => Some(include_bytes!("../../static/logos/mistral.svg").as_slice()),
                "deepseek.svg" => Some(include_bytes!("../../static/logos/deepseek.svg").as_slice()),
                "qwen.svg" => Some(include_bytes!("../../static/logos/qwen.svg").as_slice()),
                "gemma.svg" => Some(include_bytes!("../../static/logos/gemma.svg").as_slice()),
                "apertus.svg" => Some(include_bytes!("../../static/logos/apertus.svg").as_slice()),
                "venice.svg" => Some(include_bytes!("../../static/logos/venice.svg").as_slice()),
                "nvidia.svg" => Some(include_bytes!("../../static/logos/nvidia.svg").as_slice()),
                "ollama.svg" => Some(include_bytes!("../../static/logos/ollama.svg").as_slice()),
                "minimax.svg" => Some(include_bytes!("../../static/logos/minimax.svg").as_slice()),
                _ => None,
            };

            if let Some(data) = bytes {
                let body = Full::new(Bytes::from_static(data)).map_err(|e| match e {}).boxed();
                (
                    StatusCode::OK,
                    vec![
                        ("Content-Type", "image/svg+xml".into()),
                        ("Cache-Control", "public, max-age=31536000, immutable".into()),
                    ],
                    body,
                )
            } else {
                (
                    StatusCode::NOT_FOUND,
                    vec![],
                    Full::new(Bytes::new()).boxed(),
                )
            }
        }

        // ---- Favicon ----
        (Method::GET, "/favicon.ico") => {
            let icon_bytes = include_bytes!("../../static/favicon.ico");
            let body = Full::new(Bytes::from_static(icon_bytes)).map_err(|e| match e {}).boxed();
            (
                StatusCode::OK,
                vec![("Content-Type", "image/x-icon".into())],
                body,
            )
        }

        // ---- CORS Preflight ----
        (Method::OPTIONS, _) => {
            (
                StatusCode::OK,
                vec![],
                full_body(String::new()),
            )
        }

        // ---- Chat Completions ----
        (Method::POST, "/v1/chat/completions") => {
            crate::routes::api::chat_completions::handle_secure_openai_proxy(state, req).await
        }

        // ---- Models ----
        (Method::GET, "/v1/models") => {
            crate::routes::api::models::handle_models_list(state, &req.uri.to_string()).await
        }

        // ---- Keys ----
        (Method::GET, "/v1/keys/ephemeral") | (Method::POST, "/v1/keys/ephemeral") => {
            crate::routes::api::keys::handle_keys_ephemeral(state).await
        }

        // ---- Landing page ----
        (Method::GET, "/") => {
            let (status, headers, body) = crate::routes::handle_landing_page(state, req);
            (status, headers, full_body(body))
        }

        // ---- Models page ----
        (Method::GET, "/models") => {
            let (status, headers, body) = crate::routes::handle_models_page(state, req).await;
            (status, headers, full_body(body))
        }

        // ---- Near AI Key Proxy ----
        (Method::GET, path) if path.starts_with("/v1/models/nearai/") && path.ends_with("/key") => {
            crate::routes::api::keys::handle_nearai_model_key(state, req).await
        }

        // ---- Endpoint Not Found ----
        (_, _) => {
            (
                StatusCode::NOT_FOUND,
                vec![],
                Full::new(Bytes::new()).boxed(),
            )
        }
    }
}
