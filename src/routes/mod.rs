pub mod api;

mod landing_page;
mod models_page;
mod providers_page;

pub use landing_page::handle_landing_page;
pub use models_page::handle_models_page;
pub use providers_page::handle_providers_page;

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
            
            // Prevent path traversal
            if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
                return (
                    StatusCode::FORBIDDEN,
                    vec![],
                    Full::new(Bytes::new()).boxed(),
                );
            }

            let file_path = format!("static/logos/{}", filename);
            match std::fs::read(&file_path) {
                Ok(data) => {
                    let mime_type = match filename.split('.').next_back() {
                        Some("svg") => "image/svg+xml",
                        Some("png") => "image/png",
                        Some("jpg") | Some("jpeg") => "image/jpeg",
                        Some("gif") => "image/gif",
                        Some("webp") => "image/webp",
                        _ => "application/octet-stream",
                    };

                    let body = Full::new(Bytes::from(data)).map_err(|e| match e {}).boxed();
                    (
                        StatusCode::OK,
                        vec![
                            ("Content-Type", mime_type.into()),
                            ("Cache-Control", "public, max-age=31536000, immutable".into()),
                        ],
                        body,
                    )
                }
                Err(_) => {
                    (
                        StatusCode::NOT_FOUND,
                        vec![],
                        Full::new(Bytes::new()).boxed(),
                    )
                }
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

        // ---- Tinfoil E2EE Proxy ----
        (Method::POST, "/v1/private/tinfoil/v1/chat/completions") => {
            crate::routes::api::tinfoil_e2ee::handle_tinfoil_chat_completions(state, req).await
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

        // ---- Providers page ----
        (Method::GET, "/providers") => {
            let (status, headers, body) = crate::routes::handle_providers_page(state, req).await;
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
