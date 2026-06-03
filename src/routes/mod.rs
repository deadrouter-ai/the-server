pub mod api;

mod landing_page;

pub use landing_page::handle_landing_page;

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

        // ---- Info endpoint ----
        (Method::GET, "/info") => {
            let onion = state
                .onion_data
                .read()
                .unwrap();
            let body = format!(
                "Onion      : {}\n\
                 DB Status  : {}\n\
                 Uptime     : {:?}\n\
                 Protocol   : {}\n",
                onion.onion_domain,
                state.db_placeholder,
                state.started_at.elapsed(),
                req.protocol,
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                full_body(body),
            )
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
