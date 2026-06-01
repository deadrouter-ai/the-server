// ======================================================================
// the-server — Hardened multi-protocol test server
//
// Protocols:
//   • HTTP/1.1 + HTTP/2  over TLS 1.3  (TCP :443)
//   • HTTP/3             over QUIC     (UDP :443)
//   • Plaintext HTTP/1.1 redirect      (TCP :80  →  https://…:443)
//   • Tor Onion Service  (ephemeral .onion, via arti-client)
//
// Crypto:
//   • aws-lc-rs (FIPS-grade) via rustls 0.23
//   • Only AES-256-GCM-SHA384  (TLS 1.3)
//   • Key exchange: FIPS Complient only
//   • Self-signed ECDSA P-256 cert (runtime-generated via rcgen)
// ======================================================================

use std::sync::Arc;
use hyper::{Method, Uri, StatusCode};

mod quic_h3;
mod connections;
mod routes;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// ======================================================================
// AppState — shared state across all protocol handlers
// ======================================================================

/// Shared application state that is passed to every request handler regardless
/// of the originating protocol (HTTPS, HTTP/3, Onion, etc.).
///
/// Use this to hold connection pools, caches, config, or any other cross-cutting
/// concerns that should be available to request handlers.
pub struct AppState {
    pub onion_data: std::sync::RwLock<OnionData>,
    pub db_placeholder: String,
    pub started_at: std::time::Instant,
}

pub struct OnionData {
    pub onion_domain: String,
    pub onion_https_cert: String,
}

impl OnionData {
    fn new() -> Self {
        Self {
            onion_domain: String::new(),
            onion_https_cert: String::new(),
        }
    }
}

impl AppState {
    fn new() -> Self {
        Self {
            onion_data: std::sync::RwLock::new(OnionData::new()),
            db_placeholder: String::from("(no database configured)"),
            started_at: std::time::Instant::now(),
        }
    }
}

// ======================================================================
// Unified Router — single function for ALL protocols
// ======================================================================

/// Protocol-agnostic request representation.
/// This normalizes the different request sources into a common type so the
/// router logic is identical for HTTP/1.1, HTTP/2, HTTP/3, and Onion.
pub struct IncomingRequest {
    pub method: Method,
    pub uri: Uri,
    pub protocol: &'static str,
}

/// Route an incoming request through the unified handler.
/// Returns (status, headers, body) regardless of transport protocol.
pub fn router(
    state: &AppState,
    req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
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
                body,
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
                body,
            )
        }

        // ---- Landing page ----
        (Method::GET, "/") => {
            crate::routes::handle_landing_page(state, req)
        }

        // ---- Default / catch-all ----
        (Method::GET, _) | (Method::HEAD, _) => {
            let onion = state
                .onion_data
                .read()
                .unwrap();
            let body = format!(
                "GREETINGS FROM THE SECURE ENCLAVE!\n\
                 \n\
                 Protocol : {}\n\
                 Method   : {}\n\
                 URI      : {}\n\
                 Onion    : {}\n",
                req.protocol, req.method, req.uri, onion.onion_domain,
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                body,
            )
        }

        // ---- Method not allowed ----
        (_, _) => {
            let body = format!("405 Method Not Allowed: {} {}\n", req.method, req.uri);
            (
                StatusCode::METHOD_NOT_ALLOWED,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                body,
            )
        }
    }
}

// ======================================================================
// main — spin up all 4 listeners
// ======================================================================

#[tokio::main]
async fn main() {
    println!("\n=======================================================");
    println!("  THE-SERVER — Hardened Multi-Protocol Enclave Server");
    println!("  Crypto : aws-lc-rs FIPS (AES-256-GCM only)");
    println!("  TLS    : 1.3 only, PQ Key Exchange (ML-KEM)");
    println!("=======================================================\n");

    if let Ok(hash) = std::env::var("LOADER_PAYLOAD_HASH") {
        println!("[info] Payload measurement: {}", hash);
    }

    let is_dev = std::env::var("DEVELOPMENT").unwrap_or_else(|_| "false".to_string()) == "true";
    let tls_port = if is_dev { 5443 } else { 443 };
    let http_port = if is_dev { 5001 } else { 80 };

    if is_dev {
        println!("[info] Running in DEVELOPMENT mode.");
    }

    // ---- Shared state ----
    let state = Arc::new(AppState::new());

    // ---- Start Clearnet ----
    connections::clearnet::start_all(state.clone(), tls_port, http_port).await;

    // ---- Start Onion Service ----
    if !is_dev {
        connections::onion::start(state.clone()).await;
    } else {
        println!("[skip] Onion service disabled in development mode.");
    }

    println!("\n[ready] All listeners active.\n");

    // Keep the main task alive forever
    std::future::pending::<()>().await;
}
