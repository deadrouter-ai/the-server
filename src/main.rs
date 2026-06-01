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
//   • Self-signed ECDSA P-256 cert (runtime-generated via rcgen)
// ======================================================================

use std::sync::Arc;
use std::collections::HashMap;
use bytes::Bytes;
use hyper::{Method, Uri, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;

mod providers;
mod dns;
mod quic_h3;
mod connections;
mod routes;
mod time;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// AppState is defined below under Provider Configurations.

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

// ── Models and Provider Configurations ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub upstream_model_name: String,
    pub price_input_1m: f64,
    pub price_output_1m: f64,
    pub direct_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CachedModelKey {
    pub expires_at: u64,
    pub x25519_bytes: [u8; 32],
}

#[derive(Debug, Default)]
pub struct ProviderHealthState {
    pub consecutive_errors: u32,
    pub rate_limited_until: Option<u64>,
}

pub struct ProviderDynamicState {
    pub health: ProviderHealthState,
    pub cached_model_keys: HashMap<String, CachedModelKey>,
}

impl Default for ProviderDynamicState {
    fn default() -> Self {
        Self {
            health: ProviderHealthState::default(),
            cached_model_keys: HashMap::new(),
        }
    }
}

pub struct ProviderConfig {
    pub id: String,
    pub endpoint: String,
    pub api_key: String,
    pub privacy_rating: u8,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
    pub supported_models: HashMap<String, ModelConfig>,
    pub dynamic_state: tokio::sync::RwLock<ProviderDynamicState>,
}

pub struct AppState {
    pub onion_data: std::sync::RwLock<OnionData>,
    pub db_placeholder: String,
    pub started_at: std::time::Instant,

    pub http_client: reqwest::Client,
    pub near_ai_client: reqwest::Client,
    pub tls_pins: Arc<tokio::sync::RwLock<HashMap<String, std::collections::HashSet<String>>>>,
    pub observed_spki: Arc<std::sync::Mutex<HashMap<String, std::collections::HashSet<String>>>>,

    pub providers: HashMap<String, Arc<ProviderConfig>>,
    pub routing_table: HashMap<String, Vec<String>>,
}

impl AppState {
    fn new(
        http_client: reqwest::Client,
        near_ai_client: reqwest::Client,
        tls_pins: Arc<tokio::sync::RwLock<HashMap<String, std::collections::HashSet<String>>>>,
        observed_spki: Arc<std::sync::Mutex<HashMap<String, std::collections::HashSet<String>>>>,
        providers: HashMap<String, Arc<ProviderConfig>>,
        routing_table: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            onion_data: std::sync::RwLock::new(OnionData::new()),
            db_placeholder: String::from("(no database configured)"),
            started_at: std::time::Instant::now(),
            http_client,
            near_ai_client,
            tls_pins,
            observed_spki,
            providers,
            routing_table,
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
    pub headers: std::collections::HashMap<String, String>,
    pub body: Bytes,
}

fn full_body(chunk: String) -> BoxBody<Bytes, Infallible> {
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

        // ---- Chat Completions ----
        (Method::POST, "/v1/chat/completions") => {
            crate::routes::api::chat_completions::handle_secure_openai_proxy(state, req).await
        }

        // ---- Landing page ----
        (Method::GET, "/") => {
            let (status, headers, body) = crate::routes::handle_landing_page(state, req);
            (status, headers, full_body(body))
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
                full_body(body),
            )
        }

        // ---- Method not allowed ----
        (_, _) => {
            let body = format!("405 Method Not Allowed: {} {}\n", req.method, req.uri);
            (
                StatusCode::METHOD_NOT_ALLOWED,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                full_body(body),
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

    // ---- Shared state initialization ----
    let mut providers: HashMap<String, Arc<ProviderConfig>> = HashMap::new();
    let mut routing_table: HashMap<String, Vec<String>> = HashMap::new();

    // NearAI Provider
    let near_ai_key = if is_dev {
        std::env::var("NEAR_AI_KEY").unwrap_or_default()
    } else {
        println!("[WARN] Production mode active: API Keys defer to external system. Using empty placeholders.");
        String::new()
    };

    let mut near_models = HashMap::new();
    near_models.insert("glm-5.1".to_string(), ModelConfig { 
        upstream_model_name: "zai-org/GLM-5.1-FP8".to_string(), 
        price_input_1m: 1.0, 
        price_output_1m: 3.5,
        direct_endpoint: Some("https://glm-5-1.completions.near.ai".to_string()),
    });
    near_models.insert("qwen-3.5-122b-a10b".to_string(), ModelConfig { 
        upstream_model_name: "Qwen/Qwen3.5-122B-A10B".to_string(), 
        price_input_1m: 0.5, 
        price_output_1m: 3.5,
        direct_endpoint: Some("https://qwen35-122b.completions.near.ai".to_string()),
    });

    let near_ai = ProviderConfig {
        id: "near-ai".to_string(),
        endpoint: "https://cloud-api.near.ai/v1/chat/completions".to_string(),
        api_key: near_ai_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        supported_models: near_models,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_near = Arc::new(near_ai);
    providers.insert(arc_near.id.clone(), arc_near.clone());
    for model_name in arc_near.supported_models.keys() {
        routing_table.entry(model_name.clone()).or_default().push(arc_near.id.clone());
    }

    let strict_provider = Arc::new(connections::crypto::hardened_crypto_provider());

    let tls_pins = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let observed_spki = Arc::new(std::sync::Mutex::new(HashMap::new()));

    let verifier = Arc::new(providers::nearai::NearAiTlsVerifier { 
        pinned_spki_hashes: tls_pins.clone(),
        observed_spki: observed_spki.clone(),
    });

    let near_tls_config = rustls::ClientConfig::builder_with_provider(strict_provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])          
        .expect("Inconsistent cipher-suite/versions selected")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let custom_resolver = Arc::new(dns::CustomDnscryptResolver::new());

    let near_ai_client = reqwest::ClientBuilder::new()
        .use_preconfigured_tls(near_tls_config)
        .dns_resolver(custom_resolver.clone())
        .build()
        .expect("Failed to build Near AI reqwest client");

    // --- Global Congis ---

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let global_tls = rustls::ClientConfig::builder_with_provider(strict_provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])          
        .expect("Inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let http_client = reqwest::ClientBuilder::new()
        .use_preconfigured_tls(global_tls)
        .dns_resolver(custom_resolver)
        .build()
        .expect("Failed to build Global HTTP client");

    let state = Arc::new(AppState::new(
        http_client,
        near_ai_client,
        tls_pins,
        observed_spki,
        providers,
        routing_table,
    ));

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
