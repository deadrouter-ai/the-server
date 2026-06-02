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
use serde_json::Value;

mod providers;
mod dns;
mod quic_h3;
mod connections;
mod routes;
mod currency;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Holds Onion domain name and self-signed TLS certificates for Onion Services.
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

// ModelConfig has been removed in favor of dynamic parsing.

/// Cached attestation keys for a provider model.
///
/// This structure stores the Ed25519-derived X25519 key bytes used to 
/// construct a shared secret for End-to-End Encryption (E2EE). To prevent 
/// excessive attestation validation delays, keys are cached until `expires_at`.
#[derive(Debug, Clone)]
pub struct CachedModelKey {
    pub expires_at: u64,
    pub x25519_bytes: [u8; 32],
}

/// Health and status information for a downstream provider.
///
/// Tracks the error rate and timeout status of a provider. If `consecutive_errors` 
/// exceeds the threshold, `rate_limited_until` will be set, effectively isolating
/// the provider from the router loop until the penalty expires.
#[derive(Debug, Default)]
pub struct ProviderHealthState {
    pub consecutive_errors: u32,
    pub rate_limited_until: Option<u64>,
}

/// Represents dynamically fetched configuration for a specific AI model.
/// 
/// These properties are scraped dynamically from the provider's `/v1/models`
/// endpoint, allowing the enclave to adapt to newly added models automatically 
/// without needing hardcoded schema definitions.
#[derive(Debug, Clone)]
pub struct DynamicModelInfo {
    pub upstream_model_name: String,
    pub name: String,
    pub price_input_1m: f64,
    pub price_output_1m: f64,
    pub context_length: u64,
    pub max_completion_tokens: u64,
    pub supported_sampling_parameters: serde_json::Value,
    pub supported_features: serde_json::Value,
    pub direct_endpoint: Option<String>,
}

#[derive(Debug)]
pub struct ChutesState {
    pub chute_id_cache: std::collections::HashMap<String, (String, u64)>,
    pub verified_instances: std::collections::HashMap<String, u64>,
    pub nonce_pools: std::collections::HashMap<String, crate::providers::chutes::CachedChutesNonces>,
}

impl Default for ChutesState {
    fn default() -> Self {
        Self {
            chute_id_cache: std::collections::HashMap::new(),
            verified_instances: std::collections::HashMap::new(),
            nonce_pools: std::collections::HashMap::new(),
        }
    }
}

/// Represents the dynamic, mutable state of a provider.
#[derive(Debug)]
pub struct ProviderDynamicState {
    pub health: ProviderHealthState,
    pub cached_model_keys: std::collections::HashMap<String, CachedModelKey>,
    /// Maps a model name to its dynamically fetched pricing and context limits.
    pub dynamic_models: std::collections::HashMap<String, DynamicModelInfo>,
    pub chutes_e2ee: ChutesState,
}

impl Default for ProviderDynamicState {
    fn default() -> Self {
        Self {
            health: ProviderHealthState::default(),
            cached_model_keys: std::collections::HashMap::new(),
            dynamic_models: std::collections::HashMap::new(),
            chutes_e2ee: ChutesState::default(),
        }
    }
}

/// Core configuration for a single AI provider.
///
/// This structure holds the root connection details for downstream AI API vendors.
/// `privacy_rating`, `zdr`, `zds`, and `tee` allow future capability-based routing.
/// The `markup` field enables automatic dynamic pricing modifications.
#[derive(Debug)]
pub struct ProviderConfig {
    pub id: String,
    pub endpoint: String,
    pub api_key: String,
    pub privacy_rating: u8,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
    /// The markup percentage applied to this provider's model pricing (e.g. 5.0 for 5%).
    pub markup: f64,
    /// Thread-safe lock over mutable tracking structures like cached keys and models.
    pub dynamic_state: tokio::sync::RwLock<ProviderDynamicState>,
}

/// Global application state shared across all HTTP/QUIC/Tor request handlers.
pub struct AppState {
    pub onion_data: std::sync::RwLock<OnionData>,
    pub db_placeholder: String,
    pub started_at: std::time::Instant,

    pub http_client: reqwest::Client,
    pub near_ai_client: reqwest::Client,
    pub tls_pins: Arc<tokio::sync::RwLock<HashMap<String, std::collections::HashSet<String>>>>,
    pub observed_spki: Arc<std::sync::Mutex<HashMap<String, std::collections::HashSet<String>>>>,

    pub providers: HashMap<String, Arc<ProviderConfig>>,
    pub routing_table: tokio::sync::RwLock<HashMap<String, Vec<String>>>,
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
            routing_table: tokio::sync::RwLock::new(routing_table),
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

/// Helper function to create a hyper response body from a String.
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

        // ---- Models ----
        (Method::GET, "/v1/models") => {
            crate::routes::api::models::handle_models_list(state, &req.uri.to_string()).await
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

// ── Dynamic Pricing Jobs ─────────────────────────────────────────────────────

// Parsers moved to utiles.rs

/// Connects to a provider's models endpoint (derived from the chat completions endpoint),
/// retrieves upstream prices, and writes them to the provider's dynamic state.
async fn fetch_and_update_prices(state: &AppState, provider: &ProviderConfig) -> Result<(), String> {
    let client = &state.http_client;

    // Construct OpenAI compatible models URL from completion endpoint
    let models_url = provider.endpoint.replace("/chat/completions", "/models");

    let mut req = client.get(&models_url);
    if !provider.api_key.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", provider.api_key));
    }

    let resp = req.send().await.map_err(|e| format!("Request failed: {:?}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Unsuccessful status: {}", resp.status()));
    }

    let json: Value = resp.json().await.map_err(|e| format!("JSON parsing failed: {}", e))?;
    let data_array = json.get("data")
        .and_then(|d| d.as_array())
        .ok_or_else(|| "Missing 'data' array in /v1/models response".to_string())?;

    // Parse models via provider-specific parser
    let updated_models = if provider.id == "near-ai" {
        crate::providers::nearai::parse_models(client, data_array).await
    } else if provider.id == "chutes-ai" {
        crate::providers::chutes::parse_models(data_array)
    } else {
        // Fallback or other providers
        crate::providers::nearai::parse_models(client, data_array).await
    };

    // Apply retrieved pricing and models to dynamic state
    if !updated_models.is_empty() {
        let mut dynamic_state = provider.dynamic_state.write().await;
        let mut router_write = state.routing_table.write().await;

        for (model_name, info) in updated_models {
            dynamic_state.dynamic_models.insert(model_name.clone(), info);
            
            // Add provider to this model's routing list if not already there
            let providers_list = router_write.entry(model_name).or_insert_with(Vec::new);
            if !providers_list.contains(&provider.id) {
                providers_list.push(provider.id.clone());
            }
        }
    }

    Ok(())
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
    let routing_table: HashMap<String, Vec<String>> = HashMap::new();

    // NearAI Provider
    let near_ai_key = if is_dev {
        std::env::var("NEAR_AI_KEY").unwrap_or_default()
    } else {
        println!("[WARN] Production mode active: API Keys defer to external system. Using empty placeholders.");
        String::new()
    };

    let near_ai = ProviderConfig {
        id: "near-ai".to_string(),
        endpoint: "https://cloud-api.near.ai/v1/chat/completions".to_string(),
        api_key: near_ai_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        markup: 5.0, // Default 5% markup
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_near = Arc::new(near_ai);
    providers.insert(arc_near.id.clone(), arc_near.clone());

    // Chutes AI Provider
    let chutes_key = if is_dev {
        std::env::var("CHUTES_AI_KEY").unwrap_or_default()
    } else {
        String::new()
    };

    let chutes_ai = ProviderConfig {
        id: "chutes-ai".to_string(),
        endpoint: "https://llm.chutes.ai/v1/chat/completions".to_string(),
        api_key: chutes_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        markup: 5.0,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };
    
    let arc_chutes = Arc::new(chutes_ai);
    providers.insert(arc_chutes.id.clone(), arc_chutes.clone());

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

    // --- Global Configs ---

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

    // ---- Spawn Dynamic Pricing background update tasks ----
    for provider in state.providers.values() {
        let state_clone = state.clone();
        let provider_clone = provider.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = fetch_and_update_prices(&state_clone, &provider_clone).await {
                    println!("[WARN] Failed to dynamically update prices for provider '{}': {}", provider_clone.id, e);
                } else {
                    println!("[INFO] Successfully updated dynamic prices for provider '{}'", provider_clone.id);
                }
                // Check and update pricing hourly
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }

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
