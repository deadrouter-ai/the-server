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
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod providers;
pub mod utils;
mod dns;
mod quic_h3;
mod connections;
mod routes;
mod currency;
pub mod crypto_e2ee;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod state;
pub use state::*;
pub use routes::{router, IncomingRequest};
use providers::fetch_and_update_prices;

#[tokio::main]
async fn main() {
    #[cfg(feature = "development")]
    let _ = dotenvy::dotenv();

    let is_dev = cfg!(feature = "development");
    
    let env_filter = if is_dev {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(env_filter)
        .init();

    if let Ok(hash) = std::env::var("LOADER_PAYLOAD_HASH") {
        tracing::info!("Payload measurement: {}", hash);
    }

    let is_dev = cfg!(feature = "development");
    let tls_port = if is_dev { 5443 } else { 443 };
    let http_port = if is_dev { 5001 } else { 80 };

    if is_dev {
        tracing::info!("Running in DEVELOPMENT mode.");
    }

    // ---- Shared state initialization ----
    let mut providers: HashMap<String, Arc<ProviderConfig>> = HashMap::new();
    let routing_table: HashMap<String, Vec<String>> = HashMap::new();

    // NearAI Provider
    let near_ai_key = if is_dev {
        std::env::var("NEAR_AI_KEY").unwrap_or_default()
    } else {
        tracing::warn!("Production mode active: API Keys defer to external system. Using empty placeholders.");
        String::new()
    };

    let near_ai = ProviderConfig {
        id: "near-ai".to_string(),
        name: "Near AI".to_string(),
        description: "A powerhouse for decentralized, zero-trust inference. Absolute cryptographically verifiable privacy combined with blazing-fast routing.".to_string(),
        legal_location: "US".to_string(),
        data_processing_location: "US".to_string(),
        location: "us".to_string(),
        endpoint: "https://cloud-api.near.ai/v1/chat/completions".to_string(),
        api_key: near_ai_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_near = Arc::new(near_ai);
    providers.insert(arc_near.id.clone(), arc_near.clone());

    // Chutes AI Provider
    let chutes_key = if is_dev {
        std::env::var("CHUTES_KEY").unwrap_or_default()
    } else {
        String::new()
    };

    let chutes_ai = ProviderConfig {
        id: "chutes".to_string(),
        name: "Chutes".to_string(),
        description: "Pioneers of E2EE payload routing. Chutes allows you to encrypt prompts directly to their hardware enclaves, blinding us completely.".to_string(),
        legal_location: "US".to_string(),
        data_processing_location: "US".to_string(),
        location: "us".to_string(),
        endpoint: "https://llm.chutes.ai/v1/chat/completions".to_string(),
        api_key: chutes_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };
    
    let arc_chutes = Arc::new(chutes_ai);
    providers.insert(arc_chutes.id.clone(), arc_chutes.clone());

    // RedPill AI Provider
    let redpill_key = if is_dev {
        std::env::var("REDPILL_AI_KEY").unwrap_or_default()
    } else {
        String::new()
    };

    let redpill_ai = ProviderConfig {
        id: "redpill".to_string(),
        name: "RedPill".to_string(),
        description: "A decentralized infrastructure layer routing prompts anonymously across diverse, hardened hardware pools with dynamic failovers.".to_string(),
        legal_location: "US".to_string(),
        data_processing_location: "US".to_string(),
        location: "us".to_string(),
        endpoint: "https://api.redpill.ai/v1/chat/completions".to_string(),
        api_key: redpill_key,
        privacy_rating: 4,
        zdr: true, zds: true, tee: true,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_redpill = Arc::new(redpill_ai);
    providers.insert(arc_redpill.id.clone(), arc_redpill.clone());

    // Infomaniak Provider
    let infomaniak_key = if is_dev {
        std::env::var("INFOMANIAK_KEY").unwrap_or_default()
    } else {
        String::new()
    };
    let infomaniak_product_id = std::env::var("INFOMANIAK_PRODUCT_ID").unwrap_or_default();

    let infomaniak_ai = ProviderConfig {
        id: "infomaniak".to_string(),
        name: "Infomaniak".to_string(),
        description: "The Swiss fortress. While they lack hardware-level TEEs, they operate under the strictest legal privacy frameworks on the planet.".to_string(),
        legal_location: "CH".to_string(),
        data_processing_location: "CH".to_string(),
        location: "ch".to_string(),
        endpoint: format!("https://api.infomaniak.com/2/ai/{}/openai/v1/chat/completions", infomaniak_product_id),
        api_key: infomaniak_key,
        privacy_rating: 4,
        zdr: true, zds: true, tee: false,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_infomaniak = Arc::new(infomaniak_ai);
    providers.insert(arc_infomaniak.id.clone(), arc_infomaniak.clone());

    // Tinfoil Provider
    let tinfoil_key = if is_dev {
        std::env::var("TINFOIL_API_KEY").unwrap_or_default()
    } else {
        String::new()
    };

    let tinfoil_ai = ProviderConfig {
        id: "tinfoil".to_string(),
        name: "Tinfoil".to_string(),
        description: "Privacy-first compute networks with attestation guarantees. Direct, shielded access to state-of-the-art models within AMD SEV enclaves.".to_string(),
        legal_location: "US".to_string(),
        data_processing_location: "US".to_string(),
        location: "us".to_string(),
        endpoint: "https://inference.tinfoil.sh/v1/chat/completions".to_string(),
        api_key: tinfoil_key,
        privacy_rating: 5,
        zdr: true, zds: true, tee: true,
        dynamic_state: tokio::sync::RwLock::new(ProviderDynamicState::default()),
    };

    let arc_tinfoil = Arc::new(tinfoil_ai);
    providers.insert(arc_tinfoil.id.clone(), arc_tinfoil.clone());

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
        .timeout(std::time::Duration::from_secs(45))
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
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .expect("Failed to build Global HTTP client");
    let ticket_secrets = Arc::new(tokio::sync::RwLock::new(crypto_e2ee::TicketSecrets::new()));
    let ticket_secrets_clone = ticket_secrets.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await; // 5 minutes
            let mut secrets = ticket_secrets_clone.write().await;
            secrets.rotate();
            tracing::info!("E2EE Ticket Master Secret rotated.");
        }
    });

    let tinfoil_client = match tinfoil::Client::new_default().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to initialize Tinfoil client securely: {}", e);
            // Fallback for dev if TINFOIL_API_KEY is not set or auth fails
            tinfoil::Client::new("", "", "").await.unwrap_or_else(|_| panic!("Failed to init fallback Tinfoil client"))
        }
    };

    let state = Arc::new(AppState::new(
        http_client,
        near_ai_client,
        tls_pins,
        observed_spki,
        providers,
        routing_table,
        ticket_secrets,
        tinfoil_client,
    ));

    // ---- Spawn Dynamic Pricing background update tasks ----
    for provider in state.providers.values() {
        let state_clone = state.clone();
        let provider_clone = provider.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = fetch_and_update_prices(&state_clone, &provider_clone).await {
                    tracing::warn!("Failed to dynamically update prices for provider '{}': {}", provider_clone.id, e);
                } else {
                    tracing::info!("Successfully updated dynamic prices for provider '{}'", provider_clone.id);
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
        tracing::info!("Onion service disabled in development mode.");
    }

    tracing::info!("All listeners active.");

    // Keep the main task alive forever
    std::future::pending::<()>().await;
}
