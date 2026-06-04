use std::sync::Arc;
use std::collections::HashMap;

/// Holds Onion domain name and self-signed TLS certificates for Onion Services.
pub struct OnionData {
    pub onion_domain: String,
    pub onion_https_cert: String,
}

impl OnionData {
    pub fn new() -> Self {
        Self {
            onion_domain: String::new(),
            onion_https_cert: String::new(),
        }
    }
}

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

#[derive(Debug, Default)]
pub struct ChutesState {
    pub chute_id_cache: std::collections::HashMap<String, (String, u64)>,
    pub verified_instances: std::collections::HashMap<String, u64>,
    pub nonce_pools: std::collections::HashMap<String, crate::providers::chutes::CachedChutesNonces>,
}

/// Represents the dynamic, mutable state of a provider.
#[derive(Debug, Default)]
pub struct ProviderDynamicState {
    pub health: ProviderHealthState,
    pub cached_model_keys: std::collections::HashMap<String, CachedModelKey>,
    /// Maps a model name to its dynamically fetched pricing and context limits.
    pub dynamic_models: std::collections::HashMap<String, DynamicModelInfo>,
    pub chutes_e2ee: ChutesState,
}

/// Core configuration for a single AI provider.
///
/// This structure holds the root connection details for downstream AI API vendors.
/// `privacy_rating`, `zdr`, `zds`, and `tee` allow future capability-based routing.
/// The `markup` field enables automatic dynamic pricing modifications.
#[derive(Debug)]
pub struct ProviderConfig {
    pub id: String,
    pub location: String,
    pub endpoint: String,
    pub api_key: String,
    pub privacy_rating: u8,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
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
    pub ticket_secrets: Arc<tokio::sync::RwLock<crate::crypto_e2ee::TicketSecrets>>,
    pub tinfoil_client: tinfoil::Client,
}

impl AppState {
    pub fn new(
        http_client: reqwest::Client,
        near_ai_client: reqwest::Client,
        tls_pins: Arc<tokio::sync::RwLock<HashMap<String, std::collections::HashSet<String>>>>,
        observed_spki: Arc<std::sync::Mutex<HashMap<String, std::collections::HashSet<String>>>>,
        providers: HashMap<String, Arc<ProviderConfig>>,
        routing_table: HashMap<String, Vec<String>>,
        ticket_secrets: Arc<tokio::sync::RwLock<crate::crypto_e2ee::TicketSecrets>>,
        tinfoil_client: tinfoil::Client,
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
            ticket_secrets,
            tinfoil_client,
        }
    }
}
