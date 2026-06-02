use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::Infallible;
use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::AppState;
use crate::providers::utiles::generate_chat_id;
use crate::providers::nearai::call_near_ai;

// ── Strict Schemas ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOptions {
    pub include_usage: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Value>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,

    #[serde(default)]
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>, 

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<Value>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,

    #[serde(skip_serializing, default)]
    pub provider: Option<Vec<String>>,
    #[serde(skip_serializing, default)]
    pub preference: Option<String>,
    #[serde(skip_serializing, default)]
    pub zdr: Option<bool>,
    #[serde(skip_serializing, default)]
    pub zds: Option<bool>,
    #[serde(skip_serializing, default)]
    pub tee: Option<bool>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn json_error(status: StatusCode, msg: &str) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let body = serde_json::json!({
        "error": {
            "message": msg,
            "type": "invalid_request_error",
            "param": null,
            "code": null
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    (
        status,
        vec![("Content-Type", "application/json".to_string())],
        Full::new(Bytes::from(body_bytes)).map_err(|e| match e {}).boxed(),
    )
}

// ── Public Router Handler ─────────────────────────────────────────────────────

pub async fn handle_secure_openai_proxy(
    state: &AppState,
    req: &crate::IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    // 1. Enforce Auth
    let auth_header = req.headers.get("authorization").cloned().unwrap_or_default();
    if !auth_header.starts_with("Bearer ") {
        return json_error(StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header");
    }

    // 2. Parse request body
    let request_body_val = Zeroizing::new(req.body.to_vec());
    let proxy_req: ChatCompletionRequest = match serde_json::from_slice(&*request_body_val) {
        Ok(r) => r,
        Err(e) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("Failed to parse request JSON: {}", e));
        }
    };
    drop(request_body_val);

    // 3. Resolve provider
    let model_name = proxy_req.model.to_lowercase();
    let is_streaming = proxy_req.stream;
    
    let provider_ids = match state.routing_table.read().await.get(&model_name).cloned() {
        Some(ids) => ids,
        None => {
            return json_error(StatusCode::BAD_REQUEST, &format!("Unsupported model: {}", model_name));
        }
    };

    let mut available_providers: Vec<std::sync::Arc<crate::ProviderConfig>> = provider_ids
        .iter()
        .filter_map(|id| state.providers.get(id).cloned())
        .collect();

    // Filtering
    if let Some(true) = proxy_req.zdr { available_providers.retain(|p| p.zdr); }
    if let Some(true) = proxy_req.zds { available_providers.retain(|p| p.zds); }
    if let Some(true) = proxy_req.tee { available_providers.retain(|p| p.tee); }

    if let Some(user_list) = &proxy_req.provider {
        let mut matched = Vec::new();
        for p_id in user_list {
            if p_id == "others" {
                let others: Vec<_> = available_providers.iter().filter(|p| !user_list.contains(&p.id)).cloned().collect();
                matched.extend(others);
            } else if let Some(p) = available_providers.iter().find(|p| &p.id == p_id) {
                matched.push(p.clone());
            } else {
                return json_error(StatusCode::BAD_REQUEST, &format!("Requested provider '{}' does not exist.", p_id));
            }
        }
        available_providers = matched;
    }

    if available_providers.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "No AI providers match your provider requirements.");
    }

    match proxy_req.preference.as_deref() {
        Some("privacy_rating") => available_providers.sort_by(|a, b| b.privacy_rating.cmp(&a.privacy_rating)),
        _ => {
            // Secure shuffle using FIPS-validated aws-lc-rs
            available_providers.sort_by_cached_key(|_| {
                let mut bytes = [0u8; 4];
                aws_lc_rs::rand::fill(&mut bytes).unwrap();
                u32::from_le_bytes(bytes)
            });
        }
    }

    let chat_id = generate_chat_id();
    let client_wants_usage = proxy_req.stream_options.as_ref().map_or(false, |o| o.include_usage);

    let mut last_error = String::from("All providers failed.");

    // ── Routing Execution ──
    for provider in available_providers {
        let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check if provider is currently heavily rate-limited/failing
        let is_unhealthy = {
            let dyn_state = provider.dynamic_state.read().await;
            let is_rate_limited = dyn_state.health.rate_limited_until.map_or(false, |timeout_ts| current_ts < timeout_ts);
            is_rate_limited || dyn_state.health.consecutive_errors >= 5
        };

        if is_unhealthy {
            continue;
        }

        // Dispatch based on provider ID
        let result = match provider.id.as_str() {
            "near-ai" => {
                call_near_ai(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone()).await
            }
            "chutes-ai" => {
                crate::providers::chutes::call_chutes_ai(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone()).await
            }
            _ => {
                Err(format!("Provider {} not implemented.", provider.id))
            }
        };

        match result {
            Ok(body) => {
                // Recover from previous errors
                let needs_reset = {
                    let dyn_state = provider.dynamic_state.read().await;
                    dyn_state.health.consecutive_errors > 0 || dyn_state.health.rate_limited_until.is_some()
                };

                if needs_reset {
                    let mut dyn_state = provider.dynamic_state.write().await;
                    dyn_state.health.consecutive_errors = 0;
                    dyn_state.health.rate_limited_until = None;
                }
                
                let headers = if is_streaming {
                    vec![
                        ("Content-Type", "text/event-stream".to_string()),
                        ("Cache-Control", "no-cache".to_string()),
                        ("Connection", "keep-alive".to_string()),
                    ]
                } else {
                    vec![
                        ("Content-Type", "application/json".to_string()),
                        ("Cache-Control", "no-cache".to_string()),
                    ]
                };
                return (StatusCode::OK, headers, body);
            }
            Err(e) => {
                let mut dyn_state = provider.dynamic_state.write().await;
                dyn_state.health.consecutive_errors += 1;
                let errors = dyn_state.health.consecutive_errors;
                let cooldown_minutes = std::cmp::min(errors * 5, 60); 
                let cooldown_seconds = (cooldown_minutes * 60) as u64;
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                dyn_state.health.rate_limited_until = Some(now + cooldown_seconds);

                last_error = format!("{} ({})", provider.id, e);
            }
        }
    }

    json_error(
        StatusCode::BAD_GATEWAY,
        &format!("All available AI providers failed to process the request. Last failure: {}", last_error)
    )
}
