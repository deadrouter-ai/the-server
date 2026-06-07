use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::Infallible;
use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;
use base64ct::Encoding;

use crate::AppState;
use crate::utils::generate_chat_id;
use crate::providers::nearai::call_near_ai;

// ── Strict Schemas ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StreamOptions {
    pub include_usage: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_prompt: Option<bool>,

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
    let mut proxy_req: ChatCompletionRequest = match serde_json::from_slice(&request_body_val) {
        Ok(r) => r,
        Err(e) => {
            return json_error(StatusCode::BAD_REQUEST, &format!("Failed to parse request JSON: {}", e));
        }
    };
    drop(request_body_val);

    // Force privacy flags unconditionally for all proxy requests
    proxy_req.store = Some(false);
    proxy_req.cache_prompt = Some(false);

    // E2EE Decryption
    let e2ee_enabled = req.headers.get("x-e2ee-enabled").map(|s| s.as_str()) == Some("true");

    let toggles_aad = {
        let mut s = String::new();
        if let Some(zdr) = proxy_req.zdr { s.push_str(&format!("zdr={};", zdr)); }
        if let Some(zds) = proxy_req.zds { s.push_str(&format!("zds={};", zds)); }
        if let Some(tee) = proxy_req.tee { s.push_str(&format!("tee={};", tee)); }
        s
    };

    if e2ee_enabled {
        if proxy_req.zdr.is_none() { proxy_req.zdr = Some(true); }
        if proxy_req.zds.is_none() { proxy_req.zds = Some(true); }
        if proxy_req.tee.is_none() { proxy_req.tee = Some(true); }
    }

    let mut e2ee_session: Option<crate::crypto_e2ee::E2eeSession> = None;
    if let Some(kx_algo) = req.headers.get("x-kx-algo")
        && kx_algo == "X25519"
            && let (Some(client_pub_b64), Some(server_ticket)) = (req.headers.get("x-client-pub-key"), req.headers.get("x-server-ticket")) {
                let ticket_secrets = state.ticket_secrets.read().await;
                if let Ok(server_static) = crate::crypto_e2ee::decrypt_ticket(&ticket_secrets, server_ticket) {
                    if let Ok(client_pub_bytes) = base64ct::Base64::decode_vec(client_pub_b64)
                        && client_pub_bytes.len() == 32 {
                            let mut pub_arr = [0u8; 32];
                            pub_arr.copy_from_slice(&client_pub_bytes);
                            
                            let session = crate::crypto_e2ee::E2eeSession::new(server_static, &pub_arr, proxy_req.model.clone());
                            
                            // Decrypt messages
                            let mut all_decrypted = true;
                            for (i, msg) in proxy_req.messages.iter_mut().enumerate() {
                                match session.decrypt_message(i, &msg.role, &msg.content, &toggles_aad) {
                                    Ok(plaintext) => {
                                        msg.content = plaintext;
                                    }
                                    Err(_) => {
                                        all_decrypted = false;
                                        break;
                                    }
                                }
                            }
                            
                            if all_decrypted {
                                e2ee_session = Some(session);
                            } else {
                                return json_error(StatusCode::BAD_REQUEST, "E2EE Decryption of messages failed.");
                            }
                        }
                } else {
                    return json_error(StatusCode::UNAUTHORIZED, "E2EE Ticket expired or invalid.");
                }
            }
    
    if e2ee_enabled && e2ee_session.is_none() {
        return json_error(StatusCode::BAD_REQUEST, "E2EE is strictly enforced but decryption or key exchange failed/was not provided.");
    }

    // 3. Resolve provider
    let mut nearai_passthrough_pubkey: Option<String> = None;
    if req.headers.get("x-nearai-e2ee-enabled").map(|s| s.as_str()) == Some("true") {
        if let Some(pubkey) = req.headers.get("x-nearai-client-pub-key") {
            nearai_passthrough_pubkey = Some(pubkey.to_string());
        } else {
            return json_error(StatusCode::BAD_REQUEST, "X-NearAI-E2EE-Enabled is true but X-NearAI-Client-Pub-Key is missing");
        }
    }

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

    // When client uses Near AI direct E2EE, only near-ai can handle the encrypted payload
    if nearai_passthrough_pubkey.is_some() {
        available_providers.retain(|p| p.id == "near-ai");
        if available_providers.is_empty() {
            return json_error(StatusCode::BAD_REQUEST, "X-NearAI-E2EE-Enabled requires a model supported by the 'near-ai' provider.");
        }
    }

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
        Some("privacy_rating") => available_providers.sort_by_key(|b| std::cmp::Reverse(b.privacy_rating)),
        None if proxy_req.provider.is_some() => {
            // Keep the explicitly requested provider order
        }
        _ => {
            // Shuffle models if the user did not specify a provider order
            available_providers.sort_by_cached_key(|_| {
                let mut bytes = [0u8; 4];
                aws_lc_rs::rand::fill(&mut bytes).unwrap();
                u32::from_le_bytes(bytes)
            });
        }
    }

    let chat_id = generate_chat_id();
    let client_wants_usage = proxy_req.stream_options.as_ref().is_some_and(|o| o.include_usage);

    let mut last_error = String::from("All providers failed.");

    let e2ee_session = e2ee_session.map(std::sync::Arc::new);
    // ── Routing Execution ──
    for provider in available_providers {
        let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check if provider is currently heavily rate-limited/failing
        let is_unhealthy = {
            let dyn_state = provider.dynamic_state.read().await;
            dyn_state.health.rate_limited_until.is_some_and(|timeout_ts| current_ts < timeout_ts)
        };

        if is_unhealthy {
            continue;
        }

        // Dispatch based on provider ID
        let result = match provider.id.as_str() {
            "near-ai" => {
                call_near_ai(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone(), e2ee_session.clone(), nearai_passthrough_pubkey.clone()).await
            }
            "chutes" => {
                crate::providers::chutes::call_chutes_ai(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone(), e2ee_session.clone()).await
            }
            "redpill" => {
                crate::providers::redpill::call_redpill_ai(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone(), e2ee_session.clone()).await
            }
            "infomaniak" => {
                crate::providers::infomaniak::call_infomaniak(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone(), e2ee_session.clone()).await
            }
            "tinfoil" => {
                crate::providers::tinfoil::call_tinfoil(state, &provider, proxy_req.clone(), chat_id.clone(), client_wants_usage, model_name.clone(), e2ee_session.clone()).await
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
                tracing::error!("Provider '{}' failed: {}", provider.id, e);
                
                let mut dyn_state = provider.dynamic_state.write().await;
                
                // Parse standard HTTP status codes or hints from the error string
                let is_400 = e.contains(" 400 ") || e.contains("400 Bad Request");
                let is_429 = e.contains(" 429 ") || e.contains("429 Too Many Requests");
                
                if is_400 {
                    // User error (e.g. invalid prompt). Do NOT rate limit provider.
                    dyn_state.health.consecutive_errors = 0;
                    dyn_state.health.rate_limited_until = None;
                } else if is_429 {
                    dyn_state.health.consecutive_errors += 1;
                    let errors = dyn_state.health.consecutive_errors;
                    
                    // Attempt to extract Retry-After if appended by provider logic
                    let mut cooldown_seconds = None;
                    if let Some(idx) = e.find("Retry-After: ") {
                        let sub = &e[idx + 13..];
                        if let Some(end_idx) = sub.find(']')
                            && let Ok(secs) = sub[..end_idx].trim().parse::<u64>() {
                                cooldown_seconds = Some(secs);
                            }
                    }
                    
                    let cooldown = cooldown_seconds.unwrap_or_else(|| {
                        // 1 minute backoff, up to 15 minutes max
                        std::cmp::min(errors, 15) as u64 * 60
                    });
                    
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    dyn_state.health.rate_limited_until = Some(now + cooldown);
                } else {
                    // Strange error (404, 500, network error) that user cannot simulate easily
                    dyn_state.health.consecutive_errors += 1;
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    // Exactly 30 seconds cooldown
                    dyn_state.health.rate_limited_until = Some(now + 30);
                }

                // Only store a generic failure message to avoid exposing sensitive data to the user
                let status_code = if is_400 { "400" } else if is_429 { "429" } else { "Unknown/500" };
                last_error = format!("Provider '{}' encountered an internal or upstream error ({})", provider.id, status_code);
            }
        }
    }

    tracing::warn!("All available providers failed for chat {}", chat_id);
    json_error(
        StatusCode::BAD_GATEWAY,
        &format!("All available AI providers failed to process the request. Last failure: {}", last_error)
    )
}
