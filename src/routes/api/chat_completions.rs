use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::Infallible;
use std::io::Error as IoError;
use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::io::StreamReader;

use crate::{AppState, CachedModelKey, ModelConfig, ProviderConfig};
use crate::providers::nearai::{v2_encrypt, v2_decrypt, E2eeSession, gen_random_bytes};

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

fn generate_chat_id() -> String {
    let rand_bytes = gen_random_bytes::<16>();
    format!("chatcmpl-{}", hex::encode(rand_bytes))
}

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

fn sanitize_and_spoof_response(
    mut original: Value,
    chat_id: &str,
    requested_model: &str,
    provider_id: &str,
    price_input: f64,
    price_output: f64,
    total_input_tokens: &mut f64,
    total_output_tokens: &mut f64,
) -> Value {
    let mut new_root = serde_json::Map::new();

    if let Some(obj) = original.as_object_mut() {
        let allowed_root_fields = ["object", "created", "system_fingerprint"];
        for field in allowed_root_fields {
            if let Some(val) = obj.remove(field) {
                new_root.insert(field.to_string(), val);
            }
        }

        new_root.insert("id".to_string(), Value::String(chat_id.to_string()));
        new_root.insert("model".to_string(), Value::String(requested_model.to_string()));
        new_root.insert("provider".to_string(), Value::String(provider_id.to_string()));

        if let Some(Value::Array(choices)) = obj.remove("choices") {
            let mut new_choices = Vec::new();
            for mut choice in choices {
                if let Some(choice_obj) = choice.as_object_mut() {
                    let mut new_choice = serde_json::Map::new();
                    let allowed_choice_fields = ["index", "finish_reason", "logprobs"];
                    
                    for field in allowed_choice_fields {
                        if let Some(val) = choice_obj.remove(field) {
                            new_choice.insert(field.to_string(), val);
                        }
                    }

                    if let Some(Value::Object(mut msg_obj)) = choice_obj.remove("message") {
                        let mut clean_msg = serde_json::Map::new();
                        let reasoning_val = msg_obj.remove("reasoning").or_else(|| msg_obj.remove("reasoning_content"));
                        if let Some(r) = reasoning_val {
                            clean_msg.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_msg_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_msg_fields {
                            if let Some(val) = msg_obj.remove(field) {
                                clean_msg.insert(field.to_string(), val);
                            }
                        }
                        new_choice.insert("message".to_string(), Value::Object(clean_msg));
                    }

                    if let Some(Value::Object(mut delta_obj)) = choice_obj.remove("delta") {
                        let mut clean_delta = serde_json::Map::new();
                        let reasoning_val = delta_obj.remove("reasoning").or_else(|| delta_obj.remove("reasoning_content"));
                        if let Some(r) = reasoning_val {
                            clean_delta.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_delta_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_delta_fields {
                            if let Some(val) = delta_obj.remove(field) {
                                clean_delta.insert(field.to_string(), val);
                            }
                        }
                        new_choice.insert("delta".to_string(), Value::Object(clean_delta));
                    }

                    new_choices.push(Value::Object(new_choice));
                }
            }
            new_root.insert("choices".to_string(), Value::Array(new_choices));
        }

        if let Some(Value::Object(mut usage)) = obj.remove("usage") {
            let mut new_usage = serde_json::Map::new();
            let allowed_usage_fields = [
                "prompt_tokens", "completion_tokens", "total_tokens",
                "prompt_tokens_details", "completion_tokens_details"
            ];

            for field in allowed_usage_fields {
                if let Some(val) = usage.remove(field) {
                    new_usage.insert(field.to_string(), val);
                }
            }

            let prompt = new_usage.get("prompt_tokens").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let completion = new_usage.get("completion_tokens").and_then(|v| v.as_f64()).unwrap_or(0.0);
            
            *total_input_tokens = prompt;
            *total_output_tokens = completion;

            let custom_cost = (prompt / 1_000_000.0) * price_input + (completion / 1_000_000.0) * price_output;

            let rounded_cost = (custom_cost * 10_000_000_000.0).round() / 10_000_000_000.0;
            if let Some(num) = serde_json::Number::from_f64(rounded_cost) {
                new_usage.insert("cost".to_string(), Value::Number(num));
            } else {
                new_usage.insert("cost".to_string(), Value::Number(serde_json::Number::from(0)));
            }

            new_root.insert("usage".to_string(), Value::Object(new_usage));
        }
    }

    Value::Object(new_root)
}

// ── Stream & Response Processing ──────────────────────────────────────────────

async fn process_near_ai_response(
    resp: reqwest::Response,
    is_streaming: bool,
    client_wants_usage: bool,
    chat_id: String,
    requested_model: String,
    provider_id: String,
    price_input_1m: f64,
    price_output_1m: f64,
    client_secret: Zeroizing<[u8; 32]>,
    provider: Arc<ProviderConfig>,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if is_streaming {
        let stream_err_mapper = resp.bytes_stream().map(|res| res.map_err(|e| IoError::new(std::io::ErrorKind::Other, e)));
        let mut stream_reader = BufReader::new(StreamReader::new(stream_err_mapper));
        let provider_clone = provider.clone();

        let stream = async_stream::stream! {
            let mut line = String::new();
            let mut total_input_tokens = 0.0;
            let mut total_output_tokens = 0.0;

            loop {
                line.clear();
                match stream_reader.read_line(&mut line).await {
                    Ok(0) => {
                        mark_provider_healthy(&provider_clone).await;
                        break;
                    } 
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() { continue; }

                        let mut is_corrupt = false;
                        let mut error_msg = "Corrupt or invalid response from downstream provider.".to_string();

                        if trimmed.starts_with("data: ") {
                            let data_content = trimmed[6..].trim();
                            if data_content == "[DONE]" {
                                yield Ok::<_, Infallible>(Frame::data(Bytes::from("data: [DONE]\n\n")));
                                break;
                            } 
                            
                            match serde_json::from_str::<Value>(data_content) {
                                Ok(mut json) => {
                                    if json.get("error").is_some() {
                                        is_corrupt = true;
                                        if let Some(msg) = json.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                                            error_msg = msg.to_string();
                                        }
                                    } else {
                                        let is_usage_chunk = json.get("usage").is_some() && 
                                            json.get("choices").and_then(|c| c.as_array()).map_or(true, |a| a.is_empty());

                                        // --- Inline Decryption for Stream Chunks ---
                                        if let Some(choices) = json.get_mut("choices").and_then(|c| c.as_array_mut()) {
                                            for choice in choices.iter_mut() {
                                                if let Some(delta) = choice.get_mut("delta").and_then(|d| d.as_object_mut()) {
                                                    if let Some(enc_content) = delta.get("content").and_then(|v| v.as_str()) {
                                                        match v2_decrypt(enc_content, &client_secret) {
                                                            Ok(plain) => {
                                                                delta.insert("content".to_string(), Value::String(plain));
                                                            }
                                                            Err(e) => {
                                                                is_corrupt = true;
                                                                error_msg = format!("Failed to decrypt stream content: {}", e);
                                                            }
                                                        }
                                                    }
                                                    if let Some(enc_reasoning) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                                                        match v2_decrypt(enc_reasoning, &client_secret) {
                                                            Ok(plain) => {
                                                                delta.insert("reasoning_content".to_string(), Value::String(plain));
                                                            }
                                                            Err(e) => {
                                                                is_corrupt = true;
                                                                error_msg = format!("Failed to decrypt stream reasoning: {}", e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if !is_corrupt {
                                            let sanitized_json = sanitize_and_spoof_response(
                                                json, &chat_id, &requested_model, &provider_id,
                                                price_input_1m, price_output_1m, &mut total_input_tokens, &mut total_output_tokens
                                            );

                                            if !is_usage_chunk || client_wants_usage {
                                                let modified_chunk = format!("data: {}\n\n", serde_json::to_string(&sanitized_json).unwrap());
                                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(modified_chunk)));
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    is_corrupt = true;
                                    error_msg = format!("Corrupt JSON in stream: {}", e);
                                }
                            }
                        } else {
                            if trimmed.starts_with('{') {
                                if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
                                    if json.get("error").is_some() {
                                        is_corrupt = true;
                                        if let Some(msg) = json.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                                            error_msg = msg.to_string();
                                        }
                                    }
                                }
                            } else {
                                is_corrupt = true;
                                error_msg = format!("Invalid stream protocol line: {}", trimmed);
                            }
                        }

                        if is_corrupt {
                            mark_provider_unhealthy(&provider_clone, 30).await;
                            let err_json = serde_json::json!({
                                "error": {
                                    "message": format!("Downstream provider '{}' is temporarily unavailable. Error: {}", provider_clone.id, error_msg),
                                    "type": "service_unavailable",
                                    "param": null,
                                    "code": "provider_unavailable"
                                }
                            });
                            let err_chunk = format!("data: {}\n\n", serde_json::to_string(&err_json).unwrap());
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from(err_chunk)));
                            break;
                        }
                    }
                    Err(e) => {
                        mark_provider_unhealthy(&provider_clone, 30).await;
                        let err_json = serde_json::json!({
                            "error": {
                                "message": format!("Downstream provider '{}' is temporarily unavailable. Stream read error: {}", provider_clone.id, e),
                                "type": "service_unavailable",
                                "param": null,
                                "code": "provider_unavailable"
                            }
                        });
                        let err_chunk = format!("data: {}\n\n", serde_json::to_string(&err_json).unwrap());
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(err_chunk)));
                        break;
                    }
                }
            }
        };

        Ok(BodyExt::boxed(StreamBody::new(stream)))
            
    } else {
        match resp.json::<Value>().await {
            Ok(mut json_resp) => {
                if json_resp.get("error").is_some() {
                    let mut error_msg = "Upstream error response".to_string();
                    if let Some(msg) = json_resp.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
                        error_msg = msg.to_string();
                    }
                    return Err(error_msg);
                }

                if let Some(choices) = json_resp.get_mut("choices").and_then(|c| c.as_array_mut()) {
                    for choice in choices.iter_mut() {
                        if let Some(message) = choice.get_mut("message").and_then(|m| m.as_object_mut()) {
                            if let Some(enc_content) = message.get("content").and_then(|v| v.as_str()) {
                                if let Ok(plain) = v2_decrypt(enc_content, &client_secret) {
                                    message.insert("content".to_string(), Value::String(plain));
                                }
                            }
                            if let Some(enc_reasoning) = message.get("reasoning_content").and_then(|v| v.as_str()) {
                                if let Ok(plain) = v2_decrypt(enc_reasoning, &client_secret) {
                                    message.insert("reasoning_content".to_string(), Value::String(plain));
                                }
                            }
                        }
                    }
                }

                let mut in_tok = 0.0;
                let mut out_tok = 0.0;

                let sanitized_json = sanitize_and_spoof_response(
                    json_resp, &chat_id, &requested_model, &provider_id,
                    price_input_1m, price_output_1m, &mut in_tok, &mut out_tok
                );

                mark_provider_healthy(&provider).await;

                let body_bytes = serde_json::to_vec(&sanitized_json).unwrap();
                Ok(BodyExt::boxed(Full::new(Bytes::from(body_bytes)).map_err(|e| match e {})))
            }
            Err(e) => Err(format!("Failed to parse JSON response: {}", e))
        }
    }
}

async fn mark_provider_unhealthy(provider: &ProviderConfig, duration_secs: u64) {
    let mut state_write = provider.dynamic_state.write().await;
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    state_write.health.consecutive_errors += 1;
    state_write.health.rate_limited_until = Some(current_ts + duration_secs);
}

async fn mark_provider_healthy(provider: &ProviderConfig) {
    let mut state_write = provider.dynamic_state.write().await;
    if state_write.health.consecutive_errors > 0 || state_write.health.rate_limited_until.is_some() {
        state_write.health.consecutive_errors = 0;
        state_write.health.rate_limited_until = None;
    }
}

// ── Provider API Implementation ──────────────────────────────────────────────

async fn call_near_ai(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    model_info: &ModelConfig,
    mut proxy_req: ChatCompletionRequest,
    chat_id: String,
    client_wants_usage: bool,
    frontend_requested_model: String,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if proxy_req.stream { proxy_req.stream_options = Some(StreamOptions { include_usage: true }); }

    let direct_url = model_info.direct_endpoint.as_deref().unwrap_or("https://cloud-api.near.ai");
    let domain = direct_url.trim_start_matches("https://").trim_end_matches('/').to_string();

    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut cached_key_opt = None;

    {
        let state_read = provider.dynamic_state.read().await;
        if let Some(key_info) = state_read.cached_model_keys.get(&frontend_requested_model) {
            if current_ts < key_info.expires_at {
                cached_key_opt = Some(key_info.x25519_bytes);
            }
        }
    }

    let model_x25519_bytes = match cached_key_opt {
        Some(key) => key,
        None => {
            let (fetched_bytes, tls_fingerprint) = crate::providers::nearai::fetch_near_ai_model_key(
                &state.near_ai_client,
                &state.http_client,
                direct_url,
            ).await?;

            // Verify live SPKI matches attestation fingerprint
            {
                let observed = state.observed_spki.lock().unwrap();
                if let Some(live_spkis) = observed.get(&domain) {
                    if !live_spkis.contains(&tls_fingerprint) {
                        return Err(format!(
                            "TLS cert mismatch: live SPKIs ({:?}) do not contain attested fingerprint ({}).",
                            live_spkis, tls_fingerprint
                        ));
                    }
                }
            }

            {
                let mut pins_write = state.tls_pins.write().await;
                pins_write.entry(domain.clone()).or_default().insert(tls_fingerprint.clone());
            }
            
            let mut state_write = provider.dynamic_state.write().await;
            state_write.cached_model_keys.insert(frontend_requested_model.clone(), CachedModelKey {
                expires_at: current_ts + (60 * 60),
                x25519_bytes: fetched_bytes,
            });
            
            fetched_bytes
        }
    };

    // E2EE Encryption
    proxy_req.model = model_info.upstream_model_name.clone();
    let session = E2eeSession::new();
    
    // Encrypt sensitive content immediately
    for msg in proxy_req.messages.iter_mut() {
        let encrypted = v2_encrypt(msg.content.as_bytes(), &model_x25519_bytes)?;
        msg.content = encrypted;
    }
    
    let req_body = Zeroizing::new(serde_json::to_vec(&proxy_req).map_err(|e| e.to_string())?);

    let chat_url = format!("{}/v1/chat/completions", direct_url);
    
    let upstream_req = state.near_ai_client
        .post(&chat_url)
        .header("Authorization", format!("Bearer {}", provider.api_key))
        .header("Content-Type", "application/json")
        .header("X-Signing-Algo", "ed25519")
        .header("X-Client-Pub-Key", &session.client_pub_hex)
        .header("X-Encryption-Version", "2")
        .body(req_body.to_vec())
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    drop(req_body);

    if !upstream_req.status().is_success() {
        return Err(format!("{} - {}", upstream_req.status(), upstream_req.text().await.unwrap_or_default()));
    }

    process_near_ai_response(
        upstream_req,
        proxy_req.stream,
        client_wants_usage,
        chat_id,
        frontend_requested_model, 
        provider.id.clone(),
        model_info.price_input_1m,
        model_info.price_output_1m,
        session.x25519_secret,
        provider.clone(),
    ).await
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
    let model_name = proxy_req.model.clone();
    let is_streaming = proxy_req.stream;
    
    let provider_ids = match state.routing_table.get(&model_name) {
        Some(ids) => ids,
        None => {
            return json_error(StatusCode::BAD_REQUEST, &format!("Unsupported model: {}", model_name));
        }
    };

    let near_provider_id = "near-ai";
    if !provider_ids.contains(&near_provider_id.to_string()) {
        return json_error(StatusCode::BAD_REQUEST, &format!("Model {} not supported by Near AI", model_name));
    }

    let provider = match state.providers.get(near_provider_id) {
        Some(p) => p,
        None => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Near AI provider state not initialized");
        }
    };

    // Check if the provider is currently rate-limited/disabled
    {
        let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let state_read = provider.dynamic_state.read().await;
        if let Some(until) = state_read.health.rate_limited_until {
            if current_ts < until {
                return json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "Downstream provider '{}' is temporarily unavailable. Please try again in {} seconds.",
                        near_provider_id,
                        until - current_ts
                    ),
                );
            }
        }
    }

    let model_info = match provider.supported_models.get(&model_name) {
        Some(info) => info,
        None => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Model configuration missing for {}", model_name));
        }
    };

    let chat_id = generate_chat_id();
    let client_wants_usage = proxy_req.stream_options.as_ref().map_or(false, |o| o.include_usage);

    match call_near_ai(
        state,
        provider,
        model_info,
        proxy_req,
        chat_id,
        client_wants_usage,
        model_name.clone(),
    ).await {
        Ok(body) => {
            let headers = if is_streaming {
                vec![
                    ("Content-Type", "text/event-stream".to_string()),
                    ("Cache-Control", "no-cache".to_string()),
                    ("Connection", "keep-alive".to_string()),
                ]
            } else {
                vec![
                    ("Content-Type", "application/json".to_string()),
                ]
            };
            (StatusCode::OK, headers, body)
        }
        Err(err_msg) => {
            mark_provider_unhealthy(provider, 30).await;
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "Downstream provider '{}' is temporarily unavailable. Error: {}",
                    near_provider_id, err_msg
                ),
            )
        }
    }
}
