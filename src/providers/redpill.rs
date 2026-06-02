use std::collections::HashMap;
use serde_json::Value;
use std::sync::Arc;
use std::convert::Infallible;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;

use crate::{AppState, ProviderConfig};
use crate::routes::api::chat_completions::ChatCompletionRequest;
use crate::providers::utiles::sanitize_and_spoof_response;
use crate::DynamicModelInfo;

pub fn parse_models(data_array: &[Value]) -> HashMap<String, DynamicModelInfo> {
    let mut models: HashMap<String, DynamicModelInfo> = HashMap::new();
    let allowed_providers = ["chutes", "near-ai", "secretai", "tinfoil", "phala"];

    for model_val in data_array {
        // Strict Provider filtering
        let providers_arr = match model_val.get("providers").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => arr,
            _ => continue, // Ignore models with empty or missing providers
        };

        let mut all_valid = true;
        for p_val in providers_arr {
            let p_str = p_val.as_str().unwrap_or("");
            if !allowed_providers.contains(&p_str) {
                all_valid = false;
                break;
            }
        }

        if !all_valid {
            continue;
        }

        let upstream_id = match model_val.get("id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => continue,
        };

        // Standardize base model ID prefix deduplication
        let frontend_name = match upstream_id.find('/') {
            Some(idx) => &upstream_id[idx + 1..],
            None => &upstream_id,
        }.to_lowercase();

        let (p_in, p_out) = crate::providers::utiles::parse_model_price(model_val).unwrap_or((0.0, 0.0));
        let cost = p_in + p_out;

        // Deduplication based on max cost
        if let Some(existing) = models.get(&frontend_name) {
            let existing_cost = existing.price_input_1m + existing.price_output_1m;
            if cost <= existing_cost {
                continue; // Keep the existing, more expensive model
            }
        }

        let ctx_len = model_val.get("context_length").and_then(|v| v.as_u64()).unwrap_or(0);
        let max_comp = model_val.get("max_output_length").and_then(|v| v.as_u64()).unwrap_or(0);

        let sampling = model_val.get("supported_parameters").cloned().unwrap_or(Value::Null);

        models.insert(frontend_name.clone(), DynamicModelInfo {
            upstream_model_name: upstream_id,
            name: model_val.get("name").and_then(|v| v.as_str()).unwrap_or(&frontend_name).to_string(),
            price_input_1m: p_in,
            price_output_1m: p_out,
            context_length: ctx_len,
            max_completion_tokens: max_comp,
            supported_sampling_parameters: sampling,
            supported_features: Value::Null,
            direct_endpoint: None,
        });
    }

    models
}

pub async fn call_redpill_ai(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    mut proxy_req: ChatCompletionRequest,
    chat_id: String,
    _client_wants_usage: bool,
    frontend_requested_model: String,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if proxy_req.stream { proxy_req.stream_options = Some(crate::routes::api::chat_completions::StreamOptions { include_usage: true }); }

    let (upstream_model_name, price_input, price_output) = {
        let state_read = provider.dynamic_state.read().await;
        if let Some(info) = state_read.dynamic_models.get(&frontend_requested_model) {
            (info.upstream_model_name.clone(), info.price_input_1m, info.price_output_1m)
        } else {
            return Err(format!("Model {} not dynamically configured", frontend_requested_model));
        }
    };

    proxy_req.model = upstream_model_name;
    let payload = serde_json::to_vec(&proxy_req).map_err(|e| format!("Serialization error: {}", e))?;

    let req = state.http_client.post(&provider.endpoint)
        .header("Authorization", format!("Bearer {}", provider.api_key))
        .header("Content-Type", "application/json")
        .body(payload);

    let resp = req.send().await.map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Upstream error: {} - {}", resp.status(), resp.text().await.unwrap_or_default()));
    }

    let markup = provider.markup;
    let provider_id = provider.id.clone();
    
    if proxy_req.stream {
        let mut stream = resp.bytes_stream();
        let mapped_stream = async_stream::stream! {
            let mut total_in = 0.0;
            let mut total_out = 0.0;
            
            while let Some(chunk_res) = stream.next().await {
                match chunk_res {
                    Ok(chunk) => {
                        let text = String::from_utf8_lossy(&chunk);
                        let mut final_out = String::new();

                        for line in text.lines() {
                            if line.starts_with("data: ") {
                                let data_str = line.trim_start_matches("data: ").trim();
                                if data_str == "[DONE]" {
                                    final_out.push_str("data: [DONE]\n\n");
                                    continue;
                                }

                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data_str) {
                                    let sanitized = sanitize_and_spoof_response(
                                        json, &chat_id, &frontend_requested_model, &provider_id,
                                        price_input, price_output, markup,
                                        &mut total_in, &mut total_out
                                    );
                                    let new_line = serde_json::to_string(&sanitized).unwrap_or_default();
                                    final_out.push_str(&format!("data: {}\n\n", new_line));
                                } else {
                                    final_out.push_str(&format!("data: {}\n\n", data_str));
                                }
                            } else {
                                final_out.push_str(&format!("{}\n", line));
                            }
                        }
                        if !final_out.is_empty() {
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from(final_out)));
                        }
                    }
                    Err(_) => break,
                }
            }
        };
        Ok(BodyExt::boxed(StreamBody::new(mapped_stream)))
    } else {
        let body_bytes = resp.bytes().await.map_err(|e| format!("Failed to read body: {}", e))?;
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
             let mut total_in = 0.0;
             let mut total_out = 0.0;
             let sanitized = sanitize_and_spoof_response(
                 json, &chat_id, &frontend_requested_model, &provider_id,
                 price_input, price_output, markup,
                 &mut total_in, &mut total_out
             );
             let new_body = serde_json::to_vec(&sanitized).unwrap_or(body_bytes.to_vec());
             Ok(BodyExt::boxed(Full::new(Bytes::from(new_body)).map_err(|e| match e {})))
        } else {
             Ok(BodyExt::boxed(Full::new(body_bytes).map_err(|e| match e {})))
        }
    }
}
