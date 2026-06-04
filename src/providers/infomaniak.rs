use std::collections::HashMap;
use serde_json::Value;
use std::sync::Arc;
use std::convert::Infallible;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;

use crate::{AppState, ProviderConfig, DynamicModelInfo};
use crate::routes::api::chat_completions::ChatCompletionRequest;
use crate::providers::utiles::sanitize_and_spoof_response;

pub fn parse_models(data_array: &[Value]) -> HashMap<String, DynamicModelInfo> {
    let mut models = HashMap::new();

    for model_val in data_array {
        // Filter out non-LLM models
        let type_str = model_val.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if type_str != "llm" {
            continue;
        }

        let upstream_id = match model_val.get("name").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => continue,
        };

        // Standardize frontend name
        let mut frontend_name = match upstream_id.find('/') {
            Some(idx) => &upstream_id[idx + 1..],
            None => &upstream_id,
        }.to_lowercase();

        // Strip quantization/format suffixes
        let suffixes_to_strip = ["-fp8", "-fp16", "-awq", "-gptq", "-int8", "-int4", "-gguf"];
        for suffix in suffixes_to_strip {
            if frontend_name.ends_with(suffix) {
                frontend_name = frontend_name.strip_suffix(suffix).unwrap().to_string();
            }
        }

        // Extract prices (we need to handle the unit)
        // Infomaniak has 'prices' array
        let mut p_in = 0.0;
        let mut p_out = 0.0;
        if let Some(prices) = model_val.get("prices").and_then(|v| v.as_array()) {
            for price_val in prices {
                // only consider USD/EUR/CHF, whatever the first is.
                let currency_id = price_val.get("currency_id").and_then(|v| v.as_u64()).unwrap_or(1);
                if currency_id == 1 { // Use CHF (1) or EUR (2) - we'll just use the first matching one
                    let input_amount = price_val.get("input_amount_excl_vat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let output_amount = price_val.get("output_amount_excl_vat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let unit_amount = price_val.get("unit").and_then(|v| v.get("amount")).and_then(|v| v.as_f64()).unwrap_or(10000.0);
                    
                    // Convert to per 1 million tokens
                    p_in = (input_amount / unit_amount) * 1_000_000.0;
                    p_out = (output_amount / unit_amount) * 1_000_000.0;
                    break;
                }
            }
        }

        let ctx_len = model_val.get("max_token_input").and_then(|v| v.as_u64()).unwrap_or(8192);
        // max completion length not strictly provided, default to 4096
        let max_comp = 4096;

        models.insert(frontend_name.clone(), DynamicModelInfo {
            upstream_model_name: upstream_id,
            name: frontend_name.clone(),
            price_input_1m: p_in,
            price_output_1m: p_out,
            context_length: ctx_len,
            max_completion_tokens: max_comp,
            supported_sampling_parameters: Value::Null,
            supported_features: Value::Null,
            direct_endpoint: None,
        });
    }

    models
}

pub async fn call_infomaniak(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    mut proxy_req: ChatCompletionRequest,
    chat_id: String,
    _client_wants_usage: bool,
    frontend_requested_model: String,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
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
        let status = resp.status();
        let mut body_text = resp.text().await.unwrap_or_default();
        if body_text.len() > 150 {
            body_text.truncate(147);
            body_text.push_str("...");
        }
        let cleaned_body = body_text.replace("\r", "").replace("\n", " ");
        return Err(format!("Upstream error: {} - {}", status, cleaned_body));
    }

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
                                        price_input, price_output,
                                        &mut total_in, &mut total_out,
                                        None
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
        Ok(BodyExt::boxed(StreamBody::new(crate::providers::utiles::wrap_stream_with_timing_padding(Box::pin(mapped_stream), e2ee_session))))
    } else {
        let body_bytes = resp.bytes().await.map_err(|e| format!("Failed to read body: {}", e))?;
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
             let mut total_in = 0.0;
             let mut total_out = 0.0;
             let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
             let sanitized = sanitize_and_spoof_response(
                 json, &chat_id, &frontend_requested_model, &provider_id,
                 price_input, price_output,
                 &mut total_in, &mut total_out,
                 ratchet.as_mut()
             );
             let new_body = serde_json::to_vec(&sanitized).unwrap_or(body_bytes.to_vec());
             Ok(BodyExt::boxed(Full::new(Bytes::from(new_body)).map_err(|e| match e {})))
        } else {
             Ok(BodyExt::boxed(Full::new(body_bytes).map_err(|e| match e {})))
        }
    }
}
