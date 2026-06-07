use std::collections::HashMap;
use std::sync::Arc;
use serde_json::Value;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;
use std::convert::Infallible;
use tinfoil::chat::CreateChatCompletionRequest;

use crate::{AppState, ProviderConfig};
use crate::routes::api::chat_completions::{ChatCompletionRequest};
use http_body_util::combinators::BoxBody;
use crate::utils::{sanitize_and_spoof_response, wrap_stream_with_timing_padding};

pub fn parse_models(data_array: &[Value]) -> HashMap<String, crate::DynamicModelInfo> {
    let mut models = HashMap::new();
    
    for model_val in data_array {
        let owned_by = model_val.get("owned_by").and_then(|v| v.as_str()).unwrap_or("");
        
        let has_tinfoil_provider = model_val.get("providers")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|p| p.as_str() == Some("tinfoil")))
            .unwrap_or(false);
            
        let is_text_model = if let Some(t) = model_val.get("type").and_then(|v| v.as_str()) {
            t == "chat" || t == "safety"
        } else if let Some(mods) = model_val.get("input_modalities").and_then(|v| v.as_array()) {
            mods.iter().any(|m| m.as_str() == Some("text"))
        } else {
            false
        };
        
        if is_text_model && (owned_by == "tinfoil" || has_tinfoil_provider)
            && let Some(id) = model_val.get("id").and_then(|v| v.as_str()) {
                let mut name = id.to_string();
                
                if name == "glm-5-1" {
                    name = "glm-5.1".to_string();
                } else if name == "gemma4-31b" {
                    name = "gemma-4-31b".to_string();
                } else if name == "kimi-k2-6" {
                    name = "kimi-k2.6".to_string();
                } else if name == "llama3-3-70b" {
                    name = "llama-3.3-70b-instruct".to_string();
                }
                
                let mut price_in = 0.0;
                let mut price_out = 0.0;
                if let Some(pricing) = model_val.get("pricing") {
                    if let Some(p_in) = pricing.get("inputTokenPricePer1M").and_then(|v| v.as_f64()) {
                        price_in = p_in;
                    } else if let Some(p_in) = pricing.get("input").and_then(|v| v.as_f64()) {
                        price_in = p_in;
                    }
                    
                    if let Some(p_out) = pricing.get("outputTokenPricePer1M").and_then(|v| v.as_f64()) {
                        price_out = p_out;
                    } else if let Some(p_out) = pricing.get("output").and_then(|v| v.as_f64()) {
                        price_out = p_out;
                    }
                }
                
                let ctx_len = model_val.get("context_length").and_then(|v| v.as_u64())
                    .or_else(|| model_val.get("context_window").and_then(|v| v.as_u64()))
                    .unwrap_or(8192);
                    
                let max_comp = model_val.get("max_output_length").and_then(|v| v.as_u64())
                    .or_else(|| model_val.get("top_provider").and_then(|tp| tp.get("max_completion_tokens").and_then(|v| v.as_u64())))
                    .unwrap_or(4096);
                
                models.insert(name.clone(), crate::DynamicModelInfo {
                    upstream_model_name: id.to_string(),
                    name,
                    price_input_1m: price_in,
                    price_output_1m: price_out,
                    context_length: ctx_len,
                    max_completion_tokens: max_comp,
                    supported_sampling_parameters: serde_json::json!(["temperature", "top_p", "max_tokens"]),
                    supported_features: serde_json::json!([]),
                    direct_endpoint: None,
                });
            }
    }
    models
}

pub async fn call_tinfoil(
    state: &AppState,
    provider: &Arc<ProviderConfig>,
    proxy_req: ChatCompletionRequest,
    chat_id: String,
    client_wants_usage: bool,
    frontend_requested_model: String,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
    pii_map_arc: std::sync::Arc<crate::utils::redaction::PiiMap>,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    
    let model_info = crate::utils::models::get_dynamic_model_info(provider, &frontend_requested_model).await?;

    let client = &state.tinfoil_client;

    let mut proxy_json = serde_json::to_value(&proxy_req).map_err(|e| e.to_string())?;
    proxy_json["model"] = Value::String(model_info.upstream_model_name.clone());
    
    if proxy_req.stream {
        proxy_json["stream_options"] = serde_json::json!({"include_usage": true});
    }

    let request: CreateChatCompletionRequest = serde_json::from_value(proxy_json)
        .map_err(|e| format!("Failed to build tinfoil request: {}", e))?;

    let provider_id = provider.id.clone();
    
    if proxy_req.stream {
        let mut raw_stream = client.chat().create_stream(request).await.map_err(|e| format!("Stream error: {}", e))?;
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        
        tokio::spawn(async move {
            while let Some(result) = raw_stream.next().await {
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        });
        
        let response_stream = async_stream::stream! {
            let mut total_input_tokens = 0.0;
            let mut total_output_tokens = 0.0;
            let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map_arc.clone());
            
            while let Some(result) = rx.recv().await {
                match result {
                    Ok(response) => {
                        let json = serde_json::to_value(response).unwrap();
                        let is_usage_chunk = json.get("usage").is_some() && 
                                            json.get("choices").and_then(|c| c.as_array()).is_none_or(|a| a.is_empty());
                                            
                        let sanitized_json = sanitize_and_spoof_response(
                            json, &chat_id, &frontend_requested_model, &provider_id,
                            model_info.price_input_1m, model_info.price_output_1m,
                            &mut total_input_tokens, &mut total_output_tokens,
                            None,
                            Some(&mut unredactor)
                        );
                        
                        if !is_usage_chunk || client_wants_usage {
                            let chunk = format!("data: {}\n\n", serde_json::to_string(&sanitized_json).unwrap());
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from(chunk)));
                        }
                    }
                    Err(e) => {
                        let err_json = serde_json::json!({
                            "error": {
                                "message": format!("Tinfoil stream error: {}", e),
                                "type": "service_unavailable",
                                "param": null,
                                "code": "provider_unavailable"
                            }
                        });
                        let chunk = format!("data: {}\n\n", serde_json::to_string(&err_json).unwrap());
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(chunk)));
                        break;
                    }
                }
            }
            yield Ok::<_, Infallible>(Frame::data(Bytes::from("data: [DONE]\n\n")));
        };
        
        let wrapped = wrap_stream_with_timing_padding(Box::pin(response_stream), e2ee_session);
        Ok(BodyExt::boxed(StreamBody::new(wrapped)))
    } else {
        let response = client.chat().create(request).await.map_err(|e| format!("Request failed: {}", e))?;
        let json_resp = serde_json::to_value(response).unwrap();
        
        let mut in_tok = 0.0;
        let mut out_tok = 0.0;
        let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
        let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map_arc.clone());
        
        let mut sanitized_json = sanitize_and_spoof_response(
            json_resp, &chat_id, &frontend_requested_model, &provider_id,
            model_info.price_input_1m, model_info.price_output_1m,
            &mut in_tok, &mut out_tok,
            ratchet.as_mut(),
            Some(&mut unredactor)
        );
        
        sanitized_json["pad"] = Value::String("".to_string());
        let base_json = serde_json::to_string(&sanitized_json).unwrap();
        let p = 1024 - (base_json.len() % 1024);
        let pad_str = "X".repeat(p);
        sanitized_json["pad"] = Value::String(pad_str);

        let body_bytes = serde_json::to_vec(&sanitized_json).unwrap();
        Ok(BodyExt::boxed(Full::new(Bytes::from(body_bytes)).map_err(|e| match e {})))
    }
}
