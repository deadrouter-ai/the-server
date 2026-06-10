use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::Infallible;
use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use futures::StreamExt;
use serde_json::Value;

use crate::AppState;

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

pub async fn handle_tinfoil_chat_completions(
    state: &AppState,
    req: &crate::IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    // 1. Check if Tinfoil provider exists
    let tinfoil_provider = match state.providers.get("tinfoil") {
        Some(p) => p,
        None => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Tinfoil provider is not configured."),
    };

    // 2. Provider Health Check
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let is_unhealthy = {
        let dyn_state = tinfoil_provider.dynamic_state.read().await;
        dyn_state.health.rate_limited_until.is_some_and(|timeout_ts| current_ts < timeout_ts)
    };
    if is_unhealthy {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "Tinfoil provider is currently rate-limited or unhealthy.");
    }

    // 3. Get API key from config
    let api_key = &tinfoil_provider.api_key;
    if api_key.is_empty() {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Tinfoil API key is missing.");
    }

    // 4. Extract the encrypted EHBP body
    let encrypted_body = req.body.clone();

    // 5. Get the Tinfoil HTTP client
    let reqwest_client = match state.tinfoil_client.http_client() {
        Ok(c) => c,
        Err(e) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, &format!("Tinfoil client not ready: {}", e)),
    };
    
    let base_url = state.tinfoil_client.secure_client().base_url();
    let target_url = format!("{}/v1/chat/completions", base_url);

    // 6. Extract headers from the proxy request to forward
    let mut request_builder = reqwest_client.post(&target_url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", req.headers.get("content-type").map(|s| s.as_str()).unwrap_or("application/json"));

    if let Some(accept) = req.headers.get("accept") {
        request_builder = request_builder.header("Accept", accept);
    }
    
    // Forward strictly allowed EHBP headers
    for (k, v) in req.headers.iter() {
        let key_str = k.as_str();
        if key_str == "ehbp-encapsulated-key" || key_str == "ehbp-response-nonce" {
            tracing::info!("Forwarding EHBP request header: {} = {:?}", key_str, v);
            request_builder = request_builder.header(k, v);
        }
    }

    // 7. Forward the encrypted body
    let reqwest_req = request_builder.body(reqwest::Body::from(encrypted_body)).build().unwrap();

    let resp_result = reqwest_client.execute(reqwest_req).await;
    
    let resp = match resp_result {
        Ok(r) => r,
        Err(e) => {
            let e_str = e.to_string();
            let mut dyn_state = tinfoil_provider.dynamic_state.write().await;
            dyn_state.health.consecutive_errors += 1;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dyn_state.health.rate_limited_until = Some(now + 30);
            return json_error(StatusCode::BAD_GATEWAY, &format!("Upstream Tinfoil error: {}", e_str));
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let err_body = resp.text().await.unwrap_or_default();
        let e_str = format!("Upstream Tinfoil returned error: {}", err_body);
        let mut dyn_state = tinfoil_provider.dynamic_state.write().await;
        
        let is_400 = status.as_u16() == 400 || err_body.contains(" 400 ") || err_body.contains("400 Bad Request");
        let is_429 = status.as_u16() == 429 || err_body.contains(" 429 ") || err_body.contains("429 Too Many Requests");
        
        if is_400 {
            dyn_state.health.consecutive_errors = 0;
            dyn_state.health.rate_limited_until = None;
        } else if is_429 {
            dyn_state.health.consecutive_errors += 1;
            let errors = dyn_state.health.consecutive_errors;
            
            let mut cooldown_seconds = None;
            if let Some(idx) = err_body.find("Retry-After: ") {
                let sub = &err_body[idx + 13..];
                if let Some(end_idx) = sub.find(']') {
                    if let Ok(secs) = sub[..end_idx].trim().parse::<u64>() {
                        cooldown_seconds = Some(secs);
                    }
                }
            }
            
            let cooldown = cooldown_seconds.unwrap_or_else(|| {
                std::cmp::min(errors, 15) as u64 * 60
            });
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dyn_state.health.rate_limited_until = Some(now + cooldown);
        } else {
            dyn_state.health.consecutive_errors += 1;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            dyn_state.health.rate_limited_until = Some(now + 30);
        }
        
        return json_error(StatusCode::from_u16(status.as_u16()).unwrap(), &e_str);
    }

    // Success - reset errors
    {
        let needs_reset = {
            let dyn_state = tinfoil_provider.dynamic_state.read().await;
            dyn_state.health.consecutive_errors > 0 || dyn_state.health.rate_limited_until.is_some()
        };
        if needs_reset {
            let mut dyn_state = tinfoil_provider.dynamic_state.write().await;
            dyn_state.health.consecutive_errors = 0;
            dyn_state.health.rate_limited_until = None;
        }
    }

    let content_type = resp.headers().get("content-type")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("");
        
    let is_streaming = content_type.starts_with("text/event-stream");
    let provider_id = tinfoil_provider.id.clone();
    let tinfoil_provider_arc = std::sync::Arc::clone(tinfoil_provider);
    let chat_id = crate::utils::response::generate_chat_id();
    
    // We don't have the user request to check x-redaction since this is EHBP, but we enable by default
    let pii_map = crate::utils::redaction::PiiMap::new();
    let pii_map_arc = std::sync::Arc::new(pii_map);
    
    if !is_streaming {
        let mut headers = vec![
            ("Content-Type", "application/json".to_string()),
        ];
        
        for (k, v) in resp.headers().iter() {
            tracing::info!("TINFOIL RAW HEADER: {} = {:?}", k.as_str(), v);
            if let Ok(v_str) = v.to_str() {
                let key_str = k.as_str();
                if key_str == "ehbp-encapsulated-key" || key_str == "ehbp-response-nonce" {
                    tracing::info!("Returning EHBP response header: {} = {}", key_str, v_str);
                    headers.push((Box::leak(key_str.to_string().into_boxed_str()), v_str.to_string()));
                }
            }
        }
        
        let body_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read response bytes"),
        };
        
        if let Ok(val) = serde_json::from_slice::<Value>(&body_bytes) {
            let mut detected_model = "tinfoil-unknown".to_string();
            let mut price_in = 0.0;
            let mut price_out = 0.0;
            let mut in_tok = 0.0;
            let mut out_tok = 0.0;
            let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map_arc.clone());
            
            if let Some(m) = val.get("model").and_then(|v| v.as_str()) {
                detected_model = m.to_string();
                if let Ok(info) = crate::utils::models::get_dynamic_model_info(&tinfoil_provider_arc, &detected_model).await {
                    price_in = info.price_input_1m;
                    price_out = info.price_output_1m;
                }
            }

            let mut sanitized_json = crate::utils::sanitize_and_spoof_response(
                val, &chat_id, &detected_model, &provider_id,
                price_in, price_out,
                &mut in_tok, &mut out_tok,
                None,
                Some(&mut unredactor)
            );
            
            sanitized_json["pad"] = Value::String("".to_string());
            let base_json = serde_json::to_string(&sanitized_json).unwrap();
            let p = 1024 - (base_json.len() % 1024);
            let pad_str = "X".repeat(p);
            sanitized_json["pad"] = Value::String(pad_str);

            let new_body = serde_json::to_vec(&sanitized_json).unwrap();
            return (StatusCode::from_u16(status.as_u16()).unwrap(), headers, Full::new(Bytes::from(new_body)).map_err(|e| match e {}).boxed());
        } else {
            tracing::error!("FAILED to parse Tinfoil EHBP response as JSON. First 200 bytes: {:?}", String::from_utf8_lossy(&body_bytes).chars().take(200).collect::<String>());
            return (StatusCode::from_u16(status.as_u16()).unwrap(), headers, Full::new(body_bytes).map_err(|e| match e {}).boxed());
        }
    }

    // Streaming
    let mut headers = vec![
        ("Content-Type", "text/event-stream".to_string()),
        ("Cache-Control", "no-cache".to_string()),
        ("Connection", "keep-alive".to_string()),
    ];

    for (k, v) in resp.headers().iter() {
        if let Ok(v_str) = v.to_str() {
            let key_str = k.as_str();
            if key_str == "ehbp-encapsulated-key" || key_str == "ehbp-response-nonce" {
                headers.push((Box::leak(key_str.to_string().into_boxed_str()), v_str.to_string()));
            }
        }
    }

    let mut byte_stream = resp.bytes_stream();

    let mapped_stream = async_stream::stream! {
        let mut buffer = String::new();
        let mut detected_model = "tinfoil-unknown".to_string();
        let mut price_input = 0.0;
        let mut price_output = 0.0;
        let mut in_tok = 0.0;
        let mut out_tok = 0.0;
        let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map_arc.clone());
        
        while let Some(chunk_res) = byte_stream.next().await {
            match chunk_res {
                Ok(chunk) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    
                    while let Some(idx) = buffer.find('\n') {
                        let raw_line = buffer[..idx].to_string();
                        buffer = buffer[idx+1..].to_string();
                        let line = raw_line.trim_end_matches('\r').to_string();
                        
                        if line.is_empty() {
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from("\n")));
                            continue;
                        }
                        
                        if line.starts_with("data: ") {
                            if line.contains("[DONE]") {
                                let padded = crate::utils::pad_raw_sse(&line);
                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}\n", padded.trim_end()))));
                                continue;
                            }
                            
                            if let Ok(json) = serde_json::from_str::<Value>(&line[6..]) {
                                if detected_model == "tinfoil-unknown" {
                                    if let Some(m) = json.get("model").and_then(|v| v.as_str()) {
                                        detected_model = m.to_string();
                                        if let Ok(info) = crate::utils::models::get_dynamic_model_info(&tinfoil_provider_arc, &detected_model).await {
                                            price_input = info.price_input_1m;
                                            price_output = info.price_output_1m;
                                        }
                                    }
                                }
                                
                                let sanitized = crate::utils::sanitize_and_spoof_response(
                                    json, &chat_id, &detected_model, &provider_id,
                                    price_input, price_output,
                                    &mut in_tok, &mut out_tok,
                                    None, Some(&mut unredactor)
                                );
                                
                                let padded = crate::utils::pad_json_sse(sanitized);
                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}\n", padded.trim_end()))));
                            } else {
                                yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}\n", line))));
                            }
                        } else {
                            yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}\n", line))));
                        }
                    }
                }
                Err(_) => break,
            }
        }
        
        if !buffer.is_empty() {
            let line = buffer.trim_end_matches('\r');
            yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}", line))));
        }
    };

    let wrapped = crate::utils::wrap_stream_with_timing_padding(Box::pin(mapped_stream), None);
    let stream_body = BodyExt::boxed(StreamBody::new(wrapped));

    (StatusCode::from_u16(status.as_u16()).unwrap(), headers, stream_body)
}

