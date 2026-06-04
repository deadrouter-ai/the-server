use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::Infallible;
use bytes::Bytes;
use hyper::body::Frame;
use serde_json::Value;
use futures::{StreamExt, Stream};

// ── Shared Helper Functions for All Providers ───────────────────────────────

pub fn generate_chat_id() -> String {
    let rand_bytes = crate::providers::nearai::gen_random_bytes::<16>();
    format!("chatcmpl-{}", hex::encode(rand_bytes))
}

pub fn sanitize_and_spoof_response(
    mut original: Value,
    chat_id: &str,
    requested_model: &str,
    provider_id: &str,
    price_input: f64,
    price_output: f64,
    total_input_tokens: &mut f64,
    total_output_tokens: &mut f64,
    mut e2ee_ratchet: Option<&mut crate::crypto_e2ee::StreamRatchet>,
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
                        if let Some(mut r) = reasoning_val {
                            if let Some(ref mut ratchet) = e2ee_ratchet {
                                if let Some(s) = r.as_str() {
                                    r = Value::String(ratchet.encrypt_chunk(s.as_bytes()));
                                }
                            }
                            clean_msg.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_msg_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_msg_fields {
                            if let Some(mut val) = msg_obj.remove(field) {
                                if field == "content" {
                                    if let Some(ref mut ratchet) = e2ee_ratchet {
                                        if let Some(s) = val.as_str() {
                                            val = Value::String(ratchet.encrypt_chunk(s.as_bytes()));
                                        }
                                    }
                                }
                                clean_msg.insert(field.to_string(), val);
                            }
                        }
                        new_choice.insert("message".to_string(), Value::Object(clean_msg));
                    }

                    if let Some(Value::Object(mut delta_obj)) = choice_obj.remove("delta") {
                        let mut clean_delta = serde_json::Map::new();
                        let reasoning_val = delta_obj.remove("reasoning").or_else(|| delta_obj.remove("reasoning_content"));
                        if let Some(mut r) = reasoning_val {
                            if let Some(ref mut ratchet) = e2ee_ratchet {
                                if let Some(s) = r.as_str() {
                                    r = Value::String(ratchet.encrypt_chunk(s.as_bytes()));
                                }
                            }
                            clean_delta.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_delta_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_delta_fields {
                            if let Some(mut val) = delta_obj.remove(field) {
                                if field == "content" {
                                    if let Some(ref mut ratchet) = e2ee_ratchet {
                                        if let Some(s) = val.as_str() {
                                            val = Value::String(ratchet.encrypt_chunk(s.as_bytes()));
                                        }
                                    }
                                }
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
                "prompt_tokens", "completion_tokens", "total_tokens"
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
            let formatted_cost = format!("{:.8}", rounded_cost);
            let formatted_cost = formatted_cost.trim_end_matches('0').trim_end_matches('.');
            let formatted_cost = if formatted_cost.is_empty() { "0.0" } else { formatted_cost };
            
            if let Ok(num) = formatted_cost.parse::<serde_json::Number>() {
                new_usage.insert("cost".to_string(), Value::Number(num));
            } else {
                new_usage.insert("cost".to_string(), Value::Number(serde_json::Number::from(0)));
            }

            new_root.insert("usage".to_string(), Value::Object(new_usage));
        }
    }

    Value::Object(new_root)
}

pub async fn mark_provider_unhealthy(provider: &crate::ProviderConfig, duration_secs: u64) {
    let mut state_write = provider.dynamic_state.write().await;
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    state_write.health.consecutive_errors += 1;
    state_write.health.rate_limited_until = Some(current_ts + duration_secs);
}

pub async fn mark_provider_healthy(provider: &crate::ProviderConfig) {
    let mut state_write = provider.dynamic_state.write().await;
    if state_write.health.consecutive_errors > 0 || state_write.health.rate_limited_until.is_some() {
        state_write.health.consecutive_errors = 0;
        state_write.health.rate_limited_until = None;
    }
}

pub fn pad_json_sse(mut json: Value) -> String {
    json["pad"] = Value::String("".to_string());
    let base_json = serde_json::to_string(&json).unwrap();
    let base_len = 6 + base_json.len() + 2; // "data: " + json + "\n\n"
    let p = 256 - (base_len % 256);
    let pad_str = "X".repeat(p);
    json["pad"] = Value::String(pad_str);
    
    let final_json = serde_json::to_string(&json).unwrap();
    format!("data: {}\n\n", final_json)
}

pub fn pad_raw_sse(line: &str) -> String {
    let comment_base_len = line.len() + 5; // line + "\n: \n\n"
    let p = 256 - (comment_base_len % 256);
    let pad_str = "X".repeat(p);
    format!("{}\n: {}\n\n", line, pad_str)
}

pub fn wrap_stream_with_timing_padding<S>(
    mut upstream_stream: S,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
) -> std::pin::Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + Sync>>
where
    S: Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + Sync + Unpin + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(1000);
    
    tokio::spawn(async move {
        while let Some(item) = upstream_stream.next().await {
            if tx.send(item).await.is_err() {
                break;
            }
        }
    });

    let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut stream_id: Option<String> = None;
    let mut stream_object: Option<String> = None;
    let mut stream_created: Option<u64> = None;
    let mut stream_model: Option<String> = None;
    let mut stream_provider: Option<String> = None;
    let mut stream_system_fingerprint: Option<String> = None;
    let mut stream_usage: Option<Value> = None;

    let mut upstream_done = false;
    let mut sent_done = false;

    let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());

    Box::pin(async_stream::stream! {
        loop {
            interval.tick().await;

            if sent_done {
                break;
            }

            let mut aggregated_content = String::new();
            let mut aggregated_reasoning = String::new();
            let mut finish_reason: Option<String> = None;
            let mut error_val: Option<Value> = None;
            let mut got_choices = false;

            loop {
                match rx.try_recv() {
                    Ok(Ok(frame)) => {
                        if frame.is_data() {
                            let data_bytes = frame.into_data().unwrap();
                            if let Ok(data_str) = std::str::from_utf8(&data_bytes) {
                                for line in data_str.split('\n') {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() {
                                        continue;
                                    }
                                    
                                    if trimmed.starts_with("data: ") {
                                        let data_content = trimmed[6..].trim();
                                        if data_content == "[DONE]" {
                                            upstream_done = true;
                                            continue;
                                        }
                                        
                                        if let Ok(json) = serde_json::from_str::<Value>(data_content) {
                                            if stream_id.is_none() { stream_id = json.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()); }
                                            if stream_object.is_none() { stream_object = json.get("object").and_then(|v| v.as_str()).map(|s| s.to_string()); }
                                            if stream_created.is_none() { stream_created = json.get("created").and_then(|v| v.as_u64()); }
                                            if stream_model.is_none() { stream_model = json.get("model").and_then(|v| v.as_str()).map(|s| s.to_string()); }
                                            if stream_provider.is_none() { stream_provider = json.get("provider").and_then(|v| v.as_str()).map(|s| s.to_string()); }
                                            if stream_system_fingerprint.is_none() { stream_system_fingerprint = json.get("system_fingerprint").and_then(|v| v.as_str()).map(|s| s.to_string()); }
                                            
                                            if json.get("error").is_some() {
                                                error_val = json.get("error").cloned();
                                            }

                                            if let Some(usage) = json.get("usage") {
                                                stream_usage = Some(usage.clone());
                                            }

                                            if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
                                                if !choices.is_empty() {
                                                    got_choices = true;
                                                }
                                                for choice in choices {
                                                    if let Some(delta) = choice.get("delta") {
                                                        if let Some(c) = delta.get("content").and_then(|v| v.as_str()) {
                                                            aggregated_content.push_str(c);
                                                        }
                                                        if let Some(r) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                                                            aggregated_reasoning.push_str(r);
                                                        }
                                                    }
                                                    if let Some(fr) = choice.get("finish_reason").and_then(|v| v.as_str()) {
                                                        finish_reason = Some(fr.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    } else if trimmed.starts_with('{') {
                                        if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
                                            if json.get("error").is_some() {
                                                error_val = json.get("error").cloned();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        upstream_done = true;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        upstream_done = true;
                        break;
                    }
                }
            }

            if error_val.is_some() {
                let err_json = serde_json::json!({
                    "error": error_val.unwrap()
                });
                let padded = pad_json_sse(err_json);
                yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                sent_done = true;
            } else if got_choices || !aggregated_content.is_empty() || !aggregated_reasoning.is_empty() || finish_reason.is_some() {
                let mut json = serde_json::json!({
                    "choices": [{
                        "index": 0,
                        "delta": {}
                    }]
                });

                if let Some(ref id) = stream_id { json["id"] = Value::String(id.clone()); }
                if let Some(ref obj) = stream_object { json["object"] = Value::String(obj.clone()); }
                if let Some(created) = stream_created { json["created"] = Value::Number(created.into()); }
                if let Some(ref model) = stream_model { json["model"] = Value::String(model.clone()); }
                if let Some(ref prov) = stream_provider { json["provider"] = Value::String(prov.clone()); }
                if let Some(ref fp) = stream_system_fingerprint { json["system_fingerprint"] = Value::String(fp.clone()); }

                let delta = json["choices"][0]["delta"].as_object_mut().unwrap();
                if !aggregated_content.is_empty() {
                    let mut final_content = aggregated_content;
                    if let Some(ref mut r) = ratchet {
                        final_content = r.encrypt_chunk(final_content.as_bytes());
                    }
                    delta.insert("content".to_string(), Value::String(final_content));
                }
                if !aggregated_reasoning.is_empty() {
                    let mut final_reasoning = aggregated_reasoning;
                    if let Some(ref mut r) = ratchet {
                        final_reasoning = r.encrypt_chunk(final_reasoning.as_bytes());
                    }
                    delta.insert("reasoning_content".to_string(), Value::String(final_reasoning));
                }
                if let Some(fr) = finish_reason {
                    json["choices"][0]["finish_reason"] = Value::String(fr);
                }

                let padded = pad_json_sse(json);
                yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
            } else {
                if upstream_done {
                    if let Some(ref usage) = stream_usage {
                        let mut json = serde_json::json!({
                            "choices": []
                        });
                        if let Some(ref id) = stream_id { json["id"] = Value::String(id.clone()); }
                        if let Some(ref obj) = stream_object { json["object"] = Value::String(obj.clone()); }
                        if let Some(created) = stream_created { json["created"] = Value::Number(created.into()); }
                        if let Some(ref model) = stream_model { json["model"] = Value::String(model.clone()); }
                        if let Some(ref prov) = stream_provider { json["provider"] = Value::String(prov.clone()); }
                        if let Some(ref fp) = stream_system_fingerprint { json["system_fingerprint"] = Value::String(fp.clone()); }
                        json["usage"] = usage.clone();

                        let padded = pad_json_sse(json);
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                        stream_usage = None;
                        continue;
                    }

                    let padded = pad_raw_sse("data: [DONE]");
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                    sent_done = true;
                } else {
                    let empty_json = serde_json::json!({
                        "choices": [{
                            "delta": {}
                        }]
                    });
                    let padded = pad_json_sse(empty_json);
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                }
            }
        }
    })
}

/// Safe coercion utility to extract f64 values from JSON fields that may contain
/// numeric types or string-encoded numbers.
pub fn get_f64_coerced(val: &Value, key: &str) -> Option<f64> {
    let field = val.get(key)?;
    if let Some(f) = field.as_f64() {
        return Some(f);
    }
    if let Some(s) = field.as_str() {
        if let Ok(f) = s.parse::<f64>() {
            return Some(f);
        }
    }
    None
}

/// Parses the prompt and completion pricing details out of a model's JSON block.
/// Automatically handles token vs. million-token pricing representations.
pub fn parse_model_price(model_val: &Value) -> Option<(f64, f64)> {
    // 1. Try pricing block (OpenRouter style)
    if let Some(pricing) = model_val.get("pricing") {
        if let (Some(p_in), Some(p_out)) = (
            get_f64_coerced(pricing, "prompt").or_else(|| get_f64_coerced(pricing, "price_input_1m")).or_else(|| get_f64_coerced(pricing, "input")),
            get_f64_coerced(pricing, "completion").or_else(|| get_f64_coerced(pricing, "price_output_1m")).or_else(|| get_f64_coerced(pricing, "output"))
        ) {
            let input_1m = if p_in < 0.01 { p_in * 1_000_000.0 } else { p_in };
            let output_1m = if p_out < 0.01 { p_out * 1_000_000.0 } else { p_out };
            return Some((input_1m, output_1m));
        }
    }

    // 2. Try price block (alternative formats)
    if let Some(price) = model_val.get("price") {
        if let (Some(p_in), Some(p_out)) = (
            get_f64_coerced(price, "prompt").or_else(|| get_f64_coerced(price, "input")),
            get_f64_coerced(price, "completion").or_else(|| get_f64_coerced(price, "output"))
        ) {
            let input_1m = if p_in < 0.01 { p_in * 1_000_000.0 } else { p_in };
            let output_1m = if p_out < 0.01 { p_out * 1_000_000.0 } else { p_out };
            return Some((input_1m, output_1m));
        }
    }

    // 3. Try root-level fields (e.g. price_input_1m, price_output_1m)
    if let (Some(p_in), Some(p_out)) = (
        get_f64_coerced(model_val, "price_input_1m"),
        get_f64_coerced(model_val, "price_output_1m")
    ) {
        return Some((p_in, p_out));
    }

    None
}

/// Generate cryptographically random bytes using aws_lc_rs.
#[inline]
pub fn gen_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes).expect("Entropy source failed");
    bytes
}
