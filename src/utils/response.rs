use serde_json::Value;

/// Generates a unique chat completion ID using 16 cryptographic random bytes.
pub fn generate_chat_id() -> String {
    let rand_bytes = crate::utils::crypto::gen_random_bytes::<16>();
    format!("chatcmpl-{}", hex::encode(rand_bytes))
}

/// Sanitizes an upstream provider response for client consumption.
#[allow(clippy::too_many_arguments)]
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
    mut unredactor: Option<&mut crate::utils::redaction::StreamingUnredactor>,
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
                            if let Some(s) = r.as_str() {
                                let mut text = s.to_string();
                                if let Some(ref mut unredactor) = unredactor {
                                    text = unredactor.process_chunk(&text);
                                    text.push_str(&unredactor.flush());
                                }
                                if let Some(ref mut ratchet) = e2ee_ratchet {
                                    r = Value::String(ratchet.encrypt_chunk(text.as_bytes()));
                                } else {
                                    r = Value::String(text);
                                }
                            }
                            clean_msg.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_msg_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_msg_fields {
                            if let Some(mut val) = msg_obj.remove(field) {
                                if field == "content" && let Some(s) = val.as_str() {
                                    let mut text = s.to_string();
                                    if let Some(ref mut unredactor) = unredactor {
                                        text = unredactor.process_chunk(&text);
                                        text.push_str(&unredactor.flush()); // non-streaming usually finishes here
                                    }
                                    if let Some(ref mut ratchet) = e2ee_ratchet {
                                        val = Value::String(ratchet.encrypt_chunk(text.as_bytes()));
                                    } else {
                                        val = Value::String(text);
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
                            if let Some(s) = r.as_str() {
                                let mut text = s.to_string();
                                if let Some(ref mut unredactor) = unredactor {
                                    text = unredactor.process_chunk(&text);
                                }
                                if let Some(ref mut ratchet) = e2ee_ratchet {
                                    r = Value::String(ratchet.encrypt_chunk(text.as_bytes()));
                                } else {
                                    r = Value::String(text);
                                }
                            }
                            clean_delta.insert("reasoning_content".to_string(), r);
                        }
                        let allowed_delta_fields = ["role", "content", "tool_calls", "function_call", "refusal"];
                        for field in allowed_delta_fields {
                            if let Some(mut val) = delta_obj.remove(field) {
                                if field == "content" && let Some(s) = val.as_str() {
                                    let mut text = s.to_string();
                                    if let Some(ref mut unredactor) = unredactor {
                                        text = unredactor.process_chunk(&text);
                                    }
                                    if let Some(ref mut ratchet) = e2ee_ratchet {
                                        val = Value::String(ratchet.encrypt_chunk(text.as_bytes()));
                                    } else {
                                        val = Value::String(text);
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

/// Pads a JSON SSE event to the nearest 256-byte boundary.
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

/// Pads a raw SSE line (e.g., `data: [DONE]`) to the nearest 256-byte boundary
pub fn pad_raw_sse(line: &str) -> String {
    let comment_base_len = line.len() + 5; // line + "\n: \n\n"
    let p = 256 - (comment_base_len % 256);
    let pad_str = "X".repeat(p);
    format!("{}\n: {}\n\n", line, pad_str)
}
