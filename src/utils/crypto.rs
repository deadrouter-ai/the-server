use std::convert::Infallible;
use bytes::Bytes;
use hyper::body::Frame;
use serde_json::Value;
use futures::{StreamExt, Stream};

/// Generate cryptographically random bytes using aws_lc_rs.
#[inline]
pub fn gen_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes).expect("Entropy source failed");
    bytes
}

/// Wraps an upstream SSE stream with 50ms interval timing padding.
///
/// Aggregates multiple upstream chunks per tick into a single padded event,
/// preventing timing side-channels that could leak token generation patterns.
/// Applies E2EE re-encryption via stream ratchet when an E2EE session is active.
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
                                    
                                    if let Some(stripped) = trimmed.strip_prefix("data: ") {
                                        let data_content = stripped.trim();
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
                                    } else if trimmed.starts_with('{')
                                        && let Ok(json) = serde_json::from_str::<Value>(trimmed)
                                            && json.get("error").is_some() {
                                                error_val = json.get("error").cloned();
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

            if let Some(err) = error_val {
                let err_json = serde_json::json!({
                    "error": err
                });
                let padded = crate::utils::response::pad_json_sse(err_json);
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

                let padded = crate::utils::response::pad_json_sse(json);
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

                        let padded = crate::utils::response::pad_json_sse(json);
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                        stream_usage = None;
                        continue;
                    }

                    let padded = crate::utils::response::pad_raw_sse("data: [DONE]");
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                    sent_done = true;
                } else {
                    let empty_json = serde_json::json!({
                        "choices": [{
                            "delta": {}
                        }]
                    });
                    let padded = crate::utils::response::pad_json_sse(empty_json);
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from(padded)));
                }
            }
        }
    })
}
