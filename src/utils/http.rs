use std::convert::Infallible;
use bytes::Bytes;
use hyper::body::Frame;
use futures::StreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};

/// Standardizes error extraction from upstream HTTP responses, including `Retry-After` headers.
pub fn format_upstream_error(status: reqwest::StatusCode, retry_after: Option<&str>, mut body_text: String) -> String {
    let retry_str = match retry_after {
        Some(r) if !r.is_empty() => format!(" [Retry-After: {}]", r),
        _ => String::new(),
    };
    if body_text.len() > 150 {
        body_text.truncate(147);
        body_text.push_str("...");
    }
    let cleaned_body = body_text.replace("\r", "").replace("\n", " ");
    format!("Upstream error: {}{} - {}", status, retry_str, cleaned_body)
}

/// Forwards a request to a standard upstream API (e.g. OpenAI compatible)
/// handling SSE stream padding, error forwarding, and body sanitization.
#[allow(clippy::too_many_arguments)]
pub async fn forward_to_standard_provider(
    state: &crate::AppState,
    provider: &std::sync::Arc<crate::ProviderConfig>,
    mut proxy_req: crate::routes::api::chat_completions::ChatCompletionRequest,
    chat_id: String,
    frontend_requested_model: String,
    upstream_model_name: String,
    price_input: f64,
    price_output: f64,
    e2ee_session: Option<std::sync::Arc<crate::crypto_e2ee::E2eeSession>>,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    if proxy_req.stream { proxy_req.stream_options = Some(crate::routes::api::chat_completions::StreamOptions { include_usage: true }); }
    proxy_req.model = upstream_model_name;
    let payload = serde_json::to_vec(&proxy_req).map_err(|e| format!("Serialization error: {}", e))?;

    let req = state.http_client.post(&provider.endpoint)
        .header("Authorization", format!("Bearer {}", provider.api_key))
        .header("Content-Type", "application/json")
        .body(payload);

    let resp = req.send().await.map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let retry_after = resp.headers().get("retry-after").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
        return Err(format_upstream_error(
            status,
            retry_after.as_deref(),
            resp.text().await.unwrap_or_default(),
        ));
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
                                    let sanitized = crate::utils::response::sanitize_and_spoof_response(
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
        Ok(BodyExt::boxed(StreamBody::new(crate::utils::crypto::wrap_stream_with_timing_padding(Box::pin(mapped_stream), e2ee_session))))
    } else {
        let body_bytes = resp.bytes().await.map_err(|e| format!("Failed to read body: {}", e))?;
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
             let mut total_in = 0.0;
             let mut total_out = 0.0;
             let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
             let sanitized = crate::utils::response::sanitize_and_spoof_response(
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
