use std::convert::Infallible;
use bytes::Bytes;
use hyper::body::Frame;
use futures::StreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use base64ct::{Base64, Encoding};

/// Lower-cases header names into a plain map for `IncomingRequest`, dropping any
/// value that isn't valid UTF-8. Shared by every transport (TCP, QUIC, Tor) so they
/// normalize headers identically before handing off to the protocol-agnostic router.
pub fn headers_to_map(headers: &hyper::HeaderMap) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::with_capacity(headers.len());
    for (k, v) in headers.iter() {
        if let Ok(val) = v.to_str() {
            map.insert(k.as_str().to_lowercase(), val.to_string());
        }
    }
    map
}

pub fn compute_sha512_b64(data: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data.as_bytes());
    let b64 = Base64::encode_string(digest.as_ref());
    format!("'sha512-{}'", b64)
}

pub fn get_security_headers(style_hash: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Security-Policy", format!(
            "default-src 'none'; \
             script-src 'none'; \
             style-src {}; \
             form-action 'self'; \
             base-uri 'none'; \
             frame-ancestors 'none'; \
             img-src 'self'; \
             font-src 'self'; \
             upgrade-insecure-requests;",
            style_hash
        )),
        ("X-Frame-Options", "DENY".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("Content-Type", "text/html; charset=utf-8".to_string()),
    ]
}

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
    pii_map: std::sync::Arc<crate::utils::redaction::PiiMap>,
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
        let stream_err_mapper = resp.bytes_stream().map(|res| res.map_err(std::io::Error::other));
        let mut stream_reader = tokio::io::BufReader::new(tokio_util::io::StreamReader::new(stream_err_mapper));
        
        let mapped_stream = async_stream::stream! {
            let mut total_in = 0.0;
            let mut total_out = 0.0;
            let mut line = String::new();
            let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map.clone());
            use tokio::io::AsyncBufReadExt;
            while let Ok(n) = stream_reader.read_line(&mut line).await {
                if n == 0 { break; }
                
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    line.clear();
                    continue;
                }

                if let Some(stripped) = trimmed.strip_prefix("data: ") {
                    let data_str = stripped.trim();
                    if data_str == "[DONE]" {
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from("data: [DONE]\n\n")));
                        line.clear();
                        continue;
                    }

                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(data_str) {
                        let sanitized = crate::utils::response::sanitize_and_spoof_response(
                            json, &chat_id, &frontend_requested_model, &provider_id,
                            price_input, price_output,
                            &mut total_in, &mut total_out,
                            None,
                            Some(&mut unredactor)
                        );
                        let new_line = serde_json::to_string(&sanitized).unwrap_or_default();
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("data: {}\n\n", new_line))));
                    } else {
                        yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("data: {}\n\n", data_str))));
                    }
                } else {
                    yield Ok::<_, Infallible>(Frame::data(Bytes::from(format!("{}\n", trimmed))));
                }
                
                line.clear();
            }
        };
        Ok(BodyExt::boxed(StreamBody::new(crate::utils::crypto::wrap_stream_with_timing_padding(Box::pin(mapped_stream), e2ee_session))))
    } else {
        let body_bytes = resp.bytes().await.map_err(|e| format!("Failed to read body: {}", e))?;
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
             let mut total_in = 0.0;
             let mut total_out = 0.0;
             let mut ratchet = e2ee_session.as_ref().map(|s| s.get_stream_ratchet());
             let mut unredactor = crate::utils::redaction::StreamingUnredactor::new(pii_map.clone());
             let sanitized = crate::utils::response::sanitize_and_spoof_response(
                 json, &chat_id, &frontend_requested_model, &provider_id,
                 price_input, price_output,
                 &mut total_in, &mut total_out,
                 ratchet.as_mut(),
                 Some(&mut unredactor)
             );
             let new_body = serde_json::to_vec(&sanitized).unwrap_or(body_bytes.to_vec());
             Ok(BodyExt::boxed(Full::new(Bytes::from(new_body)).map_err(|e| match e {})))
        } else {
             Ok(BodyExt::boxed(Full::new(body_bytes).map_err(|e| match e {})))
        }
    }
}
