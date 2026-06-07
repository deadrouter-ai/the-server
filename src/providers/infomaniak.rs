use std::collections::HashMap;
use serde_json::Value;
use std::sync::Arc;
use std::convert::Infallible;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;

use crate::{AppState, ProviderConfig, DynamicModelInfo};
use crate::routes::api::chat_completions::ChatCompletionRequest;

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
        let frontend_name = crate::utils::standardize_model_name(&upstream_id);

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
    let model_info = crate::utils::models::get_dynamic_model_info(provider, &frontend_requested_model).await?;

    // Infomaniak (specifically Llama-3 based models) strictly enforces that `system`
    // can only be the very first message, and there can only be one.
    let mut normalized_messages: Vec<crate::routes::api::chat_completions::Message> = Vec::new();
    let mut seen_non_system = false;
    for mut msg in std::mem::take(&mut proxy_req.messages) {
        if msg.role == "system" {
            if seen_non_system {
                // If a system message appears after a user/assistant message, change it to user
                msg.role = "user".to_string();
            } else if let Some(first_msg) = normalized_messages.first_mut() {
                // Merge consecutive system messages at the start
                first_msg.content.push_str("\n\n");
                first_msg.content.push_str(&msg.content);
                continue;
            }
        } else {
            seen_non_system = true;
        }
        normalized_messages.push(msg);
    }
    proxy_req.messages = normalized_messages;

    crate::utils::http::forward_to_standard_provider(
        state,
        provider,
        proxy_req,
        chat_id,
        frontend_requested_model,
        model_info.upstream_model_name,
        model_info.price_input_1m,
        model_info.price_output_1m,
        e2ee_session
    ).await
}
