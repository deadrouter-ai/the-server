use std::collections::HashMap;
use serde_json::Value;
use std::sync::Arc;
use std::convert::Infallible;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;

use crate::{AppState, ProviderConfig};
use crate::routes::api::chat_completions::ChatCompletionRequest;
use crate::DynamicModelInfo;

pub fn parse_models(data_array: &[Value]) -> HashMap<String, DynamicModelInfo> {
    let mut models: HashMap<String, DynamicModelInfo> = HashMap::new();
    let allowed_providers = ["chutes", "near-ai", "secretai", "tinfoil", "phala", "0g"];

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
        let frontend_name = crate::utils::standardize_model_name(&upstream_id);

        let (p_in, p_out) = crate::utils::parse_model_price(model_val).unwrap_or((0.0, 0.0));
        let cost = p_in + p_out;

        // Deduplication based on max cost
        if let Some(existing) = models.get(&frontend_name) {
            let existing_cost = existing.price_input_1m + existing.price_output_1m;
            if cost >= existing_cost {
                continue; // Keep the existing cheaper model
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
    proxy_req: ChatCompletionRequest,
    ctx: crate::providers::ProviderCallContext,
) -> Result<BoxBody<Bytes, Infallible>, String> {
    let model_info = crate::utils::models::get_dynamic_model_info(provider, &ctx.frontend_requested_model).await?;

    crate::utils::http::forward_to_standard_provider(
        state,
        provider,
        proxy_req,
        ctx.chat_id,
        ctx.frontend_requested_model,
        model_info.upstream_model_name,
        model_info.price_input_1m,
        model_info.price_output_1m,
        ctx.e2ee_session,
        ctx.pii_map_arc,
    ).await
}
