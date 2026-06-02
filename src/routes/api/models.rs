use std::convert::Infallible;
use hyper::StatusCode;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use serde::Serialize;
use crate::AppState;

#[derive(Serialize)]
struct ModelPricing {
    input: f64,
    output: f64,
    prompt: String,
    completion: String,
    image: String,
    request: String,
    currency: &'static str,
}

#[derive(Serialize)]
struct TopProvider {
    context_length: u64,
    max_completion_tokens: u64,
    is_moderated: bool,
}

#[derive(Serialize)]
struct ShortModelItem {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: &'static str,
}

#[derive(Serialize)]
struct ModelItem {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: &'static str,
    name: String,
    pricing: ModelPricing,
    context_length: u64,
    max_output_length: u64,
    architecture: serde_json::Value,
    input_modalities: serde_json::Value,
    output_modalities: serde_json::Value,
    supported_sampling_parameters: serde_json::Value,
    supported_features: serde_json::Value,
    top_provider: TopProvider,
    providers: Vec<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum AnyModelItem {
    Short(ShortModelItem),
    Detailed(Box<ModelItem>),
}

#[derive(Serialize)]
struct ModelsResponse {
    object: &'static str,
    data: Vec<AnyModelItem>,
}

/// Helper function to format prices to strings with up to 10 decimal places,
/// trimming unnecessary trailing zeros.
fn format_price(price: f64) -> String {
    if price == 0.0 {
        return "0".to_string();
    }
    let s = format!("{:.10}", price);
    let mut s = s.trim_end_matches('0').to_string();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Handler for `/v1/models` request. Aggregates all configured models dynamically
/// and returns the pricing corresponding to the cheapest provider for each.
pub async fn handle_models_list(
    state: &AppState,
    req_uri: &str,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let mut target_currency = crate::currency::Currency::Usd;
    let mut is_detailed = false;
    if let Some(query) = req_uri.split('?').nth(1) {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "currency" {
                    if let Some(curr) = crate::currency::Currency::from_str(v) {
                        target_currency = curr;
                    }
                } else if k == "detailed" && v == "true" {
                    is_detailed = true;
                }
            }
        }
    }

    let mut model_items = Vec::new();
    
    let routing_read = state.routing_table.read().await;

    // Iterate through all configured models in routing table
    for (model_name, provider_ids) in routing_read.iter() {
        let mut cheapest_prompt = f64::MAX;
        let mut cheapest_completion = f64::MAX;
        let mut cheapest_input_1m = 0.0;
        let mut cheapest_output_1m = 0.0;
        
        let mut top_ctx_len = 0;
        let mut top_max_comp = 0;
        let mut best_dyn_info = None;
        let mut found = false;

        // Resolve providers supporting this model
        for provider_id in provider_ids {
            if let Some(provider) = state.providers.get(provider_id) {
                let state_read = provider.dynamic_state.read().await;
                if let Some(info) = state_read.dynamic_models.get(model_name) {
                    
                    let markup_factor = 1.0 + (provider.markup / 100.0);
                    let final_input = crate::currency::convert_usd_to(info.price_input_1m * markup_factor, target_currency);
                    let final_output = crate::currency::convert_usd_to(info.price_output_1m * markup_factor, target_currency);

                    let final_input = crate::currency::round_nice(final_input);
                    let final_output = crate::currency::round_nice(final_output);

                    // Convert from price-per-million to price-per-token
                    let prompt_price = final_input / 1_000_000.0;
                    let completion_price = final_output / 1_000_000.0;

                    // Compare to find cheapest provider rates
                    if !found 
                        || prompt_price < cheapest_prompt 
                        || (prompt_price == cheapest_prompt && completion_price < cheapest_completion) 
                    {
                        cheapest_prompt = prompt_price;
                        cheapest_completion = completion_price;
                        cheapest_input_1m = final_input;
                        cheapest_output_1m = final_output;
                        top_ctx_len = info.context_length;
                        top_max_comp = info.max_completion_tokens;
                        best_dyn_info = Some(info.clone());
                        found = true;
                    }
                }
            }
        }

        if found {
            if is_detailed {
                if let Some(info) = best_dyn_info {
                    let mut supported_sampling = info.supported_sampling_parameters.clone();
                    if let Some(arr) = supported_sampling.as_array_mut() {
                        arr.retain(|v| v.as_str() != Some("stop"));
                    }
                    model_items.push(AnyModelItem::Detailed(Box::new(ModelItem {
                        id: model_name.clone(),
                        object: "model",
                        created: 0,
                        owned_by: "system",
                        name: info.name,
                        pricing: ModelPricing {
                            input: cheapest_input_1m,
                            output: cheapest_output_1m,
                            prompt: format_price(cheapest_prompt),
                            completion: format_price(cheapest_completion),
                            image: "0".to_string(),
                            request: "0".to_string(),
                            currency: target_currency.as_str(),
                        },
                        context_length: top_ctx_len,
                        max_output_length: top_max_comp,
                        architecture: serde_json::json!({
                            "inputModalities": ["text"],
                            "outputModalities": ["text"]
                        }),
                        input_modalities: serde_json::json!(["text"]),
                        output_modalities: serde_json::json!(["text"]),
                        supported_sampling_parameters: supported_sampling,
                        supported_features: info.supported_features,
                        top_provider: TopProvider {
                            context_length: top_ctx_len,
                            max_completion_tokens: top_max_comp,
                            is_moderated: false,
                        },
                        providers: provider_ids.clone(),
                    })));
                }
            } else {
                model_items.push(AnyModelItem::Short(ShortModelItem {
                    id: model_name.clone(),
                    object: "model",
                    created: 0,
                    owned_by: "system",
                }));
            }
        }
    }

    // Sort models by ID for deterministic, readable output
    model_items.sort_by(|a, b| {
        let id_a = match a {
            AnyModelItem::Short(s) => &s.id,
            AnyModelItem::Detailed(d) => &d.id,
        };
        let id_b = match b {
            AnyModelItem::Short(s) => &s.id,
            AnyModelItem::Detailed(d) => &d.id,
        };
        id_a.cmp(id_b)
    });

    let response = ModelsResponse {
        object: "list",
        data: model_items,
    };

    let body_bytes = serde_json::to_vec(&response).unwrap();

    (
        StatusCode::OK,
        vec![("Content-Type", "application/json".to_string())],
        Full::new(Bytes::from(body_bytes)).map_err(|e| match e {}).boxed(),
    )
}
