pub mod nearai;
pub mod chutes;
pub mod redpill;
pub mod infomaniak;
pub mod tinfoil;

use serde_json::Value;
use crate::{AppState, ProviderConfig};

/// Connects to a provider's models endpoint (derived from the chat completions endpoint),
/// retrieves upstream prices, and writes them to the provider's dynamic state.
pub async fn fetch_and_update_prices(state: &AppState, provider: &ProviderConfig) -> Result<(), String> {
    let client = &state.http_client;

    // Construct OpenAI compatible models URL from completion endpoint
    let models_url = if provider.id == "infomaniak" {
        "https://api.infomaniak.com/1/ai/models?with=pricing".to_string()
    } else if provider.id == "tinfoil" {
        "https://inference.tinfoil.sh/v1/models".to_string()
    } else {
        provider.endpoint.replace("/chat/completions", "/models")
    };

    let mut req = client.get(&models_url);
    if !provider.api_key.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", provider.api_key));
    }

    let resp = req.send().await.map_err(|e| format!("Request failed: {:?}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Unsuccessful status: {}", resp.status()));
    }

    let json: Value = resp.json().await.map_err(|e| format!("JSON parsing failed: {}", e))?;
    let data_array = if let Some(d) = json.get("data") {
        d.as_array()
            .ok_or_else(|| "Missing 'data' array in /v1/models response".to_string())?
    } else if let Some(arr) = json.as_array() {
        arr
    } else {
        return Err("Unexpected /v1/models response format".to_string());
    };

    // Parse models via provider-specific parser
    let updated_models = if provider.id == "near-ai" {
        crate::providers::nearai::parse_models(client, data_array).await
    } else if provider.id == "chutes" {
        crate::providers::chutes::parse_models(data_array)
    } else if provider.id == "redpill" {
        crate::providers::redpill::parse_models(data_array)
    } else if provider.id == "infomaniak" {
        crate::providers::infomaniak::parse_models(data_array)
    } else if provider.id == "tinfoil" {
        crate::providers::tinfoil::parse_models(data_array)
    } else {
        // Fallback or other providers
        crate::providers::nearai::parse_models(client, data_array).await
    };

    // Apply retrieved pricing and models to dynamic state
    if !updated_models.is_empty() {
        let mut dynamic_state = provider.dynamic_state.write().await;
        let mut router_write = state.routing_table.write().await;

        for (model_name, info) in updated_models {
            dynamic_state.dynamic_models.insert(model_name.clone(), info);
            
            // Add provider to this model's routing list if not already there
            let providers_list = router_write.entry(model_name).or_insert_with(Vec::new);
            if !providers_list.contains(&provider.id) {
                providers_list.push(provider.id.clone());
            }
        }
    }

    Ok(())
}
