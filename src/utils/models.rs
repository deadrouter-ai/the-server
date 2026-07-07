use serde_json::Value;

/// Standardizes an upstream model ID into a consistent frontend model name.
/// It strips organization prefixes and common quantization/format suffixes.
pub fn standardize_model_name(id: &str) -> String {
    let mut name = match id.find('/') {
        Some(idx) => &id[idx + 1..],
        None => id,
    }.to_string();

    let suffixes = ["-FP8", "-TEE", "-AWQ", "-NVFP4", "-GGUF", "-GPTQ", "-INT8", "-INT4"];
    for suffix in suffixes {
        if name.ends_with(suffix) {
            name = name.trim_end_matches(suffix).to_string();
        }
    }
    
    name.to_lowercase()
}

/// Safe coercion utility to extract f64 values from JSON fields that may contain
/// numeric types or string-encoded numbers.
pub fn get_f64_coerced(val: &Value, key: &str) -> Option<f64> {
    let field = val.get(key)?;
    if let Some(f) = field.as_f64() {
        return Some(f);
    }
    if let Some(s) = field.as_str()
        && let Ok(f) = s.parse::<f64>() {
            return Some(f);
        }
    None
}

/// Parses the prompt and completion pricing details out of a model's JSON block.
/// Automatically handles token vs. million-token pricing representations.
pub fn parse_model_price(model_val: &Value) -> Option<(f64, f64)> {
    // 1. Try root-level fields (unambiguous)
    if let (Some(p_in), Some(p_out)) = (
        get_f64_coerced(model_val, "price_input_1m"),
        get_f64_coerced(model_val, "price_output_1m")
    ) {
        return Some((p_in, p_out));
    }

    // 2. Try pricing block (OpenRouter style)
    if let Some(pricing) = model_val.get("pricing") {
        let p_in_1m = get_f64_coerced(pricing, "price_input_1m")
            .or_else(|| get_f64_coerced(pricing, "prompt").map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p }))
            .or_else(|| get_f64_coerced(pricing, "input").map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p }));
        
        let p_out_1m = get_f64_coerced(pricing, "price_output_1m")
            .or_else(|| get_f64_coerced(pricing, "completion").map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p }))
            .or_else(|| get_f64_coerced(pricing, "output").map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p }));
            
        if let (Some(i), Some(o)) = (p_in_1m, p_out_1m) {
            return Some((i, o));
        }
    }

    // 3. Try price block (alternative formats)
    if let Some(price) = model_val.get("price") {
        let p_in_1m = get_f64_coerced(price, "prompt")
            .or_else(|| get_f64_coerced(price, "input"))
            .map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p });
            
        let p_out_1m = get_f64_coerced(price, "completion")
            .or_else(|| get_f64_coerced(price, "output"))
            .map(|p| if p < 0.001 && p > 0.0 { p * 1_000_000.0 } else { p });

        if let (Some(i), Some(o)) = (p_in_1m, p_out_1m) {
            return Some((i, o));
        }
    }


    None
}

/// Helper function to asynchronously fetch dynamic model information for a given provider.
pub async fn get_dynamic_model_info(
    provider: &std::sync::Arc<crate::ProviderConfig>,
    frontend_requested_model: &str,
) -> Result<crate::DynamicModelInfo, String> {
    let state_read = provider.dynamic_state.read().await;
    state_read.dynamic_models.get(frontend_requested_model).cloned()
        .ok_or_else(|| format!("Model {} not dynamically configured", frontend_requested_model))
}
