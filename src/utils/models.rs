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
    // 1. Try pricing block (OpenRouter style)
    if let Some(pricing) = model_val.get("pricing")
        && let (Some(p_in), Some(p_out)) = (
            get_f64_coerced(pricing, "prompt").or_else(|| get_f64_coerced(pricing, "price_input_1m")).or_else(|| get_f64_coerced(pricing, "input")),
            get_f64_coerced(pricing, "completion").or_else(|| get_f64_coerced(pricing, "price_output_1m")).or_else(|| get_f64_coerced(pricing, "output"))
        ) {
            let input_1m = if p_in < 0.001 { p_in * 1_000_000.0 } else { p_in };
            let output_1m = if p_out < 0.001 { p_out * 1_000_000.0 } else { p_out };
            return Some((input_1m, output_1m));
        }

    // 2. Try price block (alternative formats)
    if let Some(price) = model_val.get("price")
        && let (Some(p_in), Some(p_out)) = (
            get_f64_coerced(price, "prompt").or_else(|| get_f64_coerced(price, "input")),
            get_f64_coerced(price, "completion").or_else(|| get_f64_coerced(price, "output"))
        ) {
            let input_1m = if p_in < 0.001 { p_in * 1_000_000.0 } else { p_in };
            let output_1m = if p_out < 0.001 { p_out * 1_000_000.0 } else { p_out };
            return Some((input_1m, output_1m));
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
