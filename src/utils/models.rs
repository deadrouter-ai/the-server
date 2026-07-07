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

    normalize_dashed_version(&name.to_lowercase())
}

/// Some providers spell a model's minor version with a hyphen instead of the
/// standard dot (Tinfoil's `glm-5-2`, `kimi-k2-6` vs. the catalog's `glm-5.2`,
/// `kimi-k2.6`), which would otherwise register as a distinct "duplicate" model.
///
/// Rewrites a hyphen as a dot only where it sits between a segment ending in a
/// digit and a segment made *entirely* of digits — e.g. `5-2` or `k2-6` — so it
/// never touches a parameter-count suffix (`70b`), a date (`instruct-2512`), or
/// an already-dotted version.
fn normalize_dashed_version(id: &str) -> String {
    let is_all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let ends_in_digit = |s: &str| s.bytes().next_back().is_some_and(|b| b.is_ascii_digit());

    let segments: Vec<&str> = id.split('-').collect();
    let mut out = String::from(segments.first().copied().unwrap_or(""));
    for pair in segments.windows(2) {
        let (prev, cur) = (pair[0], pair[1]);
        out.push(if ends_in_digit(prev) && is_all_digits(cur) { '.' } else { '-' });
        out.push_str(cur);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_dashed_version() {
        assert_eq!(normalize_dashed_version("glm-5-2"), "glm-5.2");
        assert_eq!(normalize_dashed_version("kimi-k2-6"), "kimi-k2.6");
        assert_eq!(normalize_dashed_version("glm-4-7"), "glm-4.7");
        assert_eq!(normalize_dashed_version("glm-5-2-flash"), "glm-5.2-flash");
        // Already-standard forms and unrelated hyphens pass through unchanged.
        assert_eq!(normalize_dashed_version("glm-5.2"), "glm-5.2");
        assert_eq!(normalize_dashed_version("glm-5"), "glm-5");
        assert_eq!(normalize_dashed_version("ministral-3-14b-instruct-2512"), "ministral-3-14b-instruct-2512");
        assert_eq!(normalize_dashed_version("apertus-70b-instruct-2509"), "apertus-70b-instruct-2509");
        assert_eq!(normalize_dashed_version("qwen3-30b-a3b-instruct-2507"), "qwen3-30b-a3b-instruct-2507");
    }

    #[test]
    fn test_standardize_model_name() {
        assert_eq!(standardize_model_name("some-org/GLM-5-2"), "glm-5.2");
        assert_eq!(standardize_model_name("kimi-k2-6-FP8"), "kimi-k2.6");
    }
}
