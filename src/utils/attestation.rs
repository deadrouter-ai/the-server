use base64ct::Encoding;

/// Universal function to verify Intel TDX quotes.
/// `expected_report_data_prefix` must match the prefix of the 64-byte REPORTDATA.
pub async fn verify_intel_tdx_quote(quote_bytes: &[u8], expected_report_data_prefix: &[u8]) -> Result<(), String> {
    if quote_bytes.len() < 632 {
        return Err("FATAL: TDX Quote is too short to contain REPORTDATA".into());
    }

    let pccs_client = dcap_qvl::collateral::CollateralClient::with_default_http("https://pccs.phala.network")
        .map_err(|e| format!("Failed to create PCCS client: {:?}", e))?;

    pccs_client.fetch_and_verify(quote_bytes)
        .await
        .map_err(|e| format!("FATAL: TDX Hardware Verification Failed! {:?}", e))?;

    let td_attributes = &quote_bytes[168..176];
    let is_debug_mode = (td_attributes[0] & 1) != 0;
    
    if is_debug_mode {
        return Err("FATAL: Intel TDX Enclave is running in DEBUG mode. Memory can be dumped!".into());
    }

    let report_data = &quote_bytes[568..632];
    if report_data.len() < expected_report_data_prefix.len() {
        return Err("FATAL: expected_report_data_prefix is larger than REPORTDATA".into());
    }
    
    if aws_lc_rs::constant_time::verify_slices_are_equal(
        &report_data[..expected_report_data_prefix.len()], 
        expected_report_data_prefix
    ).is_err() {
        return Err("FATAL: Intel TDX Key/TLS/Nonce binding verification failed! Possible MITM attack.".into());
    }

    Ok(())
}

/// Universal function to verify NVIDIA GPU NRAS attestation.
/// Requires the request body to be fully prepared (including nonce, arch, and evidence).
/// `expected_nonce` is the byte array that the `eat_nonce` claim in the GPU JWT must match.
pub async fn verify_nvidia_gpu_attestation(
    client: &reqwest::Client,
    nras_req_body: serde_json::Value,
    expected_nonce: &[u8]
) -> Result<(), String> {
    let nras_url = "https://nras.attestation.nvidia.com/v3/attest/gpu";
    let nras_resp = client.post(nras_url)
        .header("Content-Type", "application/json")
        .json(&nras_req_body)
        .send()
        .await
        .map_err(|e| format!("NRAS Network error: {}", e))?;

    if !nras_resp.status().is_success() {
        return Err(format!("FATAL: NVIDIA Verification HTTP Failed! Status: {} - Body: {}", 
            nras_resp.status(), nras_resp.text().await.unwrap_or_default()));
    }

    let nras_json: serde_json::Value = nras_resp.json().await.map_err(|_| "Failed to parse NRAS V3 response".to_string())?;

    let top_jwt = nras_json.get(0)
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_str())
        .ok_or("Missing top-level JWT in NRAS response")?;

    let top_parts: Vec<&str> = top_jwt.split('.').collect();
    if top_parts.len() < 2 { return Err("Invalid Top JWT format".into()); }
    
    let top_decoded = base64ct::Base64UrlUnpadded::decode_vec(top_parts[1])
        .map_err(|e| format!("Base64 decode failed for top JWT: {}", e))?;
    let top_claims: serde_json::Value = serde_json::from_slice(&top_decoded)
        .map_err(|_| "Failed to parse Top JWT claims".to_string())?;

    if top_claims.get("x-nvidia-overall-att-result").and_then(|v| v.as_bool()) != Some(true) {
        return Err("FATAL: NVIDIA attestation verdict was not PASS".into());
    }

    let gpu_jwt = nras_json.get(1)
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("GPU-0"))
        .and_then(|v| v.as_str())
        .ok_or("Missing GPU-0 JWT in NRAS response")?;

    let gpu_parts: Vec<&str> = gpu_jwt.split('.').collect();
    if gpu_parts.len() < 2 { return Err("Invalid GPU JWT format".into()); }
    
    let gpu_decoded = base64ct::Base64UrlUnpadded::decode_vec(gpu_parts[1])
        .map_err(|e| format!("Base64 decode failed for GPU JWT: {}", e))?;
    let gpu_claims: serde_json::Value = serde_json::from_slice(&gpu_decoded)
        .map_err(|_| "Failed to parse GPU JWT claims".to_string())?;

    let dbgstat = gpu_claims.get("dbgstat").and_then(|v| v.as_str()).unwrap_or("");
    if dbgstat != "disabled" {
        return Err("FATAL: NVIDIA GPU debug mode is enabled. Memory can be dumped!".into());
    }

    if gpu_claims.get("secboot").and_then(|v| v.as_bool()) != Some(true) {
        return Err("FATAL: NVIDIA GPU Secure Boot is disabled.".into());
    }

    let eat_nonce_str = gpu_claims.get("eat_nonce").and_then(|v| v.as_str()).unwrap_or("");
    let mut eat_nonce_bytes = [0u8; 32];
    if hex::decode_to_slice(eat_nonce_str, &mut eat_nonce_bytes).is_err() ||
       aws_lc_rs::constant_time::verify_slices_are_equal(&eat_nonce_bytes, expected_nonce).is_err() {
        return Err(format!("FATAL: NVIDIA GPU payload nonce ({}) does not match request nonce", eat_nonce_str));
    }

    Ok(())
}
