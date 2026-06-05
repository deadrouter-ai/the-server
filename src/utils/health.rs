use std::time::{SystemTime, UNIX_EPOCH};

/// Marks a provider as temporarily unhealthy for the given duration.
///
/// Increments the consecutive error counter and sets a rate-limit backoff timestamp.
pub async fn mark_provider_unhealthy(provider: &crate::ProviderConfig, duration_secs: u64) {
    let mut state_write = provider.dynamic_state.write().await;
    let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    state_write.health.consecutive_errors += 1;
    state_write.health.rate_limited_until = Some(current_ts + duration_secs);
}

/// Clears a provider's error state, marking it as healthy.
pub async fn mark_provider_healthy(provider: &crate::ProviderConfig) {
    let mut state_write = provider.dynamic_state.write().await;
    if state_write.health.consecutive_errors > 0 || state_write.health.rate_limited_until.is_some() {
        state_write.health.consecutive_errors = 0;
        state_write.health.rate_limited_until = None;
    }
}
