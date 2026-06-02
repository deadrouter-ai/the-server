use bytes::Bytes;
use hyper::StatusCode;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use crate::AppState;
use crate::crypto_e2ee::generate_ticket;

pub async fn handle_keys_ephemeral(
    state: &AppState,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let secrets = state.ticket_secrets.read().await;
    let ticket = generate_ticket(&secrets);
    
    let body_bytes = serde_json::to_vec(&ticket).unwrap();
    (
        StatusCode::OK,
        vec![("Content-Type", "application/json".to_string())],
        Full::new(Bytes::from(body_bytes)).map_err(|e| match e {}).boxed(),
    )
}
