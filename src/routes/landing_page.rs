use askama::Template;
use hyper::StatusCode;
use crate::{AppState, IncomingRequest};

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub csp_nonce: String,
    pub onion_site: String,
}

pub fn handle_landing_page(
    state: &AppState,
    _req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    // 1. Generate a secure, 64-character random nonce
    let mut rand_bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut rand_bytes).unwrap();

    let mut hex_buf = [0u8; 64];
    let nonce = base16ct::lower::encode_str(&rand_bytes, &mut hex_buf).expect("base16ct encoding failed");

    // 2. Populate the Askama template
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    let template = IndexTemplate { csp_nonce: nonce.to_string(), onion_site };

    // 3. Render the HTML
    let html_string = match template.render() {
        Ok(html) => html,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], "Render failed".to_string()),
    };

    // 4. Construct the ultra-strict CSP string dynamically
    let csp_string = format!(
        "default-src 'none'; \
         script-src 'none'; \
         style-src 'nonce-{}'; \
         form-action 'self'; \
         base-uri 'none'; \
         frame-ancestors 'none'; \
         img-src 'self'; \
         upgrade-insecure-requests;",
        nonce
    );

    // 5. Build the Response with the headers
    let headers = vec![
        ("Content-Security-Policy", csp_string),
        ("X-Frame-Options", "DENY".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("Content-Type", "text/html; charset=utf-8".to_string()),
    ];

    (StatusCode::OK, headers, html_string)
}
