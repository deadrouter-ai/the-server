use askama::Template;
use hyper::StatusCode;
use crate::{AppState, IncomingRequest};

const INDEX_CSS: &str = include_str!("../../templates/style_index.css");

fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(INDEX_CSS))
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub onion_site: String,
}

pub fn handle_landing_page(
    state: &AppState,
    _req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    let template = IndexTemplate { onion_site };

    let html_string = match template.render() {
        Ok(html) => html,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], "Render failed".to_string()),
    };

    let headers = crate::utils::http::get_security_headers(get_style_hash());
    (StatusCode::OK, headers, html_string)
}
