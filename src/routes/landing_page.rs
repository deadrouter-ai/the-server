use askama::Template;
use hyper::StatusCode;
use crate::{AppState, IncomingRequest};

const INDEX_CSS: &str = include_str!("../../templates/style_index.css");

pub fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(INDEX_CSS.trim_end()))
}

#[derive(Template)]
#[template(path = "la/index.html")]
pub struct IndexTemplateLa {
    pub onion_site: String,
}

#[derive(Template)]
#[template(path = "en/index.html")]
pub struct IndexTemplateEn {
    pub onion_site: String,
}

pub fn handle_landing_page(
    state: &AppState,
    _req: &IncomingRequest,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();

    let html_result = match locale {
        "en" => IndexTemplateEn { onion_site }.render(),
        _ => IndexTemplateLa { onion_site }.render(),
    };

    let html_string = match html_result {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    let headers = crate::utils::http::get_security_headers(get_style_hash());
    (StatusCode::OK, headers, html_string)
}
