pub mod api;

mod landing_page;
mod models_page;
mod providers_page;

pub use landing_page::handle_landing_page;
pub use models_page::handle_models_page;
pub use providers_page::handle_providers_page;

use askama::Template;
use bytes::Bytes;
use hyper::{Method, Uri, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use crate::AppState;

/// Protocol-agnostic request representation.
/// This normalizes the different request sources into a common type so the
/// router logic is identical for HTTP/1.1, HTTP/2, HTTP/3, and Onion.
pub struct IncomingRequest {
    pub method: Method,
    pub uri: Uri,
    pub protocol: &'static str,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Bytes,
}

/// Helper function to create a hyper response body from a String.
pub fn full_body(chunk: String) -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from(chunk)).map_err(|e| match e {}).boxed()
}

fn parse_locale_and_path(path: &str) -> (&str, &str) {
    let supported_locales = ["en", "la"];
    
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > 1 && !segments[1].is_empty() {
        let potential_locale = segments[1];
        if supported_locales.contains(&potential_locale) {
            let remaining_path = if segments.len() == 2 || (segments.len() == 3 && segments[2].is_empty()) {
                "/"
            } else {
                &path[potential_locale.len() + 1..]
            };
            return (potential_locale, remaining_path);
        }
    }
    ("la", path) // default to Latin
}

const STYLE_404_CSS: &str = include_str!("../../templates/404/style.css");

pub fn get_404_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(STYLE_404_CSS.trim_end()))
}

fn handle_not_found(
    _state: &AppState,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    #[derive(Template)]
    #[template(path = "404/page.html")]
    struct NotFoundTemplate {
        locale: crate::i18n::Locale,
    }

    impl NotFoundTemplate {
        fn t(&self, key: &str) -> &'static str {
            crate::i18n::t(self.locale, key)
        }
    }

    let template = NotFoundTemplate { locale: crate::i18n::Locale::from_code(locale) };
    let html_string = match template.render() {
        Ok(html) => html,
        Err(_) => "404 - Sanctuary Not Found (Render failed)".to_string(),
    };

    let headers = crate::utils::http::get_security_headers(get_404_style_hash());
    (StatusCode::NOT_FOUND, headers, full_body(html_string))
}

pub async fn router(
    state: &AppState,
    req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, BoxBody<Bytes, Infallible>) {
    let path = req.uri.path();

    // Check if it's an API, asset, or metadata route first
    if path == "/health"
        || path.starts_with("/fonts/")
        || path.starts_with("/static/")
        || path == "/favicon.ico"
        || path.starts_with("/v1/")
        || req.method == Method::OPTIONS
    {
        match (req.method.clone(), path) {
            // ---- Health / readiness probe ----
            (Method::GET, "/health") => {
                let uptime = state.started_at.elapsed();
                let body = format!(
                    "{{\"status\":\"ok\",\"uptime_secs\":{}}}\n",
                    uptime.as_secs(),
                );
                return (
                    StatusCode::OK,
                    vec![("Content-Type", "application/json; charset=utf-8".into())],
                    full_body(body),
                );
            }

            // ---- Fonts ----
            (Method::GET, path) if path.starts_with("/fonts/") => {
                let filename = path.trim_start_matches("/fonts/");
                
                // Prevent path traversal
                if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
                    return (
                        StatusCode::FORBIDDEN,
                        vec![],
                        Full::new(Bytes::new()).boxed(),
                    );
                }

                let file_path = format!("static/fonts/{}", filename);
                match std::fs::read(&file_path) {
                    Ok(data) => {
                        let mime_type = match filename.split('.').next_back() {
                            Some("woff") => "font/woff",
                            Some("woff2") => "font/woff2",
                            Some("ttf") => "font/ttf",
                            Some("otf") => "font/otf",
                            _ => "application/octet-stream",
                        };

                        let body = Full::new(Bytes::from(data)).map_err(|e| match e {}).boxed();
                        return (
                            StatusCode::OK,
                            vec![
                                ("Content-Type", mime_type.into()),
                                ("Cache-Control", "public, max-age=31536000, immutable".into()),
                                ("Access-Control-Allow-Origin", "*".into()),
                            ],
                            body,
                        );
                    }
                    Err(_) => {
                        return (
                            StatusCode::NOT_FOUND,
                            vec![],
                            Full::new(Bytes::new()).boxed(),
                        );
                    }
                }
            }

            // ---- Static Files ----
            (Method::GET, path) if path.starts_with("/static/") => {
                let filename = path.trim_start_matches("/static/");
                
                // Prevent path traversal
                if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
                    return (
                        StatusCode::FORBIDDEN,
                        vec![],
                        Full::new(Bytes::new()).boxed(),
                    );
                }

                let file_path = format!("static/{}", filename);
                match std::fs::read(&file_path) {
                    Ok(data) => {
                        let mime_type = match filename.split('.').next_back() {
                            Some("png") => "image/png",
                            Some("jpg") | Some("jpeg") => "image/jpeg",
                            Some("ico") => "image/x-icon",
                            Some("svg") => "image/svg+xml",
                            Some("webmanifest") => "application/manifest+json",
                            Some("txt") => "text/plain; charset=utf-8",
                            Some("css") => "text/css; charset=utf-8",
                            Some("js") => "application/javascript; charset=utf-8",
                            _ => "application/octet-stream",
                        };

                        let body = Full::new(Bytes::from(data)).map_err(|e| match e {}).boxed();
                        return (
                            StatusCode::OK,
                            vec![
                                ("Content-Type", mime_type.into()),
                                ("Cache-Control", "public, max-age=31536000, immutable".into()),
                            ],
                            body,
                        );
                    }
                    Err(_) => {
                        return (
                            StatusCode::NOT_FOUND,
                            vec![],
                            Full::new(Bytes::new()).boxed(),
                        );
                    }
                }
            }

            // ---- Favicon ----
            (Method::GET, "/favicon.ico") => {
                let icon_bytes = include_bytes!("../../static/favicon.ico");
                let body = Full::new(Bytes::from_static(icon_bytes)).map_err(|e| match e {}).boxed();
                return (
                    StatusCode::OK,
                    vec![("Content-Type", "image/x-icon".into())],
                    body,
                );
            }

            // ---- CORS Preflight ----
            (Method::OPTIONS, _) => {
                return (
                    StatusCode::OK,
                    vec![],
                    full_body(String::new()),
                );
            }

            // ---- Chat Completions ----
            (Method::POST, "/v1/chat/completions") => {
                return crate::routes::api::chat_completions::handle_secure_openai_proxy(state, req).await;
            }

            // ---- Models ----
            (Method::GET, "/v1/models") => {
                return crate::routes::api::models::handle_models_list(state, &req.uri.to_string()).await;
            }

            // ---- Keys ----
            (Method::GET, "/v1/keys/ephemeral") | (Method::POST, "/v1/keys/ephemeral") => {
                return crate::routes::api::keys::handle_keys_ephemeral(state).await;
            }

            // ---- Near AI Key Proxy ----
            (Method::GET, path) if path.starts_with("/v1/models/nearai/") && path.ends_with("/key") => {
                return crate::routes::api::keys::handle_nearai_model_key(state, req).await;
            }

            // ---- Fallback 404 page ----
            (_, _) => {
                return (
                    StatusCode::NOT_FOUND,
                    vec![],
                    full_body(String::new()),
                );
            }
        }
    }

    // Dynamic localization routing for UI pages
    let (locale, inner_path) = parse_locale_and_path(path);

    // Redirect /la prefix paths to their un-prefixed equivalents (Latin is default)
    if path == "/la" || path.starts_with("/la/") {
        let redirect_uri = match req.uri.query() {
            Some(q) => format!("{}?{}", inner_path, q),
            None => inner_path.to_string(),
        };
        return (
            StatusCode::MOVED_PERMANENTLY,
            vec![("Location", redirect_uri)],
            full_body(String::new()),
        );
    }

    match (req.method.clone(), inner_path) {
        // ---- Landing page ----
        (Method::GET, "/") => {
            let (status, headers, body) = crate::routes::handle_landing_page(state, req, locale).await;
            (status, headers, full_body(body))
        }

        // ---- Models page ----
        (Method::GET, "/models") => {
            let (status, headers, body) = crate::routes::handle_models_page(state, req, locale).await;
            (status, headers, full_body(body))
        }

        // ---- Providers page ----
        (Method::GET, "/providers") => {
            let (status, headers, body) = crate::routes::handle_providers_page(state, req, locale).await;
            (status, headers, full_body(body))
        }

        // ---- Fallback 404 page ----
        (_, _) => {
            handle_not_found(state, locale)
        }
    }
}
