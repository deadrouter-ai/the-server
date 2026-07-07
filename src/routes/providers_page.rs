use askama::Template;
use hyper::StatusCode;
use crate::{AppState, IncomingRequest};

#[derive(Clone)]
#[allow(dead_code)]
pub struct RenderProviderItem {
    pub id: String,
    pub name: String,
    pub description: String,
    pub logo_letter: String,
    pub logo_url: Option<String>,
    pub privacy_rating: u8,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
    pub legal_location: String,
    pub legal_flag: String,
    pub data_processing_location: String,
    pub processing_flag: String,
    pub supported: bool,
}

const PROVIDERS_CSS: &str = include_str!("../../templates/providers/style.css");

fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(PROVIDERS_CSS.trim_end()))
}

#[derive(Template)]
#[template(path = "providers/page.html")]
pub struct ProvidersTemplate {
    pub locale: crate::i18n::Locale,
    pub onion_site: String,
    pub supported_providers: Vec<RenderProviderItem>,
    pub unsupported_providers: Vec<RenderProviderItem>,
    pub search_query: String,
    pub filter_zdr: bool,
    pub filter_zds: bool,
    pub filter_tee: bool,
}

impl ProvidersTemplate {
    fn t(&self, key: &str) -> &'static str {
        crate::i18n::t(self.locale, key)
    }
}

fn get_flag(country_code: &str) -> String {
    match country_code.to_uppercase().as_str() {
        "CH" => "🇨🇭".to_string(),
        "US" => "🇺🇸".to_string(),
        "DE" => "🇩🇪".to_string(),
        "FR" => "🇫🇷".to_string(),
        "GB" => "🇬🇧".to_string(),
        _ => "🌐".to_string(),
    }
}

/// Decodes URL percent-encoding and `+` → space substitution.
fn url_decode(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(&c1), Some(&c2)) = (h1, h2) {
                let hex_str = [c1, c2];
                if let Ok(hex_s) = std::str::from_utf8(&hex_str) {
                    if let Ok(val) = u8::from_str_radix(hex_s, 16) {
                        bytes.push(val);
                    } else {
                        bytes.push(b'%');
                        bytes.push(c1);
                        bytes.push(c2);
                    }
                } else {
                    bytes.push(b'%');
                    bytes.push(c1);
                    bytes.push(c2);
                }
            } else {
                bytes.push(b'%');
                if let Some(&c1) = h1 { bytes.push(c1); }
                if let Some(&c2) = h2 { bytes.push(c2); }
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub async fn handle_providers_page(
    state: &AppState,
    req: &IncomingRequest,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    // 1. Parse search & filter query from URI
    let mut search_query = String::new();
    let mut filter_zdr = false;
    let mut filter_zds = false;
    let mut filter_tee = false;

    if let Some(query) = req.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "q" {
                    search_query = url_decode(v).trim().to_lowercase();
                } else if k == "zdr" && v == "1" {
                    filter_zdr = true;
                } else if k == "zds" && v == "1" {
                    filter_zds = true;
                } else if k == "tee" && v == "1" {
                    filter_tee = true;
                }
            }
        }
    }

    // 2. Fetch and filter active (supported) providers
    let mut supported_items = Vec::new();

    for provider in state.providers.values() {
        // Apply search query filter
        if !search_query.is_empty() {
            let name_lower = provider.name.to_lowercase();
            let id_lower = provider.id.to_lowercase();
            if !name_lower.contains(&search_query) && !id_lower.contains(&search_query) {
                continue;
            }
        }

        // Apply toggle filters
        if filter_zdr && !provider.zdr { continue; }
        if filter_zds && !provider.zds { continue; }
        if filter_tee && !provider.tee { continue; }

        let logo_letter = provider.name
            .chars()
            .find(|c| c.is_alphanumeric())
            .unwrap_or('P')
            .to_string()
            .to_uppercase();

        let logo_url = if let Ok(entries) = std::fs::read_dir("static/logos") {
            let mut found = None;
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let prefix = format!("{}.", provider.id);
                    if name.to_lowercase().starts_with(&prefix) {
                        found = Some(format!("/logos/{}", name));
                        break;
                    }
                }
            }
            found
        } else {
            None
        };

        let legal_flag = get_flag(&provider.legal_location);
        let processing_flag = get_flag(&provider.data_processing_location);

        supported_items.push(RenderProviderItem {
            id: provider.id.clone(),
            name: provider.name.clone(),
            description: provider.description.clone(),
            logo_letter,
            logo_url,
            privacy_rating: provider.privacy_rating,
            zdr: provider.zdr,
            zds: provider.zds,
            tee: provider.tee,
            legal_location: provider.legal_location.to_uppercase(),
            legal_flag,
            data_processing_location: provider.data_processing_location.to_uppercase(),
            processing_flag,
            supported: true,
        });
    }

    // Sort active providers by name
    supported_items.sort_by(|a, b| a.name.cmp(&b.name));

    // 3. Define and filter non-supported (external) providers
    let mut unsupported_candidates = vec![
        RenderProviderItem {
            id: "openai".to_string(),
            name: "OpenAI".to_string(),
            description: "The industry standard for general LLMs. Operates under standard corporate clouds with data retention, telemetry, and training enabled by default.".to_string(),
            logo_letter: "O".to_string(),
            logo_url: Some("/logos/openai.svg".to_string()),
            privacy_rating: 2,
            zdr: false,
            zds: false,
            tee: false,
            legal_location: "US".to_string(),
            legal_flag: get_flag("US"),
            data_processing_location: "US".to_string(),
            processing_flag: get_flag("US"),
            supported: false,
        },
        RenderProviderItem {
            id: "anthropic".to_string(),
            name: "Anthropic".to_string(),
            description: "Creators of the Claude models. Focuses on AI alignment, but processes prompts within central corporate clouds under standard US jurisdictions.".to_string(),
            logo_letter: "A".to_string(),
            logo_url: None,
            privacy_rating: 2,
            zdr: false,
            zds: false,
            tee: false,
            legal_location: "US".to_string(),
            legal_flag: get_flag("US"),
            data_processing_location: "US".to_string(),
            processing_flag: get_flag("US"),
            supported: false,
        },
    ];

    let mut unsupported_items = Vec::new();
    for provider in unsupported_candidates.drain(..) {
        // Apply search query filter
        if !search_query.is_empty() {
            let name_lower = provider.name.to_lowercase();
            let id_lower = provider.id.to_lowercase();
            if !name_lower.contains(&search_query) && !id_lower.contains(&search_query) {
                continue;
            }
        }

        // Apply toggle filters
        if filter_zdr && !provider.zdr { continue; }
        if filter_zds && !provider.zds { continue; }
        if filter_tee && !provider.tee { continue; }

        unsupported_items.push(provider);
    }

    // Sort non-supported by name
    unsupported_items.sort_by(|a, b| a.name.cmp(&b.name));

    // 4. Populate and render the Askama template
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    
    let template = ProvidersTemplate {
        locale: crate::i18n::Locale::from_code(locale),
        onion_site,
        supported_providers: supported_items,
        unsupported_providers: unsupported_items,
        search_query,
        filter_zdr,
        filter_zds,
        filter_tee,
    };

    let html_string = match template.render() {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    // 5. Build the Response with the headers
    let headers = crate::utils::http::get_security_headers(get_style_hash());

    (StatusCode::OK, headers, html_string)
}
