use hyper::StatusCode;
use askama::Template;
use std::cmp::Ordering;
use crate::AppState;
use crate::IncomingRequest;

include!(concat!(env!("OUT_DIR"), "/model_catalog_generated.rs"));

enum SortChunk {
    Num(u64),
    Text(String),
}

fn parse_sort_chunks(s: &str) -> Vec<SortChunk> {
    let mut chunks = Vec::new();
    let mut chars = s.chars().peekable();
    
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut num_str = String::new();
            while let Some(&next_c) = chars.peek() {
                if next_c.is_ascii_digit() {
                    num_str.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }
            if let Ok(num) = num_str.parse::<u64>() {
                chunks.push(SortChunk::Num(num));
            }
        } else {
            let mut text_str = String::new();
            while let Some(&next_c) = chars.peek() {
                if !next_c.is_ascii_digit() {
                    text_str.push(next_c);
                    chars.next();
                } else {
                    break;
                }
            }
            chunks.push(SortChunk::Text(text_str.to_lowercase()));
        }
    }
    chunks
}

pub(crate) fn compare_model_names(a: &str, b: &str) -> Ordering {
    let chunks_a = parse_sort_chunks(a);
    let chunks_b = parse_sort_chunks(b);
    
    for (ca, cb) in chunks_a.iter().zip(chunks_b.iter()) {
        match (ca, cb) {
            (SortChunk::Num(na), SortChunk::Num(nb)) => {
                if na != nb {
                    return na.cmp(nb);
                }
            }
            (SortChunk::Text(ta), SortChunk::Text(tb)) => {
                if ta != tb {
                    return ta.cmp(tb);
                }
            }
            (SortChunk::Text(_), SortChunk::Num(_)) => return Ordering::Greater,
            (SortChunk::Num(_), SortChunk::Text(_)) => return Ordering::Less,
        }
    }
    chunks_a.len().cmp(&chunks_b.len())
}

#[derive(Clone)]
pub struct RenderModelItem {
    pub name: String,
    pub description: String,
    pub price_input: String,
    pub price_output: String,
    pub zdr: bool,
    pub zds: bool,
    pub tee: bool,
}

const MODELS_CSS: &str = include_str!("../../templates/models/style.css");

fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(MODELS_CSS.trim_end()))
}

#[derive(Template)]
#[template(path = "models/page.html")]
pub struct ModelsTemplate {
    pub locale: crate::i18n::Locale,
    pub onion_site: String,
    pub models: Vec<RenderModelItem>,
    pub search_query: String,
    pub filter_zdr: bool,
    pub filter_zds: bool,
    pub filter_tee: bool,
}

impl ModelsTemplate {
    fn t(&self, key: &str) -> &'static str {
        crate::i18n::t(self.locale, key)
    }
}

pub fn get_model_details(model_id: &str, locale: &str) -> (String, String) {
    if let Some((name, en, la)) = model_catalog_raw(model_id) {
        let desc = if locale == "la" { la } else { en };
        return (name.to_string(), desc.to_string());
    }

    // Fallback for models not yet in the catalog: derive a readable name and a
    // generic description from the raw id (e.g. "some-new-model" -> "Some New Model").
    let fallback_name = model_id
        .replace(['-', '_'], " ")
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<String>>()
        .join(" ");
    let fallback_desc = if locale == "la" {
        format!("Modelum AI anonyme directum: {}. In DeadRouter cum tutela securitatis tuto processum.", fallback_name)
    } else {
        format!("An anonymously routed AI model: {}. Securely processed through DeadRouter with privacy protection.", fallback_name)
    };
    (fallback_name, fallback_desc)
}
fn format_price_1m(price: f64) -> String {
    if price == 0.0 {
        return "0.00".to_string();
    }
    if price < 0.01 {
        format!("{:.4}", price)
    } else if price < 0.1 {
        format!("{:.3}", price)
    } else {
        format!("{:.2}", price)
    }
}

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

/// Collects every routable model with live pricing/capability data, keyed by its
/// upstream model id. Shared by the models page and the homepage's featured-models
/// selection so both read the exact same live routing/pricing state.
pub(crate) async fn collect_model_items(state: &AppState, locale: &str) -> Vec<(String, RenderModelItem)> {
    let mut model_items = Vec::new();
    let routing_read = state.routing_table.read().await;

    for (model_name, provider_ids) in routing_read.iter() {
        let mut cheapest_prompt = f64::MAX;
        let mut cheapest_completion = f64::MAX;
        let mut cheapest_input_1m = 0.0;
        let mut cheapest_output_1m = 0.0;

        let mut zdr_any = false;
        let mut zds_any = false;
        let mut tee_any = false;
        let mut found = false;

        for provider_id in provider_ids {
            if let Some(provider) = state.providers.get(provider_id) {
                let state_read = provider.dynamic_state.read().await;
                if let Some(info) = state_read.dynamic_models.get(model_name) {

                    let final_input = info.price_input_1m;
                    let final_output = info.price_output_1m;

                    let final_input = crate::currency::round_nice(final_input);
                    let final_output = crate::currency::round_nice(final_output);

                    let prompt_price = final_input / 1_000_000.0;
                    let completion_price = final_output / 1_000_000.0;

                    if !found
                        || prompt_price < cheapest_prompt
                        || (prompt_price == cheapest_prompt && completion_price < cheapest_completion)
                    {
                        cheapest_prompt = prompt_price;
                        cheapest_completion = completion_price;
                        cheapest_input_1m = final_input;
                        cheapest_output_1m = final_output;
                        found = true;
                    }

                    if provider.zdr { zdr_any = true; }
                    if provider.zds { zds_any = true; }
                    if provider.tee { tee_any = true; }
                }
            }
        }

        if found {
            let (name, description) = get_model_details(model_name, locale);
            model_items.push((model_name.clone(), RenderModelItem {
                name,
                description,
                price_input: format_price_1m(cheapest_input_1m),
                price_output: format_price_1m(cheapest_output_1m),
                zdr: zdr_any,
                zds: zds_any,
                tee: tee_any,
            }));
        }
    }

    model_items
}

pub async fn handle_models_page(
    state: &AppState,
    req: &IncomingRequest,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    // 1. Parse search query from URI
    let mut search_query = String::new();
    let mut filter_zdr = false;
    let mut filter_zds = false;
    let mut filter_tee = false;

    if let Some(query) = req.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "q" {
                    search_query = url_decode(v)
                        .trim()
                        .to_lowercase();
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

    // 2. Fetch models dynamically, then apply search & toggle filters
    let mut model_items = Vec::new();
    for (model_name, item) in collect_model_items(state, locale).await {
        if !search_query.is_empty() {
            let name_lower = item.name.to_lowercase();
            let id_lower = model_name.to_lowercase();
            if !name_lower.contains(&search_query) && !id_lower.contains(&search_query) {
                continue;
            }
        }

        if filter_zdr && !item.zdr { continue; }
        if filter_zds && !item.zds { continue; }
        if filter_tee && !item.tee { continue; }

        model_items.push(item);
    }

    model_items.sort_by(|a, b| compare_model_names(&a.name, &b.name));

    // 3. Populate and render the Askama template
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    
    let template = ModelsTemplate {
        locale: crate::i18n::Locale::from_code(locale),
        onion_site,
        models: model_items,
        search_query,
        filter_zdr,
        filter_zds,
        filter_tee,
    };

    let html_string = match template.render() {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    // 4. Build the Response with the headers
    let headers = crate::utils::http::get_security_headers(get_style_hash());

    (StatusCode::OK, headers, html_string)
}
