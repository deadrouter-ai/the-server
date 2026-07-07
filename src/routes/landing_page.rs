use askama::Template;
use hyper::StatusCode;
use std::collections::HashSet;
use crate::{AppState, IncomingRequest};
use crate::routes::models_page::{self, RenderModelItem, compare_model_names};

const INDEX_CSS: &str = include_str!("../../templates/index/style.css");

fn get_style_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| crate::utils::http::compute_sha512_b64(INDEX_CSS.trim_end()))
}

#[derive(Template)]
#[template(path = "index/page.html")]
pub struct IndexTemplate {
    pub locale: crate::i18n::Locale,
    pub onion_site: String,
    pub featured_models: Vec<RenderModelItem>,
}

impl IndexTemplate {
    fn t(&self, key: &str) -> &'static str {
        crate::i18n::t(self.locale, key)
    }
}

/// Strips everything but alphanumerics, so id spelling variants (e.g. `glm-5.2`
/// vs `glm-5-2`) that refer to the same release are recognized as duplicates.
fn normalize_id(id: &str) -> String {
    id.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase()
}

/// Picks up to `count` of the highest-version models whose id starts with `prefix`,
/// skipping any that normalize to an id already in `seen`.
fn add_latest_by_prefix(
    pool: &[(String, RenderModelItem)],
    prefix: &str,
    count: usize,
    seen: &mut HashSet<String>,
    selected: &mut Vec<RenderModelItem>,
) {
    let mut family: Vec<&(String, RenderModelItem)> =
        pool.iter().filter(|(id, _)| id.starts_with(prefix)).collect();
    family.sort_by(|a, b| compare_model_names(&b.0, &a.0));

    let mut added = 0;
    for (id, item) in family {
        if added >= count {
            break;
        }
        if seen.insert(normalize_id(id)) {
            selected.push(item.clone());
            added += 1;
        }
    }
}

/// Curates the homepage's "featured models" row from live routing data: the two
/// latest GLM releases, the two latest Kimi releases, and the two most capable
/// remaining models that carry the full ZDR+ZDS+TEE privacy trifecta.
async fn select_featured_models(state: &AppState, locale: &str) -> Vec<RenderModelItem> {
    const TARGET: usize = 6;
    let pool = models_page::collect_model_items(state, locale).await;

    let mut seen = HashSet::new();
    let mut selected = Vec::new();

    add_latest_by_prefix(&pool, "glm", 2, &mut seen, &mut selected);
    add_latest_by_prefix(&pool, "kimi", 2, &mut seen, &mut selected);

    if selected.len() < TARGET {
        let mut rest: Vec<&(String, RenderModelItem)> = pool
            .iter()
            .filter(|(id, item)| item.zdr && item.zds && item.tee && !seen.contains(&normalize_id(id)))
            .collect();
        // Higher output price is a rough proxy for a more capable/flagship model.
        rest.sort_by(|a, b| {
            let price_a: f64 = a.1.price_output.parse().unwrap_or(0.0);
            let price_b: f64 = b.1.price_output.parse().unwrap_or(0.0);
            price_b.partial_cmp(&price_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        for (id, item) in rest {
            if selected.len() >= TARGET {
                break;
            }
            if seen.insert(normalize_id(id)) {
                selected.push(item.clone());
            }
        }
    }

    selected
}

pub async fn handle_landing_page(
    state: &AppState,
    _req: &IncomingRequest,
    locale: &str,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let onion_site = state.onion_data.read().unwrap().onion_domain.clone();
    let locale = crate::i18n::Locale::from_code(locale);
    let featured_models = select_featured_models(state, locale.code()).await;

    let template = IndexTemplate { locale, onion_site, featured_models };
    let html_string = match template.render() {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, vec![], format!("Render failed: {}", e)),
    };

    let headers = crate::utils::http::get_security_headers(get_style_hash());
    (StatusCode::OK, headers, html_string)
}
