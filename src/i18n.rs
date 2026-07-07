//! Locale-aware string lookup, generated at compile time from `locales/*.json`
//! (see `build.rs`). Adding or editing copy is a JSON edit; adding a whole new
//! language additionally needs a `Locale` variant here plus its routing
//! behavior (`code`, `prefix`, `home_href`).
//!
//! Latin is the site's default, unprefixed locale (`/models`); English lives
//! under an `/en` prefix (`/en/models`). Templates call `self.locale.prefix()`
//! to build locale-aware internal links and `self.t("key")` for copy.

include!(concat!(env!("OUT_DIR"), "/i18n_generated.rs"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    La,
}

impl Locale {
    pub fn from_code(code: &str) -> Self {
        match code {
            "en" => Locale::En,
            _ => Locale::La,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::La => "la",
        }
    }

    /// Path prefix for locale-aware internal links (Latin is unprefixed).
    pub fn prefix(self) -> &'static str {
        match self {
            Locale::En => "/en",
            Locale::La => "",
        }
    }

    /// Href for the home page (`prefix() + "/"` would double up for Latin).
    pub fn home_href(self) -> &'static str {
        match self {
            Locale::En => "/en",
            Locale::La => "/",
        }
    }
}

/// Looks up `key` for `locale`, falling back to English for languages with an
/// incomplete translation, then to an empty string if the key doesn't exist at all.
pub fn t(locale: Locale, key: &str) -> &'static str {
    t_raw(locale.code(), key)
        .or_else(|| t_raw("en", key))
        .unwrap_or("")
}
