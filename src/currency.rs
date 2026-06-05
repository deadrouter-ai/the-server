//! Currency types and conversion utilities.
//!
//! Provides a simple USD-based currency conversion system with hardcoded exchange
//! rates. Used by the models page to display pricing in the user's preferred currency.

use serde::{Deserialize, Serialize};

/// Supported display currencies for model pricing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    #[default]
    Usd,
    Eur,
    Jpy,
    Chf,
}

impl Currency {
    /// Parses a currency code string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "USD" => Some(Currency::Usd),
            "EUR" => Some(Currency::Eur),
            "JPY" => Some(Currency::Jpy),
            "CHF" => Some(Currency::Chf),
            _ => None,
        }
    }

    /// Returns the uppercase ISO 4217 code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Currency::Usd => "USD",
            Currency::Eur => "EUR",
            Currency::Jpy => "JPY",
            Currency::Chf => "CHF",
        }
    }
}

/// Convert an amount from USD into the target currency using the hardcoded rates:
/// 1 USD = 200 JPY
/// 1 USD = 0.96 EUR
/// 1 USD = 0.90 CHF
pub fn convert_usd_to(usd_amount: f64, target_currency: Currency) -> f64 {
    match target_currency {
        Currency::Usd => usd_amount,
        Currency::Eur => usd_amount * 0.96,
        Currency::Chf => usd_amount * 0.90,
        Currency::Jpy => usd_amount * 200.0,
    }
}

/// Fixes floating-point imprecision by rounding to a reasonable number of decimal places (e.g., 6)
pub fn round_nice(val: f64) -> f64 {
    (val * 1_000_000.0).round() / 1_000_000.0
}
