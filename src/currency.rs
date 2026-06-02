use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Currency {
    #[default]
    USD,
    EUR,
    JPY,
    CHF,
}

impl Currency {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "USD" => Some(Currency::USD),
            "EUR" => Some(Currency::EUR),
            "JPY" => Some(Currency::JPY),
            "CHF" => Some(Currency::CHF),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Currency::USD => "USD",
            Currency::EUR => "EUR",
            Currency::JPY => "JPY",
            Currency::CHF => "CHF",
        }
    }
}

/// Convert an amount from USD into the target currency using the hardcoded rates:
/// 1 USD = 200 JPY
/// 1 USD = 0.96 EUR
/// 1 USD = 0.90 CHF
pub fn convert_usd_to(usd_amount: f64, target_currency: Currency) -> f64 {
    match target_currency {
        Currency::USD => usd_amount,
        Currency::EUR => usd_amount * 0.96,
        Currency::CHF => usd_amount * 0.90,
        Currency::JPY => usd_amount * 200.0,
    }
}

/// Fixes floating-point imprecision by rounding to a reasonable number of decimal places (e.g., 6)
pub fn round_nice(val: f64) -> f64 {
    (val * 1_000_000.0).round() / 1_000_000.0
}
