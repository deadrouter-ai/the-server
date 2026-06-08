use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use regex::Regex;
use zeroize::Zeroize;

fn get_email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap())
}

fn get_ip_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}(?::[0-9a-f]{1,4}){1,7}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}\b").unwrap())
}

fn get_phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(^|[^a-zA-Z0-9])((?:(?:\+|00)[\s\.\-]*\d{1,3}[\s\.\-]*|\b\d{1,3}[\s\.\-]+)?\(?\d{2,4}\)?(?:[\s\.\-]*\d){5,12}(?:[\s\.\-]*(?:ext\.?|x|extension)[\s\.\-]*\d{1,5})?)\b").unwrap())
}

fn get_cc_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap())
}

fn get_ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b").unwrap())
}

#[derive(Default, Clone)]
pub struct PiiMap {
    pub map: HashMap<String, String>,
}

impl Drop for PiiMap {
    fn drop(&mut self) {
        for v in self.map.values_mut() {
            v.zeroize();
        }
        self.map.clear();
    }
}

impl PiiMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn redact(&mut self, text: &str) -> String {
        let mut result = text.to_string();
        
        let mut counter = 1;
        result = get_email_regex().replace_all(&result, |caps: &regex::Captures| {
            let original = caps[0].to_string();
            let replacement = format!("[EMAIL_{}]", counter);
            self.map.insert(replacement.clone(), original);
            counter += 1;
            replacement
        }).to_string();

        counter = 1;
        result = get_ip_regex().replace_all(&result, |caps: &regex::Captures| {
            let original = caps[0].to_string();
            let replacement = format!("[IP_ADDRESS_{}]", counter);
            self.map.insert(replacement.clone(), original);
            counter += 1;
            replacement
        }).to_string();
        
        counter = 1;
        result = get_cc_regex().replace_all(&result, |caps: &regex::Captures| {
            let original = caps[0].to_string();
            let replacement = format!("[CREDIT_CARD_{}]", counter);
            self.map.insert(replacement.clone(), original);
            counter += 1;
            replacement
        }).to_string();

        counter = 1;
        result = get_ssn_regex().replace_all(&result, |caps: &regex::Captures| {
            let original = caps[0].to_string();
            let replacement = format!("[SSN_{}]", counter);
            self.map.insert(replacement.clone(), original);
            counter += 1;
            replacement
        }).to_string();

        counter = 1;
        result = get_phone_regex().replace_all(&result, |caps: &regex::Captures| {
            let prefix = caps[1].to_string();
            let original = caps[2].to_string();
            let replacement = format!("[PHONE_{}]", counter);
            self.map.insert(replacement.clone(), original);
            counter += 1;
            format!("{}{}", prefix, replacement)
        }).to_string();

        result
    }

    pub fn unredact(&self, text: &str) -> String {
        if self.map.is_empty() { return text.to_string(); }
        let mut result = text.to_string();
        for (redacted, original) in self.map.iter() {
            result = result.replace(redacted, original);
        }
        result
    }
}

pub struct StreamingUnredactor {
    pub pii_map: Arc<PiiMap>,
    buffer: String,
}

impl StreamingUnredactor {
    pub fn new(pii_map: Arc<PiiMap>) -> Self {
        Self {
            pii_map,
            buffer: String::new(),
        }
    }

    pub fn process_chunk(&mut self, chunk: &str) -> String {
        if self.pii_map.map.is_empty() {
            return chunk.to_string();
        }
        self.buffer.push_str(chunk);
        
        let mut output = String::new();
        
        while let Some(pos) = self.buffer.find('[') {
            if let Some(end_pos) = self.buffer[pos..].find(']') {
                let mut actual_start = pos;
                if let Some(inner_pos) = self.buffer[pos + 1..pos + end_pos].rfind('[') {
                    actual_start = pos + 1 + inner_pos;
                }
                let end_idx = pos + end_pos;
                let tag = &self.buffer[actual_start..=end_idx];
                
                output.push_str(&self.buffer[..actual_start]);
                
                if let Some(original) = self.pii_map.map.get(tag) {
                    output.push_str(original);
                } else {
                    output.push_str(tag);
                }
                
                self.buffer = self.buffer[end_idx + 1..].to_string();
            } else {
                if self.buffer.len() - pos > 30 {
                    output.push_str(&self.buffer[..=pos]);
                    self.buffer = self.buffer[pos+1..].to_string();
                } else {
                    output.push_str(&self.buffer[..pos]);
                    self.buffer = self.buffer[pos..].to_string();
                    return output;
                }
            }
        }
        
        output.push_str(&self.buffer);
        self.buffer.clear();
        output
    }
    
    pub fn flush(&mut self) -> String {
        let res = self.buffer.clone();
        self.buffer.clear();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let mut pii_map = PiiMap::new();
        let text = "Contact us at admin@example.com or support@test.co.uk!";
        let redacted = pii_map.redact(text);
        assert_eq!(redacted, "Contact us at [EMAIL_1] or [EMAIL_2]!");
        assert_eq!(pii_map.unredact(&redacted), text);
    }

    #[test]
    fn test_ip_redaction() {
        let mut pii_map = PiiMap::new();
        let text = "IPv4: 192.168.1.1, IPv6: 2001:0db8:85a3::8a2e:0370:7334 and ::1";
        let redacted = pii_map.redact(text);
        assert_eq!(redacted, "IPv4: [IP_ADDRESS_1], IPv6: [IP_ADDRESS_2] and [IP_ADDRESS_3]");
        assert_eq!(pii_map.unredact(&redacted), text);
        
        let mut pii_map2 = PiiMap::new();
        let false_positives = "std::string and http://example.com";
        let redacted2 = pii_map2.redact(false_positives);
        assert_eq!(redacted2, false_positives);
    }

    #[test]
    fn test_phone_redaction() {
        let cases = vec![
            ("Call +1 202 800 9999 now", "Call [PHONE_1] now"),
            ("Or (202) 800-9999", "Or [PHONE_1]"),
            ("What about +44 20 7946 0958?", "What about [PHONE_1]?"),
            ("Unformatted 2028009999 is here", "Unformatted [PHONE_1] is here"),
            ("Extension 202-800-9999 ext 123", "Extension [PHONE_1]"),
            ("E164 +12028009999 format", "E164 [PHONE_1] format"),
            ("Spaced 202 800 9999 format", "Spaced [PHONE_1] format"),
        ];
        
        for (original, expected) in cases {
            let mut map = PiiMap::new();
            assert_eq!(map.redact(original), expected);
            assert_eq!(map.unredact(expected), original);
        }
    }

    #[test]
    fn test_cc_redaction() {
        let mut pii_map = PiiMap::new();
        let text = "My card is 4111 1111 1111 1111 and 1234-5678-9012-3456.";
        let redacted = pii_map.redact(text);
        assert_eq!(redacted, "My card is [CREDIT_CARD_1] and [CREDIT_CARD_2].");
        assert_eq!(pii_map.unredact(&redacted), text);
    }

    #[test]
    fn test_ssn_redaction() {
        let mut pii_map = PiiMap::new();
        let text = "My SSN is 123-45-6789 or 987 65 4321.";
        let redacted = pii_map.redact(text);
        assert_eq!(redacted, "My SSN is [SSN_1] or [SSN_2].");
        assert_eq!(pii_map.unredact(&redacted), text);
    }
}
