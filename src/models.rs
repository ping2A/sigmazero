use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Sigma rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub detection: Detection,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Detection section of a Sigma rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Detection {
    #[serde(flatten)]
    pub selections: HashMap<String, SelectionValue>,
    pub condition: String,
    #[serde(default)]
    pub timeframe: Option<String>,
}

/// A selection can be a single condition or multiple conditions
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SelectionValue {
    Single(ConditionMap),
    Multiple(Vec<ConditionMap>),
}

/// Map of field names to their matching values
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionMap {
    #[serde(flatten)]
    pub conditions: HashMap<String, FieldValue>,
}

/// Values that a field can match against
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    String(String),
    Number(i64),
    Array(Vec<String>),
    Bool(bool),
    Null,
}

/// Field modifiers for advanced matching
#[derive(Debug, Clone, PartialEq)]
pub enum FieldModifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
    Base64,
    Base64Offset,
    Utf16le,
    Utf16be,
    Wide,
    Re,
    Lt,
    Lte,
    Gt,
    Gte,
}

/// Represents a log entry to be evaluated
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

impl LogEntry {
    /// Get a field value as a string
    pub fn get_field(&self, field: &str) -> Option<String> {
        self.fields.get(field).and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    }

    /// Parse field name to extract base field and modifiers
    /// Format: field_name|modifier1|modifier2
    /// Example: CommandLine|contains, ProcessName|endswith
    pub fn parse_field_modifiers(field: &str) -> (String, Vec<FieldModifier>) {
        let parts: Vec<&str> = field.split('|').collect();
        let base_field = parts[0].to_string();
        
        let modifiers = parts[1..]
            .iter()
            .filter_map(|m| match m.to_lowercase().as_str() {
                "contains" => Some(FieldModifier::Contains),
                "startswith" => Some(FieldModifier::StartsWith),
                "endswith" => Some(FieldModifier::EndsWith),
                "all" => Some(FieldModifier::All),
                "base64" => Some(FieldModifier::Base64),
                "base64offset" => Some(FieldModifier::Base64Offset),
                "utf16le" => Some(FieldModifier::Utf16le),
                "utf16be" => Some(FieldModifier::Utf16be),
                "wide" => Some(FieldModifier::Wide),
                "re" => Some(FieldModifier::Re),
                "lt" => Some(FieldModifier::Lt),
                "lte" => Some(FieldModifier::Lte),
                "gt" => Some(FieldModifier::Gt),
                "gte" => Some(FieldModifier::Gte),
                _ => None,
            })
            .collect();
        
        (base_field, modifiers)
    }

    /// Check if a field matches a value with given modifiers
    pub fn field_matches_with_modifiers(
        &self,
        field: &str,
        value: &str,
        modifiers: &[FieldModifier],
    ) -> bool {
        let field_value = match self.get_field(field) {
            Some(v) => v,
            None => return false,
        };

        let field_lower = field_value.to_lowercase();
        let value_lower = value.to_lowercase();

        // If no modifiers or only contains, use default behavior
        if modifiers.is_empty() || modifiers.contains(&FieldModifier::Contains) {
            return self.match_with_wildcard(&field_lower, &value_lower);
        }

        // Apply modifiers
        for modifier in modifiers {
            match modifier {
                FieldModifier::StartsWith => {
                    if !self.match_startswith(&field_lower, &value_lower) {
                        return false;
                    }
                }
                FieldModifier::EndsWith => {
                    if !self.match_endswith(&field_lower, &value_lower) {
                        return false;
                    }
                }
                FieldModifier::All => {
                    // All modifier: split by whitespace and check all parts are present
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.is_empty() {
                        continue;
                    }
                    for part in parts {
                        if !field_lower.contains(&part.to_lowercase()) {
                            return false;
                        }
                    }
                }
                FieldModifier::Re => {
                    if !self.match_regex(&field_value, value) {
                        return false;
                    }
                }
                FieldModifier::Lt => {
                    if !self.compare_numeric(&field_value, value, |a, b| a < b) {
                        return false;
                    }
                }
                FieldModifier::Lte => {
                    if !self.compare_numeric(&field_value, value, |a, b| a <= b) {
                        return false;
                    }
                }
                FieldModifier::Gt => {
                    if !self.compare_numeric(&field_value, value, |a, b| a > b) {
                        return false;
                    }
                }
                FieldModifier::Gte => {
                    if !self.compare_numeric(&field_value, value, |a, b| a >= b) {
                        return false;
                    }
                }
                FieldModifier::Base64 => {
                    if !self.match_base64(&field_value, value) {
                        return false;
                    }
                }
                _ => {
                    // Other modifiers not yet implemented
                    continue;
                }
            }
        }

        true
    }

    /// Match with startswith modifier
    fn match_startswith(&self, field: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Remove leading * if present
            let pattern = pattern.trim_start_matches('*');
            field.starts_with(pattern)
        } else {
            field.starts_with(pattern)
        }
    }

    /// Match with endswith modifier
    fn match_endswith(&self, field: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Remove trailing * if present
            let pattern = pattern.trim_end_matches('*');
            field.ends_with(pattern)
        } else {
            field.ends_with(pattern)
        }
    }

    /// Match with regex modifier
    fn match_regex(&self, field: &str, pattern: &str) -> bool {
        use regex::Regex;
        match Regex::new(pattern) {
            Ok(re) => re.is_match(field),
            Err(_) => false,
        }
    }

    /// Compare numeric values
    fn compare_numeric<F>(&self, field: &str, value: &str, comparator: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        match (field.parse::<f64>(), value.parse::<f64>()) {
            (Ok(field_num), Ok(value_num)) => comparator(field_num, value_num),
            _ => false,
        }
    }

    /// Match base64 encoded content
    fn match_base64(&self, field: &str, pattern: &str) -> bool {
        use base64::{Engine as _, engine::general_purpose};
        
        // Try to decode the field value
        if let Ok(decoded) = general_purpose::STANDARD.decode(field.as_bytes()) {
            if let Ok(decoded_str) = String::from_utf8(decoded) {
                let decoded_lower = decoded_str.to_lowercase();
                let pattern_lower = pattern.to_lowercase();
                return decoded_lower.contains(&pattern_lower);
            }
        }
        false
    }

    /// Match with wildcard support (existing functionality)
    fn match_with_wildcard(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            self.wildcard_match(text, pattern)
        } else {
            text.contains(pattern)
        }
    }

    /// Check if a field contains any of the given values
    pub fn field_contains_any(&self, field: &str, values: &[String]) -> bool {
        // Parse field for modifiers
        let (base_field, modifiers) = Self::parse_field_modifiers(field);
        
        if let Some(field_value) = self.get_field(&base_field) {
            let field_lower = field_value.to_lowercase();
            
            // Check if ALL modifier is present
            let require_all = modifiers.contains(&FieldModifier::All);
            
            if require_all {
                // ALL: every value must match
                values.iter().all(|v| {
                    self.field_matches_with_modifiers(&base_field, v, &modifiers)
                })
            } else {
                // Default: any value can match
                values.iter().any(|v| {
                    if modifiers.is_empty() {
                        let v_lower = v.to_lowercase();
                        if v_lower.contains('*') {
                            self.wildcard_match(&field_lower, &v_lower)
                        } else {
                            field_lower.contains(&v_lower)
                        }
                    } else {
                        self.field_matches_with_modifiers(&base_field, v, &modifiers)
                    }
                })
            }
        } else {
            false
        }
    }

    /// Simple wildcard matching (* matches any characters)
    pub fn wildcard_match(&self, text: &str, pattern: &str) -> bool {
        let parts: Vec<&str> = pattern.split('*').collect();
        
        if parts.is_empty() {
            return true;
        }

        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if i == 0 && !pattern.starts_with('*') {
                // First part must match at the beginning
                if !text.starts_with(part) {
                    return false;
                }
                pos = part.len();
            } else if i == parts.len() - 1 && !pattern.ends_with('*') {
                // Last part must match at the end
                return text.ends_with(part);
            } else {
                // Middle parts can match anywhere after current position
                if let Some(idx) = text[pos..].find(part) {
                    pos += idx + part.len();
                } else {
                    return false;
                }
            }
        }

        true
    }
    
    /// Check if a field exists in the log entry
    pub fn field_exists(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }
}

/// Result of a rule match
#[derive(Debug, Clone, Serialize)]
pub struct RuleMatch {
    pub rule_id: Option<String>,
    pub rule_title: String,
    pub level: Option<String>,
    pub matched_log: LogEntry,
    pub timestamp: String,
}