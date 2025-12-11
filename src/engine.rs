use anyhow::{Context, Result};
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::models::{
    ConditionMap, FieldValue, LogEntry, RuleMatch, SelectionValue, SigmaRule,
};
use crate::parser;
use crate::correlation::{CorrelationEngine, CorrelationMatch};

/// The main Sigma rule evaluation engine
pub struct SigmaEngine {
    rules: Vec<Arc<SigmaRule>>,
    workers: usize,
    correlation_engine: Option<Arc<CorrelationEngine>>,
}

impl SigmaEngine {
    /// Create a new Sigma engine
    pub fn new(workers: Option<usize>) -> Self {
        let workers = workers.unwrap_or_else(get_num_cpus);
        
        // Configure rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to set thread pool size: {}", e);
            });

        Self {
            rules: Vec::new(),
            workers,
            correlation_engine: None,
        }
    }

    /// Create a new Sigma engine with correlation support
    pub fn new_with_correlation(workers: Option<usize>, max_history_size: usize) -> Self {
        let workers = workers.unwrap_or_else(get_num_cpus);
        
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to set thread pool size: {}", e);
            });

        Self {
            rules: Vec::new(),
            workers,
            correlation_engine: Some(Arc::new(CorrelationEngine::new(max_history_size))),
        }
    }

    /// Get mutable access to correlation engine
    pub fn correlation_engine_mut(&mut self) -> Option<&mut CorrelationEngine> {
        if let Some(engine) = &mut self.correlation_engine {
            Arc::get_mut(engine)
        } else {
            None
        }
    }

    /// Get reference to correlation engine
    pub fn correlation_engine(&self) -> Option<&CorrelationEngine> {
        self.correlation_engine.as_ref().map(|arc| arc.as_ref())
    }

    /// Load Sigma rules from a directory or a file (#yolo)
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<usize> {
        if rules_dir.is_dir() {
            info!("Loading rules from directory: {:?}", rules_dir);
            let loaded_rules = parser::load_rules_from_directory(rules_dir)?;
            let count = loaded_rules.len();
            self.rules = loaded_rules.into_iter().map(Arc::new).collect();
            Ok(count)
        } else if rules_dir.is_file() {
            info!("Loading rules from file: {:?}", rules_dir);
            let loaded_rule = parser::load_rules_from_file(rules_dir)?;
            self.rules.push(Arc::new(loaded_rule));
            Ok(1)
        } else {
            anyhow::bail!("Rules directory/file does not exist: {:?}", rules_dir);
        }
    }

    /// Evaluate logs against all loaded rules
    pub async fn evaluate_logs(&self, logs_path: &Path) -> Result<Vec<RuleMatch>> {
        if !logs_path.exists() {
            anyhow::bail!("Logs path does not exist: {:?}", logs_path);
        }

        let mut all_matches = Vec::new();

        if logs_path.is_file() {
            let matches = self.process_log_file(logs_path)?;
            all_matches.extend(matches);
        } else if logs_path.is_dir() {
            // Process all JSON log files in the directory
            for entry in std::fs::read_dir(logs_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "json" || ext == "log" {
                            info!("Processing log file: {:?}", path);
                            let matches = self.process_log_file(&path)?;
                            all_matches.extend(matches);
                        }
                    }
                }
            }
        }

        Ok(all_matches)
    }

    /// Process a single log file
    fn process_log_file(&self, file_path: &Path) -> Result<Vec<RuleMatch>> {
        info!("Reading log file: {:?}", file_path);
        
        let file = File::open(file_path)
            .with_context(|| format!("Failed to open log file: {:?}", file_path))?;
        
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
        
        info!("Processing {} log entries in parallel", lines.len());

        // Parse logs in parallel
        let log_entries: Vec<LogEntry> = lines
            .par_iter()
            .filter_map(|line| {
                serde_json::from_str::<LogEntry>(line)
                    .map_err(|e| {
                        debug!("Failed to parse log line: {}", e);
                        e
                    })
                    .ok()
            })
            .collect();

        info!("Successfully parsed {} log entries", log_entries.len());

        // Evaluate each log against all rules in parallel
        let matches: Vec<RuleMatch> = log_entries
            .par_iter()
            .flat_map(|log| {
                self.rules
                    .iter()
                    .filter_map(|rule| self.evaluate_rule(rule, log))
                    .collect::<Vec<_>>()
            })
            .collect();

        // Record matches in correlation engine if enabled
        if let Some(ref correlation_engine) = self.correlation_engine {
            for rule_match in &matches {
                correlation_engine.record_match(rule_match.clone());
            }
        }

        Ok(matches)
    }

        /// Evaluate a single log entry against all rules (for streaming/real-time processing)
    pub fn evaluate_log_entry(&self, log: &LogEntry) -> Vec<RuleMatch> {
        let matches: Vec<RuleMatch> = self.rules
            .iter()
            .filter_map(|rule| self.evaluate_rule(rule, log))
            .collect();

        // Record matches in correlation engine if enabled
        if let Some(ref correlation_engine) = self.correlation_engine {
            for rule_match in &matches {
                correlation_engine.record_match(rule_match.clone());
            }
        }

        matches
    }

    /// Evaluate a batch of log entries against all rules
    pub fn evaluate_log_batch(&self, logs: &[LogEntry]) -> Vec<RuleMatch> {
        let matches: Vec<RuleMatch> = logs
            .par_iter()
            .flat_map(|log| {
                self.rules
                    .iter()
                    .filter_map(|rule| self.evaluate_rule(rule, log))
                    .collect::<Vec<_>>()
            })
            .collect();

        if let Some(ref correlation_engine) = self.correlation_engine {
            for rule_match in &matches {
                correlation_engine.record_match(rule_match.clone());
            }
        }

        matches
    }

    /// Evaluate a stream of log entries with a callback for each match
    pub fn evaluate_log_stream<F>(&self, logs: &[LogEntry], mut callback: F)
    where
        F: FnMut(&RuleMatch),
    {
        for log in logs {
            let matches = self.evaluate_log_entry(log);
            for rule_match in matches {
                callback(&rule_match);
            }
        }
    }

    /// Parse a JSON log line and evaluate it (convenience method)
    pub fn evaluate_log_line(&self, log_line: &str) -> Option<Vec<RuleMatch>> {
        match serde_json::from_str::<LogEntry>(log_line) {
            Ok(log) => Some(self.evaluate_log_entry(&log)),
            Err(e) => {
                debug!("Failed to parse log line: {}", e);
                None
            }
        }
    }

    /// Check for correlation matches
    pub fn check_correlations(&self) -> Vec<CorrelationMatch> {
        if let Some(ref correlation_engine) = self.correlation_engine {
            correlation_engine.check_correlations()
        } else {
            Vec::new()
        }
    }

    /// Evaluate a single rule against a log entry
    fn evaluate_rule(&self, rule: &SigmaRule, log: &LogEntry) -> Option<RuleMatch> {
        // Evaluate the condition expression
        let is_match = self.evaluate_condition_expression(&rule.detection.condition, rule, log);

        if is_match {
            Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                level: rule.level.clone(),
                matched_log: log.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    /// Evaluate a condition expression (supports AND, OR, NOT, parentheses, 1/all of them, etc.)
    fn evaluate_condition_expression(&self, condition: &str, rule: &SigmaRule, log: &LogEntry) -> bool {
        let condition = condition.trim();
        
        // Handle "1 of them" or "all of them" patterns
        if condition.contains("of them") || condition.contains("of selection") {
            return self.evaluate_of_pattern(condition, rule, log);
        }
        
        // Handle "1 of" pattern (e.g., "1 of filter*")
        if condition.starts_with("1 of") || condition.contains("| count") {
            return self.evaluate_aggregation_pattern(condition, rule, log);
        }

        // Parse and evaluate the expression
        self.parse_and_evaluate_expression(condition, rule, log)
    }

    /// Parse and evaluate complex boolean expressions with AND, OR, NOT, and parentheses
    fn parse_and_evaluate_expression(&self, expr: &str, rule: &SigmaRule, log: &LogEntry) -> bool {
        let expr = expr.trim();
        
        // Handle NOT operator
        if expr.starts_with("not ") {
            let inner = &expr[4..].trim();
            return !self.parse_and_evaluate_expression(inner, rule, log);
        }
        
        // Handle parentheses
        if expr.starts_with('(') && expr.ends_with(')') {
            let inner = &expr[1..expr.len()-1];
            return self.parse_and_evaluate_expression(inner, rule, log);
        }
        
        // Split by OR (lower precedence)
        if let Some(or_pos) = find_operator(expr, " or ") {
            let left = &expr[..or_pos];
            let right = &expr[or_pos + 4..];
            return self.parse_and_evaluate_expression(left, rule, log) 
                || self.parse_and_evaluate_expression(right, rule, log);
        }
        
        // Split by AND (higher precedence)
        if let Some(and_pos) = find_operator(expr, " and ") {
            let left = &expr[..and_pos];
            let right = &expr[and_pos + 5..];
            return self.parse_and_evaluate_expression(left, rule, log) 
                && self.parse_and_evaluate_expression(right, rule, log);
        }
        
        // Base case: evaluate single selection
        self.evaluate_selection(expr.trim(), rule, log)
    }

    /// Evaluate "of them" patterns like "1 of them", "all of them", "1 of selection*"
    fn evaluate_of_pattern(&self, condition: &str, rule: &SigmaRule, log: &LogEntry) -> bool {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        
        if parts.len() < 3 {
            return false;
        }
        
        let count_spec = parts[0];
        let pattern = if parts.len() > 3 { parts[3] } else { "*" };
        
        // Get matching selections
        let matching_selections: Vec<_> = rule.detection.selections.keys()
            .filter(|key| {
                *key != "condition" && *key != "timeframe" && 
                (pattern == "*" || pattern == "them" || 
                 key.starts_with(&pattern.trim_end_matches('*')))
            })
            .collect();
        
        // Count how many match
        let match_count = matching_selections.iter()
            .filter(|sel| self.evaluate_selection(sel, rule, log))
            .count();
        
        // Evaluate based on count specification
        match count_spec {
            "1" => match_count >= 1,
            "all" => match_count == matching_selections.len() && !matching_selections.is_empty(),
            _ => {
                // Handle numeric patterns like "2" or ranges
                if let Ok(required) = count_spec.parse::<usize>() {
                    match_count >= required
                } else {
                    false
                }
            }
        }
    }

    /// Evaluate aggregation patterns (placeholder for future implementation)
    fn evaluate_aggregation_pattern(&self, condition: &str, rule: &SigmaRule, log: &LogEntry) -> bool {
        // For now, treat like "1 of them"
        self.evaluate_of_pattern(condition, rule, log)
    }

    /// Evaluate a specific selection against a log
    fn evaluate_selection(&self, selection_name: &str, rule: &SigmaRule, log: &LogEntry) -> bool {
        if let Some(selection) = rule.detection.selections.get(selection_name) {
            match selection {
                SelectionValue::Single(condition_map) => {
                    self.evaluate_condition_map(condition_map, log)
                }
                SelectionValue::Multiple(condition_maps) => {
                    // Multiple conditions: at least one must match
                    condition_maps
                        .iter()
                        .any(|cm| self.evaluate_condition_map(cm, log))
                }
            }
        } else {
            false
        }
    }

    /// Evaluate a condition map against a log
    fn evaluate_condition_map(&self, condition_map: &ConditionMap, log: &LogEntry) -> bool {
        // All conditions in the map must be satisfied
        for (field, value) in &condition_map.conditions {
            if !self.evaluate_field_condition(field, value, log) {
                return false;
            }
        }
        true
    }

    /// Evaluate a single field condition
    fn evaluate_field_condition(&self, field: &str, value: &FieldValue, log: &LogEntry) -> bool {
        use crate::models::{LogEntry as _, FieldModifier};
        
        // Parse field name and modifiers
        let (base_field, modifiers) = LogEntry::parse_field_modifiers(field);
        
        // Special handling for null values
        if matches!(value, FieldValue::Null) {
            return !log.field_exists(&base_field);
        }
        
        match value {
            FieldValue::String(s) => {
                self.evaluate_string_with_modifiers(&base_field, s, &modifiers, log)
            }
            FieldValue::Array(arr) => {
                arr.iter().any(|v| {
                    self.evaluate_string_with_modifiers(&base_field, v, &modifiers, log)
                })
            }
            FieldValue::Number(n) => {
                if modifiers.iter().any(|m| matches!(m, 
                    FieldModifier::Lt | FieldModifier::Lte | 
                    FieldModifier::Gt | FieldModifier::Gte)) 
                {
                    self.evaluate_numeric_comparison(&base_field, *n, &modifiers, log)
                } else if let Some(field_value) = log.get_field(&base_field) {
                    field_value == n.to_string()
                } else {
                    false
                }
            }
            FieldValue::Bool(b) => {
                if let Some(field_value) = log.get_field(&base_field) {
                    field_value.to_lowercase() == b.to_string().to_lowercase()
                } else {
                    false
                }
            }
            FieldValue::Null => false, // Already handled above
        }
    }
    
    /// Evaluate string value with field modifiers
    fn evaluate_string_with_modifiers(
        &self, 
        field: &str, 
        value: &str, 
        modifiers: &[crate::models::FieldModifier], 
        log: &LogEntry
    ) -> bool {
        use crate::models::FieldModifier;
        
        if modifiers.is_empty() {
            // Default behavior: wildcard or contains matching
            return log.field_contains_any(field, &[value.to_string()]);
        }
        
        let field_value = match log.get_field(field) {
            Some(v) => v,
            None => return false,
        };
        
        let field_lower = field_value.to_lowercase();
        let value_lower = value.to_lowercase();
        
        for modifier in modifiers {
            let matches = match modifier {
                FieldModifier::Contains => field_lower.contains(&value_lower),
                FieldModifier::StartsWith => field_lower.starts_with(&value_lower),
                FieldModifier::EndsWith => field_lower.ends_with(&value_lower),
                FieldModifier::Re => {
                    if let Ok(re) = regex::Regex::new(value) {
                        re.is_match(&field_value)
                    } else {
                        false
                    }
                }
                FieldModifier::All => {
                    // For "all" modifier, all parts must be present
                    value.split_whitespace()
                        .all(|part| field_lower.contains(&part.to_lowercase()))
                }
                FieldModifier::Base64 | FieldModifier::Base64Offset => {
                    // Decode base64 encoded search term
                    if let Ok(decoded) = base64::decode(value) {
                        if let Ok(decoded_str) = String::from_utf8(decoded) {
                            field_lower.contains(&decoded_str.to_lowercase())
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                FieldModifier::Utf16le | FieldModifier::Utf16be | FieldModifier::Wide => {
                    // Convert search term to UTF-16 and look for it in field
                    let utf16: Vec<u16> = value.encode_utf16().collect();
                    let search_bytes: Vec<u8> = utf16.iter()
                        .flat_map(|&c| {
                            if matches!(modifier, FieldModifier::Utf16be) {
                                vec![(c >> 8) as u8, c as u8]
                            } else {
                                vec![c as u8, (c >> 8) as u8]
                            }
                        })
                        .collect();
                    
                    field_value.as_bytes()
                        .windows(search_bytes.len())
                        .any(|window| window == search_bytes.as_slice())
                }
                _ => false,
            };
            
            if !matches {
                return false;
            }
        }
        
        true
    }
    
    /// Evaluate numeric comparisons
    fn evaluate_numeric_comparison(
        &self,
        field: &str,
        value: i64,
        modifiers: &[crate::models::FieldModifier],
        log: &LogEntry,
    ) -> bool {
        use crate::models::FieldModifier;
        
        let field_value = match log.get_field(field) {
            Some(v) => v,
            None => return false,
        };
        
        let field_num: i64 = match field_value.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        
        for modifier in modifiers {
            let matches = match modifier {
                FieldModifier::Lt => field_num < value,
                FieldModifier::Lte => field_num <= value,
                FieldModifier::Gt => field_num > value,
                FieldModifier::Gte => field_num >= value,
                _ => continue,
            };
            
            if !matches {
                return false;
            }
        }
        
        true
    }
}

// Helper function to get number of CPUs
fn get_num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// Helper function to find operator position outside of parentheses
fn find_operator(expr: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let expr_lower = expr.to_lowercase();
    let op_lower = op.to_lowercase();
    let chars: Vec<char> = expr.chars().collect();
    
    for i in 0..chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        
        if depth == 0 && i + op.len() <= expr.len() {
            let substr = &expr_lower[i..std::cmp::min(i + op.len(), expr.len())];
            if substr == op_lower {
                return Some(i);
            }
        }
    }
    
    None
}
