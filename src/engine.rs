use anyhow::{Context, Result};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::models::{
    ConditionMap, FieldValue, LogEntry, RuleMatch, SelectionValue, SigmaRule, FieldModifier
};
use crate::parser;
use crate::correlation::{CorrelationEngine, CorrelationMatch};

/// Pre-parsed condition expression (avoids re-parsing on every log entry)
/// Operator for threshold/count conditions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CountOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

#[derive(Debug, Clone)]
pub enum ConditionExpr {
    SelectionRef(String),
    Not(Box<ConditionExpr>),
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    OfThem { count_spec: String, pattern: String },
    /// Threshold: selection | count > N (evaluated only over a batch of logs)
    CountOver {
        selection_ref: String,
        op: CountOp,
        threshold: u64,
    },
}

/// Pre-parsed field condition (base field + modifiers parsed once at load time)
#[derive(Debug, Clone)]
pub struct ParsedFieldCondition {
    pub base_field: String,
    pub modifiers: Vec<FieldModifier>,
    pub value: FieldValue,
}

/// Per-selection compiled condition maps (each map = list of parsed field conditions)
pub type CompiledConditionMap = Vec<ParsedFieldCondition>;

/// All condition maps for one selection (Single = one map, Multiple = many)
pub type CompiledSelection = Vec<CompiledConditionMap>;

/// Pre-parsed detection: selection name -> list of condition maps
pub type CompiledDetection = HashMap<String, CompiledSelection>;

/// The main Sigma rule evaluation engine
pub struct SigmaEngine {
    /// Rules with pre-parsed condition AST and compiled field conditions (None = fallback)
    pub rules: Vec<(Arc<SigmaRule>, Option<ConditionExpr>, Option<CompiledDetection>)>,
    /// Pre-compiled regexes keyed by pattern string (avoids compiling on every match)
    regex_cache: HashMap<String, Arc<regex::Regex>>,
    /// Optional field mapping: rule field name -> log field name (e.g. CommandLine -> command_line)
    field_map: Option<HashMap<String, String>>,
    pub workers: usize,
    pub correlation_engine: Option<Arc<CorrelationEngine>>,
}

impl SigmaEngine {
    /// Create a new Sigma engine
    pub fn new(workers: Option<usize>) -> Self {
        let workers = workers.unwrap_or_else(get_num_cpus);
        
        // Configure rayon thread pool (native only)
        #[cfg(not(target_arch = "wasm32"))]
        {
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build_global()
                .unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to set thread pool size: {}", e);
                });
        }

        Self {
            rules: Vec::new(),
            regex_cache: HashMap::new(),
            field_map: None,
            workers,
            correlation_engine: None,
        }
    }

    /// Create a new Sigma engine with correlation support
    pub fn new_with_correlation(workers: Option<usize>, max_history_size: usize) -> Self {
        let workers = workers.unwrap_or_else(get_num_cpus);
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build_global()
                .unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to set thread pool size: {}", e);
                });
        }

        Self {
            rules: Vec::new(),
            regex_cache: HashMap::new(),
            field_map: None,
            workers,
            correlation_engine: Some(Arc::new(CorrelationEngine::new(max_history_size))),
        }
    }

    /// Set field mapping: rule field name -> log field name (e.g. CommandLine -> command_line)
    pub fn set_field_map(&mut self, map: HashMap<String, String>) {
        self.field_map = Some(map);
    }

    /// Resolve rule field name to log field name using field_map if set
    fn resolve_field(&self, rule_field: &str) -> String {
        self.field_map
            .as_ref()
            .and_then(|m| m.get(rule_field).cloned())
            .unwrap_or_else(|| rule_field.to_string())
    }

    /// Load rules from an already-parsed list (e.g. after filtering). Returns number of rules loaded.
    pub fn load_rules_from_rules(&mut self, rules: Vec<SigmaRule>) -> Result<usize> {
        let count = rules.len();
        self.rules = rules
            .into_iter()
            .map(|r| (Arc::new(r), None, None))
            .collect();
        self.build_regex_cache();
        self.parse_condition_asts();
        self.build_compiled_detections();
        Ok(count)
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

    /// Load Sigma rules from a directory or a file (native only)
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_rules(&mut self, rules_dir: &Path) -> Result<usize> {
        if rules_dir.is_dir() {
            info!("Loading rules from directory: {:?}", rules_dir);
            let loaded_rules = parser::load_rules_from_directory(rules_dir)?;
            let count = loaded_rules.len();
            self.rules = loaded_rules
                .into_iter()
                .map(|r| (Arc::new(r), None, None))
                .collect();
            self.build_regex_cache();
            self.parse_condition_asts();
            self.build_compiled_detections();
            Ok(count)
        } else if rules_dir.is_file() {
            info!("Loading rules from file: {:?}", rules_dir);
            let loaded_rule = parser::load_rules_from_file(rules_dir)?;
            self.rules.push((Arc::new(loaded_rule), None, None));
            self.build_regex_cache();
            self.parse_condition_asts();
            self.build_compiled_detections();
            Ok(1)
        } else {
            anyhow::bail!("Rules directory/file does not exist: {:?}", rules_dir);
        }
    }

    /// Load rules from string (works on both WASM and native)
    pub fn load_rules_from_string(&mut self, yaml_content: &str) -> Result<usize> {
        let rules: Vec<SigmaRule> = serde_yaml::from_str(yaml_content)?;
        let count = rules.len();
        self.rules = rules
            .into_iter()
            .map(|r| (Arc::new(r), None, None))
            .collect();
        self.build_regex_cache();
        self.parse_condition_asts();
        self.build_compiled_detections();
        Ok(count)
    }

    /// Extract all regex patterns from rules and compile them into the cache
    fn build_regex_cache(&mut self) {
        for (rule, _, _) in &self.rules {
            for pattern in extract_regex_patterns(rule) {
                if !self.regex_cache.contains_key(&pattern) {
                    if let Ok(re) = regex::Regex::new(&pattern) {
                        self.regex_cache.insert(pattern, Arc::new(re));
                    }
                }
            }
        }
    }

    /// Parse condition strings into ASTs for all rules
    fn parse_condition_asts(&mut self) {
        for (rule, ast, _) in &mut self.rules {
            *ast = parse_condition_to_ast(rule.detection.condition.trim());
        }
    }

    /// Pre-parse field modifiers for all rules (avoids parsing on every evaluation)
    fn build_compiled_detections(&mut self) {
        for (rule, _, compiled) in &mut self.rules {
            *compiled = Some(compile_detection(rule));
        }
    }

    /// Evaluate logs against all loaded rules (native only - requires file I/O)
    #[cfg(not(target_arch = "wasm32"))]
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

    /// Process a single log file (native only)
    #[cfg(not(target_arch = "wasm32"))]
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

        // Wrap logs in Arc once so matches can share references (no full log clone per match)
        let log_arcs: Vec<Arc<LogEntry>> = log_entries.into_iter().map(Arc::new).collect();

        // Evaluate each log against all rules in parallel (skip count rules; handled below)
        let mut matches: Vec<RuleMatch> = log_arcs
            .par_iter()
            .flat_map(|log_arc| {
                self.rules
                    .iter()
                    .filter_map(|(rule, ast, compiled)| {
                        if matches!(ast, Some(ConditionExpr::CountOver { .. })) {
                            return None;
                        }
                        self.evaluate_rule(rule, ast.as_ref(), compiled.as_ref(), log_arc)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        // Evaluate threshold/count rules over the full batch
        for (rule, ast, compiled) in &self.rules {
            if let Some(ConditionExpr::CountOver {
                selection_ref,
                op,
                threshold,
            }) = ast
            {
                let count = log_arcs
                    .par_iter()
                    .filter(|log_arc| {
                        self.evaluate_selection(
                            selection_ref,
                            rule,
                            compiled.as_ref(),
                            log_arc.as_ref(),
                        )
                    })
                    .count() as u64;
                let satisfied = match op {
                    CountOp::Gt => count > *threshold,
                    CountOp::Gte => count >= *threshold,
                    CountOp::Lt => count < *threshold,
                    CountOp::Lte => count <= *threshold,
                    CountOp::Eq => count == *threshold,
                };
                if satisfied {
                    for log_arc in &log_arcs {
                        if self.evaluate_selection(
                            selection_ref,
                            rule,
                            compiled.as_ref(),
                            log_arc.as_ref(),
                        ) {
                            matches.push(RuleMatch {
                                rule_id: rule.id.clone(),
                                rule_title: rule.title.clone(),
                                level: rule.level.clone(),
                                matched_log: Arc::clone(log_arc),
                                timestamp: current_timestamp(),
                            });
                        }
                    }
                }
            }
        }

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
        let log_arc = Arc::new(log.clone());
        let matches: Vec<RuleMatch> = self.rules
            .iter()
            .filter_map(|(rule, ast, compiled)| {
                self.evaluate_rule(rule, ast.as_ref(), compiled.as_ref(), &log_arc)
            })
            .collect();

        // Record matches in correlation engine if enabled
        if let Some(ref correlation_engine) = self.correlation_engine {
            for rule_match in &matches {
                correlation_engine.record_match(rule_match.clone());
            }
        }

        matches
    }

    /// Evaluate a batch of log entries against all rules (with conditional parallelization).
    /// Includes threshold/count rules (e.g. "selection | count > 5") evaluated over the batch.
    pub fn evaluate_log_batch(&self, logs: &[LogEntry]) -> Vec<RuleMatch> {
        let log_arcs: Vec<Arc<LogEntry>> = logs.iter().map(|l| Arc::new(l.clone())).collect();

        #[cfg(not(target_arch = "wasm32"))]
        let mut matches: Vec<RuleMatch> = log_arcs
            .par_iter()
            .flat_map(|log_arc| {
                self.rules
                    .iter()
                    .filter_map(|(rule, ast, compiled)| {
                        // Skip count rules; they are evaluated below over the full batch
                        if matches!(ast, Some(ConditionExpr::CountOver { .. })) {
                            return None;
                        }
                        self.evaluate_rule(rule, ast.as_ref(), compiled.as_ref(), log_arc)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        #[cfg(target_arch = "wasm32")]
        let mut matches: Vec<RuleMatch> = log_arcs
            .iter()
            .flat_map(|log_arc| {
                self.rules
                    .iter()
                    .filter_map(|(rule, ast, compiled)| {
                        if matches!(ast, Some(ConditionExpr::CountOver { .. })) {
                            return None;
                        }
                        self.evaluate_rule(rule, ast.as_ref(), compiled.as_ref(), log_arc)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        // Evaluate threshold/count rules over the batch
        for (rule, ast, compiled) in &self.rules {
            if let Some(ConditionExpr::CountOver {
                selection_ref,
                op,
                threshold,
            }) = ast
            {
                let count = log_arcs
                    .iter()
                    .filter(|log_arc| {
                        self.evaluate_selection(
                            selection_ref,
                            rule,
                            compiled.as_ref(),
                            log_arc.as_ref(),
                        )
                    })
                    .count() as u64;
                let satisfied = match op {
                    CountOp::Gt => count > *threshold,
                    CountOp::Gte => count >= *threshold,
                    CountOp::Lt => count < *threshold,
                    CountOp::Lte => count <= *threshold,
                    CountOp::Eq => count == *threshold,
                };
                if satisfied {
                    // Emit one match per matching log (or we could emit a single aggregate)
                    for log_arc in &log_arcs {
                        if self.evaluate_selection(
                            selection_ref,
                            rule,
                            compiled.as_ref(),
                            log_arc.as_ref(),
                        ) {
                            matches.push(RuleMatch {
                                rule_id: rule.id.clone(),
                                rule_title: rule.title.clone(),
                                level: rule.level.clone(),
                                matched_log: Arc::clone(log_arc),
                                timestamp: current_timestamp(),
                            });
                        }
                    }
                }
            }
        }

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

    /// Evaluate a single rule against a log entry.
    /// `log` is `Arc<LogEntry>` so the match can store a cheap clone instead of cloning the full log.
    pub fn evaluate_rule(
        &self,
        rule: &SigmaRule,
        condition_ast: Option<&ConditionExpr>,
        compiled_detection: Option<&CompiledDetection>,
        log: &Arc<LogEntry>,
    ) -> Option<RuleMatch> {
        let log_ref: &LogEntry = log.as_ref();
        let is_match = if let Some(ast) = condition_ast {
            self.evaluate_condition_ast(ast, rule, compiled_detection, log_ref)
        } else {
            self.evaluate_condition_expression(
                &rule.detection.condition,
                rule,
                compiled_detection,
                log_ref,
            )
        };

        if is_match {
            Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_title: rule.title.clone(),
                level: rule.level.clone(),
                matched_log: Arc::clone(log),
                timestamp: current_timestamp(),
            })
        } else {
            None
        }
    }

    /// Evaluate a pre-parsed condition AST
    fn evaluate_condition_ast(
        &self,
        ast: &ConditionExpr,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        match ast {
            ConditionExpr::SelectionRef(name) => {
                self.evaluate_selection(name, rule, compiled_detection, log)
            }
            ConditionExpr::Not(inner) => {
                !self.evaluate_condition_ast(inner, rule, compiled_detection, log)
            }
            ConditionExpr::And(left, right) => {
                self.evaluate_condition_ast(left, rule, compiled_detection, log)
                    && self.evaluate_condition_ast(right, rule, compiled_detection, log)
            }
            ConditionExpr::Or(left, right) => {
                self.evaluate_condition_ast(left, rule, compiled_detection, log)
                    || self.evaluate_condition_ast(right, rule, compiled_detection, log)
            }
            ConditionExpr::OfThem { count_spec, pattern } => {
                self.evaluate_of_pattern_ast(count_spec, pattern, rule, compiled_detection, log)
            }
            ConditionExpr::CountOver { .. } => {
                // Per-log we cannot evaluate count; only batch evaluation can
                false
            }
        }
    }

    /// Evaluate "of them" AST node
    fn evaluate_of_pattern_ast(
        &self,
        count_spec: &str,
        pattern: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        let pattern = if pattern.is_empty() { "*" } else { pattern };
        let matching_selections: Vec<_> = rule
            .detection
            .selections
            .keys()
            .filter(|key| {
                if *key == "condition" || *key == "timeframe" {
                    return false;
                }
                if pattern == "*" || pattern == "them" {
                    true
                } else if pattern.ends_with('*') {
                    key.starts_with(pattern.trim_end_matches('*'))
                } else {
                    *key == pattern
                }
            })
            .collect();
        let match_count = matching_selections
            .iter()
            .filter(|sel| self.evaluate_selection(sel, rule, compiled_detection, log))
            .count();
        match count_spec {
            "1" => match_count >= 1,
            "all" => match_count == matching_selections.len() && !matching_selections.is_empty(),
            _ => count_spec
                .parse::<usize>()
                .map(|required| match_count >= required)
                .unwrap_or(false),
        }
    }

    /// Evaluate a condition expression (supports AND, OR, NOT, parentheses, 1/all of them, etc.)
    /// Used as fallback when AST parsing failed.
    fn evaluate_condition_expression(
        &self,
        condition: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        let condition = condition.trim();

        if condition.contains("of them") || condition.contains("of selection") {
            return self.evaluate_of_pattern(condition, rule, compiled_detection, log);
        }
        if condition.starts_with("1 of") || condition.contains("| count") {
            return self.evaluate_aggregation_pattern(condition, rule, compiled_detection, log);
        }
        self.parse_and_evaluate_expression(condition, rule, compiled_detection, log)
    }

    /// Parse and evaluate complex boolean expressions with AND, OR, NOT, and parentheses
    fn parse_and_evaluate_expression(
        &self,
        expr: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        let expr = expr.trim();

        if expr.starts_with("not ") {
            let inner = expr[4..].trim();
            return !self.parse_and_evaluate_expression(inner, rule, compiled_detection, log);
        }

        if expr.starts_with('(') && expr.ends_with(')') {
            let mut depth = 0;
            let chars: Vec<char> = expr.chars().collect();
            let mut valid_outer_parens = true;
            for (i, &ch) in chars.iter().enumerate() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 && i < chars.len() - 1 {
                            valid_outer_parens = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if valid_outer_parens && depth == 0 {
                let inner = &expr[1..expr.len() - 1];
                return self.parse_and_evaluate_expression(inner, rule, compiled_detection, log);
            }
        }

        if let Some(or_pos) = find_operator(expr, " or ") {
            let left = expr[..or_pos].trim();
            let right = expr[or_pos + 4..].trim();
            return self.parse_and_evaluate_expression(left, rule, compiled_detection, log)
                || self.parse_and_evaluate_expression(right, rule, compiled_detection, log);
        }
        if let Some(and_pos) = find_operator(expr, " and ") {
            let left = expr[..and_pos].trim();
            let right = expr[and_pos + 5..].trim();
            return self.parse_and_evaluate_expression(left, rule, compiled_detection, log)
                && self.parse_and_evaluate_expression(right, rule, compiled_detection, log);
        }
        self.evaluate_selection(expr.trim(), rule, compiled_detection, log)
    }

    /// Evaluate "of them" patterns like "1 of them", "all of them", "1 of selection*"
    fn evaluate_of_pattern(
        &self,
        condition: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        if parts.len() < 3 {
            return false;
        }
        let count_spec = parts[0];
        let pattern = parts.get(2).unwrap_or(&"*");
        let matching_selections: Vec<_> = rule
            .detection
            .selections
            .keys()
            .filter(|key| {
                if *key == "condition" || *key == "timeframe" {
                    return false;
                }
                if *pattern == "*" || *pattern == "them" {
                    true
                } else if pattern.ends_with('*') {
                    key.starts_with(pattern.trim_end_matches('*'))
                } else {
                    *key == *pattern
                }
            })
            .collect();
        let match_count = matching_selections
            .iter()
            .filter(|sel| self.evaluate_selection(sel, rule, compiled_detection, log))
            .count();
        match count_spec {
            "1" => match_count >= 1,
            "all" => match_count == matching_selections.len() && !matching_selections.is_empty(),
            _ => count_spec
                .parse::<usize>()
                .map(|required| match_count >= required)
                .unwrap_or(false),
        }
    }

    /// Evaluate aggregation patterns (placeholder for future implementation)
    fn evaluate_aggregation_pattern(
        &self,
        condition: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        self.evaluate_of_pattern(condition, rule, compiled_detection, log)
    }

    /// Evaluate a specific selection against a log (uses pre-parsed conditions when available)
    fn evaluate_selection(
        &self,
        selection_name: &str,
        rule: &SigmaRule,
        compiled_detection: Option<&CompiledDetection>,
        log: &LogEntry,
    ) -> bool {
        // Use pre-parsed field conditions when available (avoids parsing modifiers on every eval)
        if let Some(compiled) = compiled_detection {
            if let Some(parsed_maps) = compiled.get(selection_name) {
                return parsed_maps
                    .iter()
                    .any(|parsed_map| self.evaluate_parsed_condition_map(parsed_map, log));
            }
        }
        // Fallback: parse field modifiers on each evaluation
        if let Some(selection) = rule.detection.selections.get(selection_name) {
            match selection {
                SelectionValue::Single(condition_map) => {
                    self.evaluate_condition_map(condition_map, log)
                }
                SelectionValue::Multiple(condition_maps) => {
                    condition_maps
                        .iter()
                        .any(|cm| self.evaluate_condition_map(cm, log))
                }
            }
        } else {
            false
        }
    }

    /// Evaluate a pre-parsed condition map (no field parsing in hot path)
    fn evaluate_parsed_condition_map(
        &self,
        parsed_map: &[ParsedFieldCondition],
        log: &LogEntry,
    ) -> bool {
        for parsed in parsed_map {
            if !self.evaluate_parsed_field_condition(parsed, log) {
                return false;
            }
        }
        true
    }

    /// Evaluate a single pre-parsed field condition
    fn evaluate_parsed_field_condition(
        &self,
        parsed: &ParsedFieldCondition,
        log: &LogEntry,
    ) -> bool {
        let base_field = &parsed.base_field;
        let modifiers = &parsed.modifiers;
        let value = &parsed.value;

        let lookup = self.resolve_field(base_field);
        if matches!(value, FieldValue::Null) {
            return !log.field_exists(&lookup);
        }

        match value {
            FieldValue::String(s) => {
                self.evaluate_string_with_modifiers(&lookup, s, modifiers, log)
            }
            FieldValue::Array(arr) => arr
                .iter()
                .any(|v| self.evaluate_string_with_modifiers(&lookup, v, modifiers, log)),
            FieldValue::Number(n) => {
                if modifiers.iter().any(|m| {
                    matches!(
                        m,
                        FieldModifier::Lt | FieldModifier::Lte
                            | FieldModifier::Gt | FieldModifier::Gte
                    )
                }) {
                    self.evaluate_numeric_comparison(&lookup, *n, modifiers, log)
                } else if let Some(field_value) = log.get_field(&lookup) {
                    field_value == n.to_string()
                } else {
                    false
                }
            }
            FieldValue::Bool(b) => {
                if let Some(field_value) = log.get_field(&lookup) {
                    field_value.to_lowercase() == b.to_string().to_lowercase()
                } else {
                    false
                }
            }
            FieldValue::Null => false,
        }
    }

    /// Evaluate a condition map against a log (fallback when no compiled detection)
    fn evaluate_condition_map(&self, condition_map: &ConditionMap, log: &LogEntry) -> bool {
        for (field, value) in &condition_map.conditions {
            if !self.evaluate_field_condition(field, value, log) {
                return false;
            }
        }
        true
    }

    /// Evaluate a single field condition (parses modifiers; used only when no compiled detection)
    fn evaluate_field_condition(&self, field: &str, value: &FieldValue, log: &LogEntry) -> bool {
        let (base_field, modifiers) = LogEntry::parse_field_modifiers(field);
        let lookup = self.resolve_field(&base_field);

        if matches!(value, FieldValue::Null) {
            return !log.field_exists(&lookup);
        }

        match value {
            FieldValue::String(s) => {
                self.evaluate_string_with_modifiers(&lookup, s, &modifiers, log)
            }
            FieldValue::Array(arr) => arr
                .iter()
                .any(|v| self.evaluate_string_with_modifiers(&lookup, v, &modifiers, log)),
            FieldValue::Number(n) => {
                if modifiers.iter().any(|m| {
                    matches!(
                        m,
                        FieldModifier::Lt | FieldModifier::Lte
                            | FieldModifier::Gt | FieldModifier::Gte
                    )
                }) {
                    self.evaluate_numeric_comparison(&lookup, *n, &modifiers, log)
                } else if let Some(field_value) = log.get_field(&lookup) {
                    field_value == n.to_string()
                } else {
                    false
                }
            }
            FieldValue::Bool(b) => {
                if let Some(field_value) = log.get_field(&lookup) {
                    field_value.to_lowercase() == b.to_string().to_lowercase()
                } else {
                    false
                }
            }
            FieldValue::Null => false,
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
        
        let lookup = self.resolve_field(field);
        if modifiers.is_empty() {
            return log.field_contains_any(&lookup, &[value.to_string()]);
        }

        let field_value = match log.get_field(&lookup) {
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
                FieldModifier::Re => self
                    .regex_cache
                    .get(value)
                    .map(|re| re.is_match(&field_value))
                    .unwrap_or(false),
                FieldModifier::All => {
                    // For "all" modifier, all parts must be present
                    value.split_whitespace()
                        .all(|part| field_lower.contains(&part.to_lowercase()))
                }
                FieldModifier::Base64 | FieldModifier::Base64Offset => {
                    // Decode base64 encoded field content and search in it
                    use base64::{Engine as _, engine::general_purpose};
                    if let Ok(decoded) = general_purpose::STANDARD.decode(field_value.as_bytes()) {
                        if let Ok(decoded_str) = String::from_utf8(decoded) {
                            decoded_str.to_lowercase().contains(&value_lower)
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
        
        let lookup = self.resolve_field(field);
        let field_value = match log.get_field(&lookup) {
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
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
    
    #[cfg(target_arch = "wasm32")]
    {
        1 // WASM is single-threaded
    }
}

// Helper function to get current timestamp
#[cfg(not(target_arch = "wasm32"))]
fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(target_arch = "wasm32")]
fn current_timestamp() -> String {
    // WASM doesn't have access to system time easily
    "wasm-timestamp".to_string()
}

// Helper function to find operator position outside of parentheses
fn find_operator(expr: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let expr_lower = expr.to_lowercase();
    let op_lower = op.to_lowercase();
    let expr_bytes = expr_lower.as_bytes();
    
    let mut i = 0;
    while i < expr_bytes.len() {
        // Track parentheses depth (using ASCII byte values)
        match expr_bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        
        // Only look for operators at depth 0 (outside any parentheses)
        if depth == 0 && i + op.len() <= expr_lower.len() {
            // Check if we have the operator at this position
            if &expr_lower[i..i + op.len()] == op_lower.as_str() {
                return Some(i);
            }
        }
        
        i += 1;
    }
    
    None
}

/// Parse a condition string into an AST (for evaluation without re-parsing on every log).
fn parse_condition_to_ast(condition: &str) -> Option<ConditionExpr> {
    let condition = condition.trim();
    if condition.is_empty() {
        return None;
    }
    // Handle "selection | count > 5" / "selection | count >= 5" (threshold/count)
    if condition.contains("| count") {
        if let Some(idx) = condition.find("| count") {
            let selection_ref = condition[..idx].trim().to_string();
            let rest = condition[idx + 2..].trim(); // after "| "
            let rest = rest.strip_prefix("count").unwrap_or(rest).trim();
            if let Some((op, threshold)) = parse_count_op_threshold(rest) {
                return Some(ConditionExpr::CountOver {
                    selection_ref,
                    op,
                    threshold,
                });
            }
        }
    }
    // Handle "1 of them" / "all of them" / "1 of selection_*"
    if condition.contains("of them") || condition.contains("of selection") {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        if parts.len() >= 3 && parts.get(1) == Some(&"of") {
            let count_spec = parts[0].to_string();
            let pattern = parts.get(2).copied().unwrap_or("*").to_string();
            return Some(ConditionExpr::OfThem { count_spec, pattern });
        }
    }
    if condition.starts_with("1 of") {
        let parts: Vec<&str> = condition.split_whitespace().collect();
        if parts.len() >= 3 && parts.get(1) == Some(&"of") {
            let count_spec = parts[0].to_string();
            let pattern = parts.get(2).copied().unwrap_or("*").to_string();
            return Some(ConditionExpr::OfThem { count_spec, pattern });
        }
    }
    parse_expression_to_ast(condition)
}

/// Parse "> 5", ">= 5", "< 5", "<= 5", "== 5" into CountOp and u64
fn parse_count_op_threshold(rest: &str) -> Option<(CountOp, u64)> {
    let rest = rest.trim();
    let (op, num_str) = if rest.starts_with(">=") {
        (CountOp::Gte, rest[2..].trim())
    } else if rest.starts_with('>') {
        (CountOp::Gt, rest[1..].trim())
    } else if rest.starts_with("<=") {
        (CountOp::Lte, rest[2..].trim())
    } else if rest.starts_with('<') {
        (CountOp::Lt, rest[1..].trim())
    } else if rest.starts_with("==") {
        (CountOp::Eq, rest[2..].trim())
    } else {
        return None;
    };
    let threshold = num_str.parse::<u64>().ok()?;
    Some((op, threshold))
}

fn parse_expression_to_ast(expr: &str) -> Option<ConditionExpr> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }
    // NOT
    if expr.starts_with("not ") {
        let inner = expr[4..].trim();
        let inner_ast = parse_expression_to_ast(inner)?;
        return Some(ConditionExpr::Not(Box::new(inner_ast)));
    }
    // Outer parentheses
    if expr.starts_with('(') && expr.ends_with(')') {
        let mut depth = 0;
        let chars: Vec<char> = expr.chars().collect();
        let mut valid_outer = true;
        for (i, &ch) in chars.iter().enumerate() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && i < chars.len() - 1 {
                        valid_outer = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if valid_outer && depth == 0 {
            return parse_expression_to_ast(&expr[1..expr.len() - 1]);
        }
    }
    // OR
    if let Some(pos) = find_operator(expr, " or ") {
        let left = parse_expression_to_ast(expr[..pos].trim())?;
        let right = parse_expression_to_ast(expr[pos + 4..].trim())?;
        return Some(ConditionExpr::Or(Box::new(left), Box::new(right)));
    }
    // AND
    if let Some(pos) = find_operator(expr, " and ") {
        let left = parse_expression_to_ast(expr[..pos].trim())?;
        let right = parse_expression_to_ast(expr[pos + 5..].trim())?;
        return Some(ConditionExpr::And(Box::new(left), Box::new(right)));
    }
    // Base: selection reference
    Some(ConditionExpr::SelectionRef(expr.to_string()))
}

/// Pre-parse all field modifiers in a rule's detection (one-time at load).
fn compile_detection(rule: &SigmaRule) -> CompiledDetection {
    let mut compiled = CompiledDetection::new();
    for (key, selection) in &rule.detection.selections {
        if key == "condition" || key == "timeframe" {
            continue;
        }
        let maps: Vec<CompiledConditionMap> = match selection {
            SelectionValue::Single(cm) => vec![compile_condition_map(cm)],
            SelectionValue::Multiple(cms) => cms.iter().map(compile_condition_map).collect(),
        };
        compiled.insert(key.clone(), maps);
    }
    compiled
}

fn compile_condition_map(condition_map: &ConditionMap) -> CompiledConditionMap {
    condition_map
        .conditions
        .iter()
        .map(|(field, value)| {
            let (base_field, modifiers) = LogEntry::parse_field_modifiers(field);
            ParsedFieldCondition {
                base_field,
                modifiers,
                value: value.clone(),
            }
        })
        .collect()
}

/// Extract all regex patterns from a rule (fields with |re modifier).
fn extract_regex_patterns(rule: &SigmaRule) -> Vec<String> {
    let mut patterns = Vec::new();
    for (_key, selection) in &rule.detection.selections {
        if _key == "condition" || _key == "timeframe" {
            continue;
        }
        let condition_maps: Vec<&ConditionMap> = match selection {
            SelectionValue::Single(cm) => vec![cm],
            SelectionValue::Multiple(cms) => cms.iter().collect(),
        };
        for cm in condition_maps {
            for (field, value) in &cm.conditions {
                let (_, modifiers) = LogEntry::parse_field_modifiers(field);
                if !modifiers.contains(&FieldModifier::Re) {
                    continue;
                }
                match value {
                    FieldValue::String(s) => {
                        patterns.push(s.clone());
                    }
                    FieldValue::Array(arr) => {
                        patterns.extend(arr.iter().cloned());
                    }
                    _ => {}
                }
            }
        }
    }
    patterns
}