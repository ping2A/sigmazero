use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc, Duration};
use serde::Serialize;
use crate::models::RuleMatch;

/// Represents a correlation rule that depends on other rules
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub level: Option<String>,
    pub correlation: CorrelationCondition,
}

/// Correlation condition that defines how rules should be correlated
#[derive(Debug, Clone)]
pub struct CorrelationCondition {
    pub rule_refs: Vec<String>,          // IDs of rules to correlate
    pub condition_type: CorrelationType,
    pub timespan: Option<Duration>,      // Time window for correlation
    pub group_by: Option<Vec<String>>,   // Fields to group by (e.g., user, host)
}

/// Type of correlation
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationType {
    Sequence,      // Events must occur in sequence
    All,           // All rules must match within timespan
    AtLeast(usize), // At least N rules must match
    Count(usize),  // Exactly N rules must match
}

/// Result of a correlation match
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationMatch {
    pub correlation_rule_id: String,
    pub correlation_rule_title: String,
    pub level: Option<String>,
    pub matched_rules: Vec<RuleMatch>,
    pub timestamp: String,
    pub grouped_by: Option<HashMap<String, String>>,
}

/// Correlation engine that tracks rule matches and detects correlations
pub struct CorrelationEngine {
    correlation_rules: Vec<Arc<CorrelationRule>>,
    match_history: Arc<Mutex<Vec<RuleMatch>>>,
    max_history_size: usize,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(max_history_size: usize) -> Self {
        Self {
            correlation_rules: Vec::new(),
            match_history: Arc::new(Mutex::new(Vec::new())),
            max_history_size,
        }
    }

    /// Add a correlation rule
    pub fn add_correlation_rule(&mut self, rule: CorrelationRule) {
        self.correlation_rules.push(Arc::new(rule));
    }

    /// Record a rule match for correlation analysis
    pub fn record_match(&self, rule_match: RuleMatch) {
        let mut history = self.match_history.lock().unwrap();
        history.push(rule_match);

        // Trim history if it exceeds max size
        if history.len() > self.max_history_size {
            let drain_count = history.len() - self.max_history_size;
            history.drain(0..drain_count);
        }
    }

    /// Check for correlation matches
    pub fn check_correlations(&self) -> Vec<CorrelationMatch> {
        let mut correlation_matches = Vec::new();
        let history = self.match_history.lock().unwrap();

        for correlation_rule in &self.correlation_rules {
            if let Some(matches) = self.evaluate_correlation(correlation_rule, &history) {
                correlation_matches.extend(matches);
            }
        }

        correlation_matches
    }

    /// Evaluate a single correlation rule against match history
    fn evaluate_correlation(
        &self,
        correlation_rule: &CorrelationRule,
        history: &[RuleMatch],
    ) -> Option<Vec<CorrelationMatch>> {
        println!("  Evaluating correlation rule: {}", correlation_rule.title);

        let correlation = &correlation_rule.correlation;

        // Filter matches by referenced rules
        let relevant_matches: Vec<&RuleMatch> = history
            .iter()
            .filter(|m| {
                if let Some(ref rule_id) = m.rule_id {
                    correlation.rule_refs.contains(rule_id)
                } else {
                    false
                }
            })
            .collect();

        if relevant_matches.is_empty() {
            return None;
        }

        // Group matches if group_by is specified
        if let Some(ref group_by_fields) = correlation.group_by {
            self.evaluate_grouped_correlation(
                correlation_rule,
                &relevant_matches,
                group_by_fields,
                correlation,
            )
        } else {
            self.evaluate_simple_correlation(
                correlation_rule,
                &relevant_matches,
                correlation,
            )
        }
    }

    /// Evaluate correlation for grouped events
    fn evaluate_grouped_correlation(
        &self,
        correlation_rule: &CorrelationRule,
        matches: &[&RuleMatch],
        group_by_fields: &[String],
        correlation: &CorrelationCondition,
    ) -> Option<Vec<CorrelationMatch>> {
        println!("  Evaluating grouped correlation {:?}", correlation_rule.id);

        // Group matches by specified fields
        let mut groups: HashMap<Vec<String>, Vec<&RuleMatch>> = HashMap::new();

        for rule_match in matches {
            let mut group_key = Vec::new();
            for field in group_by_fields {
                if let Some(value) = rule_match.matched_log.get_field(field) {
                    group_key.push(value);
                } else {
                    group_key.push("__missing__".to_string());
                }
            }
            groups.entry(group_key).or_insert_with(Vec::new).push(rule_match);
        }

        // Check each group for correlation
        let mut correlation_matches = Vec::new();
        for (group_key, group_matches) in groups {
            if let Some(match_result) = self.check_correlation_condition(
                correlation_rule,
                &group_matches,
                correlation,
            ) {
                // Create grouped_by map
                let mut grouped_by = HashMap::new();
                for (i, field) in group_by_fields.iter().enumerate() {
                    if let Some(value) = group_key.get(i) {
                        if value != "__missing__" {
                            grouped_by.insert(field.clone(), value.clone());
                        }
                    }
                }

                let mut result = match_result;
                result.grouped_by = Some(grouped_by);
                correlation_matches.push(result);
            }
        }

        println!("  Found {} correlation matches", correlation_matches.len());


        if correlation_matches.is_empty() {
            None
        } else {
            Some(correlation_matches)
        }
    }

    /// Evaluate correlation for ungrouped events
    fn evaluate_simple_correlation(
        &self,
        correlation_rule: &CorrelationRule,
        matches: &[&RuleMatch],
        correlation: &CorrelationCondition,
    ) -> Option<Vec<CorrelationMatch>> {
        println!("  Evaluating simple correlation");

        if let Some(match_result) = self.check_correlation_condition(
            correlation_rule,
            matches,
            correlation,
        ) {
            Some(vec![match_result])
        } else {
            None
        }
    }

    /// Check if correlation condition is met
    fn check_correlation_condition(
        &self,
        correlation_rule: &CorrelationRule,
        matches: &[&RuleMatch],
        correlation: &CorrelationCondition,
    ) -> Option<CorrelationMatch> {
        println!("    Checking correlation condition {:?} {:?}", correlation_rule.id, matches.len());

        // Filter by timespan if specified
        let filtered_matches = if let Some(timespan) = correlation.timespan {
            let now = Utc::now();
            let cutoff = now - timespan;

            matches
                .iter()
                .filter(|m| {
                    if let Ok(timestamp) = DateTime::parse_from_rfc3339(&m.timestamp) {
                        timestamp.with_timezone(&Utc) >= cutoff
                    } else {
                        false
                    }
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            matches.to_vec()
        };

        if filtered_matches.is_empty() {
            return None;
        }

        // Check correlation type
        println!("      Checking correlation type {:?} {:?}", correlation.condition_type, filtered_matches.len());

        let condition_met = match correlation.condition_type {
            CorrelationType::All => {
                // All referenced rules must have at least one match
                let matched_rule_ids: std::collections::HashSet<_> = filtered_matches
                    .iter()
                    .filter_map(|m| m.rule_id.as_ref())
                    .collect();

                correlation.rule_refs.iter().all(|rule_ref| {
                    matched_rule_ids.contains(rule_ref)
                })
            }
            CorrelationType::AtLeast(n) => {
                // At least N different rules must match
                let matched_rule_ids: std::collections::HashSet<_> = filtered_matches
                    .iter()
                    .filter_map(|m| m.rule_id.as_ref())
                    .collect();

                matched_rule_ids.len() >= n

            }
            CorrelationType::Count(n) => {               
                filtered_matches.len() >= n
            }
            CorrelationType::Sequence => {
                // Rules must match in sequence
                self.check_sequence(&filtered_matches, &correlation.rule_refs)
            }
        };

        if condition_met {
            Some(CorrelationMatch {
                correlation_rule_id: correlation_rule.id.clone(),
                correlation_rule_title: correlation_rule.title.clone(),
                level: correlation_rule.level.clone(),
                matched_rules: filtered_matches.iter().map(|m| (*m).clone()).collect(),
                timestamp: Utc::now().to_rfc3339(),
                grouped_by: None,
            })
        } else {
            None
        }
    }

    /// Check if matches occur in the specified sequence
    fn check_sequence(&self, matches: &[&RuleMatch], sequence: &[String]) -> bool {       
        if sequence.is_empty() {
            return false;
        }

        // Sort matches by timestamp
        let mut sorted_matches = matches.to_vec();
        //sorted_matches.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        sorted_matches.sort_by(|a, b| {
            let a_ts = a.matched_log.get_field("timestamp").unwrap_or_default();
            let b_ts = b.matched_log.get_field("timestamp").unwrap_or_default();
            a_ts.cmp(&b_ts)
        });

        // Track which sequence position we're looking for
        let mut sequence_idx = 0;

        for rule_match in sorted_matches {
            if let Some(ref rule_id) = rule_match.rule_id {
                if sequence_idx < sequence.len() && rule_id == &sequence[sequence_idx] {
                    sequence_idx += 1;
                }
            }
        }

        // All sequence elements must be found
        sequence_idx == sequence.len()
    }

    /// Clear match history (useful for testing)
    pub fn clear_history(&self) {
        let mut history = self.match_history.lock().unwrap();
        history.clear();
    }

    /// Get current history size
    pub fn history_size(&self) -> usize {
        let history = self.match_history.lock().unwrap();
        history.len()
    }
}

/// Builder for creating correlation rules
pub struct CorrelationRuleBuilder {
    id: String,
    title: String,
    description: Option<String>,
    level: Option<String>,
    rule_refs: Vec<String>,
    condition_type: CorrelationType,
    timespan: Option<Duration>,
    group_by: Option<Vec<String>>,
}

impl CorrelationRuleBuilder {
    pub fn new(id: String, title: String) -> Self {
        Self {
            id,
            title,
            description: None,
            level: None,
            rule_refs: Vec::new(),
            condition_type: CorrelationType::All,
            timespan: None,
            group_by: None,
        }
    }

    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn level(mut self, level: String) -> Self {
        self.level = Some(level);
        self
    }

    pub fn rule_refs(mut self, refs: Vec<String>) -> Self {
        self.rule_refs = refs;
        self
    }

    pub fn condition_type(mut self, condition_type: CorrelationType) -> Self {
        self.condition_type = condition_type;
        self
    }

    pub fn timespan_minutes(mut self, minutes: i64) -> Self {
        self.timespan = Some(Duration::minutes(minutes));
        self
    }

    pub fn timespan_seconds(mut self, seconds: i64) -> Self {
        self.timespan = Some(Duration::seconds(seconds));
        self
    }

    pub fn group_by(mut self, fields: Vec<String>) -> Self {
        self.group_by = Some(fields);
        self
    }

    pub fn build(self) -> CorrelationRule {
        CorrelationRule {
            id: self.id,
            title: self.title,
            description: self.description,
            level: self.level,
            correlation: CorrelationCondition {
                rule_refs: self.rule_refs,
                condition_type: self.condition_type,
                timespan: self.timespan,
                group_by: self.group_by,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LogEntry;
    use std::collections::HashMap;
    use serde_json::json;

    fn create_test_log(fields: Vec<(&str, serde_json::Value)>) -> LogEntry {
        let mut field_map = HashMap::new();
        for (key, value) in fields {
            field_map.insert(key.to_string(), value);
        }
        LogEntry { fields: field_map }
    }

    fn create_test_match(rule_id: String, rule_title: String, log: LogEntry) -> RuleMatch {
        RuleMatch {
            rule_id: Some(rule_id),
            rule_title,
            level: Some("medium".to_string()),
            matched_log: std::sync::Arc::new(log),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_correlation_engine_creation() {
        let engine = CorrelationEngine::new(1000);
        assert_eq!(engine.history_size(), 0);
    }

    #[test]
    fn test_record_match() {
        let engine = CorrelationEngine::new(1000);
        let log = create_test_log(vec![("test", json!("value"))]);
        let rule_match = create_test_match("rule1".to_string(), "Test Rule".to_string(), log);

        engine.record_match(rule_match);
        assert_eq!(engine.history_size(), 1);
    }

    #[test]
    fn test_correlation_all_type() {
        let mut engine = CorrelationEngine::new(1000);

        // Create correlation rule: all of rule1 and rule2 must match
        let correlation = CorrelationRuleBuilder::new(
            "corr1".to_string(),
            "Test Correlation".to_string(),
        )
        .rule_refs(vec!["rule1".to_string(), "rule2".to_string()])
        .condition_type(CorrelationType::All)
        .timespan_minutes(5)
        .build();

        engine.add_correlation_rule(correlation);

        // Record matches for both rules
        let log1 = create_test_log(vec![("event", json!("first"))]);
        let match1 = create_test_match("rule1".to_string(), "Rule 1".to_string(), log1);
        engine.record_match(match1);

        let log2 = create_test_log(vec![("event", json!("second"))]);
        let match2 = create_test_match("rule2".to_string(), "Rule 2".to_string(), log2);
        engine.record_match(match2);

        // Check correlations
        let correlations = engine.check_correlations();
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].matched_rules.len(), 2);
    }

    #[test]
    fn test_correlation_at_least() {
        let mut engine = CorrelationEngine::new(1000);

        let correlation = CorrelationRuleBuilder::new(
            "corr1".to_string(),
            "At Least 2".to_string(),
        )
        .rule_refs(vec!["rule1".to_string(), "rule2".to_string(), "rule3".to_string()])
        .condition_type(CorrelationType::AtLeast(2))
        .build();

        engine.add_correlation_rule(correlation);

        // Record matches for 2 rules
        let log1 = create_test_log(vec![("test", json!("1"))]);
        engine.record_match(create_test_match("rule1".to_string(), "R1".to_string(), log1));

        let log2 = create_test_log(vec![("test", json!("2"))]);
        engine.record_match(create_test_match("rule2".to_string(), "R2".to_string(), log2));

        let correlations = engine.check_correlations();
        assert_eq!(correlations.len(), 1);
    }

    #[test]
    fn test_correlation_with_grouping() {
        let mut engine = CorrelationEngine::new(1000);

        let correlation = CorrelationRuleBuilder::new(
            "corr1".to_string(),
            "Grouped Correlation".to_string(),
        )
        .rule_refs(vec!["rule1".to_string(), "rule2".to_string()])
        .condition_type(CorrelationType::All)
        .group_by(vec!["user".to_string()])
        .build();

        engine.add_correlation_rule(correlation);

        // Record matches for same user
        let log1 = create_test_log(vec![("user", json!("alice")), ("event", json!("login"))]);
        engine.record_match(create_test_match("rule1".to_string(), "R1".to_string(), log1));

        let log2 = create_test_log(vec![("user", json!("alice")), ("event", json!("suspicious"))]);
        engine.record_match(create_test_match("rule2".to_string(), "R2".to_string(), log2));

        // Record matches for different user (should not correlate with alice)
        let log3 = create_test_log(vec![("user", json!("bob")), ("event", json!("login"))]);
        engine.record_match(create_test_match("rule1".to_string(), "R1".to_string(), log3));

        let correlations = engine.check_correlations();
        assert_eq!(correlations.len(), 1); // Only alice's events should correlate
        assert!(correlations[0].grouped_by.is_some());
    }

    #[test]
    fn test_history_size_limit() {
        let engine = CorrelationEngine::new(5);

        // Add 10 matches
        for i in 0..10 {
            let log = create_test_log(vec![("index", json!(i))]);
            engine.record_match(create_test_match(
                format!("rule{}", i),
                "Test".to_string(),
                log,
            ));
        }

        // Should only keep last 5
        assert_eq!(engine.history_size(), 5);
    }
}
