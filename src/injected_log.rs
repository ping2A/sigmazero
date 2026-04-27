//! Log lines can embed Sigma test rules for isolated evaluation.
//!
//! In JSON/JSONL logs, set one of:
//! - **`_sigma_injected_rule`**: string — YAML of a single Sigma rule
//! - **`_sigma_injected_rules`**: array of strings — each element is one rule YAML, or a single
//!   string (same as one element of the array)
//!
//! These fields are **removed** before the event is evaluated, so they never appear in `RuleMatch`
//! data. The embedded rules are evaluated **only** for that line (not merged with the global
//! engine rules), so you can test rules without a rules directory.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::models::{LogEntry, SigmaRule};

/// JSON key: one Sigma rule as YAML string
pub const INJECTED_RULE: &str = "_sigma_injected_rule";
/// JSON key: multiple rules as array of YAML strings, or a single string
pub const INJECTED_RULES: &str = "_sigma_injected_rules";

/// Result of parsing one JSON line from a log file
pub enum PreparedLogLine {
    /// Normal line: evaluate with the main engine
    Standard(LogEntry),
    /// Test line: evaluate only the embedded rules against the stripped log
    Injected { rules: Vec<SigmaRule>, log: LogEntry },
}

/// Parse a JSON line. Injected-rule keys are removed from the object before building `LogEntry`.
pub fn parse_json_log_line(line: &str) -> Result<PreparedLogLine> {
    let v: Value = serde_json::from_str(line).context("line is not valid JSON")?;
    if let Value::Object(mut map) = v {
        if !map.contains_key(INJECTED_RULE) && !map.contains_key(INJECTED_RULES) {
            let log: LogEntry = serde_json::from_value(Value::Object(map))?;
            return Ok(PreparedLogLine::Standard(log));
        }
        let mut yamls: Vec<String> = Vec::new();
        if let Some(removed) = map.remove(INJECTED_RULE) {
            let s = as_yaml_string(removed, INJECTED_RULE)?;
            yamls.push(s);
        }
        if let Some(removed) = map.remove(INJECTED_RULES) {
            match removed {
                Value::Array(arr) => {
                    for (i, e) in arr.into_iter().enumerate() {
                        yamls.push(as_yaml_string(e, &format!("{INJECTED_RULES}[{i}]"))?);
                    }
                }
                Value::String(s) => yamls.push(s),
                _ => {
                    anyhow::bail!("{} must be a JSON array of strings or a single string", INJECTED_RULES);
                }
            }
        }
        if yamls.is_empty() {
            anyhow::bail!("expected at least one rule in {} or {}", INJECTED_RULE, INJECTED_RULES);
        }
        let rules = parse_injected_yamls(&yamls)?;
        let log: LogEntry = serde_json::from_value(Value::Object(map))
            .context("log fields after stripping injection keys")?;
        return Ok(PreparedLogLine::Injected { rules, log });
    }
    let log: LogEntry = serde_json::from_value(v).context("value is not a log object")?;
    Ok(PreparedLogLine::Standard(log))
}

fn as_yaml_string(v: Value, name: &str) -> Result<String> {
    match v {
        Value::String(s) => Ok(s),
        _ => anyhow::bail!("{} must be a string containing Sigma rule YAML", name),
    }
}

fn parse_injected_yamls(chunks: &[String]) -> Result<Vec<SigmaRule>> {
    let mut out = Vec::new();
    for chunk in chunks {
        for doc in split_yaml_docs(chunk) {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            out.push(
                crate::parser::parse_sigma_rule_str(doc)
                    .with_context(|| format!("parse embedded rule YAML: {}", doc.chars().take(80).collect::<String>()))?,
            );
        }
    }
    if out.is_empty() {
        anyhow::bail!("no parseable Sigma rule in embedded YAML");
    }
    Ok(out)
}

/// Split a string into YAML documents (lines that are only `---` separate documents)
fn split_yaml_docs(s: &str) -> Vec<String> {
    if !s.contains("---") {
        return vec![s.to_string()];
    }
    s.split("\n---\n")
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_injected_rule() {
        let rule_yaml = "title: embedded\n\
detection:\n  selection:\n    command_line: powershell\n  condition: selection\n";
        let line = serde_json::json!({
            INJECTED_RULE: rule_yaml,
            "command_line": "powershell -enc ABC"
        })
        .to_string();
        let p = parse_json_log_line(&line).unwrap();
        match p {
            PreparedLogLine::Injected { log, rules } => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].title, "embedded");
                assert!(!log.fields.contains_key("_sigma_injected_rule"));
                assert_eq!(
                    log.get_field("command_line"),
                    Some("powershell -enc ABC".to_string())
                );
            }
            _ => panic!("expected injected"),
        }
    }

    #[test]
    fn test_evaluate_injected_rules_via_engine() {
        use crate::engine::SigmaEngine;
        let rule_yaml = "title: enc-test\ndetection:\n  selection:\n    command_line|re: '.*-enc\\s+ABC.*'\n  condition: selection\n";
        let line = serde_json::json!({
            INJECTED_RULE: rule_yaml,
            "command_line": "powershell.exe -enc ABC"
        })
        .to_string();
        let p = parse_json_log_line(&line).unwrap();
        let PreparedLogLine::Injected { rules, log } = p else {
            panic!("expected Injected");
        };
        let engine = SigmaEngine::new(Some(1));
        let matches = engine
            .evaluate_log_entry_with_injected_rules(&log, rules)
            .unwrap();
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_title, "enc-test");

        // Non-match
        let line2 = serde_json::json!({
            INJECTED_RULE: rule_yaml,
            "command_line": "notepad"
        })
        .to_string();
        let p2 = parse_json_log_line(&line2).unwrap();
        if let PreparedLogLine::Injected { rules, log } = p2 {
            let m2 = engine.evaluate_log_entry_with_injected_rules(&log, rules).unwrap();
            assert!(m2.is_empty());
        }
    }
}
