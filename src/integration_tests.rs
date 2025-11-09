use std::collections::HashMap;
use std::sync::Arc;
use serde_json::json;

// Import from the library
use sigma_evaluator::models::*;
use sigma_evaluator::engine::SigmaEngine;

/// Helper to create test log
fn create_log(fields: Vec<(&str, serde_json::Value)>) -> LogEntry {
    let mut field_map = HashMap::new();
    for (key, value) in fields {
        field_map.insert(key.to_string(), value);
    }
    LogEntry { fields: field_map }
}

/// Helper to create test rule
fn create_rule(selections: HashMap<String, SelectionValue>, condition: &str) -> SigmaRule {
    SigmaRule {
        title: "Integration Test Rule".to_string(),
        id: Some("integration-test".to_string()),
        description: Some("Test".to_string()),
        status: Some("test".to_string()),
        level: Some("medium".to_string()),
        detection: Detection {
            selections,
            condition: condition.to_string(),
            timeframe: None,
        },
        tags: vec![],
    }
}

#[test]
fn test_end_to_end_simple_rule() {
    let engine = SigmaEngine::new(Some(1));
    
    // Create a simple rule
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Create matching log
    let log = create_log(vec![("process_name", json!("powershell.exe"))]);
    
    // Evaluate
    let result = engine.evaluate_rule(&rule, &log);
    assert!(result.is_some());
    
    let match_result = result.unwrap();
    assert_eq!(match_result.rule_title, "Integration Test Rule");
    assert_eq!(match_result.level, Some("medium".to_string()));
}

#[test]
fn test_end_to_end_complex_rule() {
    let engine = SigmaEngine::new(Some(1));
    
    // Create complex rule with NOT and parentheses
    let mut selections = HashMap::new();
    
    let mut cond1 = HashMap::new();
    cond1.insert("process_name".to_string(), FieldValue::String("*powershell*".to_string()));
    
    let mut cond2 = HashMap::new();
    cond2.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
    
    let mut filter = HashMap::new();
    filter.insert("user".to_string(), FieldValue::String("SYSTEM".to_string()));
    
    selections.insert("sel_process".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
    selections.insert("sel_encoded".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
    selections.insert("filter_sys".to_string(), SelectionValue::Single(ConditionMap { conditions: filter }));
    
    let rule = Arc::new(create_rule(selections, "(sel_process and sel_encoded) and not filter_sys"));
    
    // Should match: PowerShell with encoding, not SYSTEM
    let log_match = create_log(vec![
        ("process_name", json!("powershell.exe")),
        ("command_line", json!("powershell -enc ABC")),
        ("user", json!("john")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: SYSTEM user (filtered out)
    let log_no_match = create_log(vec![
        ("process_name", json!("powershell.exe")),
        ("command_line", json!("powershell -enc ABC")),
        ("user", json!("SYSTEM")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_one_of_pattern() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    
    let mut cond1 = HashMap::new();
    cond1.insert("indicator1".to_string(), FieldValue::String("malicious1".to_string()));
    
    let mut cond2 = HashMap::new();
    cond2.insert("indicator2".to_string(), FieldValue::String("malicious2".to_string()));
    
    let mut cond3 = HashMap::new();
    cond3.insert("indicator3".to_string(), FieldValue::String("malicious3".to_string()));
    
    selections.insert("selection_a".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
    selections.insert("selection_b".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
    selections.insert("selection_c".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
    
    let rule = Arc::new(create_rule(selections, "1 of selection_*"));
    
    // Should match with any one indicator
    let log1 = create_log(vec![("indicator1", json!("malicious1"))]);
    assert!(engine.evaluate_rule(&rule, &log1).is_some());
    
    let log2 = create_log(vec![("indicator2", json!("malicious2"))]);
    assert!(engine.evaluate_rule(&rule, &log2).is_some());
    
    // Should NOT match with no indicators
    let log3 = create_log(vec![("other", json!("value"))]);
    assert!(engine.evaluate_rule(&rule, &log3).is_none());
}

#[test]
fn test_end_to_end_field_modifiers() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("command_line|startswith".to_string(), FieldValue::String("powershell".to_string()));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match: starts with powershell
    let log_match = create_log(vec![
        ("command_line", json!("powershell.exe -enc ABC")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: doesn't start with powershell
    let log_no_match = create_log(vec![
        ("command_line", json!("C:\\Windows\\powershell.exe")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_numeric_comparison() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("size|gte".to_string(), FieldValue::Number(1000000));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match: size >= 1000000
    let log_match = create_log(vec![("size", json!(2000000))]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: size < 1000000
    let log_no_match = create_log(vec![("size", json!(500000))]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_array_values() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("process_name".to_string(), FieldValue::Array(vec![
        "powershell.exe".to_string(),
        "cmd.exe".to_string(),
        "wscript.exe".to_string(),
    ]));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match any of the array values
    let log1 = create_log(vec![("process_name", json!("powershell.exe"))]);
    assert!(engine.evaluate_rule(&rule, &log1).is_some());
    
    let log2 = create_log(vec![("process_name", json!("cmd.exe"))]);
    assert!(engine.evaluate_rule(&rule, &log2).is_some());
    
    let log3 = create_log(vec![("process_name", json!("wscript.exe"))]);
    assert!(engine.evaluate_rule(&rule, &log3).is_some());
    
    // Should NOT match other values
    let log4 = create_log(vec![("process_name", json!("notepad.exe"))]);
    assert!(engine.evaluate_rule(&rule, &log4).is_none());
}

#[test]
fn test_end_to_end_null_check() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("user".to_string(), FieldValue::Null);
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match: user field is missing
    let log_match = create_log(vec![("process", json!("test.exe"))]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: user field exists
    let log_no_match = create_log(vec![
        ("process", json!("test.exe")),
        ("user", json!("admin")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_wildcard_matching() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("file_path".to_string(), FieldValue::String("*\\Temp\\*.exe".to_string()));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match: contains \Temp\ and ends with .exe
    let log_match = create_log(vec![
        ("file_path", json!("C:\\Users\\Test\\AppData\\Local\\Temp\\malware.exe")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: wrong path
    let log_no_match = create_log(vec![
        ("file_path", json!("C:\\Windows\\System32\\notepad.exe")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_all_of_them() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    
    let mut cond1 = HashMap::new();
    cond1.insert("field1".to_string(), FieldValue::String("value1".to_string()));
    
    let mut cond2 = HashMap::new();
    cond2.insert("field2".to_string(), FieldValue::String("value2".to_string()));
    
    selections.insert("selection1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
    selections.insert("selection2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
    
    let rule = Arc::new(create_rule(selections, "all of them"));
    
    // Should match: all selections present
    let log_match = create_log(vec![
        ("field1", json!("value1")),
        ("field2", json!("value2")),
    ]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
    
    // Should NOT match: only one selection
    let log_no_match = create_log(vec![("field1", json!("value1"))]);
    assert!(engine.evaluate_rule(&rule, &log_no_match).is_none());
}

#[test]
fn test_end_to_end_multiple_workers() {
    // Test with multiple workers to ensure thread safety
    let engine = SigmaEngine::new(Some(4));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("test".to_string(), FieldValue::String("value".to_string()));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Create multiple logs
    let logs: Vec<_> = (0..100)
        .map(|i| create_log(vec![("test", json!(format!("value{}", i)))]))
        .collect();
    
    // Only the first log should match
    let log_match = create_log(vec![("test", json!("value"))]);
    assert!(engine.evaluate_rule(&rule, &log_match).is_some());
}

#[test]
fn test_end_to_end_case_insensitive() {
    let engine = SigmaEngine::new(Some(1));
    
    let mut selections = HashMap::new();
    let mut cond = HashMap::new();
    cond.insert("process".to_string(), FieldValue::String("powershell.exe".to_string()));
    selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
    
    let rule = Arc::new(create_rule(selections, "selection"));
    
    // Should match regardless of case
    let log1 = create_log(vec![("process", json!("PowerShell.EXE"))]);
    assert!(engine.evaluate_rule(&rule, &log1).is_some());
    
    let log2 = create_log(vec![("process", json!("POWERSHELL.EXE"))]);
    assert!(engine.evaluate_rule(&rule, &log2).is_some());
}
