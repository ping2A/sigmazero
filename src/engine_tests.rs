#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::models::*;
    use std::collections::HashMap;
    use serde_json::json;

    /// Helper function to create a test log entry
    fn create_log(fields: Vec<(&str, serde_json::Value)>) -> LogEntry {
        let mut field_map = HashMap::new();
        for (key, value) in fields {
            field_map.insert(key.to_string(), value);
        }
        LogEntry { fields: field_map }
    }

    /// Helper function to create a simple Sigma rule
    fn create_rule(selections: HashMap<String, SelectionValue>, condition: &str) -> SigmaRule {
        SigmaRule {
            title: "Test Rule".to_string(),
            id: Some("test-id".to_string()),
            description: Some("Test description".to_string()),
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
    fn test_simple_and_condition() {
        let engine = SigmaEngine::new(Some(1));
        
        // Create rule with AND condition
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
        
        selections.insert("selection1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("selection2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "selection1 and selection2");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test matching log
        let log_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell.exe -enc ABC123")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Test non-matching log (missing command_line pattern)
        let log_no_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell.exe -help")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_no_match).is_none());
    }

    #[test]
    fn test_simple_or_condition() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("process_name".to_string(), FieldValue::String("cmd.exe".to_string()));
        
        selections.insert("selection1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("selection2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "selection1 or selection2");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test with first selection
        let log1 = create_log(vec![("process_name", json!("powershell.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Test with second selection
        let log2 = create_log(vec![("process_name", json!("cmd.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Test with neither
        let log3 = create_log(vec![("process_name", json!("notepad.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_not_condition() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("command_line".to_string(), FieldValue::String("*System32*".to_string()));
        
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("filter".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "selection and not filter");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test matching (powershell but not in System32)
        let log_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("C:\\Users\\test\\powershell.exe")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Test not matching (powershell in System32 - filtered out)
        let log_no_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("C:\\Windows\\System32\\powershell.exe")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_no_match).is_none());
    }

    #[test]
    fn test_parentheses_precedence() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("field1".to_string(), FieldValue::String("a".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("field2".to_string(), FieldValue::String("b".to_string()));
        
        let mut cond3 = HashMap::new();
        cond3.insert("field3".to_string(), FieldValue::String("c".to_string()));
        
        selections.insert("sel1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("sel2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("sel3".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
        
        // Test: sel1 and (sel2 or sel3)
        let rule = create_rule(selections, "sel1 and (sel2 or sel3)");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match: sel1=true, sel2=true, sel3=false
        let log1 = create_log(vec![
            ("field1", json!("a")),
            ("field2", json!("b")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Should match: sel1=true, sel2=false, sel3=true
        let log2 = create_log(vec![
            ("field1", json!("a")),
            ("field3", json!("c")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Should NOT match: sel1=false
        let log3 = create_log(vec![
            ("field2", json!("b")),
            ("field3", json!("c")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_one_of_them_pattern() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("field1".to_string(), FieldValue::String("value1".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("field2".to_string(), FieldValue::String("value2".to_string()));
        
        let mut cond3 = HashMap::new();
        cond3.insert("field3".to_string(), FieldValue::String("value3".to_string()));
        
        selections.insert("selection1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("selection2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("selection3".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
        
        let rule = create_rule(selections, "1 of them");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match with any one selection
        let log1 = create_log(vec![("field1", json!("value1"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        let log2 = create_log(vec![("field2", json!("value2"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Should NOT match with none
        let log3 = create_log(vec![("field4", json!("value4"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_all_of_them_pattern() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("field1".to_string(), FieldValue::String("value1".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("field2".to_string(), FieldValue::String("value2".to_string()));
        
        selections.insert("selection1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("selection2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "all of them");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match only when all selections match
        let log_match = create_log(vec![
            ("field1", json!("value1")),
            ("field2", json!("value2")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Should NOT match with only one
        let log_no_match = create_log(vec![("field1", json!("value1"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_no_match).is_none());
    }

    #[test]
    fn test_one_of_pattern_wildcard() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("field1".to_string(), FieldValue::String("value1".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("field2".to_string(), FieldValue::String("value2".to_string()));
        
        let mut cond3 = HashMap::new();
        cond3.insert("field3".to_string(), FieldValue::String("other".to_string()));
        
        selections.insert("selection_a".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("selection_b".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("filter_c".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
        
        let rule = create_rule(selections, "1 of selection_*");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match selection_a
        let log1 = create_log(vec![("field1", json!("value1"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Should match selection_b
        let log2 = create_log(vec![("field2", json!("value2"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Should NOT match filter_c (doesn't match pattern)
        let log3 = create_log(vec![("field3", json!("other"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_wildcard_matching() {
        let log = create_log(vec![
            ("process_name", json!("C:\\Windows\\System32\\powershell.exe")),
        ]);
        
        // Test contains wildcard
        assert!(log.field_contains_any("process_name", &["*powershell*".to_string()]));
        
        // Test startswith wildcard
        assert!(log.field_contains_any("process_name", &["C:\\Windows*".to_string()]));
        
        // Test endswith wildcard
        assert!(log.field_contains_any("process_name", &["*powershell.exe".to_string()]));
        
        // Test no match
        assert!(!log.field_contains_any("process_name", &["*cmd.exe".to_string()]));
    }

    #[test]
    fn test_field_modifier_startswith() {
        let log = create_log(vec![
            ("command_line", json!("powershell.exe -enc ABC")),
        ]);
        
        let modifiers = vec![FieldModifier::StartsWith];
        
        assert!(log.field_matches_with_modifiers("command_line", "powershell", &modifiers));
        assert!(!log.field_matches_with_modifiers("command_line", "cmd", &modifiers));
    }

    #[test]
    fn test_field_modifier_endswith() {
        let log = create_log(vec![
            ("file_path", json!("C:\\temp\\malware.exe")),
        ]);
        
        let modifiers = vec![FieldModifier::EndsWith];
        
        assert!(log.field_matches_with_modifiers("file_path", ".exe", &modifiers));
        assert!(!log.field_matches_with_modifiers("file_path", ".dll", &modifiers));
    }

    #[test]
    fn test_field_modifier_contains() {
        let log = create_log(vec![
            ("command_line", json!("powershell.exe -ExecutionPolicy Bypass")),
        ]);
        
        let modifiers = vec![FieldModifier::Contains];
        
        assert!(log.field_matches_with_modifiers("command_line", "bypass", &modifiers));
        assert!(!log.field_matches_with_modifiers("command_line", "encoded", &modifiers));
    }

    #[test]
    fn test_field_modifier_all() {
        let log = create_log(vec![
            ("command_line", json!("powershell.exe -ExecutionPolicy Bypass -NoProfile")),
        ]);
        
        let modifiers = vec![FieldModifier::All];
        
        // Both words should be present
        assert!(log.field_matches_with_modifiers("command_line", "bypass noprofile", &modifiers));
        
        // Missing one word
        assert!(!log.field_matches_with_modifiers("command_line", "bypass encoded", &modifiers));
    }

    #[test]
    fn test_field_modifier_regex() {
        let log = create_log(vec![
            ("command_line", json!("powershell.exe -enc ABC123")),
        ]);
        
        let modifiers = vec![FieldModifier::Re];
        
        assert!(log.field_matches_with_modifiers("command_line", r".*-enc\s+[A-Z0-9]+.*", &modifiers));
        assert!(!log.field_matches_with_modifiers("command_line", r"^cmd\.exe.*", &modifiers));
    }

    #[test]
    fn test_numeric_comparison_gt() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("size|gt".to_string(), FieldValue::Number(1000));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test greater than
        let log_match = create_log(vec![("size", json!(2000))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Test equal (should not match gt)
        let log_equal = create_log(vec![("size", json!(1000))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_equal).is_none());
        
        // Test less than
        let log_less = create_log(vec![("size", json!(500))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_less).is_none());
    }

    #[test]
    fn test_numeric_comparison_gte() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("size|gte".to_string(), FieldValue::Number(1000));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test greater than
        let log_greater = create_log(vec![("size", json!(2000))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_greater).is_some());
        
        // Test equal (should match gte)
        let log_equal = create_log(vec![("size", json!(1000))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_equal).is_some());
        
        // Test less than
        let log_less = create_log(vec![("size", json!(500))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_less).is_none());
    }

    #[test]
    fn test_numeric_comparison_lt() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("port|lt".to_string(), FieldValue::Number(1024));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test less than
        let log_match = create_log(vec![("port", json!(80))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Test equal (should not match lt)
        let log_equal = create_log(vec![("port", json!(1024))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_equal).is_none());
        
        // Test greater than
        let log_greater = create_log(vec![("port", json!(8080))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_greater).is_none());
    }

    #[test]
    fn test_null_field_check() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("user".to_string(), FieldValue::Null);
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test with missing field (should match)
        let log_match = create_log(vec![("process", json!("test.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Test with existing field (should not match)
        let log_no_match = create_log(vec![
            ("process", json!("test.exe")),
            ("user", json!("admin")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_no_match).is_none());
    }

    #[test]
    fn test_array_field_values() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::Array(vec![
            "powershell.exe".to_string(),
            "cmd.exe".to_string(),
            "wscript.exe".to_string(),
        ]));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Test matching first value
        let log1 = create_log(vec![("process_name", json!("powershell.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Test matching second value
        let log2 = create_log(vec![("process_name", json!("cmd.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Test not matching
        let log3 = create_log(vec![("process_name", json!("notepad.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_complex_nested_condition() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("a".to_string(), FieldValue::String("1".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("b".to_string(), FieldValue::String("2".to_string()));
        
        let mut cond3 = HashMap::new();
        cond3.insert("c".to_string(), FieldValue::String("3".to_string()));
        
        let mut cond4 = HashMap::new();
        cond4.insert("d".to_string(), FieldValue::String("4".to_string()));
        
        selections.insert("s1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("s2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("s3".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
        selections.insert("s4".to_string(), SelectionValue::Single(ConditionMap { conditions: cond4 }));
        
        // Test: (s1 or s2) and (s3 or s4)
        let rule = create_rule(selections, "(s1 or s2) and (s3 or s4)");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match: s1=true, s3=true
        let log1 = create_log(vec![("a", json!("1")), ("c", json!("3"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Should match: s2=true, s4=true
        let log2 = create_log(vec![("b", json!("2")), ("d", json!("4"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Should NOT match: s1=true, but no s3 or s4
        let log3 = create_log(vec![("a", json!("1"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }

    #[test]
    fn test_case_insensitive_matching() {
        let log = create_log(vec![
            ("process_name", json!("PowerShell.EXE")),
        ]);
        
        // Should match regardless of case
        assert!(log.field_contains_any("process_name", &["powershell.exe".to_string()]));
        assert!(log.field_contains_any("process_name", &["POWERSHELL.EXE".to_string()]));
        assert!(log.field_contains_any("process_name", &["PoWeRsHeLl.ExE".to_string()]));
    }

    #[test]
    fn test_multiple_conditions_in_selection() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        cond.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Both conditions must match
        let log_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell.exe -enc ABC")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some());
        
        // Missing one condition
        let log_no_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_no_match).is_none());
    }

    #[test]
    fn test_field_exists() {
        let log = create_log(vec![
            ("process_name", json!("test.exe")),
            ("user", json!("admin")),
        ]);
        
        assert!(log.field_exists("process_name"));
        assert!(log.field_exists("user"));
        assert!(!log.field_exists("nonexistent_field"));
    }

    #[test]
    fn test_operator_precedence() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("a".to_string(), FieldValue::String("1".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("b".to_string(), FieldValue::String("2".to_string()));
        
        let mut cond3 = HashMap::new();
        cond3.insert("c".to_string(), FieldValue::String("3".to_string()));
        
        selections.insert("s1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("s2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("s3".to_string(), SelectionValue::Single(ConditionMap { conditions: cond3 }));
        
        // Test: s1 and s2 or s3 (should be evaluated as (s1 and s2) or s3)
        let rule = create_rule(selections, "s1 and s2 or s3");
        let rule_arc = std::sync::Arc::new(rule);
        
        // Should match with s1 and s2
        let log1 = create_log(vec![("a", json!("1")), ("b", json!("2"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_some());
        
        // Should match with just s3 (due to OR)
        let log2 = create_log(vec![("c", json!("3"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_some());
        
        // Should NOT match with only s1
        let log3 = create_log(vec![("a", json!("1"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log3).is_none());
    }
}
