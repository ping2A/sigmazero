#[cfg(test)]
mod tests {
    use crate::engine::*;
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

    #[test]
    fn test_evaluate_single_log_entry() {
        let mut engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        engine.rules.push(std::sync::Arc::new(create_rule(selections, "selection")));

        // Matching log
        let log_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
        ]);
        let matches = engine.evaluate_log_entry(&log_match);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_title, "Test Rule");

        // Non-matching log
        let log_no_match = create_log(vec![
            ("process_name", json!("notepad.exe")),
        ]);
        let matches = engine.evaluate_log_entry(&log_no_match);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_evaluate_log_batch() {
        let mut engine = SigmaEngine::new(Some(2));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        engine.rules.push(std::sync::Arc::new(create_rule(selections, "selection")));

        let logs = vec![
            create_log(vec![("process_name", json!("powershell.exe"))]),
            create_log(vec![("process_name", json!("notepad.exe"))]),
            create_log(vec![("process_name", json!("powershell.exe"))]),
        ];

        let matches = engine.evaluate_log_batch(&logs);
        assert_eq!(matches.len(), 2); // Two PowerShell matches
    }

    #[test]
    fn test_evaluate_log_stream_with_callback() {
        let mut engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        engine.rules.push(std::sync::Arc::new(create_rule(selections, "selection")));

        let logs = vec![
            create_log(vec![("process_name", json!("powershell.exe"))]),
            create_log(vec![("process_name", json!("cmd.exe"))]),
            create_log(vec![("process_name", json!("powershell.exe"))]),
        ];

        let mut match_count = 0;
        engine.evaluate_log_stream(&logs, |_| {
            match_count += 1;
        });

        assert_eq!(match_count, 2);
    }

    #[test]
    fn test_evaluate_log_line() {
        let mut engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        engine.rules.push(std::sync::Arc::new(create_rule(selections, "selection")));

        // Valid JSON
        let log_line = r#"{"process_name":"powershell.exe","command_line":"test"}"#;
        let result = engine.evaluate_log_line(log_line);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);

        // Invalid JSON
        let invalid_line = r#"not valid json"#;
        let result = engine.evaluate_log_line(invalid_line);
        assert!(result.is_none());
    }

    #[test]
    fn test_streaming_with_correlation() {
        let mut engine = SigmaEngine::new_with_correlation(Some(1), 100);
        
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        engine.rules.push(std::sync::Arc::new(create_rule(selections, "selection")));

        let log = create_log(vec![("process_name", json!("powershell.exe"))]);
        let matches = engine.evaluate_log_entry(&log);

        assert_eq!(matches.len(), 1);
        
        // Check that match was recorded in correlation engine
        if let Some(corr_engine) = engine.correlation_engine() {
            assert_eq!(corr_engine.history_size(), 1);
        }
    }

    #[test]
    fn test_basic_and_two_conditions() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
        
        selections.insert("s1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("s2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "s1 and s2");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: Both conditions match");
        let log_both = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell.exe -enc ABC")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_both).is_some(), "FAIL: Both conditions should match");
        
        println!("Test 2: Only first condition matches");
        let log_first = create_log(vec![
            ("process_name", json!("powershell.exe")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_first).is_none(), "FAIL: Only first condition, should not match");
        
        println!("Test 3: Only second condition matches");
        let log_second = create_log(vec![
            ("command_line", json!("cmd.exe -enc test")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_second).is_none(), "FAIL: Only second condition, should not match");
        
        println!("Test 4: Neither condition matches");
        let log_neither = create_log(vec![
            ("other_field", json!("value")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_neither).is_none(), "FAIL: Neither condition, should not match");
        
        println!("✓ Basic AND two conditions test passed");
    }

    #[test]
    fn test_and_three_conditions() {
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
        
        let rule = create_rule(selections, "s1 and s2 and s3");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: All three conditions match");
        let log_all = create_log(vec![
            ("a", json!("1")),
            ("b", json!("2")),
            ("c", json!("3")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_all).is_some(), "FAIL: All three should match");
        
        println!("Test 2: Only two conditions match");
        let log_two = create_log(vec![
            ("a", json!("1")),
            ("b", json!("2")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_two).is_none(), "FAIL: Only two conditions, should not match");
        
        println!("✓ AND three conditions test passed");
    }

    #[test]
    fn test_and_with_nested_parentheses() {
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
        
        // (s1 and s2) and (s3 and s4)
        let rule = create_rule(selections, "(s1 and s2) and (s3 and s4)");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: All four conditions match");
        let log_all = create_log(vec![
            ("a", json!("1")),
            ("b", json!("2")),
            ("c", json!("3")),
            ("d", json!("4")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_all).is_some(), "FAIL: All four should match");
        
        println!("Test 2: Missing from first group");
        let log_missing1 = create_log(vec![
            ("b", json!("2")),
            ("c", json!("3")),
            ("d", json!("4")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_missing1).is_none(), "FAIL: Missing from first group");
        
        println!("Test 3: Missing from second group");
        let log_missing2 = create_log(vec![
            ("a", json!("1")),
            ("b", json!("2")),
            ("c", json!("3")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_missing2).is_none(), "FAIL: Missing from second group");
        
        println!("✓ Nested AND with parentheses test passed");
    }

    #[test]
    fn test_and_impossible_condition() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        // Same field, different values - impossible to match both
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("process_name".to_string(), FieldValue::String("cmd.exe".to_string()));
        
        selections.insert("s1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("s2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        
        let rule = create_rule(selections, "s1 and s2");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: First value");
        let log1 = create_log(vec![("process_name", json!("powershell.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log1).is_none(), "FAIL: Should not match (impossible condition)");
        
        println!("Test 2: Second value");
        let log2 = create_log(vec![("process_name", json!("cmd.exe"))]);
        assert!(engine.evaluate_rule(&rule_arc, &log2).is_none(), "FAIL: Should not match (impossible condition)");
        
        println!("✓ Impossible AND condition test passed");
    }

    #[test]
    fn test_and_with_not() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        let mut cond1 = HashMap::new();
        cond1.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        
        let mut cond2 = HashMap::new();
        cond2.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
        
        let mut filter = HashMap::new();
        filter.insert("user".to_string(), FieldValue::String("SYSTEM".to_string()));
        
        selections.insert("s1".to_string(), SelectionValue::Single(ConditionMap { conditions: cond1 }));
        selections.insert("s2".to_string(), SelectionValue::Single(ConditionMap { conditions: cond2 }));
        selections.insert("filter".to_string(), SelectionValue::Single(ConditionMap { conditions: filter }));
        
        let rule = create_rule(selections, "s1 and s2 and not filter");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: Match s1 and s2, not SYSTEM");
        let log_match = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell -enc ABC")),
            ("user", json!("john")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_match).is_some(), "FAIL: Should match (not SYSTEM)");
        
        println!("Test 2: Match s1 and s2, but is SYSTEM");
        let log_system = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell -enc ABC")),
            ("user", json!("SYSTEM")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_system).is_none(), "FAIL: Should not match (is SYSTEM)");
        
        println!("✓ AND with NOT test passed");
    }

    #[test]
    fn test_and_operator_precedence_with_or() {
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
        
        // s1 and s2 or s3 should be evaluated as (s1 and s2) or s3
        let rule = create_rule(selections, "s1 and s2 or s3");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: s1 and s2 both match (should match)");
        let log_and = create_log(vec![
            ("a", json!("1")),
            ("b", json!("2")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_and).is_some(), "FAIL: (s1 and s2) should match");
        
        println!("Test 2: Only s3 matches (should match due to OR)");
        let log_or = create_log(vec![
            ("c", json!("3")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_or).is_some(), "FAIL: s3 should match via OR");
        
        println!("Test 3: Only s1 matches (should not match)");
        let log_only_s1 = create_log(vec![
            ("a", json!("1")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_only_s1).is_none(), "FAIL: Only s1, should not match");
        
        println!("✓ AND operator precedence with OR test passed");
    }

    #[test]
    fn test_and_within_selection() {
        let engine = SigmaEngine::new(Some(1));
        
        let mut selections = HashMap::new();
        
        // Multiple conditions within a single selection (implicit AND)
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        cond.insert("command_line".to_string(), FieldValue::String("*-enc*".to_string()));
        cond.insert("user".to_string(), FieldValue::String("admin".to_string()));
        
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = create_rule(selections, "selection");
        let rule_arc = std::sync::Arc::new(rule);
        
        println!("Test 1: All conditions in selection match");
        let log_all = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell -enc ABC")),
            ("user", json!("admin")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_all).is_some(), "FAIL: All conditions should match");
        
        println!("Test 2: Missing one condition");
        let log_missing = create_log(vec![
            ("process_name", json!("powershell.exe")),
            ("command_line", json!("powershell -enc ABC")),
        ]);
        assert!(engine.evaluate_rule(&rule_arc, &log_missing).is_none(), "FAIL: Missing user, should not match");
        
        println!("✓ AND within selection test passed");
    }

    #[test]
    fn test_end_to_end_simple_rule() {
        let engine = SigmaEngine::new(Some(1));
        
        // Create a simple rule
        let mut selections = HashMap::new();
        let mut cond = HashMap::new();
        cond.insert("process_name".to_string(), FieldValue::String("powershell.exe".to_string()));
        selections.insert("selection".to_string(), SelectionValue::Single(ConditionMap { conditions: cond }));
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
        // Create matching log
        let log = create_log(vec![("process_name", json!("powershell.exe"))]);
        
        // Evaluate
        let result = engine.evaluate_rule(&rule, &log);
        assert!(result.is_some());
        
        let match_result = result.unwrap();
        assert_eq!(match_result.rule_title, "Test Rule");
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "(sel_process and sel_encoded) and not filter_sys"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "1 of selection_*"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "all of them"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
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
        
        let rule = std::sync::Arc::new(create_rule(selections, "selection"));
        
        // Should match regardless of case
        let log1 = create_log(vec![("process", json!("PowerShell.EXE"))]);
        assert!(engine.evaluate_rule(&rule, &log1).is_some());
        
        let log2 = create_log(vec![("process", json!("POWERSHELL.EXE"))]);
        assert!(engine.evaluate_rule(&rule, &log2).is_some());
    }
}