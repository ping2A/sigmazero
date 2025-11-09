#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_log_entry_get_field() {
        let mut fields = HashMap::new();
        fields.insert("string_field".to_string(), json!("test_value"));
        fields.insert("number_field".to_string(), json!(42));
        fields.insert("bool_field".to_string(), json!(true));
        
        let log = LogEntry { fields };
        
        assert_eq!(log.get_field("string_field"), Some("test_value".to_string()));
        assert_eq!(log.get_field("number_field"), Some("42".to_string()));
        assert_eq!(log.get_field("bool_field"), Some("true".to_string()));
        assert_eq!(log.get_field("nonexistent"), None);
    }

    #[test]
    fn test_wildcard_match_simple() {
        let mut fields = HashMap::new();
        fields.insert("test".to_string(), json!("hello world test"));
        let log = LogEntry { fields };
        
        // Contains
        assert!(log.wildcard_match("hello world test", "*world*"));
        
        // Starts with
        assert!(log.wildcard_match("hello world test", "hello*"));
        
        // Ends with
        assert!(log.wildcard_match("hello world test", "*test"));
        
        // Exact match with wildcards on both sides
        assert!(log.wildcard_match("hello world test", "*hello world test*"));
        
        // No match
        assert!(!log.wildcard_match("hello world test", "*xyz*"));
    }

    #[test]
    fn test_wildcard_match_complex() {
        let mut fields = HashMap::new();
        fields.insert("test".to_string(), json!("test"));
        let log = LogEntry { fields };
        
        // Multiple wildcards
        assert!(log.wildcard_match("C:\\Windows\\System32\\cmd.exe", "C:\\*\\System32\\*"));
        assert!(log.wildcard_match("powershell.exe", "*shell*"));
        assert!(log.wildcard_match("process.exe", "*.exe"));
        
        // Edge cases
        assert!(log.wildcard_match("test", "*test*"));
        assert!(log.wildcard_match("test", "test"));
        assert!(log.wildcard_match("", "*"));
    }

    #[test]
    fn test_field_contains_any() {
        let mut fields = HashMap::new();
        fields.insert("command_line".to_string(), json!("powershell.exe -ExecutionPolicy Bypass"));
        let log = LogEntry { fields };
        
        // Should match with substring
        assert!(log.field_contains_any("command_line", &["bypass".to_string()]));
        
        // Should match with wildcard
        assert!(log.field_contains_any("command_line", &["*powershell*".to_string()]));
        
        // Should match with any of multiple values
        assert!(log.field_contains_any("command_line", &[
            "notfound".to_string(),
            "bypass".to_string(),
        ]));
        
        // Should not match
        assert!(!log.field_contains_any("command_line", &["notfound".to_string()]));
    }

    #[test]
    fn test_parse_field_modifiers() {
        // No modifiers
        let (field, mods) = LogEntry::parse_field_modifiers("process_name");
        assert_eq!(field, "process_name");
        assert_eq!(mods.len(), 0);
        
        // Single modifier
        let (field, mods) = LogEntry::parse_field_modifiers("command_line|contains");
        assert_eq!(field, "command_line");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0], FieldModifier::Contains);
        
        // Multiple modifiers
        let (field, mods) = LogEntry::parse_field_modifiers("command_line|contains|all");
        assert_eq!(field, "command_line");
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0], FieldModifier::Contains);
        assert_eq!(mods[1], FieldModifier::All);
        
        // Numeric modifiers
        let (field, mods) = LogEntry::parse_field_modifiers("size|gte");
        assert_eq!(field, "size");
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0], FieldModifier::Gte);
    }

    #[test]
    fn test_field_matches_with_modifiers_startswith() {
        let mut fields = HashMap::new();
        fields.insert("command_line".to_string(), json!("powershell.exe -enc ABC"));
        let log = LogEntry { fields };
        
        let modifiers = vec![FieldModifier::StartsWith];
        
        assert!(log.field_matches_with_modifiers("command_line", "powershell", &modifiers));
        assert!(!log.field_matches_with_modifiers("command_line", "cmd", &modifiers));
    }

    #[test]
    fn test_field_matches_with_modifiers_endswith() {
        let mut fields = HashMap::new();
        fields.insert("file_path".to_string(), json!("C:\\temp\\malware.exe"));
        let log = LogEntry { fields };
        
        let modifiers = vec![FieldModifier::EndsWith];
        
        assert!(log.field_matches_with_modifiers("file_path", ".exe", &modifiers));
        assert!(!log.field_matches_with_modifiers("file_path", ".dll", &modifiers));
    }

    #[test]
    fn test_field_matches_with_modifiers_all() {
        let mut fields = HashMap::new();
        fields.insert("description".to_string(), json!("malicious threat detected"));
        let log = LogEntry { fields };
        
        let modifiers = vec![FieldModifier::All];
        
        // All words present
        assert!(log.field_matches_with_modifiers("description", "malicious detected", &modifiers));
        
        // One word missing
        assert!(!log.field_matches_with_modifiers("description", "malicious encrypted", &modifiers));
    }

    #[test]
    fn test_field_matches_with_modifiers_regex() {
        let mut fields = HashMap::new();
        fields.insert("command_line".to_string(), json!("powershell.exe -enc ABC123"));
        let log = LogEntry { fields };
        
        let modifiers = vec![FieldModifier::Re];
        
        assert!(log.field_matches_with_modifiers("command_line", r".*-enc\s+[A-Z0-9]+.*", &modifiers));
        assert!(!log.field_matches_with_modifiers("command_line", r"^cmd\.exe.*", &modifiers));
    }

    #[test]
    fn test_field_exists() {
        let mut fields = HashMap::new();
        fields.insert("process_name".to_string(), json!("test.exe"));
        fields.insert("user".to_string(), json!("admin"));
        let log = LogEntry { fields };
        
        assert!(log.field_exists("process_name"));
        assert!(log.field_exists("user"));
        assert!(!log.field_exists("nonexistent"));
    }

    #[test]
    fn test_case_insensitive_matching() {
        let mut fields = HashMap::new();
        fields.insert("process".to_string(), json!("PowerShell.EXE"));
        let log = LogEntry { fields };
        
        // Contains should be case-insensitive
        assert!(log.field_contains_any("process", &["powershell.exe".to_string()]));
        assert!(log.field_contains_any("process", &["POWERSHELL.EXE".to_string()]));
        assert!(log.field_contains_any("process", &["PoWeRsHeLl".to_string()]));
    }

    #[test]
    fn test_field_value_deserialization() {
        // String
        let json_str = r#""test_value""#;
        let value: FieldValue = serde_json::from_str(json_str).unwrap();
        assert!(matches!(value, FieldValue::String(_)));
        
        // Number
        let json_num = r#"42"#;
        let value: FieldValue = serde_json::from_str(json_num).unwrap();
        assert!(matches!(value, FieldValue::Number(_)));
        
        // Array
        let json_arr = r#"["value1", "value2"]"#;
        let value: FieldValue = serde_json::from_str(json_arr).unwrap();
        assert!(matches!(value, FieldValue::Array(_)));
        
        // Boolean
        let json_bool = r#"true"#;
        let value: FieldValue = serde_json::from_str(json_bool).unwrap();
        assert!(matches!(value, FieldValue::Bool(_)));
        
        // Null
        let json_null = r#"null"#;
        let value: FieldValue = serde_json::from_str(json_null).unwrap();
        assert!(matches!(value, FieldValue::Null));
    }

    #[test]
    fn test_sigma_rule_deserialization() {
        let yaml = r#"
title: Test Rule
id: 12345678-1234-1234-1234-123456789abc
description: Test description
status: test
level: medium
detection:
  selection:
    process_name: powershell.exe
  condition: selection
tags:
  - attack.execution
"#;
        
        let rule: Result<SigmaRule, _> = serde_yaml::from_str(yaml);
        assert!(rule.is_ok());
        
        let rule = rule.unwrap();
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.id, Some("12345678-1234-1234-1234-123456789abc".to_string()));
        assert_eq!(rule.level, Some("medium".to_string()));
        assert_eq!(rule.detection.condition, "selection");
        assert_eq!(rule.tags.len(), 1);
    }

    #[test]
    fn test_wildcard_edge_cases() {
        let mut fields = HashMap::new();
        fields.insert("test".to_string(), json!("value"));
        let log = LogEntry { fields };
        
        // Empty pattern parts
        assert!(log.wildcard_match("test", "**test**"));
        
        // Single wildcard
        assert!(log.wildcard_match("anything", "*"));
        
        // No wildcards
        assert!(log.wildcard_match("exact", "exact"));
        assert!(!log.wildcard_match("exact", "other"));
        
        // Wildcard at start
        assert!(log.wildcard_match("test.exe", "*.exe"));
        
        // Wildcard at end
        assert!(log.wildcard_match("C:\\Windows\\test", "C:\\Windows\\*"));
    }

    #[test]
    fn test_multiple_field_modifiers() {
        let mut fields = HashMap::new();
        fields.insert("command".to_string(), json!("powershell.exe -ExecutionPolicy Bypass"));
        let log = LogEntry { fields };
        
        // Multiple modifiers applied in sequence
        let modifiers = vec![FieldModifier::Contains, FieldModifier::StartsWith];
        
        // Should match if all modifiers pass
        assert!(log.field_matches_with_modifiers("command", "powershell", &modifiers));
    }

    #[test]
    fn test_numeric_field_comparison() {
        let mut fields = HashMap::new();
        fields.insert("size".to_string(), json!(1500));
        let log = LogEntry { fields };
        
        let modifiers_gt = vec![FieldModifier::Gt];
        let modifiers_lt = vec![FieldModifier::Lt];
        
        assert!(log.field_matches_with_modifiers("size", "1000", &modifiers_gt));
        assert!(!log.field_matches_with_modifiers("size", "2000", &modifiers_gt));
        
        assert!(log.field_matches_with_modifiers("size", "2000", &modifiers_lt));
        assert!(!log.field_matches_with_modifiers("size", "1000", &modifiers_lt));
    }

    #[test]
    fn test_selection_value_variants() {
        // Single condition map
        let yaml_single = r#"
field1: value1
"#;
        let selection: ConditionMap = serde_yaml::from_str(yaml_single).unwrap();
        assert_eq!(selection.conditions.len(), 1);
        
        // Test SelectionValue can be deserialized
        let yaml_selection = r#"
field1: value1
field2: value2
"#;
        let selection: ConditionMap = serde_yaml::from_str(yaml_selection).unwrap();
        assert_eq!(selection.conditions.len(), 2);
    }

    #[test]
    fn test_field_value_array_matching() {
        let mut fields = HashMap::new();
        fields.insert("process".to_string(), json!("cmd.exe"));
        let log = LogEntry { fields };
        
        // Array should match if any value matches
        assert!(log.field_contains_any("process", &[
            "powershell.exe".to_string(),
            "cmd.exe".to_string(),
            "wscript.exe".to_string(),
        ]));
    }

    #[test]
    fn test_empty_field_value() {
        let mut fields = HashMap::new();
        fields.insert("empty".to_string(), json!(""));
        let log = LogEntry { fields };
        
        assert_eq!(log.get_field("empty"), Some("".to_string()));
        assert!(!log.field_contains_any("empty", &["test".to_string()]));
    }

    #[test]
    fn test_special_characters_in_values() {
        let mut fields = HashMap::new();
        fields.insert("path".to_string(), json!("C:\\Users\\Test\\file.exe"));
        let log = LogEntry { fields };
        
        assert!(log.field_contains_any("path", &["C:\\Users\\*".to_string()]));
        assert!(log.field_contains_any("path", &["*file.exe".to_string()]));
    }

    #[test]
    fn test_unicode_content() {
        let mut fields = HashMap::new();
        fields.insert("text".to_string(), json!("Hello 世界 🌍"));
        let log = LogEntry { fields };
        
        assert!(log.field_contains_any("text", &["世界".to_string()]));
        assert!(log.field_contains_any("text", &["🌍".to_string()]));
    }
}
