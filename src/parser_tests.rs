#[cfg(test)]
mod tests {
    use crate::parser::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;
    use std::path::Path;

    fn create_test_rule_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
        let file_path = dir.path().join(filename);
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }

    #[test]
    fn test_parse_simple_rule() {
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
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "test.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.id, Some("12345678-1234-1234-1234-123456789abc".to_string()));
        assert_eq!(rule.level, Some("medium".to_string()));
    }

    #[test]
    fn test_parse_rule_with_multiple_selections() {
        let yaml = r#"
title: Multiple Selections
id: test-id
detection:
  selection1:
    field1: value1
  selection2:
    field2: value2
  condition: selection1 and selection2
level: high
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "multi.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.title, "Multiple Selections");
        assert!(rule.detection.selections.contains_key("selection1"));
        assert!(rule.detection.selections.contains_key("selection2"));
    }

    #[test]
    fn test_parse_rule_with_array_values() {
        let yaml = r#"
title: Array Values
detection:
  selection:
    process_name:
      - powershell.exe
      - cmd.exe
      - wscript.exe
  condition: selection
level: medium
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "array.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.title, "Array Values");
    }

    #[test]
    fn test_parse_rule_with_field_modifiers() {
        let yaml = r#"
title: Field Modifiers
detection:
  selection:
    command_line|startswith: powershell
    size|gte: 1000
  condition: selection
level: high
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "modifiers.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_rule_with_complex_condition() {
        let yaml = r#"
title: Complex Condition
detection:
  sel1:
    field1: value1
  sel2:
    field2: value2
  filter:
    field3: value3
  condition: (sel1 or sel2) and not filter
level: critical
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "complex.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.detection.condition, "(sel1 or sel2) and not filter");
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let invalid_yaml = r#"
title: Invalid
detection:
  selection:
    - invalid structure here
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "invalid.yml", invalid_yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let result = parse_sigma_rule(Path::new("/nonexistent/file.yml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_rules_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create multiple rule files
        let rule1 = r#"
title: Rule 1
detection:
  selection:
    field: value1
  condition: selection
level: low
"#;
        
        let rule2 = r#"
title: Rule 2
detection:
  selection:
    field: value2
  condition: selection
level: medium
"#;
        
        create_test_rule_file(&temp_dir, "rule1.yml", rule1);
        create_test_rule_file(&temp_dir, "rule2.yaml", rule2);
        
        let result = load_rules_from_directory(temp_dir.path());
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_load_rules_recursive() {
        let temp_dir = TempDir::new().unwrap();
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        
        // Create rule in root
        let rule1 = r#"
title: Root Rule
detection:
  selection:
    field: value1
  condition: selection
level: low
"#;
        create_test_rule_file(&temp_dir, "root.yml", rule1);
        
        // Create rule in subdirectory
        let rule2 = r#"
title: Sub Rule
detection:
  selection:
    field: value2
  condition: selection
level: medium
"#;
        let sub_file = sub_dir.join("sub.yml");
        let mut file = fs::File::create(&sub_file).unwrap();
        file.write_all(rule2.as_bytes()).unwrap();
        
        let result = load_rules_from_directory(temp_dir.path());
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_load_rules_mixed_extensions() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create .yml file
        let rule1 = r#"
title: YML Rule
detection:
  selection:
    field: value
  condition: selection
level: low
"#;
        create_test_rule_file(&temp_dir, "test.yml", rule1);
        
        // Create .yaml file
        let rule2 = r#"
title: YAML Rule
detection:
  selection:
    field: value
  condition: selection
level: low
"#;
        create_test_rule_file(&temp_dir, "test.yaml", rule2);
        
        // Create non-rule file (should be ignored)
        create_test_rule_file(&temp_dir, "readme.txt", "Not a rule");
        
        let result = load_rules_from_directory(temp_dir.path());
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2); // Only .yml and .yaml files
    }

    #[test]
    fn test_load_rules_from_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        
        let result = load_rules_from_directory(temp_dir.path());
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        assert_eq!(rules.len(), 0);
    }

    #[test]
    fn test_load_rules_nonexistent_directory() {
        let result = load_rules_from_directory(Path::new("/nonexistent/directory"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rule_with_tags() {
        let yaml = r#"
title: Tagged Rule
detection:
  selection:
    field: value
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059
  - attack.t1059.001
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "tagged.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.tags.len(), 3);
        assert!(rule.tags.contains(&"attack.execution".to_string()));
    }

    #[test]
    fn test_parse_rule_without_optional_fields() {
        let yaml = r#"
title: Minimal Rule
detection:
  selection:
    field: value
  condition: selection
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "minimal.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.title, "Minimal Rule");
        assert!(rule.id.is_none());
        assert!(rule.description.is_none());
        assert!(rule.level.is_none());
        assert_eq!(rule.tags.len(), 0);
    }

    #[test]
    fn test_parse_rule_with_numeric_values() {
        let yaml = r#"
title: Numeric Values
detection:
  selection:
    port: 8080
    count: 100
  condition: selection
level: low
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "numeric.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_rule_with_boolean_values() {
        let yaml = r#"
title: Boolean Values
detection:
  selection:
    enabled: true
    disabled: false
  condition: selection
level: low
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "boolean.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_rule_with_null_value() {
        let yaml = r#"
title: Null Value
detection:
  selection:
    user: null
  condition: selection
level: medium
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "null.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_rules_with_some_invalid() {
        let temp_dir = TempDir::new().unwrap();
        
        // Valid rule
        let valid_rule = r#"
title: Valid Rule
detection:
  selection:
    field: value
  condition: selection
level: low
"#;
        create_test_rule_file(&temp_dir, "valid.yml", valid_rule);
        
        // Invalid rule (should be skipped with warning)
        let invalid_rule = r#"
title: Invalid
detection:
  bad structure here
"#;
        create_test_rule_file(&temp_dir, "invalid.yml", invalid_rule);
        
        let result = load_rules_from_directory(temp_dir.path());
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        // Should only load the valid rule
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].title, "Valid Rule");
    }

    #[test]
    fn test_parse_rule_with_one_of_pattern() {
        let yaml = r#"
title: One Of Pattern
detection:
  sel1:
    field1: value1
  sel2:
    field2: value2
  sel3:
    field3: value3
  condition: 1 of sel*
level: medium
"#;
        
        let temp_dir = TempDir::new().unwrap();
        let rule_path = create_test_rule_file(&temp_dir, "oneof.yml", yaml);
        
        let result = parse_sigma_rule(&rule_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.detection.condition, "1 of sel*");
    }
}
