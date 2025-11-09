use std::path::Path;
use std::fs;
use serde_yaml::Value;
use anyhow::{Result, Context, bail};
use chrono::Duration;
use crate::correlation::{CorrelationRule, CorrelationCondition, CorrelationType};

/// Parse a correlation rule from a YAML file
pub fn parse_correlation_rule(path: &Path) -> Result<CorrelationRule> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read correlation rule file: {:?}", path))?;
    
    let yaml: Value = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML in file: {:?}", path))?;
    
    // Extract basic fields
    let id = yaml.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    
    let title = yaml.get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled Correlation")
        .to_string();
    
    let description = yaml.get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let level = yaml.get("level")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Parse correlation section
    let correlation_section = yaml.get("correlation")
        .ok_or_else(|| anyhow::anyhow!("Missing 'correlation' section in file: {:?}", path))?;
    
    let correlation = parse_correlation_condition(correlation_section)?;
    
    Ok(CorrelationRule {
        id,
        title,
        description,
        level,
        correlation,
    })
}

/// Parse the correlation condition from YAML
fn parse_correlation_condition(yaml: &Value) -> Result<CorrelationCondition> {
    // Parse rule references
    let rule_refs = yaml.get("rules")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'rules' field in correlation"))?
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    
    if rule_refs.is_empty() {
        bail!("Correlation must reference at least one rule");
    }
    
    // Parse correlation type
    let type_str = yaml.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("temporal");
    
    // Parse condition (now as a YAML object with gte/lte/eq)
    let condition_yaml = yaml.get("condition");
    
    let condition_type = parse_correlation_type(type_str, condition_yaml, rule_refs.len())?;
    
    // Parse timespan
    let timespan = yaml.get("timespan")
        .and_then(|v| v.as_str())
        .map(|s| parse_timespan(s))
        .transpose()?;
    
    // Parse group-by (with hyphen, official Sigma syntax)
    let group_by = yaml.get("group-by")
        .or_else(|| yaml.get("group_by")) // Also support underscore for backwards compatibility
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        });
    
    Ok(CorrelationCondition {
        rule_refs,
        condition_type,
        timespan,
        group_by,
    })
}

/// Parse correlation type from YAML
fn parse_correlation_type(type_str: &str, condition_yaml: Option<&Value>, num_rules: usize) -> Result<CorrelationType> {
    match type_str {
        "temporal" => {
            // Temporal: events within timeframe with condition
            if let Some(cond) = condition_yaml {
                if let Some(gte_val) = cond.get("gte").and_then(|v| v.as_u64()) {
                    return Ok(CorrelationType::AtLeast(gte_val as usize));
                }
                if let Some(eq_val) = cond.get("eq").and_then(|v| v.as_u64()) {
                    if eq_val as usize == num_rules {
                        return Ok(CorrelationType::All);
                    }
                    return Ok(CorrelationType::AtLeast(eq_val as usize));
                }
            }
            // Default to "all" if no condition specified
            Ok(CorrelationType::All)
        }
        "temporal_ordered" => {
            // Ordered sequence of events
            Ok(CorrelationType::Sequence)
        }
        "event_count" => {
            // Count-based correlation (e.g., 10+ failed logins)
            if let Some(cond) = condition_yaml {
                if let Some(gte_val) = cond.get("gte").and_then(|v| v.as_u64()) {
                    return Ok(CorrelationType::Count(gte_val as usize));
                }
            }
            bail!("event_count requires condition with 'gte' field")
        }
        "value_count" => {
            // Count unique values (e.g., unique IPs)
            if let Some(cond) = condition_yaml {
                if let Some(gte_val) = cond.get("gte").and_then(|v| v.as_u64()) {
                    return Ok(CorrelationType::Count(gte_val as usize));
                }
            }
            bail!("value_count requires condition with 'gte' field")
        }
        _ => bail!("Unknown correlation type: {}. Use: temporal, temporal_ordered, event_count, or value_count", type_str)
    }
}

/// Parse timespan string like "5m", "1h", "2h30m"
fn parse_timespan(s: &str) -> Result<Duration> {
    let s = s.trim().to_lowercase();
    
    // Try simple formats first
    if s.ends_with("s") {
        let num = s.trim_end_matches("s").parse::<i64>()?;
        return Ok(Duration::seconds(num));
    }
    
    if s.ends_with("m") && !s.contains("h") {
        let num = s.trim_end_matches("m").parse::<i64>()?;
        return Ok(Duration::minutes(num));
    }
    
    if s.ends_with("h") && !s.contains("m") {
        let num = s.trim_end_matches("h").parse::<i64>()?;
        return Ok(Duration::hours(num));
    }
    
    if s.ends_with("d") {
        let num = s.trim_end_matches("d").parse::<i64>()?;
        return Ok(Duration::days(num));
    }
    
    // Handle complex format like "2h30m"
    if s.contains("h") && s.contains("m") {
        let parts: Vec<&str> = s.split("h").collect();
        if parts.len() == 2 {
            let hours = parts[0].parse::<i64>()?;
            let minutes = parts[1].trim_end_matches("m").parse::<i64>()?;
            return Ok(Duration::hours(hours) + Duration::minutes(minutes));
        }
    }
    
    bail!("Invalid timespan format: {}. Use: 5s, 30m, 1h, 2h30m, 1d", s)
}

/// Load all correlation rules from a directory
pub fn load_correlation_rules(dir_path: &Path) -> Result<Vec<CorrelationRule>> {
    let mut rules = Vec::new();
    
    if !dir_path.exists() {
        bail!("Correlation rules directory does not exist: {:?}", dir_path);
    }
    
    if !dir_path.is_dir() {
        bail!("Path is not a directory: {:?}", dir_path);
    }
    
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        
        // Only process .yml and .yaml files
        if let Some(ext) = path.extension() {
            if ext == "yml" || ext == "yaml" {
                match parse_correlation_rule(&path) {
                    Ok(rule) => {
                        println!("  Loaded correlation rule: {}", rule.title);
                        rules.push(rule);
                    }
                    Err(e) => {
                        eprintln!("  Warning: Failed to parse {:?}: {}", path.file_name(), e);
                    }
                }
            }
        }
    }
    
    if rules.is_empty() {
        eprintln!("Warning: No correlation rules loaded from {:?}", dir_path);
    }
    
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml;
    
    #[test]
    fn test_parse_timespan() {
        assert_eq!(parse_timespan("5s").unwrap(), Duration::seconds(5));
        assert_eq!(parse_timespan("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_timespan("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_timespan("2h30m").unwrap(), Duration::hours(2) + Duration::minutes(30));
        assert_eq!(parse_timespan("1d").unwrap(), Duration::days(1));
    }
    
    #[test]
    fn test_parse_timespan_invalid() {
        assert!(parse_timespan("invalid").is_err());
        assert!(parse_timespan("").is_err());
        assert!(parse_timespan("5x").is_err());
    }
    
    #[test]
    fn test_parse_correlation_type_temporal() {
        let yaml = serde_yaml::from_str("gte: 3").unwrap();
        let result = parse_correlation_type("temporal", Some(&yaml), 5);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::AtLeast(n) => assert_eq!(n, 3),
            _ => panic!("Expected AtLeast"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_temporal_no_condition() {
        let result = parse_correlation_type("temporal", None, 3);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::All => {},
            _ => panic!("Expected All when no condition specified"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_temporal_eq() {
        let yaml = serde_yaml::from_str("eq: 5").unwrap();
        let result = parse_correlation_type("temporal", Some(&yaml), 5);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::All => {},
            _ => panic!("Expected All when eq matches num_rules"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_temporal_ordered() {
        let result = parse_correlation_type("temporal_ordered", None, 3);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::Sequence => {},
            _ => panic!("Expected Sequence"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_event_count() {
        let yaml = serde_yaml::from_str("gte: 10").unwrap();
        let result = parse_correlation_type("event_count", Some(&yaml), 1);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::Count(n) => assert_eq!(n, 10),
            _ => panic!("Expected Count"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_event_count_no_condition() {
        let result = parse_correlation_type("event_count", None, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires condition"));
    }
    
    #[test]
    fn test_parse_correlation_type_value_count() {
        let yaml = serde_yaml::from_str("gte: 5").unwrap();
        let result = parse_correlation_type("value_count", Some(&yaml), 1);
        assert!(result.is_ok());
        match result.unwrap() {
            CorrelationType::Count(n) => assert_eq!(n, 5),
            _ => panic!("Expected Count"),
        }
    }
    
    #[test]
    fn test_parse_correlation_type_invalid() {
        let result = parse_correlation_type("invalid_type", None, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown correlation type"));
    }
    
    #[test]
    fn test_parse_correlation_condition_basic() {
        let yaml_str = r#"
type: temporal
rules:
  - rule1
  - rule2
timespan: 1h
condition:
  gte: 2
group-by:
  - user
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        let result = parse_correlation_condition(&yaml);
        
        assert!(result.is_ok());
        let condition = result.unwrap();
        assert_eq!(condition.rule_refs.len(), 2);
        assert_eq!(condition.rule_refs[0], "rule1");
        assert_eq!(condition.rule_refs[1], "rule2");
        assert!(condition.timespan.is_some());
        assert_eq!(condition.timespan.unwrap(), Duration::hours(1));
        assert!(condition.group_by.is_some());
        assert_eq!(condition.group_by.unwrap(), vec!["user"]);
    }
    
    #[test]
    fn test_parse_correlation_condition_no_rules() {
        let yaml_str = r#"
type: temporal
rules: []
timespan: 1h
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        let result = parse_correlation_condition(&yaml);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least one rule"));
    }
    
    #[test]
    fn test_parse_correlation_condition_missing_rules() {
        let yaml_str = r#"
type: temporal
timespan: 1h
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        let result = parse_correlation_condition(&yaml);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_parse_correlation_condition_group_by_hyphen() {
        let yaml_str = r#"
type: temporal
rules:
  - rule1
group-by:
  - user
  - host
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        let result = parse_correlation_condition(&yaml);
        
        assert!(result.is_ok());
        let condition = result.unwrap();
        assert!(condition.group_by.is_some());
        let group_by = condition.group_by.unwrap();
        assert_eq!(group_by.len(), 2);
        assert_eq!(group_by[0], "user");
        assert_eq!(group_by[1], "host");
    }
    
    #[test]
    fn test_parse_correlation_condition_group_by_underscore() {
        // Test backward compatibility with underscore
        let yaml_str = r#"
type: temporal
rules:
  - rule1
group_by:
  - user
  - host
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        let result = parse_correlation_condition(&yaml);
        
        assert!(result.is_ok());
        let condition = result.unwrap();
        assert!(condition.group_by.is_some());
        let group_by = condition.group_by.unwrap();
        assert_eq!(group_by.len(), 2);
    }
    
    #[test]
    fn test_parse_correlation_rule_ssh_brute_force() {
        let yaml_str = r#"
title: SSH Brute Force Attack
id: ssh-brute-force-001
description: Detects multiple failed SSH attempts
level: high

correlation:
  type: event_count
  rules:
    - ssh-authentication-failed
  timespan: 5m
  condition:
    gte: 10
  group-by:
    - source_ip
    - destination_ip

tags:
  - attack.credential_access
"#;
        
        // Write to temp file
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_ssh_rule.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.id, "ssh-brute-force-001");
        assert_eq!(rule.title, "SSH Brute Force Attack");
        assert_eq!(rule.level, Some("high".to_string()));
        assert_eq!(rule.description, Some("Detects multiple failed SSH attempts".to_string()));
        
        let corr = &rule.correlation;
        assert_eq!(corr.rule_refs.len(), 1);
        assert_eq!(corr.rule_refs[0], "ssh-authentication-failed");
        assert!(corr.timespan.is_some());
        assert_eq!(corr.timespan.unwrap(), Duration::minutes(5));
        assert!(corr.group_by.is_some());
        assert_eq!(corr.group_by.as_ref().unwrap().len(), 2);
        
        match &corr.condition_type {
            CorrelationType::Count(n) => assert_eq!(*n, 10),
            _ => panic!("Expected Count type"),
        }
        
        // Cleanup
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_parse_correlation_rule_temporal_ordered() {
        let yaml_str = r#"
title: Data Exfiltration Chain
id: data-exfil-001
description: Sequential data theft
level: critical

correlation:
  type: temporal_ordered
  rules:
    - file-access
    - data-staging
    - outbound-transfer
  timespan: 2h
  group-by:
    - user

tags:
  - attack.exfiltration
"#;
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_exfil_rule.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.id, "data-exfil-001");
        assert_eq!(rule.level, Some("critical".to_string()));
        
        let corr = &rule.correlation;
        assert_eq!(corr.rule_refs.len(), 3);
        
        match &corr.condition_type {
            CorrelationType::Sequence => {},
            _ => panic!("Expected Sequence type"),
        }
        
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_parse_correlation_rule_apt_chain() {
        let yaml_str = r#"
title: APT Attack Chain
id: apt-001
level: critical

correlation:
  type: temporal
  rules:
    - credential-dumping
    - suspicious-powershell
    - lateral-movement
  timespan: 4h
  condition:
    gte: 3
  group-by:
    - user
"#;
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_apt_rule.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert_eq!(rule.correlation.rule_refs.len(), 3);
        
        match &rule.correlation.condition_type {
            CorrelationType::AtLeast(n) => assert_eq!(*n, 3),
            _ => panic!("Expected AtLeast"),
        }
        
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_parse_correlation_rule_invalid_file() {
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("nonexistent_rule.yml");
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_parse_correlation_rule_invalid_yaml() {
        let yaml_str = "this is not valid: [yaml";
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("invalid_yaml.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_err());
        
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_parse_correlation_rule_missing_correlation_section() {
        let yaml_str = r#"
title: Test Rule
id: test-001
level: high
"#;
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("no_correlation.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("correlation"));
        
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_load_correlation_rules_directory() {
        // Create temp directory with test rules
        let temp_dir = std::env::temp_dir().join("test_corr_rules");
        std::fs::create_dir_all(&temp_dir).unwrap();
        
        // Create valid rule 1
        let rule1 = r#"
title: Rule 1
id: rule-001
level: high
correlation:
  type: temporal
  rules:
    - base-rule-1
  timespan: 1h
"#;
        std::fs::write(temp_dir.join("rule1.yml"), rule1).unwrap();
        
        // Create valid rule 2
        let rule2 = r#"
title: Rule 2
id: rule-002
level: medium
correlation:
  type: event_count
  rules:
    - base-rule-2
  timespan: 5m
  condition:
    gte: 5
"#;
        std::fs::write(temp_dir.join("rule2.yml"), rule2).unwrap();
        
        // Create invalid rule (should be skipped with warning)
        std::fs::write(temp_dir.join("invalid.yml"), "invalid yaml: [").unwrap();
        
        // Create non-yaml file (should be skipped)
        std::fs::write(temp_dir.join("readme.txt"), "not a rule").unwrap();
        
        let result = load_correlation_rules(&temp_dir);
        assert!(result.is_ok());
        
        let rules = result.unwrap();
        assert_eq!(rules.len(), 2); // Only 2 valid rules loaded
        
        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }
    
    #[test]
    fn test_load_correlation_rules_nonexistent_directory() {
        let temp_dir = std::env::temp_dir().join("nonexistent_dir_12345");
        let result = load_correlation_rules(&temp_dir);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_load_correlation_rules_file_instead_of_directory() {
        let temp_file = std::env::temp_dir().join("test_file.txt");
        std::fs::write(&temp_file, "test").unwrap();
        
        let result = load_correlation_rules(&temp_file);
        assert!(result.is_err());
        
        std::fs::remove_file(&temp_file).ok();
    }
    
    #[test]
    fn test_parse_correlation_with_lte_condition() {
        let yaml_str = r#"
type: temporal
rules:
  - rule1
condition:
  lte: 2
"#;
        let yaml: Value = serde_yaml::from_str(yaml_str).unwrap();
        
        // Currently we don't support lte, but test that it doesn't crash
        let result = parse_correlation_condition(&yaml);
        // This should succeed but not parse lte (falls back to default)
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_parse_timespan_complex() {
        // Test edge cases
        assert_eq!(parse_timespan("0s").unwrap(), Duration::seconds(0));
        assert_eq!(parse_timespan("1d").unwrap(), Duration::days(1));
        assert_eq!(parse_timespan("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_timespan("60m").unwrap(), Duration::minutes(60));
        
        // Complex format
        assert_eq!(
            parse_timespan("3h15m").unwrap(), 
            Duration::hours(3) + Duration::minutes(15)
        );
    }
    
    #[test]
    fn test_correlation_rule_with_no_group_by() {
        let yaml_str = r#"
title: Test Rule
id: test-001
level: high
correlation:
  type: event_count
  rules:
    - base-rule
  timespan: 5m
  condition:
    gte: 10
"#;
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("no_groupby.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert!(rule.correlation.group_by.is_none());
        
        std::fs::remove_file(&temp_path).ok();
    }
    
    #[test]
    fn test_correlation_rule_with_no_timespan() {
        let yaml_str = r#"
title: Test Rule
id: test-001
level: high
correlation:
  type: temporal
  rules:
    - base-rule
"#;
        
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("no_timespan.yml");
        std::fs::write(&temp_path, yaml_str).unwrap();
        
        let result = parse_correlation_rule(&temp_path);
        assert!(result.is_ok());
        
        let rule = result.unwrap();
        assert!(rule.correlation.timespan.is_none());
        
        std::fs::remove_file(&temp_path).ok();
    }
}