use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::models::SigmaRule;

/// Parse a Sigma rule from a YAML file
pub fn parse_sigma_rule(path: &Path) -> Result<SigmaRule> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read rule file: {:?}", path))?;
    
    let rule: SigmaRule = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML in file: {:?}", path))?;
    
    Ok(rule)
}

/// Filter rules by tag, level, or id. Each non-empty filter must match (AND).
/// Empty filter list means no filter for that dimension.
pub fn filter_rules(
    rules: Vec<SigmaRule>,
    tags: &[String],
    levels: &[String],
    ids: &[String],
) -> Vec<SigmaRule> {
    if tags.is_empty() && levels.is_empty() && ids.is_empty() {
        return rules;
    }
    rules
        .into_iter()
        .filter(|rule| {
            let tag_ok = tags.is_empty()
                || rule.tags.iter().any(|t| tags.iter().any(|f| t.eq_ignore_ascii_case(f)));
            let level_ok = levels.is_empty()
                || rule
                    .level
                    .as_ref()
                    .map(|l| levels.iter().any(|f| l.eq_ignore_ascii_case(f)))
                    .unwrap_or(false);
            let id_ok = ids.is_empty()
                || rule
                    .id
                    .as_ref()
                    .map(|i| ids.iter().any(|f| i.eq_ignore_ascii_case(f)))
                    .unwrap_or(false);
            tag_ok && level_ok && id_ok
        })
        .collect()
}

/// Load all Sigma rules from a directory
pub fn load_rules_from_directory(dir_path: &Path) -> Result<Vec<SigmaRule>> {
    let mut rules = Vec::new();

    if !dir_path.exists() {
        anyhow::bail!("Rules directory does not exist: {:?}", dir_path);
    }

    if !dir_path.is_dir() {
        anyhow::bail!("Rules path is not a directory: {:?}", dir_path);
    }

    // Read all YAML files recursively
    visit_dirs(dir_path, &mut |entry| {
        if let Some(ext) = entry.path().extension() {
            if ext == "yml" || ext == "yaml" {
                match parse_sigma_rule(&entry.path()) {
                    Ok(rule) => {
                        rules.push(rule);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse rule {:?}: {}", entry.path(), e);
                    }
                }
            }
        }
    })?;

    Ok(rules)
}

/// Load all Sigma rules from a file
pub fn load_rules_from_file(rule_path: &Path) -> Result<SigmaRule> {
    parse_sigma_rule(&rule_path)
}

/// Recursively visit all files in a directory
fn visit_dirs(dir: &Path, cb: &mut dyn FnMut(&fs::DirEntry)) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry);
            }
        }
    }
    Ok(())
}