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