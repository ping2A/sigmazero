use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber;

use sigma_zero::engine::SigmaEngine;
use sigma_zero::correlation::CorrelationEngine;
use sigma_zero::correlation_parser::load_correlation_rules;
use sigma_zero::parser::{self, filter_rules};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to directory containing Sigma rules (YAML files)
    #[arg(short, long)]
    rules_dir: PathBuf,

    /// Path to log file or directory containing log files (JSON format)
    #[arg(short, long)]
    logs: PathBuf,

    /// Path to directory containing correlation rules (optional)
    #[arg(short = 'c', long)]
    correlation_rules: Option<PathBuf>,

    /// Number of parallel workers (defaults to number of CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Output file for matches (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format: json, jsonl, or text
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Validate rules only (parse and exit; no log evaluation)
    #[arg(long)]
    validate: bool,

    /// Filter rules by tag (can be repeated)
    #[arg(long)]
    filter_tag: Vec<String>,

    /// Filter rules by level (can be repeated)
    #[arg(long)]
    filter_level: Vec<String>,

    /// Filter rules by id (can be repeated)
    #[arg(long)]
    filter_id: Vec<String>,

    /// Field mapping: rule_field:log_field (e.g. CommandLine:command_line). Can be repeated or comma-separated.
    #[arg(long)]
    field_map: Vec<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    info!("Starting Sigma Zero Rule Evaluator");
    info!("Rules directory: {:?}", args.rules_dir);

    // Parse field mapping from --field-map
    let field_map = parse_field_map(&args.field_map)?;
    if !field_map.is_empty() {
        info!("Field mapping: {} entries", field_map.len());
    }

    let mut engine = SigmaEngine::new(args.workers);
    if !field_map.is_empty() {
        engine.set_field_map(field_map);
    }

    // Load rules (with optional filtering)
    let rules_loaded = if args.filter_tag.is_empty()
        && args.filter_level.is_empty()
        && args.filter_id.is_empty()
    {
        engine.load_rules(&args.rules_dir)?
    } else {
        let rules = parser::load_rules_from_directory(&args.rules_dir)?;
        let filtered = filter_rules(
            rules,
            &args.filter_tag,
            &args.filter_level,
            &args.filter_id,
        );
        info!("Filtered to {} rules", filtered.len());
        engine.load_rules_from_rules(filtered)?
    };
    info!("Loaded {} Sigma rules", rules_loaded);

    // Validate-only mode: exit after loading rules
    if args.validate {
        println!("Validation OK: {} rules loaded successfully.", rules_loaded);
        if let Some(correlation_dir) = &args.correlation_rules {
            match load_correlation_rules(correlation_dir) {
                Ok(corr_rules) => {
                    println!("Correlation rules: {} loaded.", corr_rules.len());
                }
                Err(e) => {
                    eprintln!("Correlation rules error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        return Ok(());
    }

    info!("Logs path: {:?}", args.logs);

    // Load correlation rules if specified
    let mut correlation_engine = CorrelationEngine::new(1000);
    let mut use_correlation = false;
    if let Some(correlation_dir) = &args.correlation_rules {
        info!("Loading correlation rules from {:?}", correlation_dir);
        match load_correlation_rules(correlation_dir) {
            Ok(corr_rules) => {
                let count = corr_rules.len();
                for rule in corr_rules {
                    correlation_engine.add_correlation_rule(rule);
                }
                info!("Loaded {} correlation rules", count);
                use_correlation = true;
            }
            Err(e) => {
                warn!("Failed to load correlation rules: {}. Continuing without correlation.", e);
            }
        }
    }

    // Process logs
    info!("Processing logs...");
    let matches = engine.evaluate_logs(&args.logs).await?;

    let correlations = if use_correlation {
        for rule_match in &matches {
            correlation_engine.record_match(rule_match.clone());
        }
        let corr_matches = correlation_engine.check_correlations();
        info!("Found {} correlation matches", corr_matches.len());
        Some(corr_matches)
    } else {
        None
    };

    // Output results
    let format_key = args.format.to_lowercase();
    match format_key.as_str() {
        "json" => output_json(&matches, &correlations, &args.output)?,
        "jsonl" => output_jsonl(&matches, &correlations, &args.output)?,
        _ => output_text(&matches, &correlations, &args.output)?,
    }

    info!("Evaluation complete. Found {} base matches", matches.len());
    if let Some(corr) = &correlations {
        info!("Found {} correlation matches", corr.len());
    }

    Ok(())
}

fn parse_field_map(entries: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for entry in entries {
        for pair in entry.split(',') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once(':') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    Ok(map)
}

fn output_json(
    matches: &[sigma_zero::models::RuleMatch],
    correlations: &Option<Vec<sigma_zero::correlation::CorrelationMatch>>,
    output_path: &Option<PathBuf>,
) -> Result<()> {
    let mut data = serde_json::json!({
        "base_matches": matches,
        "base_match_count": matches.len(),
    });
    if let Some(corr) = correlations {
        data["correlation_matches"] = serde_json::json!(corr);
        data["correlation_match_count"] = serde_json::json!(corr.len());
    }
    let out = serde_json::to_string_pretty(&data)?;
    if let Some(path) = output_path {
        std::fs::write(path, out)?;
    } else {
        println!("{}", out);
    }
    Ok(())
}

fn output_jsonl(
    matches: &[sigma_zero::models::RuleMatch],
    correlations: &Option<Vec<sigma_zero::correlation::CorrelationMatch>>,
    output_path: &Option<PathBuf>,
) -> Result<()> {
    let mut lines = Vec::new();
    for m in matches {
        lines.push(serde_json::to_string(m)?);
    }
    if let Some(corr) = correlations {
        for c in corr {
            lines.push(serde_json::to_string(&serde_json::json!({ "correlation": c }))?);
        }
    }
    let out = lines.join("\n");
    if let Some(path) = output_path {
        std::fs::write(path, out)?;
    } else {
        for line in &lines {
            println!("{}", line);
        }
    }
    Ok(())
}

fn output_text(
    matches: &[sigma_zero::models::RuleMatch],
    correlations: &Option<Vec<sigma_zero::correlation::CorrelationMatch>>,
    output_path: &Option<PathBuf>,
) -> Result<()> {
    let mut buf = String::new();
    buf.push_str("\n╔══════════════════════════════════════════╗\n");
    buf.push_str("║   Sigma Rule Evaluation Results          ║\n");
    buf.push_str("╚══════════════════════════════════════════╝\n\n");
    buf.push_str(&format!("=== Base Rule Matches ({}) ===\n\n", matches.len()));
    for m in matches {
        buf.push_str(&serde_json::to_string_pretty(m)?);
        buf.push('\n');
    }
    if let Some(corr) = correlations {
        buf.push_str(&format!(
            "\n╔══════════════════════════════════════════╗\n║   Correlation Matches ({:3})              ║\n╚══════════════════════════════════════════╝\n\n",
            corr.len()
        ));
        if corr.is_empty() {
            buf.push_str("No correlations detected.\n");
        } else {
            for c in corr {
                buf.push_str("🚨 CORRELATION ALERT!\n");
                buf.push_str(&format!("  ID: {}\n", c.correlation_rule_id));
                buf.push_str(&format!("  Title: {}\n", c.correlation_rule_title));
                if let Some(l) = &c.level {
                    buf.push_str(&format!("  Level: {}\n", l));
                }
                buf.push_str(&format!("  Related Events: {}\n", c.matched_rules.len()));
                if let Some(g) = &c.grouped_by {
                    if !g.is_empty() {
                        buf.push_str("  Grouped By:\n");
                        for (k, v) in g {
                            buf.push_str(&format!("    {}: {}\n", k, v));
                        }
                    }
                }
                buf.push_str(&format!("  Timestamp: {}\n\n", c.timestamp));
            }
        }
    }
    if let Some(path) = output_path {
        std::fs::write(path, buf)?;
    } else {
        print!("{}", buf);
    }
    Ok(())
}
