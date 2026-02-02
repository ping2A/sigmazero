// Sigma Zero Streaming Log Processor
// bin/streaming.rs
// 
// This binary demonstrates real-time log processing with Sigma rules.
// It reads JSON logs from stdin and evaluates them in real-time.
//
// Usage:
//   tail -f /var/log/app.log | sigma-zero-streaming -r ./rules
//   journalctl -f -o json | sigma-zero-streaming -r ./rules
//   docker logs -f container | sigma-zero-streaming -r ./rules

use clap::Parser;
use std::path::PathBuf;
use std::io::{self, BufRead};
use anyhow::Result;
use tracing::{info, warn, error};
use tracing_subscriber;

use sigma_zero::engine::SigmaEngine;
use sigma_zero::models::{LogEntry, RuleMatch};
use sigma_zero::correlation_parser::load_correlation_rules;

#[derive(Parser, Debug)]
#[command(author, version, about = "Real-time Sigma rule evaluator", long_about = None)]
struct Args {
    /// Path to directory containing Sigma rules (YAML files)
    #[arg(short, long)]
    rules_dir: PathBuf,

    /// Path to directory containing correlation rules (optional)
    #[arg(short = 'c', long)]
    correlation_rules: Option<PathBuf>,

    /// Number of parallel workers (defaults to number of CPU cores)
    #[arg(short, long)]
    workers: Option<usize>,

    /// Batch size for processing logs (default: 1 for real-time)
    #[arg(short, long, default_value = "1")]
    batch_size: usize,

    /// Output format: json, text, or silent
    #[arg(short, long, default_value = "text")]
    output_format: String,

    /// Only show matches at or above this level (low, medium, high, critical)
    #[arg(short, long)]
    min_level: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting Sigma Zero Streaming Processor");
    info!("Rules directory: {:?}", args.rules_dir);

    // Initialize engine
    let mut engine = if args.correlation_rules.is_some() {
        SigmaEngine::new_with_correlation(args.workers, 10000)
    } else {
        SigmaEngine::new(args.workers)
    };

    // Load rules
    info!("Loading Sigma rules...");
    let rules_loaded = engine.load_rules(&args.rules_dir)?;
    info!("Loaded {} Sigma rules", rules_loaded);

    // Load correlation rules if specified
    if let Some(correlation_dir) = &args.correlation_rules {
        info!("Loading correlation rules from {:?}", correlation_dir);
        match load_correlation_rules(correlation_dir) {
            Ok(corr_rules) => {
                if let Some(corr_engine) = engine.correlation_engine_mut() {
                    let count = corr_rules.len();
                    for rule in corr_rules {
                        corr_engine.add_correlation_rule(rule);
                    }
                    info!("Loaded {} correlation rules", count);
                }
            }
            Err(e) => {
                warn!("Failed to load correlation rules: {}", e);
            }
        }
    }

    info!("Ready to process logs from stdin (batch size: {})", args.batch_size);
    info!("Press Ctrl+C to stop");

    // Process stdin
    process_stdin_stream(&engine, &args)?;

    Ok(())
}

fn process_stdin_stream(engine: &SigmaEngine, args: &Args) -> Result<()> {
    let stdin = io::stdin();
    let mut batch: Vec<LogEntry> = Vec::with_capacity(args.batch_size);
    let mut line_count: u64 = 0;
    let mut match_count: u64 = 0;

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to read line: {}", e);
                continue;
            }
        };

        line_count += 1;

        // Parse log entry
        let log_entry: LogEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Failed to parse log line {}: {}", line_count, e);
                continue;
            }
        };

        if args.batch_size == 1 {
            // Real-time mode: process immediately
            let matches = engine.evaluate_log_entry(&log_entry);
            for rule_match in matches {
                if should_output_match(&rule_match, &args.min_level) {
                    output_match(&rule_match, &args.output_format);
                    match_count += 1;
                }
            }
        } else {
            // Batch mode: accumulate and process in batches
            batch.push(log_entry);
            
            if batch.len() >= args.batch_size {
                let matches = engine.evaluate_log_batch(&batch);
                for rule_match in matches {
                    if should_output_match(&rule_match, &args.min_level) {
                        output_match(&rule_match, &args.output_format);
                        match_count += 1;
                    }
                }
                batch.clear();
            }
        }

        // Periodic stats
        if line_count % 10000 == 0 {
            info!("Processed {} logs, found {} matches", line_count, match_count);
        }
    }

    // Process remaining batch
    if !batch.is_empty() {
        let matches = engine.evaluate_log_batch(&batch);
        for rule_match in matches {
            if should_output_match(&rule_match, &args.min_level) {
                output_match(&rule_match, &args.output_format);
                match_count += 1;
            }
        }
    }

    info!("Stream ended. Processed {} logs, found {} matches", line_count, match_count);

    // Check for final correlations
    let correlations = engine.check_correlations();
    if !correlations.is_empty() {
        info!("Found {} correlation matches", correlations.len());
        for corr in correlations {
            output_correlation(&corr, &args.output_format);
        }
    }

    Ok(())
}

fn should_output_match(rule_match: &RuleMatch, min_level: &Option<String>) -> bool {
    if let Some(ref min) = min_level {
        if let Some(ref level) = rule_match.level {
            return level_priority(level) >= level_priority(min);
        }
        return false;
    }
    true
}

fn level_priority(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn output_match(rule_match: &RuleMatch, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(rule_match) {
                println!("{}", json);
            }
        }
        "silent" => {
            // No output, just count
        }
        _ => {
            // Text format (default)
            let level = rule_match.level.as_deref().unwrap_or("unknown");
            let level_icon = match level {
                "critical" => "🔥",
                "high" => "🚨",
                "medium" => "⚠️ ",
                "low" => "ℹ️ ",
                _ => "• ",
            };
            
            println!("{} [{}] {} ({})", 
                level_icon,
                level.to_uppercase(),
                rule_match.rule_title,
                rule_match.rule_id.as_deref().unwrap_or("unknown")
            );
        }
    }
}

fn output_correlation(corr: &sigma_zero::correlation::CorrelationMatch, format: &str) {
    match format {
        "json" => {
            if let Ok(json) = serde_json::to_string(corr) {
                println!("{}", json);
            }
        }
        "silent" => {}
        _ => {
            println!("🔥🔥🔥 CORRELATION: {} ({} related events)", 
                corr.correlation_rule_title,
                corr.matched_rules.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_priority() {
        assert_eq!(level_priority("critical"), 4);
        assert_eq!(level_priority("high"), 3);
        assert_eq!(level_priority("medium"), 2);
        assert_eq!(level_priority("low"), 1);
        assert_eq!(level_priority("unknown"), 0);
    }

    #[test]
    fn test_should_output_match_no_filter() {
        let rule_match = RuleMatch {
            rule_id: Some("test".to_string()),
            rule_title: "Test".to_string(),
            level: Some("high".to_string()),
            matched_log: std::sync::Arc::new(LogEntry { fields: std::collections::HashMap::new() }),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };
        
        assert!(should_output_match(&rule_match, &None));
    }

    #[test]
    fn test_should_output_match_with_filter() {
        let rule_match_high = RuleMatch {
            rule_id: Some("test".to_string()),
            rule_title: "Test".to_string(),
            level: Some("high".to_string()),
            matched_log: std::sync::Arc::new(LogEntry { fields: std::collections::HashMap::new() }),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };
        
        let rule_match_low = RuleMatch {
            rule_id: Some("test".to_string()),
            rule_title: "Test".to_string(),
            level: Some("low".to_string()),
            matched_log: std::sync::Arc::new(LogEntry { fields: std::collections::HashMap::new() }),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };
        
        assert!(should_output_match(&rule_match_high, &Some("medium".to_string())));
        assert!(!should_output_match(&rule_match_low, &Some("medium".to_string())));
    }
}