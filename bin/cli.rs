use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber;


use sigma_zero::engine::SigmaEngine;
use sigma_zero::correlation::CorrelationEngine;
use sigma_zero::correlation_parser::load_correlation_rules;

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

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
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

    info!("Starting Sigma Zero Rule Evaluator");
    info!("Rules directory: {:?}", args.rules_dir);
    info!("Logs path: {:?}", args.logs);

    // Initialize the Sigma engine
    let mut engine = SigmaEngine::new(args.workers);

    // Load Sigma rules
    info!("Loading Sigma rules...");
    let rules_loaded = engine.load_rules(&args.rules_dir)?;
    info!("Loaded {} Sigma rules", rules_loaded);

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

    // If correlation is enabled, record matches and evaluate correlations
    let correlations = if use_correlation {
        info!("Recording matches for correlation analysis...");
        for rule_match in &matches {
            correlation_engine.record_match(rule_match.clone());
        }
        
        info!("Evaluating correlations...");
        let corr_matches = correlation_engine.check_correlations();
        info!("Found {} correlation matches", corr_matches.len());
        Some(corr_matches)
    } else {
        None
    };

    // Output results
    if let Some(output_path) = args.output {
        info!("Writing results to {:?}", output_path);
        
        let mut output_data = serde_json::json!({
            "base_matches": matches,
            "base_match_count": matches.len(),
        });
        
        if let Some(corr) = &correlations {
            output_data["correlation_matches"] = serde_json::json!(corr);
            output_data["correlation_match_count"] = serde_json::json!(corr.len());
        }
        
        let output = serde_json::to_string_pretty(&output_data)?;
        std::fs::write(output_path, output)?;
    } else {
        println!("\n╔══════════════════════════════════════════╗");
        println!("║   Sigma Rule Evaluation Results          ║");
        println!("╚══════════════════════════════════════════╝\n");
        
        println!("=== Base Rule Matches ({}) ===\n", matches.len());
        for match_result in &matches {
            println!("{}", serde_json::to_string_pretty(match_result)?);
        }
        
        if let Some(corr) = &correlations {
            println!("\n╔══════════════════════════════════════════╗");
            println!("║   Correlation Matches ({:3})              ║", corr.len());
            println!("╚══════════════════════════════════════════╝\n");
            
            if corr.is_empty() {
                println!("No correlations detected.");
            } else {
                for corr_match in corr {
                    println!("🚨 CORRELATION ALERT!");
                    println!("  ID: {}", corr_match.correlation_rule_id);
                    println!("  Title: {}", corr_match.correlation_rule_title);
                    if let Some(level) = &corr_match.level {
                        println!("  Level: {}", level);
                    }
                    println!("  Related Events: {}", corr_match.matched_rules.len());
                    if let Some(grouped) = &corr_match.grouped_by {
                        if !grouped.is_empty() {
                            println!("  Grouped By:");
                            for (k, v) in grouped {
                                println!("    {}: {}", k, v);
                            }
                        }
                    }
                    println!("  Timestamp: {}", corr_match.timestamp);
                    println!();
                }
            }
        }
    }

    info!("Evaluation complete. Found {} base matches", matches.len());
    if let Some(corr) = &correlations {
        info!("Found {} correlation matches", corr.len());
    }

    Ok(())
}
