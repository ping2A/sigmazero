
<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Sigma Zero</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
[![License: APACHE 2.0](https://img.shields.io/badge/License-APACHE_2.0-2596be.svg?style=for-the-badge)](LICENSE)

</div>

<br>

# Sigma (Zero) Rule Evaluator

A high-performance Rust application for evaluating Sigma detection rules against large volumes of security logs with parallel processing capabilities.

## Features

- ⚡ **Parallel Processing**: Leverages all CPU cores using Rayon for maximum throughput
- 📊 **Scalable**: Efficiently handles huge log files with streaming and batch processing
- 🎯 **Flexible Rule Support**: Supports standard Sigma rule YAML format
- 🔍 **Pattern Matching**: Includes wildcard matching, regex support, and IP/domain detection
- 🚀 **Fast**: Optimized for speed with zero-copy parsing where possible
- 📝 **JSON Output**: Results in structured JSON format for easy integration
- **Embedded test rules (JSONL)**: Optional `_sigma_injected_rule` / `_sigma_injected_rules` fields per line to ship Sigma YAML inside a log and evaluate it in isolation (no global rules file required; useful for testing and CI)

## Installation

### Prerequisites
- Rust 1.70+ (install from https://rustup.rs)

### Build from Source

```bash
# Clone or download the project
cd sigmazero

# Build in release mode for maximum performance
cargo build --release

# The binary will be at target/release/sigma-zero
```

## Usage

### Basic Usage

```bash
sigma-zero --rules-dir ./examples/rules --logs ./examples/logs
```

Omit `--rules-dir` if every line that should match supplies its own rule via [`_sigma_injected_rule`](#embedded-test-rules-in-logs) (see `examples/logs/injection_test.jsonl`).

### Command Line Options

```
Options:
  -r, --rules-dir <PATH>         Directory or file of Sigma rules (YAML). Optional if logs use
                                 only per-line _sigma_injected_rule / _sigma_injected_rules
  -l, --logs <LOGS>            Path to log file or directory (JSON/JSONL; one object per line)
  -c, --correlation-rules      Optional correlation rules directory
  -w, --workers <N>            Parallel workers (default: CPU count)
  -o, --output                 Output file (default: stdout)
  -f, --format <json|jsonl|text>  [default: text]
      --validate                Parse rules and exit (no log evaluation)
      --filter-tag / --filter-level / --filter-id
      --field-map <MAP>         e.g. CommandLine:command_line; comma-separated or repeated
  -v, --verbose
  -h, --help
  -V, --version
```

Run `sigma-zero --help` for the exact list on your build.

### Examples

**Process a single log file:**
```bash
sigma-zero -r ./rules -l ./logs/security.json
```

**Evaluate a JSONL file that only uses embedded test rules (no `--rules-dir`):**
```bash
sigma-zero -l examples/logs/injection_test.jsonl
```

**Process a directory of logs with 8 parallel workers:**
```bash
sigma-zero -r ./rules -l ./logs -w 8
```

**Output as JSON or JSONL:**
```bash
sigma-zero -r ./rules -l ./logs -f json -o matches.json
sigma-zero -r ./rules -l ./logs -f jsonl
```

**Validate rules only (no log evaluation):**
```bash
sigma-zero -r ./rules --validate
```

**Filter rules by tag or level:**
```bash
sigma-zero -r ./rules -l ./logs --filter-tag attack.execution --filter-level high
```

**Map rule field names to log field names (e.g. Windows rule fields to your log schema):**
```bash
sigma-zero -r ./rules -l ./logs --field-map CommandLine:command_line,ProcessName:process_name
```

**Save results to a file:**
```bash
sigma-zero -r ./rules -l ./logs -o matches.json
```

**Enable verbose logging for debugging:**
```bash
sigma-zero -r ./rules -l ./logs -v
```

### Streaming mode

For real-time or pipe-based evaluation, use **sigma-zero-streaming**. It reads JSON logs from stdin and evaluates them as they arrive:

```bash
tail -f /var/log/app.json | sigma-zero-streaming -r ./rules
journalctl -f -o json | sigma-zero-streaming -r ./rules
```

**Streaming options:**
- `-r, --rules-dir` – Path to Sigma rules (optional if stdin lines use `_sigma_injected_rule` only)
- `-c, --correlation-rules` – Optional correlation rules directory
- `-b, --batch-size <N>` – Process logs in batches of N (default: 1 for real-time)
- `-f, --output-format <json|text|silent>` – Output format (default: text)
- `-m, --min-level <LEVEL>` – Only output matches at or above this level (low, medium, high, critical)

**Throughput:** Use a larger batch size (e.g. `-b 100`) to trade latency for higher throughput when reading from a pipe or file.

## Log Format

Logs must be in JSON format with one log entry per line (JSONL). Each log entry should be a JSON object with arbitrary fields:

```json
{
  "timestamp": "2025-11-06T10:15:30Z",
  "event_type": "process_creation",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=",
  "user": "john.doe",
  "source_ip": "192.168.1.50"
}
```

### Embedded test rules in logs

For **testing, debugging, and CI**, any JSONL line can include Sigma rule YAML **in the line itself**. Those fields are **removed** before matching, so they are never part of the evaluated event (and do not appear in `matched_log` in the output).

| Field | Meaning |
|-------|--------|
| `_sigma_injected_rule` | String: one complete Sigma rule as **YAML** (same structure as a `.yml` file). |
| `_sigma_injected_rules` | Array of strings (each a full rule YAML), **or** a single string. Multiple YAML documents in one string can be separated by a line containing only `---` between them. |

**Behavior**

- A line with `_sigma_injected_rule` (and/or `_sigma_injected_rules`) is evaluated with **only** the embedded rules — it does not use the global engine rules from `--rules-dir` for that line.
- Lines **without** those keys are evaluated with the **global** rule set (from `--rules-dir` when provided).
- You can omit `--rules-dir` entirely and rely only on embedded rules on the lines you care about.

**Example (one line, pretty-printed for reading):**

```json
{
  "_sigma_injected_rule": "title: test-rule\ndetection:\n  selection:\n    command_line|re: '.*-enc\\s+ABC.*'\n  condition: selection\n",
  "command_line": "powershell.exe -enc ABC",
  "process_name": "powershell.exe"
}
```

A runnable sample file is in **`examples/logs/injection_test.jsonl`**. To try it with no global rules:

```bash
sigma-zero -l examples/logs/injection_test.jsonl
```

The streaming binary **`sigma-zero-streaming`** supports the same per-line fields on stdin: `--rules-dir` is optional when lines only use embedded rules.

**Library API:** `sigma_zero::injected_log::parse_json_log_line`, and `SigmaEngine::evaluate_log_entry_with_injected_rules` for the same idea in code. A full file pipeline test is `test_evaluate_jsonl_file_with_embedded_sigma_rules` in `src/engine_tests.rs`.

## Sigma Rule Format

Rules follow the standard Sigma format. Here's an example:

```yaml
title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789abc
description: Detects execution of suspicious processes
status: experimental
level: high
detection:
  selection:
    process_name:
      - '*powershell.exe'
      - '*cmd.exe'
      - '*mimikatz*'
    command_line:
      - '*-enc*'
      - '*bypass*'
  condition: selection
tags:
  - attack.execution
  - attack.t1059
```

### Supported Features

- **Field matching**: Exact match, substring match, wildcard (*) support
- **Field modifiers**: 
  - `startswith` - Match values that start with pattern
  - `endswith` - Match values that end with pattern
  - `contains` - Match values containing pattern (default)
  - `all` - Require all values to match (instead of any)
  - `re` - Regular expression matching
  - `base64` - Match base64-decoded content
  - `lt/lte/gt/gte` - Numeric comparisons
- **Advanced Conditions**:
  - `AND` - All conditions must match
  - `OR` - At least one condition must match
  - `NOT` - Negate/exclude conditions
  - Parentheses `()` for grouping
  - `1 of them`, `all of them` - Pattern-based selection
  - `1 of selection_*` - Wildcard selection matching
  - **Threshold/count conditions**: `selection_name | count > 5` or `| count >= N` – rule fires when the number of logs matching the selection (in the current batch) satisfies the threshold. Evaluated only in batch mode (file or `evaluate_log_batch`).

📖 **See [CONDITION_OPERATORS.md](docs/CONDITION_OPERATORS.md) for complete documentation on all operators and modifiers.**
- **Multiple values**: Arrays of values for OR logic
- **Conditions**: 
  - Single selection
  - AND conditions (all selections must match)
  - OR conditions (at least one selection must match)
- **Wildcards**: Use `*` for wildcard matching (e.g., `*powershell*`)

**See [FIELD_MODIFIERS.md](docs/FIELD_MODIFIERS.md) for complete field modifier documentation.**

### Example Rules Included

1. **suspicious_process.yml**: Detects suspicious process executions like PowerShell with encoded commands
2. **suspicious_network.yml**: Detects connections to known malicious domains or suspicious IPs
3. **privilege_escalation.yml**: Detects privilege escalation attempts
4. **modifiers_startswith.yml**: Demonstrates startswith modifier usage
5. **modifiers_endswith.yml**: Demonstrates endswith modifier for file extensions
6. **modifiers_regex.yml**: Demonstrates regex pattern matching
7. **modifiers_all.yml**: Demonstrates all modifier for multi-condition matching
8. **modifiers_base64.yml**: Demonstrates base64 content detection
9. **modifiers_comparison.yml**: Demonstrates numeric comparison operators

### Example Log Files Included

The project includes 4 realistic security log files (170 total events):

1. **security_events.json** (15 events) - Basic security events with mixed legitimate and suspicious activity
2. **critical_security_events.json** (50 events) - Comprehensive attack lifecycle from initial compromise to ransomware
3. **apt_attack_chain.json** (50 events) - Advanced Persistent Threat multi-stage attack campaign
4. **mixed_traffic.json** (55 events) - Realistic mix of legitimate (70%) and malicious (30%) traffic for false positive testing

**Attack Coverage**: All 12 MITRE ATT&CK tactics represented  
**Use Cases**: Development, testing, training, incident response simulation

## Performance Considerations

### Parallel Processing
The engine automatically uses all available CPU cores. You can control this with the `-w` flag:

```bash
# Use 16 workers for maximum throughput on a 16+ core system
sigma-zero -r ./rules -l ./huge-logs -w 16
```

### Memory Efficiency
- Logs are streamed line-by-line to minimize memory usage
- Parsed logs are processed in batches
- Results are collected incrementally

### Optimization Tips
1. **Compile in release mode**: Always use `cargo build --release`
2. **Adjust worker count**: Match to your CPU core count for best results
3. **Use SSD storage**: Faster disk I/O significantly improves performance
4. **Rule optimization**: More specific rules (fewer wildcards) evaluate faster

## Benchmarking

To benchmark performance on your system:

```bash
# Create a large test log file
seq 1 1000000 | while read i; do 
  echo "{\"id\": $i, \"process_name\": \"test.exe\", \"command_line\": \"test command $i\"}"
done > large_test.json

# Time the evaluation
time sigma-zero -r ./examples/rules -l large_test.json -w $(nproc)
```

## Output Format

Matches are output in JSON format:

```json
{
  "rule_id": "12345678-1234-1234-1234-123456789abc",
  "rule_title": "Suspicious Process Execution",
  "level": "high",
  "matched_log": {
    "timestamp": "2025-11-06T10:15:30Z",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -enc ...",
    "user": "john.doe"
  },
  "timestamp": "2025-11-06T12:30:45.123Z"
}
```

## Limitations

- **Condition complexity**: Complex condition expressions with nested parentheses and NOT operators are simplified
- **Aggregation**: Time-based aggregations and correlations not yet supported
- **Field modifiers**: Most common modifiers implemented (startswith, endswith, contains, all, re, base64, comparisons). Advanced modifiers like utf16le/utf16be are planned for future releases

## Resources

- [Sigma Rule Format](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)


## About

This project has been mainly generated with the help of [Claude.ai](https://claude.ai) during an Amsterdam trip for the startup, but it seems to work correctly and can handle many cases without the need of a full SIEM !
You can see it like a micro SIEM for local evaluation of your logs or if you would like to evaluate specific logs for edge cases !

