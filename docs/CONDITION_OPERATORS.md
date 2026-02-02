# Advanced Sigma Condition Operators

This document describes the advanced condition operators supported by the Sigma Rule Evaluator.

## Table of Contents
1. [Boolean Operators](#boolean-operators)
2. [Pattern Matching](#pattern-matching)
3. [Threshold / Count Conditions](#threshold--count-conditions)
4. [Field Modifiers](#field-modifiers)
5. [Numeric Comparisons](#numeric-comparisons)
6. [Null Handling](#null-handling)
7. [Examples](#examples)

## Boolean Operators

### AND Operator
All conditions must be true.

```yaml
condition: selection1 and selection2
```

**Example:**
```yaml
detection:
  selection_process:
    process_name: 'powershell.exe'
  selection_command:
    command_line: '*-enc*'
  condition: selection_process and selection_command
```

### OR Operator
At least one condition must be true.

```yaml
condition: selection1 or selection2
```

**Example:**
```yaml
detection:
  selection_ps:
    process_name: 'powershell.exe'
  selection_cmd:
    process_name: 'cmd.exe'
  condition: selection_ps or selection_cmd
```

### NOT Operator
Negates a condition (excludes matches).

```yaml
condition: selection and not filter
```

**Example:**
```yaml
detection:
  selection:
    process_name: 'powershell.exe'
  filter:
    command_line: '*System32*'
  condition: selection and not filter
```

This matches PowerShell processes that are NOT in System32.

### Parentheses
Group conditions to control precedence.

```yaml
condition: selection1 and (selection2 or selection3)
```

**Example:**
```yaml
detection:
  sel_process:
    process_name: 'powershell.exe'
  sel_encoded:
    command_line: '*-enc*'
  sel_download:
    command_line: '*downloadstring*'
  condition: sel_process and (sel_encoded or sel_download)
```

This matches PowerShell with EITHER encoded commands OR download strings.

## Pattern Matching

### "1 of them" Pattern
Matches if at least one of ALL selections matches.

```yaml
condition: 1 of them
```

**Example:**
```yaml
detection:
  selection_a:
    field1: 'value1'
  selection_b:
    field2: 'value2'
  selection_c:
    field3: 'value3'
  condition: 1 of them
```

### "all of them" Pattern
Matches if ALL selections match.

```yaml
condition: all of them
```

**Example:**
```yaml
detection:
  selection_a:
    field1: 'value1'
  selection_b:
    field2: 'value2'
  condition: all of them
```

### "1 of pattern*" Pattern
Matches if at least one selection matching the pattern matches.

```yaml
condition: 1 of selection_*
```

**Example:**
```yaml
detection:
  selection_ps:
    process_name: 'powershell.exe'
  selection_cmd:
    process_name: 'cmd.exe'
  selection_wscript:
    process_name: 'wscript.exe'
  filter_legit:
    user: 'SYSTEM'
  condition: 1 of selection_*
```

This checks if ANY selection starting with "selection_" matches (ignores filter_legit).

### Numeric "of" Pattern
Require a specific number of selections to match.

```yaml
condition: 2 of selection_*
```

**Example:**
```yaml
detection:
  selection_a:
    indicator1: 'bad1'
  selection_b:
    indicator2: 'bad2'
  selection_c:
    indicator3: 'bad3'
  condition: 2 of selection_*
```

Requires at least 2 of the 3 selections to match.

## Threshold / Count Conditions

Rules can fire when the **number of log entries** matching a selection (in the current batch) satisfies a threshold. This is useful for detecting “N+ failed logins”, “more than 5 errors from same host”, etc.

**Syntax:**
```yaml
condition: selection_name | count > N
condition: selection_name | count >= N
condition: selection_name | count < N
condition: selection_name | count <= N
condition: selection_name | count == N
```

**Example – multiple failed logins:**
```yaml
title: Multiple Failed SSH Logins
detection:
  failed_login:
    event_type: 'ssh_failed'
    user: '*'
  condition: failed_login | count > 5
```

The rule triggers when, in the **current batch** of logs (e.g. one file or one `evaluate_log_batch` call), more than 5 entries match the `failed_login` selection.

**Behaviour:**
- **Batch-only:** Threshold/count is evaluated only when processing a batch of logs (e.g. `sigma-zero -r ./rules -l ./logs` or `evaluate_log_batch`). It is **not** evaluated per log in streaming mode (`sigma-zero-streaming` or `evaluate_log_entry`).
- **Operators:** `>`, `>=`, `<`, `<=`, `==` with a non-negative integer threshold.
- **Output:** When the condition is satisfied, one match is emitted per matching log entry (each with the same rule metadata).

**CLI:** Use file or directory input so the engine runs in batch mode; count conditions are then applied over that batch.

## Field Modifiers

Field modifiers change how field values are matched. They are added after the field name using pipe notation: `field_name|modifier`

### contains (default)
Substring matching (this is the default behavior).

```yaml
field|contains: 'substring'
# Equivalent to:
field: '*substring*'
```

### startswith
Matches if field value starts with the pattern.

```yaml
command_line|startswith: 'powershell'
```

**Example:**
```yaml
detection:
  selection:
    command_line|startswith:
      - 'powershell'
      - 'cmd'
  condition: selection
```

### endswith
Matches if field value ends with the pattern.

```yaml
file_path|endswith: '.exe'
```

**Example:**
```yaml
detection:
  selection:
    file_path|endswith:
      - '.exe'
      - '.dll'
  condition: selection
```

### all
All values in array must be present (AND logic for arrays).

```yaml
command_line|contains|all:
  - 'bypass'
  - 'executionpolicy'
```

Both "bypass" AND "executionpolicy" must be in the command line.

### re (regex)
Regular expression matching.

```yaml
command_line|re: '.*-enc[oded]*\s+[A-Za-z0-9+/=]{50,}.*'
```

**Example:**
```yaml
detection:
  selection:
    command_line|re: 'powershell.*-e(nc|ncodedcommand).*'
  condition: selection
```

### base64 / base64offset
The search value is base64-encoded. The decoder will decode the value and search for it.

```yaml
command_line|base64: 'IEX'
```

Searches for the base64-encoded version of "IEX" in the command line.

### utf16le / utf16be / wide
Encodes the search string as UTF-16 (Little Endian, Big Endian, or Wide).

```yaml
file_content|utf16le: 'malicious'
```

Useful for finding strings in binary files or Unicode-encoded content.

## Numeric Comparisons

### Greater Than (gt)
```yaml
field|gt: 1000
```

### Greater Than or Equal (gte)
```yaml
field|gte: 1000
```

### Less Than (lt)
```yaml
field|lt: 100
```

### Less Than or Equal (lte)
```yaml
field|lte: 100
```

**Example:**
```yaml
detection:
  selection:
    bytes_transferred|gte: 1000000
    response_code|lt: 400
  condition: selection
```

This matches large transfers (>= 1MB) with successful response codes (< 400).

## Null Handling

### Checking for Missing Fields
Use `null` to match when a field is NOT present.

```yaml
detection:
  selection:
    user: null
  condition: selection
```

This matches logs where the "user" field is missing.

### Combining with NOT
```yaml
detection:
  selection:
    field: null
  condition: not selection
```

This matches logs where the field EXISTS (opposite of null check).

## Complete Examples

### Example 1: Advanced Threat Detection
```yaml
title: APT-Style Attack Detection
detection:
  initial_access:
    process_name: 'powershell.exe'
    command_line|contains:
      - 'downloadstring'
      - 'invoke-expression'
  
  persistence:
    registry_path|startswith: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
  
  defense_evasion:
    command_line|contains|all:
      - 'bypass'
      - 'executionpolicy'
  
  command_and_control:
    destination_domain|endswith:
      - '.tk'
      - '.ru'
      - '.cn'
  
  filter_legitimate:
    user: 'SYSTEM'
    parent_process: '*svchost.exe'
  
  condition: (initial_access or persistence) and defense_evasion and not filter_legitimate
```

### Example 2: Multiple Indicators Required
```yaml
title: High-Confidence Malware Detection
detection:
  sel_process:
    process_name:
      - '*powershell.exe'
      - '*cmd.exe'
  
  sel_network:
    destination_ip|re: '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
  
  sel_file:
    file_path|endswith:
      - '.bat'
      - '.vbs'
      - '.ps1'
  
  sel_registry:
    registry_action: 'add'
  
  condition: 2 of sel_*
```

Requires at least 2 different types of indicators to trigger.

### Example 3: Complex Logic with NOT
```yaml
title: Suspicious But Not False Positive
detection:
  suspicious:
    process_name: 'powershell.exe'
    command_line|contains:
      - '-nop'
      - '-w hidden'
  
  false_positive_path:
    command_line|contains:
      - 'Program Files'
      - 'Windows\System32'
  
  false_positive_parent:
    parent_process|endswith:
      - 'explorer.exe'
      - 'services.exe'
  
  condition: suspicious and not (false_positive_path or false_positive_parent)
```

### Example 4: Numeric Thresholds
```yaml
title: Suspicious Network Activity
detection:
  large_transfer:
    bytes_sent|gte: 10000000
  
  unusual_port:
    destination_port|gt: 49152
    destination_port|lt: 65535
  
  frequent_connections:
    connection_count|gte: 100
  
  condition: large_transfer and unusual_port and frequent_connections
```

### Example 5: Field Modifiers Showcase
```yaml
title: Advanced Pattern Matching
detection:
  sel_startswith:
    command_line|startswith: 'powershell'
  
  sel_endswith:
    file_path|endswith: '.exe'
  
  sel_regex:
    command_line|re: '.*-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{50,}.*'
  
  sel_all:
    description|contains|all:
      - 'malicious'
      - 'detected'
      - 'threat'
  
  sel_base64:
    command_line|base64: 'Invoke-Expression'
  
  condition: 1 of sel_*
```

## Best Practices

### 1. Use Specific Conditions
More specific conditions are faster to evaluate:
```yaml
# Better (specific)
condition: selection1 and selection2

# Slower (generic)
condition: 1 of them
```

### 2. Put Rare Conditions First
The evaluator short-circuits, so put unlikely matches first:
```yaml
# Better
condition: rare_indicator and common_indicator

# Slower
condition: common_indicator and rare_indicator
```

### 3. Use Filters with NOT
Exclude known false positives:
```yaml
condition: suspicious and not filter_false_positive
```

### 4. Combine Modifiers Appropriately
```yaml
# Valid
command_line|contains|all:
  - 'value1'
  - 'value2'

# Valid
field|startswith|endswith: 'value'  # matches exactly 'value'
```

### 5. Test Complex Conditions
Break down complex logic into smaller selections:
```yaml
detection:
  initial:
    field1: 'value1'
  
  secondary:
    field2: 'value2'
  
  tertiary:
    field3: 'value3'
  
  # Easier to understand than one huge condition
  condition: initial and (secondary or tertiary)
```

## Operator Precedence

From highest to lowest:
1. **Parentheses** `( )`
2. **NOT** `not`
3. **AND** `and`
4. **OR** `or`

**Example:**
```yaml
# This is evaluated as: (a and b) or c
condition: a and b or c

# Use parentheses to change precedence: a and (b or c)
condition: a and (b or c)
```

## Limitations

### Currently Supported
✅ AND, OR, NOT operators
✅ Parentheses for grouping
✅ "1 of them" / "all of them" patterns
✅ "1 of selection_*" patterns
✅ **Threshold / count conditions** (`selection_name | count > N`, `>=`, `<`, `<=`, `==`) in batch mode
✅ Field modifiers (contains, startswith, endswith, all, re, etc.)
✅ Numeric comparisons (gt, gte, lt, lte)
✅ Null checks

### Not Yet Implemented
❌ Time-based aggregations (e.g., "within 5m")
❌ Cross-field comparisons
❌ Correlation across multiple log entries (use correlation rules for multi-event patterns)

## Testing Your Rules

Use the verbose flag to debug rule matching:
```bash
sigma-zero -r ./rules -l ./logs -v
```

This will show which selections matched and why.
