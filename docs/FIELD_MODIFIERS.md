# Field Modifiers Guide

## Overview

Field modifiers extend Sigma rule matching capabilities by allowing precise control over how field values are compared. Modifiers are appended to field names using the pipe (`|`) separator.

## Syntax

```yaml
field_name|modifier: value
field_name|modifier1|modifier2: value
```

## Available Modifiers

### 1. `contains` (Default)

Matches if the field contains the specified value as a substring.

**Usage:**
```yaml
detection:
  selection:
    command_line|contains:
      - 'malware'
      - 'suspicious'
```

**Example:**
- Field: `"C:\Windows\System32\cmd.exe /c malware.bat"`
- Pattern: `malware`
- **Matches:** ✅ Yes (contains "malware")

### 2. `startswith`

Matches if the field value starts with the specified pattern.

**Usage:**
```yaml
detection:
  selection:
    command_line|startswith:
      - 'powershell -enc'
      - 'cmd.exe /c'
```

**Example:**
- Field: `"powershell -enc ABC123"`
- Pattern: `powershell -enc`
- **Matches:** ✅ Yes (starts with pattern)

**Rule Example:**
```yaml
title: PowerShell Encoded Command
detection:
  selection:
    process_name|endswith: 'powershell.exe'
    command_line|startswith:
      - 'powershell -enc'
      - 'powershell -encodedcommand'
  condition: selection
```

### 3. `endswith`

Matches if the field value ends with the specified pattern.

**Usage:**
```yaml
detection:
  selection:
    file_path|endswith:
      - '.exe'
      - '.dll'
      - '.scr'
```

**Example:**
- Field: `"C:\Users\victim\malware.exe"`
- Pattern: `.exe`
- **Matches:** ✅ Yes (ends with ".exe")

**Rule Example:**
```yaml
title: Executable Download
detection:
  selection:
    event_type: 'file_download'
    file_path|endswith:
      - '.exe'
      - '.dll'
      - '.bat'
  condition: selection
```

### 4. `all`

Requires ALL specified values to match (instead of ANY).

**Usage:**
```yaml
detection:
  selection:
    command_line|contains|all:
      - 'net'
      - 'user'
      - 'add'
```

**Example:**
- Field: `"net user attacker password /add"`
- Patterns: `['net', 'user', 'add']`
- **Matches:** ✅ Yes (all three are present)

**Rule Example:**
```yaml
title: User Creation Command
detection:
  selection:
    command_line|contains|all:
      - 'net'
      - 'user'
      - 'add'
  condition: selection
```

### 5. `re` (Regular Expression)

Matches using regular expression patterns.

**Usage:**
```yaml
detection:
  selection:
    destination_ip|re:
      - '^10\.0\.0\.\d+$'
      - '^192\.168\.\d+\.\d+$'
```

**Example:**
- Field: `"192.168.1.100"`
- Pattern: `^192\.168\.\d+\.\d+$`
- **Matches:** ✅ Yes (matches regex pattern)

**Rule Example:**
```yaml
title: Suspicious IP Pattern
detection:
  selection:
    destination_ip|re:
      - '^10\.0\.0\.(50|51|52)$'
      - '^203\.0\.113\.\d+$'
  condition: selection
```

**Common Regex Patterns:**
- `^value` - Starts with value
- `value$` - Ends with value
- `\d+` - One or more digits
- `[a-z]+` - One or more lowercase letters
- `.*` - Any characters
- `(opt1|opt2)` - Either opt1 or opt2

### 6. `base64`

Decodes base64-encoded field values before matching.

**Usage:**
```yaml
detection:
  selection:
    command_line|base64:
      - 'invoke-expression'
      - 'downloadstring'
```

**Example:**
- Field (base64): `"aW52b2tlLWV4cHJlc3Npb24="`
- Field (decoded): `"invoke-expression"`
- Pattern: `invoke-expression`
- **Matches:** ✅ Yes (decoded content matches)

**Rule Example:**
```yaml
title: Base64 Encoded Malicious Command
detection:
  selection:
    command_line|base64:
      - 'invoke-expression'
      - 'webclient'
      - 'downloadstring'
  condition: selection
```

### 7. Comparison Modifiers

#### `lt` - Less Than
#### `lte` - Less Than or Equal
#### `gt` - Greater Than
#### `gte` - Greater Than or Equal

**Usage:**
```yaml
detection:
  selection:
    port|gte: '50000'
    file_size|lt: '1024'
```

**Examples:**
- Field: `55000`, Pattern: `50000`, Modifier: `gte`
  - **Matches:** ✅ Yes (55000 >= 50000)
  
- Field: `512`, Pattern: `1024`, Modifier: `lt`
  - **Matches:** ✅ Yes (512 < 1024)

**Rule Example:**
```yaml
title: High Port Connection
detection:
  selection:
    event_type: 'network_connection'
    port|gte: '50000'
  condition: selection
```

## Combining Modifiers

Multiple modifiers can be chained together:

```yaml
detection:
  selection:
    command_line|contains|all:
      - 'powershell'
      - '-enc'
```

This requires the field to contain ALL specified values.

## Complete Rule Examples

### Example 1: Advanced PowerShell Detection

```yaml
title: Suspicious PowerShell with Multiple Modifiers
id: example-001
description: Detects PowerShell with encoded commands
status: experimental
level: high
detection:
  selection_process:
    process_name|endswith:
      - 'powershell.exe'
      - 'pwsh.exe'
  selection_command:
    command_line|startswith|contains:
      - 'powershell -enc'
  condition: selection_process and selection_command
tags:
  - attack.execution
  - attack.t1059.001
```

### Example 2: File Extension Check

```yaml
title: Dangerous File Download
id: example-002
description: Detects downloads of executable files
status: stable
level: medium
detection:
  selection:
    event_type: 'file_download'
    file_path|endswith:
      - '.exe'
      - '.dll'
      - '.scr'
      - '.bat'
      - '.ps1'
  condition: selection
tags:
  - attack.execution
```

### Example 3: Network Port Range

```yaml
title: Suspicious High Port Usage
id: example-003
description: Detects connections to non-standard high ports
status: experimental
level: medium
detection:
  selection:
    event_type: 'network_connection'
    port|gte: '49152'
  filter:
    destination_domain|endswith:
      - '.local'
      - '.internal'
  condition: selection and not filter
tags:
  - attack.command_and_control
```

### Example 4: Regex IP Pattern

```yaml
title: Specific IP Range Detection
id: example-004
description: Detects connections to specific IP ranges
status: experimental
level: high
detection:
  selection:
    destination_ip|re:
      - '^10\.0\.0\.(100|101|102)$'
      - '^192\.168\.1\.(50|51|52)$'
      - '^203\.0\.113\.\d+$'
  condition: selection
tags:
  - attack.command_and_control
```

### Example 5: Base64 Encoded Content

```yaml
title: Encoded Malicious Command
id: example-005
description: Detects base64 encoded malicious commands
status: experimental
level: high
detection:
  selection:
    command_line|base64:
      - 'invoke-expression'
      - 'downloadstring'
      - 'webclient'
      - 'iex'
  condition: selection
tags:
  - attack.defense_evasion
  - attack.t1027
```

### Example 6: Combined Conditions with All

```yaml
title: Complete Attack Chain
id: example-006
description: Detects full attack chain with all components
status: experimental
level: critical
detection:
  selection:
    process_name|endswith: 'cmd.exe'
    command_line|contains|all:
      - 'net'
      - 'user'
      - 'add'
      - '/domain'
  condition: selection
tags:
  - attack.persistence
  - attack.t1136.002
```

## Testing Modifiers

### Sample Log Entry
```json
{
  "timestamp": "2025-11-06T10:00:00Z",
  "event_type": "process_creation",
  "process_name": "powershell.exe",
  "command_line": "powershell -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA==",
  "user": "attacker",
  "port": 55000
}
```

### Matching Tests

| Modifier | Field | Pattern | Result |
|----------|-------|---------|--------|
| `endswith` | `process_name` | `powershell.exe` | ✅ Match |
| `startswith` | `command_line` | `powershell -enc` | ✅ Match |
| `contains` | `command_line` | `-enc` | ✅ Match |
| `base64` | `command_line` | `invoke` | ✅ Match (after decode) |
| `gte` | `port` | `50000` | ✅ Match (55000 >= 50000) |

## Performance Considerations

### Fast Modifiers
- `contains` - Very fast (substring search)
- `startswith` - Very fast (prefix check)
- `endswith` - Very fast (suffix check)

### Moderate Modifiers
- `re` - Moderate (regex compilation and matching)
- `base64` - Moderate (requires decoding)
- Comparison (`lt`, `gt`, etc.) - Fast (numeric comparison)

### Tips for Optimal Performance
1. Use specific modifiers instead of wildcards when possible
2. Place `startswith`/`endswith` before `contains`
3. Avoid complex regex when simple string matching works
4. Use numeric comparisons for ports and sizes
5. Combine modifiers efficiently

## Troubleshooting

### Modifier Not Working?

**Check:**
1. Correct syntax: `field|modifier: value`
2. Field name matches log field exactly (case-sensitive)
3. Modifier is supported (see list above)
4. Value format is correct for modifier type

### Common Mistakes

❌ **Wrong:** `field|modifier : value` (space before colon)
✅ **Correct:** `field|modifier: value`

❌ **Wrong:** `field:modifier: value` (colon instead of pipe)
✅ **Correct:** `field|modifier: value`

❌ **Wrong:** `field|Modifier: value` (wrong case)
✅ **Correct:** `field|modifier: value` (lowercase)

### Debug Tips

Enable verbose logging to see matching details:
```bash
sigma-zero -r ./rules -l ./logs -v
```

## Field Mapping (Log Mapping)

When rule field names differ from log field names (e.g. Sigma/Windows use `CommandLine`, `ProcessName`, while your logs use `command_line`, `process_name`), use **field mapping** so the evaluator looks up the correct log keys.

**CLI:**
```bash
sigma-zero -r ./rules -l ./logs --field-map CommandLine:command_line,ProcessName:process_name
```

Multiple mappings can be given as comma-separated pairs or by repeating the option:
```bash
sigma-zero -r ./rules -l ./logs --field-map CommandLine:command_line --field-map ProcessName:process_name
```

**Behaviour:**
- Each mapping is `rule_field_name:log_field_name`.
- When evaluating a condition on a field (e.g. `CommandLine|contains`), the engine resolves the field via the map: if `CommandLine` is mapped to `command_line`, the log is queried for `command_line`.
- Unmapped fields are used as-is (rule field name = log field name).
- Mapping applies to all rules in the run; it is global for the evaluation.

**Example:** A rule uses `TargetFilename|endswith: '.exe'` but your logs have `target_path`. Use:
```bash
sigma-zero -r ./rules -l ./logs --field-map TargetFilename:target_path
```

## Future Modifiers (Planned)

- `base64offset` - Base64 with offset
- `utf16le` / `utf16be` - UTF-16 encoding
- `wide` - Wide character matching
- Additional encoding formats

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Field Modifiers](https://github.com/SigmaHQ/sigma-specification/blob/main/Sigma_specification.md#field-modifiers)
- Examples directory: `examples/rules/modifiers_*.yml`

## Summary Table

| Modifier | Purpose | Example Use Case |
|----------|---------|------------------|
| `contains` | Substring match | Finding keywords in commands |
| `startswith` | Prefix match | Detecting command patterns |
| `endswith` | Suffix match | File extension checking |
| `all` | All must match | Multi-condition validation |
| `re` | Regex pattern | Complex pattern matching |
| `base64` | Decode first | Encoded command detection |
| `lt/lte/gt/gte` | Numeric compare | Port/size thresholds |

**Field mapping** (CLI `--field-map`) is not a modifier but maps rule field names to log field names so rules written for one schema work against another.

---

**Updated:** January 2026  
**Version:** 0.2.0  
**Status:** Active Development
