# Quick Start

## 1. Set Up

Run the interactive setup wizard to create your config file:

```bash
dlpscan init
```

Or check system info:

```bash
dlpscan info
```

## 2. Scan Text

```bash
# From the command line
dlpscan scan-text "My SSN is 123-45-6789 and card 4532015112830366"

# Pipe from stdin
echo "email: secret@example.com" | dlpscan scan-text

# JSON output
dlpscan scan-text "SSN: 123-45-6789" --format json
```

## 3. Scan Files

```bash
# Single file
dlpscan scan document.txt

# Directory (recursive)
dlpscan scan-dir ./data/

# With confidence filter
dlpscan scan-dir ./src/ --min-confidence 0.5

# JSON output
dlpscan scan-dir ./data/ --format json
```

## 4. Use InputGuard (Rust API)

```rust
use dlpscan::{InputGuard, Preset, Action};

// Flag sensitive data (find without modifying)
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss, Preset::Pii])
    .with_action(Action::Flag);
let result = guard.scan("Card: 4532015112830366")?;
println!("Clean: {}", result.is_clean);        // false
println!("Findings: {}", result.finding_count()); // 1

// Redact sensitive data
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss])
    .with_action(Action::Redact);
let result = guard.scan("card: 4532015112830366")?;
println!("{}", result.redacted_text.unwrap());
// "card: XXXXXXXXXXXXXXXX"

// Reject (returns error on detection)
let guard = InputGuard::new()
    .with_presets(vec![Preset::Credentials])
    .with_action(Action::Reject);
let result = guard.scan("password=secret123");
// Err(SensitiveDataDetected { ... })

// Obfuscate with realistic fake data
let guard = InputGuard::new()
    .with_presets(vec![Preset::PciDss])
    .with_action(Action::Obfuscate);
let result = guard.scan("card: 4532015112830366")?;
// "card: 4758286118069724" (Luhn-valid fake)
```

## 5. Test Patterns

Test a custom regex against sample text:

```bash
dlpscan test-pattern '\bPROJ-\d{6}\b' --text "Project PROJ-123456 is active"
```

## 6. Manage Configuration

```bash
dlpscan config show                        # View config
dlpscan config set min_confidence 0.5      # Set threshold
dlpscan config set block_unreadable true   # Block binary files
dlpscan config blocked                     # List blocked extensions
dlpscan config block enc                   # Block .enc files
```

## 7. Interactive TUI (optional)

```bash
# Build with TUI feature
cargo build --release --features tui

# Launch interactive menu
dlpscan tui

# Live statistics dashboard
dlpscan top
```

## Next Steps

- [Core Concepts](concepts.md) — specificity, context keywords, validators
- [Configuration](configuration.md) — full config reference
- [PATTERNS.md](../PATTERNS.md) — all 560 patterns
- [KEYWORDS.md](../KEYWORDS.md) — all context keywords
- [Enterprise features](../enterprise/api.md) — API server, audit, SIEM
