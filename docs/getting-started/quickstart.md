# Quick Start

## Scan Text

```python
from dlpscan import enhanced_scan_text

for match in enhanced_scan_text("My SSN is 123-45-6789"):
    print(f"{match.category} > {match.sub_category}: {match.text}")
    print(f"  Confidence: {match.confidence:.0%}")
```

## Use InputGuard

The `InputGuard` is the recommended API for application integration:

```python
from dlpscan import InputGuard, Preset, Action

# Reject sensitive data (raises InputGuardError)
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REJECT)

# Redact sensitive data
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)
result = guard.scan("Card: 4111-1111-1111-1111")
print(result.redacted_text)  # "Card: XXXX-XXXX-XXXX-XXXX"

# Tokenize (reversible)
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.TOKENIZE)
result = guard.scan("Card: 4111-1111-1111-1111")
print(result.redacted_text)     # "Card: TOK_CC_a8f3b2c1"
print(guard.detokenize(result.redacted_text))  # original restored

# Obfuscate (irreversible fake data)
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.OBFUSCATE)
result = guard.scan("Card: 4111-1111-1111-1111")
print(result.redacted_text)  # "Card: 4539-7884-2165-0347"
```

## Protect Function Arguments

```python
guard = InputGuard(presets=[Preset.PCI_DSS], action=Action.REDACT)

@guard.protect(param="user_input")
def save_comment(user_id: int, user_input: str):
    db.save(user_id, user_input)  # user_input is already redacted
```

## Scan Files

```bash
# CLI
dlpscan myfile.txt
dlpscan ./data/ --format json --redact

# Python
from dlpscan import scan_file, scan_directory

for match in scan_file("data.csv"):
    print(match.text)
```

## Use a Masking Profile

```python
from dlpscan.profiles import get_profile

profile = get_profile("pci-production")
guard = profile.to_guard()
result = guard.scan("Card: 4111111111111111")
```

## Next Steps

- [InputGuard deep dive](../guide/inputguard.md)
- [Masking Profiles](../guide/profiles.md)
- [Policy Engine](../guide/policy.md)
- [Enterprise features](../enterprise/api.md)
