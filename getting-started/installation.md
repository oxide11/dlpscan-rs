# Installation

## Basic Install

```bash
pip install dlpscan
```

## Optional Dependencies

dlpscan supports several optional dependency groups:

```bash
# PDF scanning
pip install dlpscan[pdf]

# Office document scanning (DOCX, XLSX, PPTX)
pip install dlpscan[office]

# Email file scanning (.msg)
pip install dlpscan[email]

# All document formats
pip install dlpscan[all-formats]

# REST API server
pip install dlpscan[api]

# Development tools
pip install dlpscan[dev]
```

## From Source

```bash
git clone https://github.com/oxide11/dlpscan.git
cd dlpscan
pip install -e ".[dev]"
```

## Docker

```bash
docker pull ghcr.io/oxide11/dlpscan:latest
docker run -v ./data:/data dlpscan scan /data
```

## Verify Installation

```python
import dlpscan
print(dlpscan.__version__)
```

## System Requirements

- Python 3.8 or later
- No native dependencies — pure Python
