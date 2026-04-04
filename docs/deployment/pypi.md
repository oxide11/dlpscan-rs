# PyPI Publishing

## Install from PyPI

```bash
pip install dlpscan

# With extras
pip install dlpscan[api]          # REST API server
pip install dlpscan[all-formats]  # All document formats
pip install dlpscan[dev]          # Development tools
```

## Publishing a Release

1. Update version in `pyproject.toml`, `setup.py`, and `dlpscan/__init__.py`
2. Update `CHANGELOG.md`
3. Create a GitHub release tag
4. The publish workflow automatically uploads to PyPI via OIDC

## Manual Publishing

```bash
pip install build twine
python -m build
twine upload dist/*
```
