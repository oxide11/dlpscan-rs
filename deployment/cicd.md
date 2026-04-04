# CI/CD

## GitHub Actions

dlpscan includes CI workflows for lint, test, and publish.

### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and PR:
- Ruff linting
- Unit tests across Python 3.9–3.13
- Integration tests
- Benchmarks (non-blocking)

### Publish Workflow (`.github/workflows/publish.yml`)

Publishes to PyPI on GitHub releases using OIDC trusted publisher.

### Docker Workflow (`.github/workflows/docker.yml`)

Builds multi-arch Docker images (amd64/arm64) to GHCR.

## GitLab CI

```yaml
stages:
  - test
  - publish

test:
  image: python:3.12
  script:
    - pip install -e ".[dev]"
    - ruff check dlpscan/ tests/
    - python -m unittest tests.unit -v
```
