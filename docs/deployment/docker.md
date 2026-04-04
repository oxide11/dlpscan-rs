# Docker

## Quick Start

```bash
docker run -v ./data:/data ghcr.io/oxide11/dlpscan scan /data
```

## Docker Compose

```yaml
services:
  dlpscan:
    image: ghcr.io/oxide11/dlpscan:latest
    volumes:
      - ./scan-target:/data
    working_dir: /data
```

## API Server

```yaml
services:
  dlpscan-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DLPSCAN_API_KEY=your-secret
      - DLPSCAN_API_RATE_LIMIT=100
    command: python -m dlpscan.api
```

## Build from Source

```bash
docker build -t dlpscan .
```
