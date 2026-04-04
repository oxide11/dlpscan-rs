# Rate Limiting

Thread-safe token bucket rate limiter for API and service protection.

## Usage

```python
from dlpscan.rate_limit import RateLimiter, rate_limited

limiter = RateLimiter(max_requests=100, window_seconds=60)

# Check before scanning
if limiter.check():
    result = guard.scan(text)

# Or use as decorator
@rate_limited(limiter)
def scan_input(text):
    return guard.scan(text)
```

## Configuration

```python
limiter = RateLimiter(
    max_requests=100,      # Max requests per window
    window_seconds=60,     # Time window in seconds
    max_payload_bytes=1_000_000,  # Max payload size
)
```

## Global Default

```python
from dlpscan.rate_limit import set_default_limiter, get_default_limiter

set_default_limiter(RateLimiter(max_requests=200, window_seconds=60))
limiter = get_default_limiter()
```
