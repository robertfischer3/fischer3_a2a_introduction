# A2A Error Handling Quick Reference Card

> **One-Page Cheat Sheet** - Print-friendly reference for error handling in A2A Protocol

---

## 📋 Standard Error Message Format

```json
{
  "message_type": "error",
  "payload": {
    "error": {
      "code": "ERROR_CODE",           // Required: UPPERCASE_UNDERSCORE
      "message": "Human description",  // Required: Client-safe message
      "details": {},                   // Optional: Additional context
      "retry_after": 60               // Optional: Seconds before retry
    }
  },
  "correlation_id": "request-id"     // Required: Original request ID
}
```

---

## 🚨 Error Code Reference

### Client Errors (4xx) - Don't Retry

| Code | When | Retry? | Action |
|------|------|--------|--------|
| `INVALID_MESSAGE` | Malformed JSON/structure | ❌ | Fix request format |
| `VALIDATION_FAILED` | Invalid field values | ❌ | Fix data validation |
| `AUTHENTICATION_FAILED` | Invalid credentials | ❌ | Re-authenticate |
| `FORBIDDEN` | No permission | ❌ | Request access |
| `NOT_FOUND` | Resource missing | ⚠️ | Check resource exists |
| `METHOD_NOT_ALLOWED` | Unsupported method | ❌ | Use different method |
| `PAYLOAD_TOO_LARGE` | Message > size limit | ❌ | Reduce payload size |
| `RATE_LIMIT_EXCEEDED` | Too many requests | ✅ | Wait `retry_after` |

### Server Errors (5xx) - Retry Allowed

| Code | When | Retry? | Action |
|------|------|--------|--------|
| `INTERNAL_ERROR` | Server error | ✅ | Retry with backoff |
| `SERVICE_UNAVAILABLE` | Temporary outage | ✅ | Retry after delay |
| `TIMEOUT` | Request timeout | ✅ | Retry with backoff |
| `BAD_GATEWAY` | Upstream failure | ✅ | Retry with backoff |

### A2A-Specific Errors

| Code | When | Retry? | Action |
|------|------|--------|--------|
| `AGENT_NOT_REGISTERED` | Agent not in registry | ⚠️ | Register first |
| `SESSION_EXPIRED` | Session timed out | ❌ | Re-authenticate |
| `NONCE_REUSED` | Replay attack detected | ❌ | Generate new nonce |
| `SIGNATURE_INVALID` | Bad signature | ❌ | Fix signing |
| `AGENT_OVERLOADED` | Agent at capacity | ✅ | Retry with backoff |

---

## 🔄 Retry Decision Tree

```
Error Occurred
    │
    ├─ 4xx Client Error?
    │   ├─ 429 Rate Limit → ✅ Retry after `retry_after`
    │   └─ Other 4xx → ❌ Don't retry, fix request
    │
    ├─ 5xx Server Error?
    │   ├─ 503, 504 → ✅ Retry with backoff
    │   └─ 500 → ⚠️  Limited retry (may be bug)
    │
    └─ A2A-Specific?
        ├─ SESSION_EXPIRED → ❌ Re-authenticate
        ├─ AGENT_OVERLOADED → ✅ Retry with backoff
        └─ SIGNATURE_INVALID → ❌ Don't retry, fix signature
```

---

## ⏱️ Exponential Backoff (Copy-Paste Ready)

```python
import asyncio
import random

async def retry_with_backoff(
    func,
    max_retries: int = 5,
    base_delay: float = 1.0
):
    """Retry with exponential backoff and jitter"""
    for attempt in range(max_retries):
        try:
            return await func()
        except RetryableError:
            if attempt == max_retries - 1:
                raise
            
            # delay = base * 2^attempt, with jitter
            delay = base_delay * (2 ** attempt)
            delay = delay * (0.5 + random.random())
            
            await asyncio.sleep(min(delay, 60))
```

**Delay Sequence**: 1s → 2s → 4s → 8s → 16s → 32s → 60s (capped)

---

## 🛡️ Security Rules

### ❌ NEVER Include in Errors

- ❌ Stack traces or code details
- ❌ Database queries or internal paths
- ❌ PII (SSN, email, names)
- ❌ Credentials or tokens
- ❌ Internal service names/IPs
- ❌ "User X does not exist" (use generic "auth failed")

### ✅ ALWAYS Include

- ✅ Error code (machine-readable)
- ✅ Generic message (human-readable)
- ✅ correlation_id (trace to request)
- ✅ retry_after (for rate limits)
- ✅ Safe details only (no sensitive data)

### Split Internal vs External

```python
# ❌ BAD: Exposes internal details
return {"error": f"Database error: {db_error}"}

# ✅ GOOD: Generic to client, detailed in logs
logger.error(f"DB error in get_user: {db_error}")
return {"error": {"code": "INTERNAL_ERROR", "message": "Request failed"}}
```

---

## 🔧 Circuit Breaker Pattern

**State Machine**: CLOSED → OPEN → HALF_OPEN → CLOSED

```python
class CircuitBreaker:
    CLOSED      # Normal: requests pass through
    OPEN        # Failed: blocking requests (after 5 failures)
    HALF_OPEN   # Testing: allow 1 request to test recovery
    
    # Parameters
    failure_threshold = 5      # Failures before OPEN
    recovery_timeout = 60      # Seconds before HALF_OPEN
    success_threshold = 2      # Successes to CLOSE
```

**Usage**:
```python
breaker = CircuitBreaker(failure_threshold=5)

try:
    result = await breaker.call(lambda: send_request())
except CircuitBreakerOpenError:
    # Use cached data or return error
    return fallback_response
```

---

## 📊 Essential Metrics

```python
# Track these metrics
- error_rate_by_code       # Errors per error code
- retry_attempts           # How many retries needed
- circuit_breaker_state    # Is circuit open?
- error_response_time      # Time to generate error
- 4xx_vs_5xx_ratio        # Client vs server errors

# Set alerts on
- error_rate > 5%          # Overall error rate
- 5xx_errors > 1%          # Server errors
- circuit_open             # Circuit breaker opened
- retry_rate > 50%         # Too many retries
```

---

## 🧪 Testing Checklist

- [ ] Test validation errors (malformed requests)
- [ ] Test authentication failures
- [ ] Test rate limiting and retry_after
- [ ] Test timeout handling
- [ ] Test circuit breaker opens after failures
- [ ] Test circuit breaker recovers
- [ ] Test no sensitive data in error responses
- [ ] Test correlation_id propagation
- [ ] Test exponential backoff delays
- [ ] Test max retry limits

---

## 💡 Common Mistakes

| Mistake | Impact | Fix |
|---------|--------|-----|
| Retry 4xx errors | Wastes resources | Only retry 5xx and 429 |
| No max retries | Infinite loops | Set max_retries=5 |
| Linear backoff | Overwhelms service | Use exponential backoff |
| No jitter | Thundering herd | Add randomness |
| Detailed errors | Information leak | Generic messages to clients |
| No correlation_id | Can't trace errors | Always include |
| Retry forever | Never fails | Set timeout limits |
| Ignore retry_after | Get banned | Honor server guidance |

---

## 🎯 Error Handling Maturity Levels

### Level 0: No Error Handling ❌
```python
result = await send_request()  # Hope it works!
```

### Level 1: Basic Try/Catch ⚠️
```python
try:
    result = await send_request()
except Exception:
    return {"error": "Failed"}  # What failed? Why?
```

### Level 2: Typed Errors ⚠️
```python
try:
    result = await send_request()
except RateLimitError:
    await asyncio.sleep(60)
    return await send_request()  # No backoff, no max retries
```

### Level 3: Production-Ready ✅
```python
breaker = CircuitBreaker()
try:
    result = await breaker.call(
        lambda: retry_with_backoff(
            send_request,
            max_retries=5
        )
    )
    return result
except RateLimitError as e:
    logger.warning(f"Rate limited: {e.retry_after}s")
    return {"error": {"code": "RATE_LIMIT_EXCEEDED", 
                      "retry_after": e.retry_after}}
except CircuitBreakerOpenError:
    logger.error("Circuit breaker open")
    return cached_fallback()
finally:
    metrics.record_request(success=(result is not None))
```

---

## 📚 Quick Links

- **Full Documentation**: [Error Handling Guide](./03_error_handling.md)
- **Message Format**: [Protocol Messages](./01_protocol_messages.md)
- **Security**: [Security Best Practices](../03_SECURITY/04_security_best_practices.md)
- **Examples**: 
  - [Crypto Agent Stage 1](https://github.com/your-org/a2a-protocol/tree/main/a2a_examples/a2a_crypto_example/) - No error handling
  - [Crypto Agent Stage 3](https://github.com/your-org/a2a-protocol/tree/main/a2a_examples/a2a_crypto_example/security/) - Production error handling

---

## 🚀 30-Second Implementation

**Minimum viable error handling**:

```python
from enum import Enum

class RetryPolicy(Enum):
    NEVER = "never"      # 4xx errors
    BACKOFF = "backoff"  # 5xx errors
    IMMEDIATE = "immediate"  # 429 with retry_after

async def handle_error(response: dict) -> RetryPolicy:
    """Determine retry policy from error response"""
    code = response["payload"]["error"]["code"]
    
    # Check if retryable
    if code in ["RATE_LIMIT_EXCEEDED"]:
        return RetryPolicy.IMMEDIATE
    
    if code in ["SERVICE_UNAVAILABLE", "TIMEOUT", "INTERNAL_ERROR"]:
        return RetryPolicy.BACKOFF
    
    return RetryPolicy.NEVER

# Usage
response = await send_request()
if response["message_type"] == "error":
    policy = await handle_error(response)
    
    if policy == RetryPolicy.IMMEDIATE:
        retry_after = response["payload"]["error"].get("retry_after", 60)
        await asyncio.sleep(retry_after)
        return await send_request()
    
    elif policy == RetryPolicy.BACKOFF:
        return await retry_with_backoff(send_request)
    
    else:  # NEVER
        raise RequestError(response["payload"]["error"]["message"])
```

---

**Print this page and keep it handy during development!** 🖨️

---

**Version**: 1.0  
**Last Updated**: December 2025  
**Format**: Quick Reference Card