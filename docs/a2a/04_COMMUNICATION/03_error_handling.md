# Error Handling in A2A Protocol

> **Learning Path**: Communication  
> **Difficulty**: Intermediate  
> **Prerequisites**: [Protocol Messages](./01_protocol_messages.md), [Core Concepts](../01_FUNDAMENTALS/01_core_concepts.md)  
> **Completion Time**: 45-60 minutes

## Navigation
← Previous: [Streaming & Events](./02_streaming_events.md) | Next: [Message Schemas](../05_REFERENCE/message_schemas.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

This document covers robust error handling patterns for A2A implementations:

- [ ] Standard A2A error codes and meanings
- [ ] Error message structure and validation
- [ ] Graceful degradation strategies
- [ ] Retry logic and backoff patterns
- [ ] Circuit breaker implementation
- [ ] Error recovery workflows
- [ ] Security considerations in error handling
- [ ] Testing error scenarios

---

## 📚 Overview

Robust error handling is critical in distributed multi-agent systems. Unlike single-process applications, agent communication involves:

- **Network failures** - Connections drop, timeouts occur
- **Agent unavailability** - Services go down, agents restart
- **Message validation failures** - Malformed or invalid requests
- **Authorization failures** - Permission denied scenarios
- **Resource exhaustion** - Rate limits, capacity constraints
- **Data inconsistencies** - State synchronization issues

Good error handling means:
- ✅ **Never crash** - Gracefully handle all error conditions
- ✅ **Informative** - Provide actionable error messages
- ✅ **Secure** - Don't leak sensitive information
- ✅ **Recoverable** - Enable automatic or manual recovery
- ✅ **Observable** - Log errors for monitoring and debugging

---

## 🏗️ A2A Error Message Structure

### Standard ERROR Message Format

```json
{
  "message_id": "uuid-v4",
  "message_type": "error",
  "sender_id": "agent-id",
  "recipient_id": "requesting-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "error": {
      "code": "string",
      "message": "string",
      "details": {},
      "retry_after": 0,
      "documentation_url": "string"
    }
  },
  "correlation_id": "original-message-id"
}
```

### Error Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | ✅ | Machine-readable error code (UPPERCASE_UNDERSCORE) |
| `message` | string | ✅ | Human-readable error description |
| `details` | object | ❌ | Additional context (safe for external consumption) |
| `retry_after` | integer | ❌ | Seconds to wait before retry (for rate limiting) |
| `documentation_url` | string | ❌ | Link to error documentation |

---

## 📋 Standard A2A Error Codes

### Client Error Codes (4xx)

| Code | HTTP Equiv | Description | Retry? |
|------|-----------|-------------|--------|
| `INVALID_MESSAGE` | 400 | Malformed message structure | ❌ No |
| `VALIDATION_FAILED` | 400 | Message validation failed | ❌ No |
| `AUTHENTICATION_REQUIRED` | 401 | No credentials provided | ❌ No |
| `AUTHENTICATION_FAILED` | 401 | Invalid credentials | ❌ No |
| `FORBIDDEN` | 403 | Authorized but not permitted | ❌ No |
| `NOT_FOUND` | 404 | Agent or resource not found | ⚠️ Maybe |
| `METHOD_NOT_ALLOWED` | 405 | Method not supported by agent | ❌ No |
| `CONFLICT` | 409 | Request conflicts with current state | ⚠️ Maybe |
| `PAYLOAD_TOO_LARGE` | 413 | Message exceeds size limit | ❌ No |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Content type not supported | ❌ No |
| `UNPROCESSABLE_ENTITY` | 422 | Semantically incorrect request | ❌ No |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests | ✅ Yes (with backoff) |

### Server Error Codes (5xx)

| Code | HTTP Equiv | Description | Retry? |
|------|-----------|-------------|--------|
| `INTERNAL_ERROR` | 500 | Unspecified server error | ✅ Yes |
| `NOT_IMPLEMENTED` | 501 | Feature not implemented | ❌ No |
| `BAD_GATEWAY` | 502 | Invalid response from upstream | ✅ Yes |
| `SERVICE_UNAVAILABLE` | 503 | Temporarily unavailable | ✅ Yes (with backoff) |
| `TIMEOUT` | 504 | Request timeout | ✅ Yes |
| `VERSION_NOT_SUPPORTED` | 505 | Protocol version unsupported | ❌ No |

### A2A-Specific Error Codes

| Code | Description | Retry? |
|------|-------------|--------|
| `AGENT_NOT_REGISTERED` | Agent not in registry | ⚠️ Maybe |
| `CAPABILITY_NOT_AVAILABLE` | Requested capability unavailable | ⚠️ Maybe |
| `SESSION_EXPIRED` | Session or token expired | ❌ No (re-authenticate) |
| `SESSION_INVALID` | Session ID invalid or hijacked | ❌ No |
| `NONCE_REUSED` | Replay attack detected | ❌ No |
| `SIGNATURE_INVALID` | Message signature verification failed | ❌ No |
| `AGENT_OVERLOADED` | Agent at capacity | ✅ Yes (with backoff) |
| `DEPENDENCY_FAILED` | Required downstream service unavailable | ✅ Yes |
| `STATE_CONFLICT` | Agent state inconsistent | ⚠️ Maybe |

---

## 💡 Error Handling Examples

### Example 1: Validation Error

**Scenario**: Client sends malformed message

```json
{
  "message_id": "e1f2g3h4-5i6j-7k8l-9m0n-1o2p3q4r5s6t",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:30:00.000Z",
  "payload": {
    "error": {
      "code": "VALIDATION_FAILED",
      "message": "Required field 'method' missing from payload",
      "details": {
        "field": "payload.method",
        "constraint": "required",
        "received_payload": {
          "parameters": {"currency": "BTC"}
        }
      }
    }
  },
  "correlation_id": "a1b2c3d4-5e6f-7g8h-9i0j-1k2l3m4n5o6p"
}
```

**Client Handling**:
```python
async def handle_validation_error(error_msg: dict):
    """Handle validation errors - don't retry, fix the request"""
    error = error_msg["payload"]["error"]
    
    # Log for debugging
    logger.error(f"Validation failed: {error['message']}")
    logger.debug(f"Details: {error['details']}")
    
    # Don't retry - validation errors won't fix themselves
    # Application logic should fix the request structure
    raise ValueError(f"Invalid request: {error['message']}")
```

---

### Example 2: Rate Limit Error

**Scenario**: Too many requests sent

```json
{
  "message_id": "f2g3h4i5-6j7k-8l9m-0n1o-2p3q4r5s6t7u",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:31:00.000Z",
  "payload": {
    "error": {
      "code": "RATE_LIMIT_EXCEEDED",
      "message": "Request rate limit exceeded. Maximum 100 requests per minute.",
      "details": {
        "limit": 100,
        "window_seconds": 60,
        "current_count": 147,
        "reset_at": "2025-12-09T15:32:00.000Z"
      },
      "retry_after": 60
    }
  },
  "correlation_id": "b2c3d4e5-6f7g-8h9i-0j1k-2l3m4n5o6p7q"
}
```

**Client Handling**:
```python
import asyncio
from datetime import datetime, timedelta

async def handle_rate_limit_error(error_msg: dict):
    """Handle rate limit with exponential backoff"""
    error = error_msg["payload"]["error"]
    retry_after = error.get("retry_after", 60)
    
    logger.warning(f"Rate limited. Waiting {retry_after}s before retry")
    
    # Honor retry_after with small buffer
    await asyncio.sleep(retry_after + 1)
    
    # After waiting, retry the original request
    # Your retry logic here
```

---

### Example 3: Service Unavailable Error

**Scenario**: Agent temporarily down

```json
{
  "message_id": "g3h4i5j6-7k8l-9m0n-1o2p-3q4r5s6t7u8v",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:32:00.000Z",
  "payload": {
    "error": {
      "code": "SERVICE_UNAVAILABLE",
      "message": "Service temporarily unavailable due to maintenance",
      "details": {
        "reason": "scheduled_maintenance",
        "estimated_duration_seconds": 300,
        "status_url": "https://status.crypto-agent.example.com"
      },
      "retry_after": 300
    }
  },
  "correlation_id": "c3d4e5f6-7g8h-9i0j-1k2l-3m4n5o6p7q8r"
}
```

**Client Handling**:
```python
async def handle_service_unavailable(
    error_msg: dict,
    max_retries: int = 3
):
    """Handle service unavailable with retry logic"""
    error = error_msg["payload"]["error"]
    retry_after = error.get("retry_after", 60)
    
    for attempt in range(max_retries):
        logger.info(f"Service unavailable. Retry {attempt+1}/{max_retries}")
        
        # Exponential backoff: retry_after * 2^attempt
        wait_time = retry_after * (2 ** attempt)
        await asyncio.sleep(wait_time)
        
        # Attempt retry
        try:
            return await retry_request()
        except ServiceUnavailableError:
            if attempt == max_retries - 1:
                raise
            continue
```

---

### Example 4: Authentication Error

**Scenario**: Invalid or expired credentials

```json
{
  "message_id": "h4i5j6k7-8l9m-0n1o-2p3q-4r5s6t7u8v9w",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:33:00.000Z",
  "payload": {
    "error": {
      "code": "AUTHENTICATION_FAILED",
      "message": "Signature verification failed",
      "details": {
        "reason": "invalid_signature",
        "expected_algorithm": "RS256",
        "received_algorithm": "HS256"
      },
      "documentation_url": "https://docs.a2a.example.com/auth#signatures"
    }
  },
  "correlation_id": "d4e5f6g7-8h9i-0j1k-2l3m-4n5o6p7q8r9s"
}
```

**Client Handling**:
```python
async def handle_authentication_error(error_msg: dict):
    """Handle authentication failures"""
    error = error_msg["payload"]["error"]
    
    logger.error(f"Authentication failed: {error['message']}")
    
    # Check if it's a signature issue
    if "signature" in error["message"].lower():
        # Regenerate signature with correct algorithm
        await regenerate_credentials()
        
    # Check if token expired
    elif "expired" in error["message"].lower():
        # Re-authenticate
        await reauthenticate()
    
    else:
        # Unknown auth error - don't retry, requires manual fix
        raise AuthenticationError(error["message"])
```

---

## 🔄 Retry Strategies

### Exponential Backoff

**When to use**: Transient failures, rate limits, service unavailability

```python
import asyncio
import random

async def exponential_backoff_retry(
    func,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    jitter: bool = True
):
    """
    Retry with exponential backoff
    
    Args:
        func: Async function to retry
        max_retries: Maximum retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap
        jitter: Add randomness to prevent thundering herd
    """
    for attempt in range(max_retries):
        try:
            return await func()
        except RetryableError as e:
            if attempt == max_retries - 1:
                raise
            
            # Calculate delay: base_delay * 2^attempt
            delay = min(base_delay * (2 ** attempt), max_delay)
            
            # Add jitter (randomness) to prevent thundering herd
            if jitter:
                delay = delay * (0.5 + random.random())
            
            logger.info(f"Retry {attempt+1}/{max_retries} after {delay:.2f}s")
            await asyncio.sleep(delay)
```

**Usage**:
```python
# Retry a request with exponential backoff
result = await exponential_backoff_retry(
    lambda: send_a2a_request(agent_id, message),
    max_retries=5,
    base_delay=1.0
)
```

---

### Circuit Breaker Pattern

**When to use**: Prevent cascading failures, protect overloaded agents

```python
from enum import Enum
from datetime import datetime, timedelta

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failures detected, blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered

class CircuitBreaker:
    """
    Circuit breaker for agent communication
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, blocking all requests
    - HALF_OPEN: Testing recovery, allowing limited requests
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 2
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
    
    async def call(self, func):
        """Execute function through circuit breaker"""
        
        # If OPEN, check if recovery timeout passed
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker OPEN. Try again after "
                    f"{self.recovery_timeout}s"
                )
        
        try:
            result = await func()
            self._on_success()
            return result
            
        except Exception as e:
            self._on_failure()
            raise
    
    def _on_success(self):
        """Handle successful request"""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            
            # Enough successes? Close circuit
            if self.success_count >= self.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                logger.info("Circuit breaker CLOSED (recovered)")
        
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed request"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.state == CircuitState.HALF_OPEN:
            # Failure during recovery - back to OPEN
            self.state = CircuitState.OPEN
            logger.warning("Circuit breaker re-OPENED (recovery failed)")
        
        elif self.failure_count >= self.failure_threshold:
            # Too many failures - open circuit
            self.state = CircuitState.OPEN
            logger.error("Circuit breaker OPENED (too many failures)")
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time passed to attempt reset"""
        if not self.last_failure_time:
            return True
        
        elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return elapsed >= self.recovery_timeout

# Usage
breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60.0
)

try:
    result = await breaker.call(
        lambda: send_a2a_request(agent_id, message)
    )
except CircuitBreakerOpenError:
    logger.error("Agent unavailable - circuit breaker open")
    # Use fallback or cached data
```

---

### Retry Decision Tree

```
┌─────────────────────────────────────┐
│ Error Occurred                      │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ What type of error?                 │
└─────────────────┬───────────────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
┌─────────────────┐ ┌─────────────────┐
│ 4xx Client      │ │ 5xx Server      │
│ Error           │ │ Error           │
└────────┬────────┘ └────────┬────────┘
         │                   │
         │                   ▼
         │         ┌─────────────────┐
         │         │ Retryable?      │
         │         └────────┬────────┘
         │                  │
         │         ┌────────┴────────┐
         │         │                 │
         │         ▼                 ▼
         │  ┌──────────────┐ ┌──────────────┐
         │  │ 503, 429,    │ │ 500          │
         │  │ 504, TIMEOUT │ │ (may be bug) │
         │  └──────┬───────┘ └──────┬───────┘
         │         │                │
         │         ▼                ▼
         │  ┌──────────────┐ ┌──────────────┐
         │  │ ✅ Retry     │ │ ⚠️  Retry    │
         │  │ with backoff │ │ limited      │
         │  └──────────────┘ └──────────────┘
         │
         ▼
┌─────────────────┐
│ Check specific  │
│ error code      │
└────────┬────────┘
         │
    ┌────┴──────────────────┐
    │                       │
    ▼                       ▼
┌──────────┐         ┌──────────────┐
│ 400, 401,│         │ 404, 409     │
│ 403, 422 │         │              │
└─────┬────┘         └─────┬────────┘
      │                    │
      ▼                    ▼
┌──────────┐         ┌──────────────┐
│ ❌ DON'T │         │ ⚠️  Maybe    │
│ Retry    │         │ retry once   │
└──────────┘         └──────────────┘
```

---

## 🛡️ Security Considerations in Error Handling

### Rule 1: Never Leak Sensitive Information

**❌ Bad Example** (Stage 1 - Vulnerable):
```python
# DON'T DO THIS
try:
    user = authenticate(username, password)
except Exception as e:
    return {
        "error": str(e),  # Might leak: "User 'admin' not found in database"
        "stack_trace": traceback.format_exc(),  # Exposes code structure
        "database": "postgresql://prod-db-1.internal:5432/users"  # Leaks infrastructure
    }
```

**✅ Good Example** (Stage 3 - Secure):
```python
# DO THIS
try:
    user = authenticate(username, password)
except AuthenticationError as e:
    # Generic message to client
    return {
        "error": {
            "code": "AUTHENTICATION_FAILED",
            "message": "Authentication failed"  # No details about why
        }
    }
    # Detailed logging server-side only
    logger.error(f"Auth failed: {username} - {str(e)}")
```

### Rule 2: Different Messages for Internal vs External

```python
class ErrorResponse:
    """Dual error messages: detailed for logs, safe for clients"""
    
    def __init__(self, code: str, internal_msg: str, client_msg: str):
        self.code = code
        self.internal_message = internal_msg
        self.client_message = client_msg
    
    def to_client(self) -> dict:
        """Safe message for external consumption"""
        return {
            "error": {
                "code": self.code,
                "message": self.client_message
            }
        }
    
    def to_log(self) -> str:
        """Detailed message for internal logs"""
        return f"[{self.code}] {self.internal_message}"

# Usage
try:
    process_file(filepath)
except FileNotFoundError as e:
    error = ErrorResponse(
        code="FILE_NOT_FOUND",
        internal_msg=f"File not found: {filepath} (user: {user_id})",
        client_msg="Requested file not found"
    )
    
    logger.error(error.to_log())  # Detailed logging
    return error.to_client()       # Safe client response
```

### Rule 3: Rate Limit Error Responses

Even error responses can be abused:

```python
from collections import defaultdict
from datetime import datetime, timedelta

class ErrorRateLimiter:
    """Rate limit error responses to prevent information leakage"""
    
    def __init__(self, max_errors_per_minute: int = 10):
        self.max_errors = max_errors_per_minute
        self.error_counts = defaultdict(list)  # agent_id -> [timestamps]
    
    def should_send_error(self, agent_id: str) -> bool:
        """Check if we should send detailed error"""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        
        # Clean old timestamps
        self.error_counts[agent_id] = [
            ts for ts in self.error_counts[agent_id]
            if ts > cutoff
        ]
        
        # Check limit
        if len(self.error_counts[agent_id]) >= self.max_errors:
            return False
        
        self.error_counts[agent_id].append(now)
        return True

# Usage
error_limiter = ErrorRateLimiter(max_errors_per_minute=10)

if not error_limiter.should_send_error(agent_id):
    # Too many errors - send generic response
    return {
        "error": {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "Too many errors. Please contact support."
        }
    }
else:
    # Send specific error
    return detailed_error_response
```

---

## 🧪 Testing Error Scenarios

### Unit Tests for Error Handling

```python
import pytest

@pytest.mark.asyncio
async def test_validation_error_handling():
    """Test handling of validation errors"""
    # Send invalid message
    message = {
        "message_id": str(uuid.uuid4()),
        "message_type": "request",
        # Missing required fields...
    }
    
    response = await send_message(message)
    
    # Should get validation error
    assert response["message_type"] == "error"
    assert response["payload"]["error"]["code"] == "VALIDATION_FAILED"
    assert "correlation_id" in response

@pytest.mark.asyncio
async def test_rate_limit_retry():
    """Test retry logic for rate limits"""
    # Send many requests to trigger rate limit
    for i in range(150):
        response = await send_request()
    
    # Should get rate limit error
    assert response["payload"]["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after" in response["payload"]["error"]
    
    # Wait and retry should succeed
    await asyncio.sleep(response["payload"]["error"]["retry_after"])
    retry_response = await send_request()
    assert retry_response["message_type"] != "error"

@pytest.mark.asyncio
async def test_circuit_breaker_opens():
    """Test circuit breaker opens after failures"""
    breaker = CircuitBreaker(failure_threshold=3)
    
    # Simulate failures
    for i in range(3):
        with pytest.raises(Exception):
            await breaker.call(lambda: failing_request())
    
    # Circuit should be open
    assert breaker.state == CircuitState.OPEN
    
    # Next call should fail immediately
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(lambda: working_request())

@pytest.mark.asyncio
async def test_no_sensitive_data_in_errors():
    """Ensure errors don't leak sensitive data"""
    # Trigger various errors
    errors = [
        await trigger_auth_error(),
        await trigger_validation_error(),
        await trigger_internal_error()
    ]
    
    # Check none contain sensitive data
    sensitive_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'password',
        r'secret',
        r'token',
        r'/var/',  # File paths
        r'postgresql://'  # Connection strings
    ]
    
    for error in errors:
        error_str = json.dumps(error)
        for pattern in sensitive_patterns:
            assert not re.search(pattern, error_str, re.IGNORECASE)
```

---

## 📊 Error Handling Metrics

### What to Monitor

```python
from prometheus_client import Counter, Histogram

# Error counters by type
error_counter = Counter(
    'a2a_errors_total',
    'Total A2A errors',
    ['agent_id', 'error_code', 'error_type']
)

# Retry attempts
retry_counter = Counter(
    'a2a_retries_total',
    'Total retry attempts',
    ['agent_id', 'attempt_number']
)

# Circuit breaker state
circuit_breaker_state = Gauge(
    'a2a_circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half_open)',
    ['agent_id']
)

# Error response time
error_response_time = Histogram(
    'a2a_error_response_seconds',
    'Time to generate error response',
    ['error_code']
)

# Usage in code
with error_response_time.labels(error_code='RATE_LIMIT_EXCEEDED').time():
    error_response = generate_error_response(...)
    error_counter.labels(
        agent_id=agent_id,
        error_code='RATE_LIMIT_EXCEEDED',
        error_type='client'
    ).inc()
```

---

## 🎓 Best Practices Summary

### ✅ DO

1. **Use standard error codes** - Consistent across all agents
2. **Include correlation_id** - Trace errors back to original request
3. **Provide retry_after** - Tell clients when to retry
4. **Log detailed errors** - But only server-side
5. **Implement exponential backoff** - Prevent overwhelming failed services
6. **Use circuit breakers** - Protect against cascading failures
7. **Test error paths** - Don't just test happy paths
8. **Monitor error rates** - Set up alerts for unusual patterns
9. **Document error codes** - Help client developers understand errors
10. **Fail gracefully** - Never crash, always return proper error message

### ❌ DON'T

1. **Don't leak sensitive data** - No PII, credentials, or system details in errors
2. **Don't expose stack traces** - Keep internal details internal
3. **Don't retry non-retryable errors** - 400-level errors won't fix themselves
4. **Don't retry forever** - Set max retry limits
5. **Don't ignore error details** - Use them to improve your code
6. **Don't use generic error codes** - Be specific about what went wrong
7. **Don't forget correlation IDs** - Always trace errors to requests
8. **Don't overwhelm with errors** - Rate limit error responses too
9. **Don't hide errors from monitoring** - Log and track all errors
10. **Don't assume retry will succeed** - Have fallback strategies

---

## 🔗 Related Documentation

- [Protocol Messages](./01_protocol_messages.md) - Message structure
- [Message Schemas](../05_REFERENCE/message_schemas.md) - JSON schemas
- [Security Best Practices](../03_SECURITY/04_security_best_practices.md) - Security considerations
- [Threat Model](../03_SECURITY/03_threat_model.md) - Attack scenarios

---

## 📚 Further Reading

### External Resources

- [Exponential Backoff and Jitter](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [HTTP Status Codes](https://httpstatuses.com/)
- [REST API Error Handling Best Practices](https://www.rfc-editor.org/rfc/rfc7807.html)

### Project Examples

Study error handling in the example implementations:

**Example 1: Crypto Agent (Stage 1)** - ❌ Poor error handling
- Generic error messages
- No retry logic
- Exposes stack traces

**Example 2: Crypto Agent (Stage 2)** - ⚠️ Improved but incomplete
- Basic error codes
- Simple retry logic
- Still some information leakage

**Example 3: Crypto Agent (Stage 3)** - ✅ Production-ready
- Complete error taxonomy
- Exponential backoff retry
- Circuit breaker implementation
- Security-conscious error messages
- Comprehensive error monitoring

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Complete  
**Author**: Based on A2A Protocol Best Practices