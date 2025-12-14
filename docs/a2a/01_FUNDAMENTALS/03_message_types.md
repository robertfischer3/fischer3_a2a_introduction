# Message Schemas Reference

> **Learning Path**: Reference  
> **Difficulty**: Intermediate  
> **Prerequisites**: [Core Concepts](../01_FUNDAMENTALS/01_core_concepts.md), [Protocol Messages](../04_COMMUNICATION/01_protocol_messages.md)  
> **Completion Time**: 45-60 minutes

## Navigation
← Previous: [Error Handling](../04_COMMUNICATION/03_error_handling.md) | Next: [Capability Vocabulary](../05_REFERENCE/02_capability_vocabulary.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

This document provides complete JSON schema definitions for all A2A message types:

- [ ] Complete schema for every message type
- [ ] Field-by-field validation rules
- [ ] Required vs optional fields
- [ ] Data type constraints
- [ ] Format specifications
- [ ] Common validation patterns
- [ ] Schema validation code examples

---

## 📚 Overview

The A2A Protocol uses **JSON (JavaScript Object Notation)** for all message serialization. Every message follows a standardized structure with specific validation rules to ensure:

- **Interoperability** - Agents from different implementations can communicate
- **Security** - Invalid or malicious messages are rejected
- **Reliability** - Message integrity is maintained
- **Debuggability** - Messages are human-readable and easy to troubleshoot

---

## 🏗️ Base Message Structure

### Core Message Schema

All A2A messages share a common base structure:

```json
{
  "message_id": "string (UUID v4)",
  "message_type": "string (enum)",
  "sender_id": "string",
  "recipient_id": "string", 
  "timestamp": "string (ISO 8601)",
  "payload": {},
  "correlation_id": "string (UUID v4) | null"
}
```

### Field Specifications

#### `message_id`
- **Type**: `string`
- **Format**: UUID v4 (RFC 4122)
- **Required**: ✅ Yes
- **Unique**: Must be globally unique per message
- **Example**: `"a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"`
- **Validation Pattern**: `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

**Validation Rules**:
```python
import uuid
import re

def validate_message_id(message_id: str) -> bool:
    """Validate message_id is a valid UUID v4"""
    try:
        uuid_obj = uuid.UUID(message_id, version=4)
        return str(uuid_obj) == message_id
    except (ValueError, AttributeError):
        return False

# Alternative regex validation
UUID_V4_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)

def validate_message_id_regex(message_id: str) -> bool:
    return bool(UUID_V4_PATTERN.match(message_id))
```

---

#### `message_type`
- **Type**: `string` (enum)
- **Required**: ✅ Yes
- **Valid Values**: See [Message Type Enum](#message-type-enum)
- **Case Sensitive**: Yes (lowercase)
- **Example**: `"request"`, `"response"`, `"handshake"`

**Validation Rules**:
```python
from enum import Enum

class MessageType(Enum):
    """A2A Protocol Message Types"""
    # Discovery
    DISCOVER_AGENTS = "discover_agents"
    AGENT_ANNOUNCEMENT = "agent_announcement"
    
    # Capability Exchange
    GET_CAPABILITIES = "get_capabilities"
    CAPABILITIES_RESPONSE = "capabilities_response"
    
    # Request/Response
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    
    # Session Management
    HANDSHAKE = "handshake"
    HANDSHAKE_ACK = "handshake_ack"
    GOODBYE = "goodbye"
    
    # Streaming
    STREAM_START = "stream_start"
    STREAM_DATA = "stream_data"
    STREAM_END = "stream_end"

def validate_message_type(msg_type: str) -> bool:
    """Validate message_type is a known type"""
    try:
        MessageType(msg_type)
        return True
    except ValueError:
        return False
```

---

#### `sender_id`
- **Type**: `string`
- **Required**: ✅ Yes
- **Format**: Agent identifier (alphanumeric + hyphens)
- **Length**: 1-128 characters
- **Pattern**: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,126}[a-zA-Z0-9]$`
- **Example**: `"crypto-agent-001"`, `"client-agent-xyz"`

**Validation Rules**:
```python
import re

AGENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,126}[a-zA-Z0-9]$')

def validate_agent_id(agent_id: str) -> bool:
    """Validate agent_id format"""
    if not isinstance(agent_id, str):
        return False
    if len(agent_id) < 1 or len(agent_id) > 128:
        return False
    if not AGENT_ID_PATTERN.match(agent_id):
        return False
    return True
```

---

#### `recipient_id`
- **Type**: `string`
- **Required**: ✅ Yes (except for broadcast messages)
- **Format**: Same as `sender_id`
- **Special Values**:
  - `"*"` - Broadcast to all agents
  - `"registry"` - Message to registry service
- **Example**: `"crypto-agent-001"`, `"*"`

**Validation Rules**: Same as `sender_id`, plus allow special values

```python
def validate_recipient_id(recipient_id: str) -> bool:
    """Validate recipient_id (allows special values)"""
    # Special broadcast/registry values
    if recipient_id in ["*", "registry"]:
        return True
    # Otherwise same rules as agent_id
    return validate_agent_id(recipient_id)
```

---

#### `timestamp`
- **Type**: `string`
- **Format**: ISO 8601 with UTC timezone
- **Required**: ✅ Yes
- **Pattern**: `YYYY-MM-DDTHH:MM:SS.sssZ`
- **Example**: `"2025-01-15T10:30:00.000Z"`

**Validation Rules**:
```python
from datetime import datetime, timezone
import re

ISO_8601_PATTERN = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$'
)

def validate_timestamp(timestamp: str) -> bool:
    """Validate ISO 8601 timestamp"""
    if not ISO_8601_PATTERN.match(timestamp):
        return False
    
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False

def validate_timestamp_freshness(timestamp: str, max_age_seconds: int = 300) -> bool:
    """Validate timestamp is recent (within max_age)"""
    try:
        msg_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        age = (now - msg_time).total_seconds()
        
        # Reject messages from the future (allow 60s clock skew)
        if age < -60:
            return False
        
        # Reject messages too old
        if age > max_age_seconds:
            return False
        
        return True
    except ValueError:
        return False
```

---

#### `payload`
- **Type**: `object`
- **Required**: ✅ Yes
- **Contents**: Varies by `message_type` (see schemas below)
- **Max Size**: 10 MB (recommended)
- **Encoding**: UTF-8

**Validation Rules**:
```python
import json

MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

def validate_payload_size(payload: dict) -> bool:
    """Validate payload doesn't exceed size limit"""
    try:
        payload_json = json.dumps(payload)
        payload_bytes = payload_json.encode('utf-8')
        return len(payload_bytes) <= MAX_PAYLOAD_SIZE
    except (TypeError, ValueError):
        return False
```

---

#### `correlation_id`
- **Type**: `string` (UUID v4) or `null`
- **Required**: ⚠️ Optional (null for initiating messages)
- **Format**: UUID v4 (same as `message_id`)
- **Purpose**: Link responses to original requests
- **Example**: `"a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"`

**Usage Rules**:
- **Requests**: `null` or omitted
- **Responses**: Must match `message_id` of the request
- **Errors**: Must match `message_id` of the request that caused the error

---

## 📋 Complete Message Type Schemas

### 1. REQUEST Message

Used to request an action or query from another agent.

#### Schema

```json
{
  "message_id": "uuid-v4",
  "message_type": "request",
  "sender_id": "agent-id",
  "recipient_id": "target-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "method": "string (required)",
    "parameters": {} // optional
  },
  "correlation_id": null
}
```

#### Payload Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | ✅ | Action to perform (e.g., "get_price", "upload_report") |
| `parameters` | object | ❌ | Method-specific parameters |

#### Example

```json
{
  "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
  "message_type": "request",
  "sender_id": "client-agent-001",
  "recipient_id": "crypto-agent-001",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "payload": {
    "method": "get_price",
    "parameters": {
      "currency": "BTC"
    }
  },
  "correlation_id": null
}
```

#### Validation Code

```python
def validate_request_payload(payload: dict) -> bool:
    """Validate REQUEST message payload"""
    # Required field: method
    if "method" not in payload:
        return False
    
    if not isinstance(payload["method"], str):
        return False
    
    if len(payload["method"]) < 1 or len(payload["method"]) > 128:
        return False
    
    # Optional field: parameters
    if "parameters" in payload:
        if not isinstance(payload["parameters"], dict):
            return False
    
    return True
```

---

### 2. RESPONSE Message

Returns the result of a previous request.

#### Schema

```json
{
  "message_id": "uuid-v4",
  "message_type": "response",
  "sender_id": "agent-id",
  "recipient_id": "requesting-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "status": "success | error",
    "data": {}, // if success
    "error": {} // if error
  },
  "correlation_id": "request-message-id"
}
```

#### Payload Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string enum | ✅ | "success" or "error" |
| `data` | object | ⚠️ | Response data (required if status=success) |
| `error` | object | ⚠️ | Error details (required if status=error) |

#### Example (Success)

```json
{
  "message_id": "b8g9e0f3-4d5c-6e7f-8g9a-0c1d2e3f4g5h",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:30:00.125Z",
  "payload": {
    "status": "success",
    "data": {
      "currency": "BTC",
      "price_usd": 125000.50,
      "timestamp": "2025-01-15T10:30:00.000Z"
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

#### Example (Error)

```json
{
  "message_id": "c9h0f1g4-5e6d-7f8g-9h0b-1d2e3f4g5h6i",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:30:00.200Z",
  "payload": {
    "status": "error",
    "error": {
      "code": "INVALID_CURRENCY",
      "message": "Currency 'XYZ' is not supported",
      "details": {
        "supported_currencies": ["BTC", "ETH", "XRP"]
      }
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

#### Validation Code

```python
def validate_response_payload(payload: dict) -> bool:
    """Validate RESPONSE message payload"""
    # Required field: status
    if "status" not in payload:
        return False
    
    if payload["status"] not in ["success", "error"]:
        return False
    
    # If success, must have data
    if payload["status"] == "success":
        if "data" not in payload:
            return False
        if not isinstance(payload["data"], dict):
            return False
    
    # If error, must have error object
    if payload["status"] == "error":
        if "error" not in payload:
            return False
        if not isinstance(payload["error"], dict):
            return False
        
        # Error must have code and message
        error = payload["error"]
        if "code" not in error or "message" not in error:
            return False
    
    return True
```

---

### 3. HANDSHAKE Message

Initiates a session and exchanges agent capabilities.

#### Schema

```json
{
  "message_id": "uuid-v4",
  "message_type": "handshake",
  "sender_id": "agent-id",
  "recipient_id": "target-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "agent_card": {
      "agent_id": "string",
      "name": "string",
      "version": "string (semver)",
      "description": "string",
      "capabilities": ["string"],
      "supported_protocols": ["string"],
      "metadata": {}
    }
  },
  "correlation_id": null
}
```

#### Agent Card Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | ✅ | Unique agent identifier (same as sender_id) |
| `name` | string | ✅ | Human-readable agent name |
| `version` | string | ✅ | Semantic version (e.g., "1.0.0") |
| `description` | string | ✅ | Brief agent description |
| `capabilities` | array[string] | ✅ | List of supported capabilities |
| `supported_protocols` | array[string] | ✅ | Supported protocol versions |
| `metadata` | object | ❌ | Additional agent-specific information |

#### Example

```json
{
  "message_id": "c9h0f1g4-5e6d-7f8g-9h0b-1d2e3f4g5h6i",
  "message_type": "handshake",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:29:55.000Z",
  "payload": {
    "agent_card": {
      "agent_id": "crypto-agent-001",
      "name": "CryptoPriceAgent",
      "version": "1.0.0",
      "description": "AI Agent providing cryptocurrency prices",
      "capabilities": [
        "price_query",
        "currency_list",
        "no_streaming"
      ],
      "supported_protocols": ["A2A/1.0"],
      "metadata": {
        "supported_currencies": ["BTC", "ETH", "XRP"],
        "update_frequency": "on_request",
        "data_source": "demo"
      }
    }
  },
  "correlation_id": null
}
```

#### Validation Code

```python
import re

SEMVER_PATTERN = re.compile(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$')

def validate_agent_card(agent_card: dict) -> bool:
    """Validate agent card structure"""
    required_fields = [
        "agent_id", "name", "version", "description",
        "capabilities", "supported_protocols"
    ]
    
    for field in required_fields:
        if field not in agent_card:
            return False
    
    # Validate agent_id
    if not validate_agent_id(agent_card["agent_id"]):
        return False
    
    # Validate version (semantic versioning)
    if not SEMVER_PATTERN.match(agent_card["version"]):
        return False
    
    # Validate capabilities array
    if not isinstance(agent_card["capabilities"], list):
        return False
    
    for cap in agent_card["capabilities"]:
        if not isinstance(cap, str):
            return False
    
    # Validate supported_protocols array
    if not isinstance(agent_card["supported_protocols"], list):
        return False
    
    for protocol in agent_card["supported_protocols"]:
        if not isinstance(protocol, str):
            return False
    
    return True

def validate_handshake_payload(payload: dict) -> bool:
    """Validate HANDSHAKE message payload"""
    if "agent_card" not in payload:
        return False
    
    return validate_agent_card(payload["agent_card"])
```

---

### 4. ERROR Message

Indicates an error occurred during message processing.

#### Schema

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
      "details": {}, // optional
      "retry_after": 0 // optional, seconds
    }
  },
  "correlation_id": "original-message-id"
}
```

#### Error Object Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | ✅ | Error code (uppercase with underscores) |
| `message` | string | ✅ | Human-readable error description |
| `details` | object | ❌ | Additional error context |
| `retry_after` | integer | ❌ | Seconds to wait before retry |

#### Standard Error Codes

| Code | HTTP Equivalent | Description |
|------|----------------|-------------|
| `INVALID_MESSAGE` | 400 | Malformed message |
| `AUTHENTICATION_FAILED` | 401 | Authentication required or failed |
| `FORBIDDEN` | 403 | Authorized but not permitted |
| `NOT_FOUND` | 404 | Agent or resource not found |
| `METHOD_NOT_ALLOWED` | 405 | Method not supported |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `SERVICE_UNAVAILABLE` | 503 | Temporarily unavailable |
| `TIMEOUT` | 504 | Request timeout |

#### Example

```json
{
  "message_id": "j6o7m8n1-2l3k-4m5n-6o7i-8k9l0m1n2o3p",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:38:00.000Z",
  "payload": {
    "error": {
      "code": "RATE_LIMIT_EXCEEDED",
      "message": "Too many requests. Please try again later.",
      "details": {
        "limit": 100,
        "reset_at": "2025-01-15T10:39:00.000Z"
      },
      "retry_after": 60
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

#### Validation Code

```python
ERROR_CODE_PATTERN = re.compile(r'^[A-Z][A-Z0-9_]*[A-Z0-9]$')

def validate_error_payload(payload: dict) -> bool:
    """Validate ERROR message payload"""
    if "error" not in payload:
        return False
    
    error = payload["error"]
    
    # Required fields
    if "code" not in error or "message" not in error:
        return False
    
    # Validate code format (UPPERCASE_WITH_UNDERSCORES)
    if not ERROR_CODE_PATTERN.match(error["code"]):
        return False
    
    # Validate message is non-empty string
    if not isinstance(error["message"], str) or len(error["message"]) < 1:
        return False
    
    # Validate retry_after if present
    if "retry_after" in error:
        if not isinstance(error["retry_after"], int):
            return False
        if error["retry_after"] < 0:
            return False
    
    return True
```

---

### 5. DISCOVER_AGENTS Message

Query for available agents matching criteria.

#### Schema

```json
{
  "message_id": "uuid-v4",
  "message_type": "discover_agents",
  "sender_id": "agent-id",
  "recipient_id": "registry",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "capability": "string", // optional
    "status": "healthy | any", // optional
    "limit": 100 // optional
  },
  "correlation_id": null
}
```

#### Payload Specification

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `capability` | string | ❌ | null | Filter by capability |
| `status` | string enum | ❌ | "healthy" | Filter by health status |
| `limit` | integer | ❌ | 100 | Max results to return |

#### Example

```json
{
  "message_id": "d0i1g2h5-6f7e-8g9h-0i1c-2e3f4g5h6i7j",
  "message_type": "discover_agents",
  "sender_id": "client-agent-001",
  "recipient_id": "registry",
  "timestamp": "2025-01-15T10:35:00.000Z",
  "payload": {
    "capability": "price_query",
    "status": "healthy",
    "limit": 10
  },
  "correlation_id": null
}
```

#### Validation Code

```python
def validate_discover_agents_payload(payload: dict) -> bool:
    """Validate DISCOVER_AGENTS message payload"""
    # All fields are optional
    
    # Validate status if present
    if "status" in payload:
        if payload["status"] not in ["healthy", "any"]:
            return False
    
    # Validate limit if present
    if "limit" in payload:
        if not isinstance(payload["limit"], int):
            return False
        if payload["limit"] < 1 or payload["limit"] > 1000:
            return False
    
    # Validate capability if present
    if "capability" in payload:
        if not isinstance(payload["capability"], str):
            return False
    
    return True
```

---

### 6. AGENT_ANNOUNCEMENT Message

Response to discovery query with matching agents.

#### Schema

```json
{
  "message_id": "uuid-v4",
  "message_type": "agent_announcement",
  "sender_id": "registry",
  "recipient_id": "requesting-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {
    "agents": [
      {
        "agent_id": "string",
        "name": "string",
        "capabilities": ["string"],
        "status": "healthy | unhealthy",
        "endpoint": "string (URL)",
        "last_heartbeat": "ISO-8601-timestamp"
      }
    ],
    "total_count": 0,
    "query_time_ms": 0
  },
  "correlation_id": "discover-message-id"
}
```

#### Example

```json
{
  "message_id": "e1j2h3i6-7g8f-9h0i-1j2d-3f4g5h6i7j8k",
  "message_type": "agent_announcement",
  "sender_id": "registry",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:35:00.050Z",
  "payload": {
    "agents": [
      {
        "agent_id": "crypto-agent-001",
        "name": "CryptoPriceAgent",
        "capabilities": ["price_query", "currency_list"],
        "status": "healthy",
        "endpoint": "http://localhost:8888",
        "last_heartbeat": "2025-01-15T10:34:55.000Z"
      }
    ],
    "total_count": 1,
    "query_time_ms": 15
  },
  "correlation_id": "d0i1g2h5-6f7e-8g9h-0i1c-2e3f4g5h6i7j"
}
```

---

## 🔒 Security-Enhanced Message Schema

For production systems, messages should include authentication tags.

### Authenticated Message Structure

```json
{
  "message_id": "uuid-v4",
  "message_type": "request",
  "sender_id": "agent-id",
  "recipient_id": "target-agent-id",
  "timestamp": "ISO-8601-timestamp",
  "payload": {},
  "correlation_id": null,
  "auth": {
    "agent_id": "agent-id",
    "timestamp": "ISO-8601-timestamp",
    "nonce": "32-char-hex",
    "signature": "RSA-signature-base64",
    "public_key_fingerprint": "SHA256-fingerprint"
  }
}
```

### Authentication Tag Specification

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | ✅ | Must match `sender_id` |
| `timestamp` | string | ✅ | Message creation time |
| `nonce` | string | ✅ | Unique 32-char hex (replay protection) |
| `signature` | string | ✅ | RSA/ECC signature (Base64) |
| `public_key_fingerprint` | string | ✅ | SHA256 of public key |

For complete authentication documentation, see: [Authentication Tags](../03_SECURITY/02_authentication_tags.md)

---

## 📏 Validation Frameworks

### Complete Message Validator

```python
from typing import Dict, Any, List
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Result of message validation"""
    valid: bool
    errors: List[str]
    warnings: List[str]

class MessageValidator:
    """Complete A2A message validator"""
    
    def validate_message(self, message: Dict[str, Any]) -> ValidationResult:
        """
        Validate complete A2A message
        
        Performs 8-layer validation:
        1. Structure validation (required fields)
        2. Type validation (correct types)
        3. Format validation (UUIDs, timestamps, etc.)
        4. Size validation (payload limits)
        5. Content validation (payload structure)
        6. Business logic validation
        7. Security validation (auth tags if present)
        8. Freshness validation (timestamp age)
        """
        errors = []
        warnings = []
        
        # Layer 1: Structure validation
        required_fields = [
            "message_id", "message_type", "sender_id",
            "recipient_id", "timestamp", "payload"
        ]
        
        for field in required_fields:
            if field not in message:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return ValidationResult(False, errors, warnings)
        
        # Layer 2: Type validation
        if not isinstance(message["message_id"], str):
            errors.append("message_id must be string")
        
        if not isinstance(message["payload"], dict):
            errors.append("payload must be object")
        
        # Layer 3: Format validation
        if not validate_message_id(message["message_id"]):
            errors.append("Invalid message_id format (not UUID v4)")
        
        if not validate_message_type(message["message_type"]):
            errors.append(f"Unknown message_type: {message['message_type']}")
        
        if not validate_agent_id(message["sender_id"]):
            errors.append("Invalid sender_id format")
        
        if not validate_timestamp(message["timestamp"]):
            errors.append("Invalid timestamp format")
        
        # Layer 4: Size validation
        if not validate_payload_size(message["payload"]):
            errors.append("Payload exceeds maximum size")
        
        # Layer 5: Content validation (message type specific)
        msg_type = message["message_type"]
        payload = message["payload"]
        
        if msg_type == "request":
            if not validate_request_payload(payload):
                errors.append("Invalid request payload")
        elif msg_type == "response":
            if not validate_response_payload(payload):
                errors.append("Invalid response payload")
        elif msg_type == "handshake":
            if not validate_handshake_payload(payload):
                errors.append("Invalid handshake payload")
        # ... other message types
        
        # Layer 6: Business logic validation
        # (application-specific, extend as needed)
        
        # Layer 7: Security validation
        if "auth" in message:
            # Validate authentication tag structure
            # (See authentication documentation)
            pass
        
        # Layer 8: Freshness validation
        if not validate_timestamp_freshness(message["timestamp"]):
            warnings.append("Message timestamp is stale")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)
```

---

## 🧪 Testing Your Validation

### Unit Test Examples

```python
import unittest
import json

class TestMessageValidation(unittest.TestCase):
    """Unit tests for message validation"""
    
    def test_valid_request_message(self):
        """Test validation of valid REQUEST message"""
        message = {
            "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
            "message_type": "request",
            "sender_id": "client-001",
            "recipient_id": "server-001",
            "timestamp": "2025-01-15T10:30:00.000Z",
            "payload": {
                "method": "get_price",
                "parameters": {"currency": "BTC"}
            },
            "correlation_id": None
        }
        
        validator = MessageValidator()
        result = validator.validate_message(message)
        
        self.assertTrue(result.valid)
        self.assertEqual(len(result.errors), 0)
    
    def test_missing_required_field(self):
        """Test validation fails with missing required field"""
        message = {
            "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
            "message_type": "request",
            # Missing sender_id
            "recipient_id": "server-001",
            "timestamp": "2025-01-15T10:30:00.000Z",
            "payload": {}
        }
        
        validator = MessageValidator()
        result = validator.validate_message(message)
        
        self.assertFalse(result.valid)
        self.assertIn("Missing required field: sender_id", result.errors)
    
    def test_invalid_uuid_format(self):
        """Test validation fails with invalid UUID"""
        message = {
            "message_id": "not-a-valid-uuid",
            "message_type": "request",
            "sender_id": "client-001",
            "recipient_id": "server-001",
            "timestamp": "2025-01-15T10:30:00.000Z",
            "payload": {}
        }
        
        validator = MessageValidator()
        result = validator.validate_message(message)
        
        self.assertFalse(result.valid)
        self.assertIn("Invalid message_id format", result.errors)
```

---

## 🎯 Best Practices

### 1. Always Validate Incoming Messages
```python
# ❌ BAD: Trust user input
def handle_message(message: dict):
    # Process without validation
    method = message["payload"]["method"]
    process(method)

# ✅ GOOD: Validate first
def handle_message(message: dict):
    validator = MessageValidator()
    result = validator.validate_message(message)
    
    if not result.valid:
        return create_error_response(
            "INVALID_MESSAGE",
            f"Validation failed: {'; '.join(result.errors)}"
        )
    
    # Now safe to process
    method = message["payload"]["method"]
    process(method)
```

### 2. Generate Valid Messages
```python
# ✅ Use helper functions
def create_request_message(
    sender_id: str,
    recipient_id: str,
    method: str,
    parameters: dict = None
) -> dict:
    """Create a valid REQUEST message"""
    return {
        "message_id": str(uuid.uuid4()),
        "message_type": "request",
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "payload": {
            "method": method,
            "parameters": parameters or {}
        },
        "correlation_id": None
    }
```

### 3. Use JSON Schema Validation (Alternative)
```python
import jsonschema

# Define JSON Schema
REQUEST_SCHEMA = {
    "type": "object",
    "required": ["message_id", "message_type", "sender_id", "recipient_id", "timestamp", "payload"],
    "properties": {
        "message_id": {"type": "string", "pattern": "^[0-9a-f-]{36}$"},
        "message_type": {"type": "string", "enum": ["request"]},
        "sender_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "recipient_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "timestamp": {"type": "string", "format": "date-time"},
        "payload": {
            "type": "object",
            "required": ["method"],
            "properties": {
                "method": {"type": "string", "minLength": 1},
                "parameters": {"type": "object"}
            }
        },
        "correlation_id": {"type": ["string", "null"]}
    }
}

def validate_with_json_schema(message: dict) -> bool:
    """Validate message using JSON Schema"""
    try:
        jsonschema.validate(instance=message, schema=REQUEST_SCHEMA)
        return True
    except jsonschema.ValidationError as e:
        print(f"Validation error: {e.message}")
        return False
```

---

## 🔗 Related Documentation

- [Protocol Messages Overview](../04_COMMUNICATION/01_protocol_messages.md) - Message types and usage
- [Authentication Tags](../03_SECURITY/02_authentication_tags.md) - Security enhancement
- [Error Handling](../04_COMMUNICATION/03_error_handling.md) - Error response patterns
- [Capability Vocabulary](../05_REFERENCE/02_capability_vocabulary.md) - Standard capability names

---

## 📋 Quick Reference Card

### Message Validation Checklist

- [ ] All required fields present
- [ ] `message_id` is valid UUID v4
- [ ] `message_type` is known enum value
- [ ] `sender_id` and `recipient_id` valid format
- [ ] `timestamp` is ISO 8601 with UTC
- [ ] `timestamp` is fresh (within 5 minutes)
- [ ] `payload` is valid object
- [ ] `payload` size under 10 MB
- [ ] Payload structure matches message type
- [ ] `correlation_id` matches request (if response)
- [ ] Authentication tag valid (if present)

---

## 💡 Common Validation Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "Invalid UUID format" | message_id not UUID v4 | Use `str(uuid.uuid4())` |
| "Unknown message_type" | Typo or unsupported type | Check MessageType enum |
| "Timestamp too old" | Clock skew or replay | Use current UTC time |
| "Missing required field" | Incomplete message | Include all required fields |
| "Payload too large" | Message over 10 MB | Reduce payload or use chunking |

---

## 🎓 Summary

You've learned:
- ✅ Complete JSON schema for all A2A message types
- ✅ Field-by-field validation rules and patterns
- ✅ Security-enhanced message structures
- ✅ Practical validation code examples
- ✅ Best practices for message handling
- ✅ Testing approaches for validation

**Next Steps**:
1. Study [Capability Vocabulary](../05_REFERENCE/02_capability_vocabulary.md) for standard capability names
2. Review [Authentication Tags](../03_SECURITY/02_authentication_tags.md) for security
3. Practice implementing validators for your agents

---

**Document Version**: 1.0  
**Last Updated**: November 27, 2025  
**Status**: ✅ Complete  
**Author**: MCP & A2A Security Learning Project

---

**Happy Validating! 🎯✅**