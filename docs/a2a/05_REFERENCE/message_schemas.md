# Message Schemas Reference

> **Learning Path**: Reference  
> **Difficulty**: Intermediate  
> **Prerequisites**: [Protocol Messages](../04_COMMUNICATION/01_protocol_messages.md), [Message Validation](../04_COMMUNICATION/04_message_validation_patterns.md)  
> **Completion Time**: 45-60 minutes

## Navigation
← Previous: [Message Validation Patterns](../04_COMMUNICATION/04_message_validation_patterns.md) | Next: [Capability Vocabulary](./capability_vocabulary.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

This reference document provides complete, production-ready schema definitions for all A2A message types:

- [ ] Complete JSON Schema definitions (JSON Schema Draft 7)
- [ ] Python validation code with Pydantic models
- [ ] TypeScript type definitions
- [ ] Field-by-field specifications
- [ ] Validation patterns and constraints
- [ ] Example messages for each type
- [ ] Schema versioning guidance

---

## 📚 Overview

The A2A Protocol uses **JSON (JavaScript Object Notation)** for all message serialization. This document provides:

1. **Formal Schemas**: JSON Schema definitions for validation
2. **Type Definitions**: TypeScript interfaces for type safety
3. **Python Models**: Pydantic models for runtime validation
4. **Validation Code**: Ready-to-use validators
5. **Examples**: Real message examples from project

### Schema Format Standards

All schemas in this document conform to:
- **JSON Schema**: Draft 7 (http://json-schema.org/draft-07/schema#)
- **TypeScript**: TypeScript 5.0+
- **Python**: Python 3.10+ with Pydantic 2.0+

---

## 🏗️ Base Message Schema

### JSON Schema Definition

All A2A messages share this base structure:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/base-message.json",
  "title": "A2A Base Message",
  "description": "Base schema for all A2A protocol messages",
  "type": "object",
  "required": [
    "message_id",
    "message_type",
    "sender_id",
    "recipient_id",
    "timestamp",
    "payload"
  ],
  "properties": {
    "message_id": {
      "type": "string",
      "description": "Globally unique message identifier",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
      "examples": ["a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"]
    },
    "message_type": {
      "type": "string",
      "description": "Type of message being sent",
      "enum": [
        "request",
        "response",
        "handshake",
        "handshake_ack",
        "error",
        "discover_agents",
        "agent_announcement",
        "goodbye"
      ]
    },
    "sender_id": {
      "type": "string",
      "description": "Identifier of the sending agent",
      "minLength": 3,
      "maxLength": 128,
      "pattern": "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"
    },
    "recipient_id": {
      "type": "string",
      "description": "Identifier of the receiving agent",
      "minLength": 3,
      "maxLength": 128,
      "pattern": "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"
    },
    "timestamp": {
      "type": "string",
      "description": "ISO 8601 timestamp in UTC",
      "format": "date-time",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{3})?Z$",
      "examples": ["2025-12-09T15:30:00.000Z"]
    },
    "payload": {
      "type": "object",
      "description": "Message-type-specific content"
    },
    "correlation_id": {
      "type": ["string", "null"],
      "description": "Links response to original request",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    },
    "auth": {
      "type": "object",
      "description": "Optional authentication tag",
      "properties": {
        "agent_id": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "nonce": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
        "signature": {"type": "string"},
        "public_key_fingerprint": {"type": "string"}
      },
      "required": ["agent_id", "timestamp", "nonce", "signature"]
    }
  },
  "additionalProperties": false
}
```

### TypeScript Definition

```typescript
/**
 * Base A2A Message
 * All messages extend this interface
 */
export interface BaseMessage {
  message_id: string;  // UUID v4
  message_type: MessageType;
  sender_id: string;
  recipient_id: string;
  timestamp: string;  // ISO 8601
  payload: Record<string, any>;
  correlation_id?: string | null;
  auth?: AuthenticationTag;
}

export type MessageType =
  | "request"
  | "response"
  | "handshake"
  | "handshake_ack"
  | "error"
  | "discover_agents"
  | "agent_announcement"
  | "goodbye";

export interface AuthenticationTag {
  agent_id: string;
  timestamp: string;
  nonce: string;  // 32 hex chars
  signature: string;  // Base64
  public_key_fingerprint?: string;
}
```

### Python Pydantic Model

```python
from datetime import datetime
from typing import Any, Dict, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field, field_validator

class AuthenticationTag(BaseModel):
    """Authentication tag for secure messages"""
    agent_id: str = Field(..., min_length=3, max_length=128)
    timestamp: datetime
    nonce: str = Field(..., pattern=r'^[0-9a-f]{32}$')
    signature: str
    public_key_fingerprint: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "crypto-agent-001",
                "timestamp": "2025-12-09T15:30:00.000Z",
                "nonce": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                "signature": "SGVsbG8gV29ybGQ="
            }
        }

class BaseMessage(BaseModel):
    """Base A2A message structure"""
    message_id: UUID = Field(..., description="Globally unique message ID")
    message_type: Literal[
        "request", "response", "handshake", "handshake_ack",
        "error", "discover_agents", "agent_announcement", "goodbye"
    ]
    sender_id: str = Field(..., min_length=3, max_length=128)
    recipient_id: str = Field(..., min_length=3, max_length=128)
    timestamp: datetime = Field(..., description="UTC timestamp")
    payload: Dict[str, Any]
    correlation_id: Optional[UUID] = None
    auth: Optional[AuthenticationTag] = None

    @field_validator('sender_id', 'recipient_id')
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        """Validate agent ID format"""
        if not v[0].isalnum() or not v[-1].isalnum():
            raise ValueError("Agent ID must start and end with alphanumeric")
        return v

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp_freshness(cls, v: datetime) -> datetime:
        """Validate timestamp is reasonably fresh"""
        now = datetime.utcnow()
        age = (now - v).total_seconds()
        
        if age < -60:  # 1 minute clock skew tolerance
            raise ValueError("Timestamp is in the future")
        
        if age > 300:  # 5 minute max age
            raise ValueError("Timestamp too old")
        
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
                "message_type": "request",
                "sender_id": "client-agent-001",
                "recipient_id": "crypto-agent-001",
                "timestamp": "2025-12-09T15:30:00.000Z",
                "payload": {"method": "get_price", "parameters": {"currency": "BTC"}},
                "correlation_id": None
            }
        }
```

---

## 1️⃣ REQUEST Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/request-message.json",
  "title": "A2A Request Message",
  "description": "Request an action or query from another agent",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "request"},
        "correlation_id": {"type": "null"},
        "payload": {
          "type": "object",
          "required": ["method"],
          "properties": {
            "method": {
              "type": "string",
              "description": "Action to perform",
              "minLength": 1,
              "maxLength": 128,
              "examples": ["get_price", "upload_report", "create_project"]
            },
            "parameters": {
              "type": "object",
              "description": "Method-specific parameters",
              "additionalProperties": true
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface RequestMessage extends BaseMessage {
  message_type: "request";
  correlation_id: null;
  payload: {
    method: string;
    parameters?: Record<string, any>;
  };
}

// Example: Crypto price request
export interface GetPriceRequest extends RequestMessage {
  payload: {
    method: "get_price";
    parameters: {
      currency: "BTC" | "ETH" | "XRP";
    };
  };
}

// Example: File upload request
export interface UploadReportRequest extends RequestMessage {
  payload: {
    method: "upload_report";
    parameters: {
      filename: string;
      content: string;  // Base64 encoded
      content_type: string;
    };
  };
}
```

### Python Pydantic Model

```python
from typing import Any, Dict, Optional
from pydantic import Field

class RequestPayload(BaseModel):
    """Payload for REQUEST messages"""
    method: str = Field(..., min_length=1, max_length=128)
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "method": "get_price",
                    "parameters": {"currency": "BTC"}
                },
                {
                    "method": "upload_report",
                    "parameters": {
                        "filename": "report.json",
                        "content": "eyAi..."
                    }
                }
            ]
        }

class RequestMessage(BaseMessage):
    """REQUEST message type"""
    message_type: Literal["request"]
    correlation_id: Literal[None] = None
    payload: RequestPayload

# Usage
request = RequestMessage(
    message_id=UUID("a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"),
    message_type="request",
    sender_id="client-001",
    recipient_id="server-001",
    timestamp=datetime.utcnow(),
    payload=RequestPayload(
        method="get_price",
        parameters={"currency": "BTC"}
    )
)
```

### Complete Example

```json
{
  "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
  "message_type": "request",
  "sender_id": "client-agent-001",
  "recipient_id": "crypto-agent-001",
  "timestamp": "2025-12-09T15:30:00.000Z",
  "payload": {
    "method": "get_price",
    "parameters": {
      "currency": "BTC"
    }
  },
  "correlation_id": null
}
```

---

## 2️⃣ RESPONSE Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/response-message.json",
  "title": "A2A Response Message",
  "description": "Response to a previous request",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "response"},
        "correlation_id": {
          "type": "string",
          "description": "Must match request message_id"
        },
        "payload": {
          "type": "object",
          "required": ["status"],
          "properties": {
            "status": {
              "type": "string",
              "enum": ["success", "error"],
              "description": "Outcome of the request"
            },
            "data": {
              "type": "object",
              "description": "Response data (required if status=success)"
            },
            "error": {
              "type": "object",
              "description": "Error details (required if status=error)",
              "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "details": {"type": "object"}
              },
              "required": ["code", "message"]
            }
          },
          "oneOf": [
            {
              "properties": {
                "status": {"const": "success"},
                "data": {"type": "object"}
              },
              "required": ["data"]
            },
            {
              "properties": {
                "status": {"const": "error"},
                "error": {"type": "object"}
              },
              "required": ["error"]
            }
          ],
          "additionalProperties": false
        }
      },
      "required": ["correlation_id"]
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface ResponseMessage extends BaseMessage {
  message_type: "response";
  correlation_id: string;  // Must be set
  payload: SuccessPayload | ErrorPayload;
}

export interface SuccessPayload {
  status: "success";
  data: Record<string, any>;
}

export interface ErrorPayload {
  status: "error";
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
}

// Example: Success response
export interface PriceResponse extends ResponseMessage {
  payload: {
    status: "success";
    data: {
      currency: string;
      price_usd: number;
      timestamp: string;
    };
  };
}
```

### Python Pydantic Model

```python
from typing import Union
from pydantic import model_validator

class ErrorObject(BaseModel):
    """Error details in response"""
    code: str = Field(..., pattern=r'^[A-Z][A-Z0-9_]*[A-Z0-9]$')
    message: str = Field(..., min_length=1)
    details: Optional[Dict[str, Any]] = None

class SuccessResponsePayload(BaseModel):
    """Success response payload"""
    status: Literal["success"]
    data: Dict[str, Any]

class ErrorResponsePayload(BaseModel):
    """Error response payload"""
    status: Literal["error"]
    error: ErrorObject

ResponsePayload = Union[SuccessResponsePayload, ErrorResponsePayload]

class ResponseMessage(BaseMessage):
    """RESPONSE message type"""
    message_type: Literal["response"]
    correlation_id: UUID  # Required for responses
    payload: ResponsePayload

    @model_validator(mode='after')
    def validate_payload_consistency(self):
        """Ensure payload is consistent with status"""
        payload = self.payload
        
        if payload.status == "success":
            if not isinstance(payload, SuccessResponsePayload):
                raise ValueError("Success status requires data field")
        elif payload.status == "error":
            if not isinstance(payload, ErrorResponsePayload):
                raise ValueError("Error status requires error field")
        
        return self
```

### Complete Examples

**Success Response**:
```json
{
  "message_id": "b8g9e0f3-4d5c-6e7f-8g9a-0c1d2e3f4g5h",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:30:00.125Z",
  "payload": {
    "status": "success",
    "data": {
      "currency": "BTC",
      "price_usd": 125000.50,
      "timestamp": "2025-12-09T15:30:00.000Z"
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

**Error Response**:
```json
{
  "message_id": "c9h0f1g4-5e6d-7f8g-9h0b-1d2e3f4g5h6i",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:30:00.200Z",
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

---

## 3️⃣ HANDSHAKE Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/handshake-message.json",
  "title": "A2A Handshake Message",
  "description": "Initiate connection and exchange capabilities",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "handshake"},
        "correlation_id": {"type": "null"},
        "payload": {
          "type": "object",
          "required": ["agent_card"],
          "properties": {
            "agent_card": {
              "type": "object",
              "required": [
                "agent_id",
                "name",
                "version",
                "description",
                "capabilities",
                "supported_protocols"
              ],
              "properties": {
                "agent_id": {"type": "string"},
                "name": {"type": "string"},
                "version": {
                  "type": "string",
                  "pattern": "^\\d+\\.\\d+\\.\\d+$"
                },
                "description": {"type": "string"},
                "capabilities": {
                  "type": "array",
                  "items": {"type": "string"},
                  "minItems": 1,
                  "maxItems": 50
                },
                "supported_protocols": {
                  "type": "array",
                  "items": {"type": "string"},
                  "minItems": 1
                },
                "metadata": {"type": "object"}
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface HandshakeMessage extends BaseMessage {
  message_type: "handshake";
  correlation_id: null;
  payload: {
    agent_card: AgentCard;
  };
}

export interface AgentCard {
  agent_id: string;
  name: string;
  version: string;  // Semantic versioning: "1.0.0"
  description: string;
  capabilities: string[];
  supported_protocols: string[];
  metadata?: Record<string, any>;
}
```

### Python Pydantic Model

```python
from pydantic import Field, field_validator
import re

class AgentCard(BaseModel):
    """Agent capability card"""
    agent_id: str = Field(..., min_length=3, max_length=128)
    name: str = Field(..., min_length=1, max_length=100)
    version: str = Field(..., pattern=r'^\d+\.\d+\.\d+$')
    description: str = Field(..., max_length=500)
    capabilities: list[str] = Field(..., min_items=1, max_items=50)
    supported_protocols: list[str] = Field(..., min_items=1)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator('version')
    @classmethod
    def validate_semver(cls, v: str) -> str:
        """Validate semantic versioning"""
        parts = v.split('.')
        if len(parts) != 3:
            raise ValueError("Version must be major.minor.patch")
        
        for part in parts:
            if not part.isdigit():
                raise ValueError("Version parts must be integers")
        
        return v

class HandshakePayload(BaseModel):
    """Payload for HANDSHAKE messages"""
    agent_card: AgentCard

class HandshakeMessage(BaseMessage):
    """HANDSHAKE message type"""
    message_type: Literal["handshake"]
    correlation_id: Literal[None] = None
    payload: HandshakePayload
```

### Complete Example

```json
{
  "message_id": "c9h0f1g4-5e6d-7f8g-9h0b-1d2e3f4g5h6i",
  "message_type": "handshake",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:29:55.000Z",
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
        "data_type": "fictitious"
      }
    }
  },
  "correlation_id": null
}
```

---

## 4️⃣ ERROR Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/error-message.json",
  "title": "A2A Error Message",
  "description": "Error occurred during message processing",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "error"},
        "correlation_id": {
          "type": "string",
          "description": "Message that caused the error"
        },
        "payload": {
          "type": "object",
          "required": ["error"],
          "properties": {
            "error": {
              "type": "object",
              "required": ["code", "message"],
              "properties": {
                "code": {
                  "type": "string",
                  "pattern": "^[A-Z][A-Z0-9_]*[A-Z0-9]$",
                  "examples": ["RATE_LIMIT_EXCEEDED", "INVALID_MESSAGE"]
                },
                "message": {
                  "type": "string",
                  "minLength": 1,
                  "maxLength": 500
                },
                "details": {
                  "type": "object",
                  "description": "Additional error context"
                },
                "retry_after": {
                  "type": "integer",
                  "minimum": 0,
                  "description": "Seconds to wait before retry"
                },
                "documentation_url": {
                  "type": "string",
                  "format": "uri"
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        }
      },
      "required": ["correlation_id"]
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface ErrorMessage extends BaseMessage {
  message_type: "error";
  correlation_id: string;
  payload: {
    error: {
      code: string;  // UPPERCASE_UNDERSCORE
      message: string;
      details?: Record<string, any>;
      retry_after?: number;
      documentation_url?: string;
    };
  };
}

// Standard error codes
export type ErrorCode =
  | "INVALID_MESSAGE"
  | "VALIDATION_FAILED"
  | "AUTHENTICATION_FAILED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "METHOD_NOT_ALLOWED"
  | "RATE_LIMIT_EXCEEDED"
  | "PAYLOAD_TOO_LARGE"
  | "INTERNAL_ERROR"
  | "SERVICE_UNAVAILABLE"
  | "TIMEOUT";
```

### Python Pydantic Model

```python
class ErrorDetails(BaseModel):
    """Error details in ERROR message"""
    code: str = Field(..., pattern=r'^[A-Z][A-Z0-9_]*[A-Z0-9]$')
    message: str = Field(..., min_length=1, max_length=500)
    details: Optional[Dict[str, Any]] = None
    retry_after: Optional[int] = Field(None, ge=0)
    documentation_url: Optional[str] = None

class ErrorPayload(BaseModel):
    """Payload for ERROR messages"""
    error: ErrorDetails

class ErrorMessage(BaseMessage):
    """ERROR message type"""
    message_type: Literal["error"]
    correlation_id: UUID  # Required
    payload: ErrorPayload
```

### Complete Example

```json
{
  "message_id": "j6o7m8n1-2l3k-4m5n-6o7i-8k9l0m1n2o3p",
  "message_type": "error",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:38:00.000Z",
  "payload": {
    "error": {
      "code": "RATE_LIMIT_EXCEEDED",
      "message": "Too many requests. Please try again later.",
      "details": {
        "limit": 100,
        "window": "1 minute",
        "reset_at": "2025-12-09T15:39:00.000Z"
      },
      "retry_after": 60,
      "documentation_url": "https://docs.a2a.example.com/errors#rate-limit"
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

---

## 5️⃣ DISCOVER_AGENTS Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/discover-agents-message.json",
  "title": "A2A Discover Agents Message",
  "description": "Query for available agents",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "discover_agents"},
        "recipient_id": {"const": "registry"},
        "correlation_id": {"type": "null"},
        "payload": {
          "type": "object",
          "properties": {
            "capabilities": {
              "type": "array",
              "items": {"type": "string"},
              "description": "Required capabilities"
            },
            "filters": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string",
                  "enum": ["healthy", "unhealthy", "all"]
                },
                "max_results": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 100
                }
              }
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface DiscoverAgentsMessage extends BaseMessage {
  message_type: "discover_agents";
  recipient_id: "registry";
  correlation_id: null;
  payload: {
    capabilities?: string[];
    filters?: {
      status?: "healthy" | "unhealthy" | "all";
      max_results?: number;
    };
  };
}
```

### Python Pydantic Model

```python
class DiscoverFilters(BaseModel):
    """Filters for agent discovery"""
    status: Optional[Literal["healthy", "unhealthy", "all"]] = "all"
    max_results: Optional[int] = Field(100, ge=1, le=100)

class DiscoverAgentsPayload(BaseModel):
    """Payload for DISCOVER_AGENTS messages"""
    capabilities: Optional[list[str]] = None
    filters: Optional[DiscoverFilters] = None

class DiscoverAgentsMessage(BaseMessage):
    """DISCOVER_AGENTS message type"""
    message_type: Literal["discover_agents"]
    recipient_id: Literal["registry"]
    correlation_id: Literal[None] = None
    payload: DiscoverAgentsPayload
```

### Complete Example

```json
{
  "message_id": "d0i1g2h5-6f7e-8g9h-0i1c-2e3f4g5h6i7j",
  "message_type": "discover_agents",
  "sender_id": "client-agent-001",
  "recipient_id": "registry",
  "timestamp": "2025-12-09T15:35:00.000Z",
  "payload": {
    "capabilities": ["price_query", "real_time_data"],
    "filters": {
      "status": "healthy",
      "max_results": 10
    }
  },
  "correlation_id": null
}
```

---

## 6️⃣ AGENT_ANNOUNCEMENT Message Schema

### JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/agent-announcement-message.json",
  "title": "A2A Agent Announcement Message",
  "description": "Response to discovery query with matching agents",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "properties": {
        "message_type": {"const": "agent_announcement"},
        "sender_id": {"const": "registry"},
        "correlation_id": {"type": "string"},
        "payload": {
          "type": "object",
          "required": ["agents", "total_count"],
          "properties": {
            "agents": {
              "type": "array",
              "items": {
                "type": "object",
                "required": [
                  "agent_id",
                  "name",
                  "capabilities",
                  "status",
                  "endpoint"
                ],
                "properties": {
                  "agent_id": {"type": "string"},
                  "name": {"type": "string"},
                  "capabilities": {
                    "type": "array",
                    "items": {"type": "string"}
                  },
                  "status": {
                    "type": "string",
                    "enum": ["healthy", "unhealthy"]
                  },
                  "endpoint": {
                    "type": "string",
                    "format": "uri"
                  },
                  "last_heartbeat": {
                    "type": "string",
                    "format": "date-time"
                  }
                }
              }
            },
            "total_count": {
              "type": "integer",
              "minimum": 0
            },
            "query_time_ms": {
              "type": "number",
              "minimum": 0
            }
          },
          "additionalProperties": false
        }
      },
      "required": ["correlation_id"]
    }
  ]
}
```

### TypeScript Definition

```typescript
export interface AgentAnnouncementMessage extends BaseMessage {
  message_type: "agent_announcement";
  sender_id: "registry";
  correlation_id: string;
  payload: {
    agents: AgentInfo[];
    total_count: number;
    query_time_ms?: number;
  };
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  capabilities: string[];
  status: "healthy" | "unhealthy";
  endpoint: string;
  last_heartbeat?: string;
}
```

### Python Pydantic Model

```python
from pydantic import HttpUrl

class AgentInfo(BaseModel):
    """Information about discovered agent"""
    agent_id: str
    name: str
    capabilities: list[str]
    status: Literal["healthy", "unhealthy"]
    endpoint: HttpUrl
    last_heartbeat: Optional[datetime] = None

class AgentAnnouncementPayload(BaseModel):
    """Payload for AGENT_ANNOUNCEMENT messages"""
    agents: list[AgentInfo]
    total_count: int = Field(..., ge=0)
    query_time_ms: Optional[float] = Field(None, ge=0)

class AgentAnnouncementMessage(BaseMessage):
    """AGENT_ANNOUNCEMENT message type"""
    message_type: Literal["agent_announcement"]
    sender_id: Literal["registry"]
    correlation_id: UUID
    payload: AgentAnnouncementPayload
```

### Complete Example

```json
{
  "message_id": "e1j2h3i6-7g8f-9h0i-1j2d-3f4g5h6i7j8k",
  "message_type": "agent_announcement",
  "sender_id": "registry",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-12-09T15:35:00.050Z",
  "payload": {
    "agents": [
      {
        "agent_id": "crypto-agent-001",
        "name": "CryptoPriceAgent",
        "capabilities": ["price_query", "currency_list"],
        "status": "healthy",
        "endpoint": "http://localhost:8888",
        "last_heartbeat": "2025-12-09T15:34:55.000Z"
      },
      {
        "agent_id": "crypto-agent-002",
        "name": "CryptoAnalysisAgent",
        "capabilities": ["price_query", "trend_analysis"],
        "status": "healthy",
        "endpoint": "http://localhost:8889",
        "last_heartbeat": "2025-12-09T15:34:58.000Z"
      }
    ],
    "total_count": 2,
    "query_time_ms": 15.3
  },
  "correlation_id": "d0i1g2h5-6f7e-8g9h-0i1c-2e3f4g5h6i7j"
}
```

---

## 🔐 Authenticated Message Schema

For production systems, all messages should include authentication tags.

### JSON Schema Extension

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/authenticated-message.json",
  "title": "A2A Authenticated Message",
  "description": "Message with authentication tag",
  "allOf": [
    {"$ref": "base-message.json"},
    {
      "required": ["auth"],
      "properties": {
        "auth": {
          "type": "object",
          "required": ["agent_id", "timestamp", "nonce", "signature"],
          "properties": {
            "agent_id": {
              "type": "string",
              "description": "Must match sender_id"
            },
            "timestamp": {
              "type": "string",
              "format": "date-time"
            },
            "nonce": {
              "type": "string",
              "pattern": "^[0-9a-f]{32}$",
              "description": "32 hex chars for replay protection"
            },
            "signature": {
              "type": "string",
              "description": "RSA/ECC signature in Base64"
            },
            "public_key_fingerprint": {
              "type": "string",
              "description": "SHA256 fingerprint of public key"
            }
          },
          "additionalProperties": false
        }
      }
    }
  ]
}
```

### Complete Authenticated Example

```json
{
  "message_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g",
  "message_type": "request",
  "sender_id": "client-agent-001",
  "recipient_id": "crypto-agent-001",
  "timestamp": "2025-12-09T15:30:00.000Z",
  "payload": {
    "method": "get_price",
    "parameters": {
      "currency": "BTC"
    }
  },
  "correlation_id": null,
  "auth": {
    "agent_id": "client-agent-001",
    "timestamp": "2025-12-09T15:30:00.000Z",
    "nonce": "a1b2c3d4e5f6789012345678901234567",
    "signature": "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzaWduYXR1cmUu",
    "public_key_fingerprint": "sha256:1234567890abcdef"
  }
}
```

---

## 📦 Schema Validation Code

### Python Validator Using JSON Schema

```python
import json
import jsonschema
from pathlib import Path

class SchemaValidator:
    """Validate A2A messages against JSON schemas"""
    
    def __init__(self, schema_dir: Path):
        """Load all schemas from directory"""
        self.schemas = {}
        
        # Load base schema
        with open(schema_dir / "base-message.json") as f:
            self.schemas["base"] = json.load(f)
        
        # Load message type schemas
        for schema_file in schema_dir.glob("*-message.json"):
            msg_type = schema_file.stem.replace("-message", "")
            with open(schema_file) as f:
                self.schemas[msg_type] = json.load(f)
    
    def validate(self, message: dict) -> tuple[bool, list[str]]:
        """
        Validate message against appropriate schema
        
        Returns: (is_valid, errors)
        """
        errors = []
        
        # Validate against base schema first
        try:
            jsonschema.validate(message, self.schemas["base"])
        except jsonschema.ValidationError as e:
            errors.append(f"Base schema error: {e.message}")
            return False, errors
        
        # Validate against message-type-specific schema
        msg_type = message.get("message_type")
        if msg_type in self.schemas:
            try:
                jsonschema.validate(message, self.schemas[msg_type])
            except jsonschema.ValidationError as e:
                errors.append(f"{msg_type} schema error: {e.message}")
                return False, errors
        else:
            errors.append(f"Unknown message_type: {msg_type}")
            return False, errors
        
        return True, []

# Usage
validator = SchemaValidator(Path("schemas/"))
message = json.loads(raw_message)

is_valid, errors = validator.validate(message)
if not is_valid:
    print(f"Validation failed: {errors}")
```

### TypeScript Validator Using AJV

```typescript
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync } from "fs";

class SchemaValidator {
  private ajv: Ajv;
  private schemas: Map<string, any>;

  constructor(schemaDir: string) {
    this.ajv = new Ajv({ allErrors: true });
    addFormats(this.ajv);
    this.schemas = new Map();

    // Load schemas
    const baseSchema = JSON.parse(
      readFileSync(`${schemaDir}/base-message.json`, "utf-8")
    );
    this.ajv.addSchema(baseSchema, "base");

    // Load message type schemas
    const messageTypes = [
      "request", "response", "handshake", "error",
      "discover-agents", "agent-announcement"
    ];

    for (const type of messageTypes) {
      const schema = JSON.parse(
        readFileSync(`${schemaDir}/${type}-message.json`, "utf-8")
      );
      this.schemas.set(type, schema);
      this.ajv.addSchema(schema, type);
    }
  }

  validate(message: any): { valid: boolean; errors: string[] } {
    const messageType = message.message_type;
    const schema = this.schemas.get(messageType);

    if (!schema) {
      return {
        valid: false,
        errors: [`Unknown message_type: ${messageType}`]
      };
    }

    const valid = this.ajv.validate(messageType, message);

    if (!valid) {
      const errors = this.ajv.errors?.map(e => 
        `${e.instancePath}: ${e.message}`
      ) || [];
      return { valid: false, errors };
    }

    return { valid: true, errors: [] };
  }
}

// Usage
const validator = new SchemaValidator("./schemas");
const result = validator.validate(message);

if (!result.valid) {
  console.error("Validation errors:", result.errors);
}
```

---

## 🔄 Schema Versioning

### Version Compatibility

The A2A protocol uses semantic versioning for schemas:

- **Major version** (1.x.x): Breaking changes
- **Minor version** (x.1.x): Backward-compatible additions
- **Patch version** (x.x.1): Bug fixes

### Schema Version Header

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://a2a-protocol.org/schemas/v1.0.0/base-message.json",
  "version": "1.0.0",
  "deprecated": false,
  "changelog": "https://a2a-protocol.org/schemas/CHANGELOG.md"
}
```

### Version Negotiation

Agents should declare supported schema versions in handshake:

```json
{
  "agent_card": {
    "supported_protocols": [
      "A2A/1.0",
      "A2A/1.1"
    ],
    "schema_versions": [
      "1.0.0",
      "1.1.0"
    ]
  }
}
```

---

## 📚 Schema Files Package

### Directory Structure

```
schemas/
├── README.md
├── CHANGELOG.md
├── package.json
├── base-message.json
├── request-message.json
├── response-message.json
├── handshake-message.json
├── error-message.json
├── discover-agents-message.json
├── agent-announcement-message.json
├── authenticated-message.json
├── python/
│   ├── __init__.py
│   ├── models.py           # Pydantic models
│   └── validator.py        # JSON Schema validator
└── typescript/
    ├── types.ts            # Type definitions
    ├── validator.ts        # AJV validator
    └── package.json
```

### NPM Package

```json
{
  "name": "@a2a-protocol/schemas",
  "version": "1.0.0",
  "description": "JSON schemas and type definitions for A2A protocol",
  "main": "typescript/types.js",
  "types": "typescript/types.d.ts",
  "files": [
    "*.json",
    "typescript/**/*",
    "python/**/*"
  ],
  "keywords": ["a2a", "agent", "schema", "validation"],
  "license": "MIT"
}
```

### PyPI Package

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="a2a-protocol-schemas",
    version="1.0.0",
    description="JSON schemas and Pydantic models for A2A protocol",
    packages=find_packages(),
    package_data={
        "a2a_schemas": ["*.json"]
    },
    install_requires=[
        "pydantic>=2.0.0",
        "jsonschema>=4.0.0"
    ],
    python_requires=">=3.10"
)
```

---

## 🎓 Best Practices

### Schema Design

1. **Use `additionalProperties: false`** - Reject unexpected fields (security)
2. **Require all critical fields** - Don't make security fields optional
3. **Use enums for fixed values** - Prevents typos and invalid values
4. **Include examples** - Helps users understand expected format
5. **Add descriptions** - Document purpose of each field
6. **Version schemas** - Track changes over time

### Validation

1. **Validate early** - Before any processing
2. **Fail fast** - Reject invalid messages immediately
3. **Provide clear errors** - Help developers fix issues
4. **Cache compiled schemas** - Improve performance
5. **Test edge cases** - Empty strings, null, max values
6. **Fuzz test** - Random inputs to find bugs

### Documentation

1. **Keep schemas and docs in sync** - Single source of truth
2. **Provide examples** - Show valid and invalid messages
3. **Document changes** - Maintain changelog
4. **Version compatibility matrix** - Which versions work together
5. **Migration guides** - How to upgrade between versions

---

## 🔗 Related Documentation

- [Protocol Messages](../04_COMMUNICATION/01_protocol_messages.md) - Message usage guide
- [Message Validation](../04_COMMUNICATION/04_message_validation_patterns.md) - Validation patterns
- [Error Handling](../04_COMMUNICATION/03_error_handling.md) - Error responses
- [Authentication Tags](../03_SECURITY/02_authentication_tags.md) - Security authentication

---

## 📦 Downloads

**Schema Package**: Download complete schema package with validators  
**Repository**: [https://github.com/a2a-protocol/schemas](https://github.com/a2a-protocol/schemas)  
**NPM**: `npm install @a2a-protocol/schemas`  
**PyPI**: `pip install a2a-protocol-schemas`

---

## 💡 Quick Reference

### Message Type Summary

| Type | Purpose | correlation_id | Response To |
|------|---------|----------------|-------------|
| `request` | Ask for action | null | None |
| `response` | Return result | required | request |
| `handshake` | Exchange capabilities | null | None |
| `handshake_ack` | Acknowledge handshake | required | handshake |
| `error` | Report error | required | Any message |
| `discover_agents` | Find agents | null | None |
| `agent_announcement` | Return agents | required | discover_agents |
| `goodbye` | Close connection | null | None |

### Validation Checklist

- [ ] Valid JSON structure
- [ ] All required fields present
- [ ] `message_id` is UUID v4
- [ ] `message_type` is known value
- [ ] `timestamp` is ISO 8601 UTC
- [ ] `timestamp` is fresh (<5 min)
- [ ] `sender_id` valid format
- [ ] `recipient_id` valid format
- [ ] `payload` structure matches type
- [ ] `correlation_id` correct (if response/error)
- [ ] No unexpected fields
- [ ] Payload under size limit (10MB)

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Schema Version**: 1.0.0  
**Status**: Complete  
**Maintainer**: A2A Protocol Working Group