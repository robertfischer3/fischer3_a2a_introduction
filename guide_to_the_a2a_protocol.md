# A Guide to the A2A Protocol

## Introduction

The Agent2Agent (A2A) Protocol is a communication framework designed to enable seamless interaction between AI agents in multi-agent systems. This guide explores the protocol's text-based nature and demonstrates its core message components.

---

## Is the A2A Protocol Text-Based?

**Yes, the A2A Protocol is fundamentally text-based.** The protocol uses JSON (JavaScript Object Notation) as its primary serialization format, making it human-readable, language-agnostic, and easy to debug.

### Why Text-Based?

The A2A protocol's text-based design offers several advantages:

- **Human-Readable**: Messages can be easily inspected and debugged without specialized tools
- **Platform-Independent**: JSON is universally supported across programming languages and platforms
- **Extensible**: New fields can be added without breaking existing implementations
- **Lightweight**: Text-based JSON is efficient for transmission over HTTP/HTTPS
- **Tool-Friendly**: Standard JSON parsers and validators work out of the box

### JSON Message Structure

All A2A messages follow a standardized JSON structure with the following core fields:

```json
{
  "message_id": "unique-identifier",
  "message_type": "request|response|handshake|etc",
  "sender_id": "agent-identifier",
  "recipient_id": "target-agent-identifier",
  "timestamp": "ISO-8601-timestamp",
  "payload": {},
  "correlation_id": "optional-tracking-id"
}
```

---

## TextPart: Simple Text-Based Messages

The **TextPart** content type represents straightforward text-based communication between agents. This is the most common message format in A2A and is used for queries, responses, and general agent-to-agent communication.

### Example 1: Simple Request (TextPart)

A client agent requests cryptocurrency price information:

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

**Key Characteristics:**
- The entire message is JSON text
- The `payload` contains structured data about the request
- Parameters are embedded as nested JSON objects

### Example 2: Text Response (TextPart)

The server agent responds with cryptocurrency price data:

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
      "timestamp": "2025-01-15T10:30:00.000Z",
      "disclaimer": "This price is fictitious for demonstration only"
    }
  },
  "correlation_id": "a7f8d9e2-3c4b-5d6e-7f8a-9b0c1d2e3f4g"
}
```

**Key Characteristics:**
- The `correlation_id` links this response to the original request
- Structured data (price, timestamp) is embedded in the JSON payload
- Status information indicates success or failure

### Example 3: Agent Card Exchange (TextPart)

During the handshake phase, agents exchange capability information:

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
        "data_type": "real-time"
      }
    }
  },
  "correlation_id": null
}
```

**Key Characteristics:**
- Agent Cards are complex nested JSON structures
- Capabilities are declared as string arrays
- Metadata provides extensible domain-specific information

---

## DataPart: Structured Data Exchange

The **DataPart** content type is used when agents need to exchange more complex, structured datasets beyond simple text responses. While still JSON-based, DataPart messages typically contain arrays, tables, or deeply nested structures.

### Example 1: List of Supported Currencies (DataPart)

```json
{
  "message_id": "d0i1g2h5-6f7e-8g9h-0i1c-2e3f4g5h6i7j",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:31:00.000Z",
  "payload": {
    "status": "success",
    "data": {
      "currencies": [
        {
          "code": "BTC",
          "name": "Bitcoin",
          "price_range": "100000-150000 USD",
          "volatility": "high"
        },
        {
          "code": "ETH",
          "name": "Ethereum",
          "price_range": "3500-4500 USD",
          "volatility": "medium"
        },
        {
          "code": "XRP",
          "name": "Ripple",
          "price_range": "2.00-3.00 USD",
          "volatility": "medium"
        }
      ],
      "total_count": 3,
      "last_updated": "2025-01-15T10:30:00.000Z"
    }
  },
  "correlation_id": "d0i1g2h5-request-id"
}
```

**Key Characteristics:**
- Contains array of structured objects
- Each object has consistent schema
- Includes metadata like counts and timestamps

### Example 2: Time-Series Data (DataPart)

An agent returning historical price data:

```json
{
  "message_id": "e1j2h3i6-7g8f-9h0i-1j2d-3f4g5h6i7j8k",
  "message_type": "response",
  "sender_id": "crypto-agent-001",
  "recipient_id": "analytics-agent-002",
  "timestamp": "2025-01-15T10:32:00.000Z",
  "payload": {
    "status": "success",
    "data": {
      "currency": "BTC",
      "time_series": [
        {"timestamp": "2025-01-15T10:00:00Z", "price": 124500.00},
        {"timestamp": "2025-01-15T10:15:00Z", "price": 124750.25},
        {"timestamp": "2025-01-15T10:30:00Z", "price": 125000.50}
      ],
      "interval": "15_minutes",
      "data_points": 3
    }
  },
  "correlation_id": "e1j2h3i6-request-id"
}
```

**Key Characteristics:**
- Optimized for bulk data transfer
- Consistent timestamp formatting (ISO-8601)
- Clear interval and count metadata

### Example 3: Multi-Agent Registry Response (DataPart)

A registry service returning available agents:

```json
{
  "message_id": "f2k3i4j7-8h9g-0i1j-2k3e-4g5h6i7j8k9l",
  "message_type": "response",
  "sender_id": "registry-service-001",
  "recipient_id": "orchestrator-agent-001",
  "timestamp": "2025-01-15T10:33:00.000Z",
  "payload": {
    "status": "success",
    "data": {
      "agents": [
        {
          "agent_id": "crypto-agent-001",
          "name": "CryptoPriceAgent",
          "status": "online",
          "capabilities": ["price_query", "no_streaming"],
          "endpoint": "http://localhost:8888",
          "last_heartbeat": "2025-01-15T10:32:45Z"
        },
        {
          "agent_id": "weather-agent-002",
          "name": "WeatherDataAgent",
          "status": "online",
          "capabilities": ["weather_forecast", "streaming"],
          "endpoint": "http://localhost:8889",
          "last_heartbeat": "2025-01-15T10:32:50Z"
        }
      ],
      "total_agents": 2,
      "query_time": "2025-01-15T10:33:00.000Z"
    }
  },
  "correlation_id": "f2k3i4j7-request-id"
}
```

**Key Characteristics:**
- Discovery and directory information
- Health status indicators
- Network endpoint information

---

## FilePart: Binary and File Content

While the A2A protocol is fundamentally text-based, real-world agent systems often need to exchange binary data such as images, documents, or media files. The **FilePart** content type addresses this requirement while maintaining compatibility with the JSON message structure.

### How FilePart Works

FilePart messages extend the base A2A message format to include file metadata and content. There are two primary approaches:

1. **Base64 Encoding** (inline): Small files embedded directly in JSON
2. **Reference-Based** (external): Large files stored separately with URL references

### Approach 1: Base64 Encoded FilePart

For small files (typically < 1MB), content can be Base64-encoded and embedded directly:

```json
{
  "message_id": "g3l4j5k8-9i0h-1j2k-3l4f-5h6i7j8k9l0m",
  "message_type": "response",
  "sender_id": "document-agent-003",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:35:00.000Z",
  "payload": {
    "status": "success",
    "file": {
      "filename": "crypto_report.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 45678,
      "encoding": "base64",
      "content": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL...[truncated]",
      "checksum": "sha256:a1b2c3d4e5f6...",
      "metadata": {
        "created_at": "2025-01-15T10:34:55Z",
        "author": "document-agent-003",
        "pages": 5
      }
    }
  },
  "correlation_id": "g3l4j5k8-request-id"
}
```

**Key Fields:**
- `filename`: Original filename for reconstruction
- `mime_type`: Standard MIME type for content identification
- `size_bytes`: Unencoded file size
- `encoding`: Always "base64" for inline content
- `content`: Base64-encoded binary data
- `checksum`: Hash for integrity verification
- `metadata`: Domain-specific file information

### Approach 2: Reference-Based FilePart

For large files (> 1MB), use external storage with URL references:

```json
{
  "message_id": "h4m5k6l9-0j1i-2k3l-4m5g-6i7j8k9l0m1n",
  "message_type": "response",
  "sender_id": "image-processing-agent-004",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:36:00.000Z",
  "payload": {
    "status": "success",
    "file": {
      "filename": "analysis_chart.png",
      "mime_type": "image/png",
      "size_bytes": 2456789,
      "encoding": "reference",
      "url": "https://storage.example.com/files/analysis_chart_20250115.png",
      "expires_at": "2025-01-16T10:36:00Z",
      "checksum": "sha256:x7y8z9a0b1c2...",
      "access_method": "GET",
      "authentication": {
        "type": "bearer_token",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      },
      "metadata": {
        "width": 1920,
        "height": 1080,
        "format": "PNG",
        "created_at": "2025-01-15T10:35:45Z"
      }
    }
  },
  "correlation_id": "h4m5k6l9-request-id"
}
```

**Additional Fields for References:**
- `url`: Direct download URL
- `expires_at`: URL expiration timestamp
- `access_method`: HTTP method (usually GET)
- `authentication`: Credentials for accessing the file

### Multi-File FilePart

When multiple files need to be transferred:

```json
{
  "message_id": "i5n6l7m0-1k2j-3l4m-5n6h-7j8k9l0m1n2o",
  "message_type": "response",
  "sender_id": "report-generator-005",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:37:00.000Z",
  "payload": {
    "status": "success",
    "files": [
      {
        "filename": "summary.pdf",
        "mime_type": "application/pdf",
        "size_bytes": 125000,
        "encoding": "reference",
        "url": "https://storage.example.com/files/summary_20250115.pdf",
        "file_type": "report",
        "checksum": "sha256:abc123..."
      },
      {
        "filename": "data.csv",
        "mime_type": "text/csv",
        "size_bytes": 45000,
        "encoding": "base64",
        "content": "Q3VycmVuY3ksUHJpY2UKQlRDLDEyNTAwMC41...",
        "file_type": "data",
        "checksum": "sha256:def456..."
      },
      {
        "filename": "chart.png",
        "mime_type": "image/png",
        "size_bytes": 890000,
        "encoding": "reference",
        "url": "https://storage.example.com/files/chart_20250115.png",
        "file_type": "visualization",
        "checksum": "sha256:ghi789..."
      }
    ],
    "total_files": 3,
    "total_size_bytes": 1060000
  },
  "correlation_id": "i5n6l7m0-request-id"
}
```

### FilePart Best Practices

**When to Use Base64 Encoding:**
- Files smaller than 100KB
- Quick transfers where latency matters
- Systems without external storage infrastructure
- Embedded thumbnails or icons

**When to Use Reference-Based:**
- Files larger than 1MB
- Shared files accessed by multiple agents
- Bandwidth-constrained environments
- Long-term file storage requirements

**Security Considerations:**
- Always include checksums for integrity verification
- Use time-limited URLs with expiration timestamps
- Implement authentication for sensitive files
- Validate MIME types on the receiving end
- Scan files for malware before processing

**Performance Tips:**
- Compress large files before Base64 encoding
- Use streaming for very large files
- Cache frequently accessed files
- Consider chunked transfer for files > 10MB
- Monitor and limit total payload sizes

### Error Handling for FilePart

```json
{
  "message_id": "j6o7m8n1-2l3k-4m5n-6o7i-8k9l0m1n2o3p",
  "message_type": "error",
  "sender_id": "document-agent-003",
  "recipient_id": "client-agent-001",
  "timestamp": "2025-01-15T10:38:00.000Z",
  "payload": {
    "status": "error",
    "error": {
      "code": "FILE_TOO_LARGE",
      "message": "File size exceeds maximum allowed size of 10MB",
      "details": {
        "requested_size": 15728640,
        "max_allowed_size": 10485760,
        "filename": "large_dataset.csv"
      }
    }
  },
  "correlation_id": "j6o7m8n1-request-id"
}
```

---

## Conclusion

The A2A Protocol's text-based JSON foundation provides a flexible, extensible framework for agent communication:

- **TextPart** handles simple queries and responses
- **DataPart** manages structured datasets and bulk information
- **FilePart** extends the protocol to support binary content through Base64 encoding or URL references

This layered approach maintains human readability for debugging while supporting the complex data exchange requirements of modern multi-agent systems. The protocol's design ensures that agents can communicate effectively whether exchanging simple text messages, complex data structures, or binary files—all while maintaining a consistent, standards-based message format.

---

## Additional Resources

- [Agent2Agent Introduction](./agent2agent_intro.md)
- [A2A and MCP Integration](./a2a_mcp_integration.md)
- [A2A Streaming Events Guide](./a2a_streaming_events_guide.md)
- [Implementation Patterns](./implementation_patterns.md)

---

*Document Version: 1.0*  
*Last Updated: January 2025*  
*Author: Based on A2A Protocol Documentation*
