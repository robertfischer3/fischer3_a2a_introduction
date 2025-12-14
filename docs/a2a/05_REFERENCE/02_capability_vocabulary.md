# Capability Vocabulary Reference

> **Learning Path**: Reference  
> **Difficulty**: Beginner to Intermediate  
> **Prerequisites**: [Agent Cards](../02_DISCOVERY/01_agent_cards.md), [Core Concepts](../01_FUNDAMENTALS/01_core_concepts.md)  
> **Completion Time**: 30-45 minutes

## Navigation
← Previous: [Message Schemas](./01_message_schemas.md) | Next: [Protocol Versions](./protocol_versions.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

This reference document provides the standard vocabulary for declaring agent capabilities:

- [ ] Standard capability names and conventions
- [ ] Capability categories and hierarchies
- [ ] Naming patterns and best practices
- [ ] How to create custom capabilities
- [ ] Capability negotiation patterns
- [ ] Security implications of capabilities
- [ ] Real examples from the project

---

## 📚 Overview

**Capabilities** are standardized tags that agents declare in their Agent Cards to advertise what they can do. Think of them as:
- **Skills** on a resume
- **Features** in a product specification
- **Methods** in an API contract

Well-defined capabilities enable:
- ✅ **Discovery** - Find agents that can perform specific tasks
- ✅ **Negotiation** - Adapt behavior based on available features
- ✅ **Compatibility** - Ensure agents can work together
- ✅ **Authorization** - Control access to sensitive operations

---

## 🎨 Naming Conventions

### Standard Format

Capabilities follow **snake_case** naming with the pattern:

```
[category]_[action]_[modifier]
```

**Examples**:
- `price_query` - Query prices (category: price, action: query)
- `data_stream` - Stream data (category: data, action: stream)
- `file_upload_async` - Asynchronous file upload (category: file, action: upload, modifier: async)

### Naming Rules

**✅ DO**:
- Use **lowercase** letters
- Separate words with **underscores** (`_`)
- Start with **noun** (what) then **verb** (how)
- Keep names **concise** (2-4 words maximum)
- Use **standard English** terms
- Be **specific** and **descriptive**

**❌ DON'T**:
- Use camelCase or PascalCase
- Use hyphens or spaces
- Use abbreviations unless universally known
- Use version numbers in capability names
- Mix languages
- Use overly generic names like `do_thing`

### Good vs Bad Examples

| ❌ Bad | ✅ Good | Why Better |
|--------|---------|------------|
| `GetPrice` | `price_query` | snake_case, noun-first |
| `stream-data` | `data_stream` | underscore separator |
| `async-upload` | `file_upload_async` | noun-first, modifier last |
| `AI` | `ai_completion` | specific, not abbreviation-only |
| `doPriceQuery` | `price_query` | snake_case, concise |
| `get` | `data_read` | specific, not too generic |

---

## 📦 Standard Capability Categories

### 1. Data Access Capabilities

**Purpose**: Reading and querying data

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `data_read` | Read data from storage | Retrieve records |
| `data_query` | Query with filters/search | Search database |
| `data_list` | List available items | Get all currencies |
| `data_summary` | Get aggregated summary | Total count, averages |
| `data_export` | Export data in formats | CSV, JSON export |

**Real Examples**:
```json
{
  "capabilities": [
    "price_query",           // Crypto: Query cryptocurrency prices
    "currency_list",         // Crypto: List supported currencies
    "report_summary"         // Credit: Get credit report summary
  ]
}
```

### 2. Data Modification Capabilities

**Purpose**: Creating, updating, deleting data

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `data_create` | Create new records | Add new entry |
| `data_update` | Modify existing records | Update price |
| `data_delete` | Remove records | Delete outdated data |
| `data_import` | Import bulk data | Bulk upload |
| `data_sync` | Synchronize data sources | Sync databases |

**Real Examples**:
```json
{
  "capabilities": [
    "project_create",        // Task Collab: Create new project
    "task_update",           // Task Collab: Update task status
    "report_upload"          // Credit: Upload credit report
  ]
}
```

### 3. Communication Capabilities

**Purpose**: How agents exchange messages

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `request_response` | Synchronous request/response | Query-answer pattern |
| `async_response` | Asynchronous responses | Long-running tasks |
| `streaming` | Real-time data stream | Price updates |
| `batch_processing` | Process multiple requests | Bulk operations |
| `event_subscription` | Subscribe to events | Notification system |

**Real Examples**:
```json
{
  "capabilities": [
    "streaming",             // Crypto: Real-time price streaming
    "no_streaming",          // Crypto: Only request/response
    "batch_processing",      // Credit: Process multiple reports
    "async_task"            // Task Collab: Async task execution
  ]
}
```

### 4. File Handling Capabilities

**Purpose**: Working with files and documents

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `file_upload` | Accept file uploads | Receive documents |
| `file_download` | Provide file downloads | Send reports |
| `file_process` | Process/analyze files | Extract text, parse |
| `format_json` | JSON format support | JSON parsing |
| `format_csv` | CSV format support | Spreadsheet data |
| `format_pdf` | PDF format support | Document processing |

**Real Examples**:
```json
{
  "capabilities": [
    "file_upload",           // Credit: Upload credit reports
    "format_json",           // All: JSON message support
    "format_csv",            // Credit: CSV data import
    "pdf_extract"            // Credit: Extract text from PDFs
  ]
}
```

### 5. Processing Capabilities

**Purpose**: Computation and analysis

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `compute_aggregate` | Aggregate calculations | Sum, average, count |
| `compute_transform` | Data transformation | Format conversion |
| `ai_completion` | LLM text generation | Generate content |
| `ai_classification` | Classify/categorize | Sentiment analysis |
| `ai_extraction` | Extract information | Named entity recognition |
| `validation` | Validate data | Schema checking |

**Real Examples**:
```json
{
  "capabilities": [
    "ai_analysis",           // Credit: AI-powered credit analysis
    "risk_calculation",      // Credit: Calculate credit risk
    "task_breakdown"         // Task Collab: Break projects into tasks
  ]
}
```

### 6. Security & Authentication Capabilities

**Purpose**: Security features supported

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `auth_signature` | RSA/ECC signature auth | Cryptographic signing |
| `auth_token` | Token-based auth | Bearer tokens |
| `auth_certificate` | Certificate-based auth | PKI authentication |
| `encryption_tls` | TLS encryption | HTTPS communication |
| `encryption_e2e` | End-to-end encryption | Encrypted payloads |
| `rate_limit` | Rate limiting support | DoS prevention |

**Real Examples**:
```json
{
  "capabilities": [
    "auth_signature",        // All secure stages: RSA signatures
    "encryption_tls",        // All: HTTPS required
    "rate_limit"             // Stage 3: Token bucket limiting
  ]
}
```

### 7. Management & Control Capabilities

**Purpose**: Administrative and operational features

| Capability | Description | Example Use |
|------------|-------------|-------------|
| `health_check` | Health monitoring | Status endpoint |
| `metrics_export` | Export metrics | Prometheus metrics |
| `config_update` | Update configuration | Runtime config |
| `admin_control` | Administrative access | System management |
| `audit_log` | Audit logging | Security logging |

**Real Examples**:
```json
{
  "capabilities": [
    "health_check",          // All: /health endpoint
    "metrics_export",        // Stage 3: Prometheus integration
    "audit_log"              // Stage 3: Structured logging
  ]
}
```

---

## 🏗️ Capability Hierarchies

### Hierarchical Structure

Capabilities can be organized in hierarchies for better organization:

```
data                        # Top-level category
├── data_read              # General read capability
│   ├── data_query         # Specific: query with filters
│   └── data_list          # Specific: list all items
├── data_write             # General write capability
│   ├── data_create        # Specific: create new
│   ├── data_update        # Specific: modify existing
│   └── data_delete        # Specific: remove
└── data_stream            # Real-time data
```

### Inheritance Pattern

When declaring capabilities, **be specific**. Don't rely on implied inheritance:

**❌ Wrong Assumption**:
```json
{
  "capabilities": ["data"]  // Too generic, what can it do?
}
```

**✅ Correct Declaration**:
```json
{
  "capabilities": [
    "data_read",
    "data_query",
    "data_list"
    // Explicitly declare what you support
  ]
}
```

### Capability Dependencies

Some capabilities require others:

```json
{
  "capabilities": [
    "streaming",           // Requires: request_response
    "ai_completion",       // Requires: data_read (for context)
    "file_upload"          // Requires: validation
  ],
  "metadata": {
    "capability_dependencies": {
      "streaming": ["request_response"],
      "ai_completion": ["data_read"]
    }
  }
}
```

---

## 🎭 Capability Modifiers

### Common Modifiers

Add modifiers to the end of capability names to indicate variations:

| Modifier | Meaning | Example |
|----------|---------|---------|
| `_async` | Asynchronous operation | `file_upload_async` |
| `_batch` | Batch processing | `data_create_batch` |
| `_stream` | Streaming mode | `price_query_stream` |
| `_secure` | Enhanced security | `data_transfer_secure` |
| `_readonly` | Read-only access | `admin_view_readonly` |

**Examples**:
```json
{
  "capabilities": [
    "file_upload",           // Synchronous file upload
    "file_upload_async",     // Asynchronous file upload
    "file_upload_batch",     // Bulk file upload
    "data_export",           // Export data
    "data_export_stream"     // Stream export for large datasets
  ]
}
```

---

## 🆕 Creating Custom Capabilities

### When to Create Custom Capabilities

Create custom capabilities when:
- ✅ No standard capability fits your use case
- ✅ You need domain-specific functionality
- ✅ You want to extend the protocol
- ✅ You're creating a new agent type

**Don't create custom capabilities when**:
- ❌ A standard capability already exists
- ❌ You can combine existing capabilities
- ❌ The operation is too granular (combine related operations)

### Custom Capability Guidelines

**1. Use Domain Prefixes**

Prefix custom capabilities with your domain:

```json
{
  "capabilities": [
    "crypto_arbitrage",        // Custom: crypto trading
    "medical_diagnosis",       // Custom: healthcare
    "iot_device_control"       // Custom: IoT
  ]
}
```

**2. Follow Naming Conventions**

```json
{
  "capabilities": [
    // ✅ Good: Follows snake_case, descriptive
    "blockchain_verify",
    "trading_algorithm_backtest",
    "sensor_data_aggregate",
    
    // ❌ Bad: Wrong format, unclear
    "BlockchainVerify",
    "verify",
    "my-capability"
  ]
}
```

**3. Document Custom Capabilities**

Always document in metadata:

```json
{
  "agent_id": "trading-bot-001",
  "capabilities": [
    "crypto_arbitrage",
    "risk_assessment"
  ],
  "metadata": {
    "capability_docs": {
      "crypto_arbitrage": {
        "description": "Detect arbitrage opportunities across exchanges",
        "parameters": ["exchanges", "currencies", "threshold"],
        "requires": ["market_data", "execution_api"]
      },
      "risk_assessment": {
        "description": "Calculate risk metrics for trading strategies",
        "parameters": ["strategy", "timeframe"],
        "output": "risk_score (0-100)"
      }
    }
  }
}
```

---

## 🔍 Capability Negotiation Patterns

### Pattern 1: Graceful Degradation

Adapt based on available capabilities:

```python
def request_price_data(agent_card):
    """Request price data with graceful degradation"""
    
    # Prefer streaming if available
    if "streaming" in agent_card["capabilities"]:
        return request_streaming_prices(agent_card)
    
    # Fall back to request/response
    elif "price_query" in agent_card["capabilities"]:
        return request_single_price(agent_card)
    
    # No compatible capability
    else:
        raise IncompatibleAgentError("No price data capability")
```

### Pattern 2: Capability Requirements

Declare required vs optional capabilities:

```python
REQUIRED_CAPABILITIES = [
    "data_read",              # Must have
    "auth_signature"          # Must have
]

OPTIONAL_CAPABILITIES = [
    "streaming",              # Nice to have
    "batch_processing"        # Nice to have
]

def is_compatible(agent_card):
    """Check if agent meets requirements"""
    capabilities = set(agent_card["capabilities"])
    
    # All required must be present
    has_required = all(
        cap in capabilities 
        for cap in REQUIRED_CAPABILITIES
    )
    
    # At least one optional is preferred
    has_optional = any(
        cap in capabilities 
        for cap in OPTIONAL_CAPABILITIES
    )
    
    return has_required, has_optional
```

### Pattern 3: Capability Discovery

Query registry for specific capabilities:

```python
def find_agents_with_capabilities(
    required: list[str], 
    optional: list[str] = None
):
    """Find agents matching capability requirements"""
    
    # Discover all agents
    all_agents = registry.discover_agents()
    
    # Filter by required capabilities
    compatible = []
    for agent in all_agents:
        caps = set(agent["capabilities"])
        
        # Must have all required
        if not all(req in caps for req in required):
            continue
        
        # Score by optional capabilities
        score = sum(1 for opt in (optional or []) if opt in caps)
        
        compatible.append((agent, score))
    
    # Return sorted by score (most optional capabilities first)
    return [agent for agent, _ in sorted(compatible, key=lambda x: -x[1])]

# Usage
agents = find_agents_with_capabilities(
    required=["price_query", "auth_signature"],
    optional=["streaming", "batch_processing"]
)
```

---

## 🔒 Security Implications of Capabilities

### Security-Sensitive Capabilities

Some capabilities have security implications and should be carefully controlled:

**High Risk** 🔴:
```json
{
  "capabilities": [
    "admin_control",         // Full system access
    "data_delete",           // Can remove data
    "config_update",         // Can change settings
    "user_impersonate"       // Can act as other users
  ]
}
```

**Medium Risk** 🟡:
```json
{
  "capabilities": [
    "data_write",            // Can modify data
    "file_upload",           // Can upload files (potential malware)
    "ai_completion"          // Can generate content (prompt injection)
  ]
}
```

**Low Risk** 🟢:
```json
{
  "capabilities": [
    "data_read",             // Read-only access
    "health_check",          // Status information
    "metrics_export"         // Performance data
  ]
}
```

### Least Privilege Principle

**✅ Good**: Minimal necessary capabilities
```json
{
  "agent_id": "price-viewer",
  "capabilities": [
    "price_query",           // Only needs to query
    "data_read"              // Read-only
  ]
}
```

**❌ Bad**: Excessive capabilities
```json
{
  "agent_id": "price-viewer",
  "capabilities": [
    "price_query",
    "data_read",
    "data_write",            // Doesn't need write
    "data_delete",           // Doesn't need delete
    "admin_control"          // Definitely doesn't need admin!
  ]
}
```

### Capability-Based Authorization

Map capabilities to permissions:

```python
CAPABILITY_PERMISSIONS = {
    "price_query": {
        "methods": ["get_price", "get_supported_currencies"],
        "rate_limit": "100/minute",
        "requires_auth": True
    },
    "data_write": {
        "methods": ["create", "update"],
        "rate_limit": "10/minute",
        "requires_auth": True,
        "requires_role": "editor"
    },
    "admin_control": {
        "methods": ["*"],
        "rate_limit": "1000/minute",
        "requires_auth": True,
        "requires_role": "admin"
    }
}

def authorize_request(agent_card, method):
    """Check if agent is authorized based on capabilities"""
    
    # Find capability that grants access to method
    for capability in agent_card["capabilities"]:
        perms = CAPABILITY_PERMISSIONS.get(capability)
        if not perms:
            continue
        
        # Check if method is allowed
        if method in perms["methods"] or "*" in perms["methods"]:
            # Check additional requirements (role, auth, etc.)
            if check_requirements(agent_card, perms):
                return True
    
    return False
```

---

## 📊 Real Examples from Project

### Crypto Price Agent (Basic)

**Stage 1** (Vulnerable):
```json
{
  "agent_id": "crypto-agent-001",
  "name": "CryptoPriceAgent",
  "capabilities": [
    "price_query",           // Can query cryptocurrency prices
    "currency_list",         // Can list supported currencies
    "no_streaming"           // Does NOT support streaming
  ]
}
```

### Crypto Price Agent (Secure)

**Stage 3** (Production):
```json
{
  "agent_id": "crypto-agent-001",
  "name": "CryptoPriceAgent",
  "capabilities": [
    "price_query",           // Query prices
    "currency_list",         // List currencies
    "no_streaming",          // No streaming support
    "auth_signature",        // RSA signature auth
    "rate_limit",            // Token bucket rate limiting
    "health_check",          // /health endpoint
    "metrics_export"         // Prometheus metrics
  ],
  "metadata": {
    "rate_limits": {
      "price_query": "100/minute",
      "currency_list": "10/minute"
    },
    "authentication": {
      "required": true,
      "methods": ["rsa_signature"]
    }
  }
}
```

### Credit Report Agent

**Stage 3** (Production):
```json
{
  "agent_id": "credit-report-001",
  "name": "CreditReportAgent",
  "capabilities": [
    "report_upload",         // Upload credit reports
    "report_query",          // Query reports
    "report_summary",        // Get summary data
    "file_upload",           // File upload support
    "format_json",           // JSON format
    "format_csv",            // CSV format
    "validation",            // 8-layer validation
    "auth_signature",        // RSA authentication
    "encryption_tls",        // TLS encryption
    "rate_limit",            // Rate limiting
    "audit_log"              // Audit logging
  ],
  "metadata": {
    "max_file_size": "5MB",
    "supported_formats": ["json", "csv"],
    "validation_layers": 8,
    "pii_handling": "sanitized",
    "rate_limits": {
      "report_upload": "10/minute",
      "report_query": "100/minute"
    }
  }
}
```

### Task Collaboration Agent

**Stage 3** (Production):
```json
{
  "agent_id": "task-collab-001",
  "name": "TaskCollaborationAgent",
  "capabilities": [
    "project_create",        // Create projects
    "project_update",        // Update projects
    "task_create",           // Create tasks
    "task_update",           // Update tasks
    "task_assign",           // Assign tasks to workers
    "ai_completion",         // AI task breakdown
    "async_task",            // Asynchronous task processing
    "auth_signature",        // RSA authentication
    "session_management",    // Session tracking
    "rate_limit",            // Rate limiting
    "audit_log"              // Audit logging
  ],
  "metadata": {
    "ai_provider": "gemini",
    "session_timeout": "30 minutes",
    "max_concurrent_sessions": 100,
    "role_based_access": true,
    "rate_limits": {
      "project_create": "10/minute",
      "task_create": "50/minute",
      "ai_completion": "20/minute"
    }
  }
}
```

---

## 📋 Capability Declaration Checklist

### For Agent Developers

When declaring capabilities, ensure:

- [ ] **All capabilities follow naming conventions** (snake_case, noun_verb pattern)
- [ ] **Capabilities are specific, not generic** ("price_query" not "query")
- [ ] **Security capabilities included** (auth_signature, rate_limit, etc.)
- [ ] **Communication pattern declared** (streaming, async_response, etc.)
- [ ] **File formats specified** (format_json, format_csv, etc.)
- [ ] **No unnecessary capabilities** (principle of least privilege)
- [ ] **Custom capabilities documented** (in metadata)
- [ ] **Dependencies noted** (if capabilities require others)
- [ ] **Capability limits specified** (in metadata: rate limits, sizes)
- [ ] **Tested for capability negotiation** (graceful degradation works)

### For Agent Consumers

When discovering agents, check:

- [ ] **Required capabilities present** (agent can do what you need)
- [ ] **Security capabilities adequate** (auth, encryption, rate limiting)
- [ ] **Communication pattern compatible** (streaming vs request/response)
- [ ] **Performance characteristics acceptable** (check metadata for limits)
- [ ] **Fallback agents identified** (if primary lacks optional capabilities)
- [ ] **Authorization requirements understood** (what capabilities grant what access)

---

## 🎓 Best Practices

### DO ✅

1. **Be Specific**: Use precise capability names
   ```json
   {"capabilities": ["price_query", "currency_list"]}
   ```

2. **Document Limits**: Use metadata for constraints
   ```json
   {
     "capabilities": ["file_upload"],
     "metadata": {"max_file_size": "5MB"}
   }
   ```

3. **Follow Conventions**: Use standard names when available
   ```json
   {"capabilities": ["data_read", "data_write"]}  // Not "read", "write"
   ```

4. **Declare Security**: Include authentication and encryption
   ```json
   {"capabilities": ["auth_signature", "encryption_tls"]}
   ```

5. **Version Separately**: Don't put versions in capability names
   ```json
   // Use version field, not capability name
   "version": "2.0.0",
   "capabilities": ["price_query"]  // Not "price_query_v2"
   ```

### DON'T ❌

1. **Don't Be Vague**: Avoid generic capability names
   ```json
   {"capabilities": ["query"]}  // Too generic!
   ```

2. **Don't Overclaim**: Only declare what you actually support
   ```json
   // Bad: Claims admin but doesn't implement
   {"capabilities": ["admin_control"]}
   ```

3. **Don't Use Abbreviations**: Use full words
   ```json
   {"capabilities": ["price_query"]}  // Not "pq" or "priceQry"
   ```

4. **Don't Mix Formats**: Stick to snake_case
   ```json
   {"capabilities": ["price_query"]}  // Not "priceQuery" or "price-query"
   ```

5. **Don't Duplicate**: One capability per unique function
   ```json
   // Bad: Redundant capabilities
   {"capabilities": ["get_price", "query_price", "price_query"]}
   // Good: Single clear capability
   {"capabilities": ["price_query"]}
   ```

---

## 🔗 Related Documentation

- [Agent Cards](../02_DISCOVERY/01_agent_cards.md) - How capabilities are declared
- [Capability Matching](../02_DISCOVERY/03_capability_matching.md) - How agents discover compatible partners
- [Message Schemas](./01_message_schemas.md) - Message structure including agent cards
- [Security Best Practices](../03_SECURITY/04_security_best_practices.md) - Security implications

---

## 📦 Standard Capabilities Reference

### Complete Alphabetical List

```
admin_control
ai_classification
ai_completion
ai_extraction
async_response
audit_log
auth_certificate
auth_signature
auth_token
batch_processing
compute_aggregate
compute_transform
config_update
currency_list
data_create
data_delete
data_export
data_import
data_list
data_query
data_read
data_stream
data_summary
data_sync
data_update
data_write
encryption_e2e
encryption_tls
event_subscription
file_download
file_process
file_upload
format_csv
format_json
format_pdf
health_check
metrics_export
no_streaming
price_query
rate_limit
report_query
report_summary
report_upload
request_response
streaming
task_assign
task_create
task_update
validation
```

---

## 💡 Quick Reference

### Capability Naming Template

```
[domain]_[operation]_[modifier?]

Examples:
price_query           # domain: price, operation: query
data_write_batch      # domain: data, operation: write, modifier: batch
file_upload_async     # domain: file, operation: upload, modifier: async
```

### Security Capability Matrix

| Capability | Required For | Risk Level |
|------------|--------------|------------|
| `auth_signature` | All production agents | Critical |
| `encryption_tls` | All communication | Critical |
| `rate_limit` | Public-facing agents | High |
| `audit_log` | Sensitive operations | High |
| `data_write` | Modifications | Medium |
| `file_upload` | File handling | Medium |
| `data_read` | Queries | Low |
| `health_check` | Monitoring | Low |

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Complete  
**Maintainer**: A2A Protocol Working Group