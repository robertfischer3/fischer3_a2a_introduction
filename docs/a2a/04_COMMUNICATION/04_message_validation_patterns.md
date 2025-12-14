# Message Validation Patterns in A2A Protocol

> **Learning Path**: Communication  
> **Difficulty**: Intermediate  
> **Prerequisites**: [Protocol Messages](./01_protocol_messages.md), [Core Concepts](../01_FUNDAMENTALS/01_core_concepts.md)  
> **Completion Time**: 60-90 minutes

## Navigation
← Previous: [Error Handling](./03_error_handling.md) | Next: [Message Schemas](../05_REFERENCE/message_schemas.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

This document covers comprehensive validation patterns for A2A messages:

- [ ] Defense-in-depth validation strategy (8 layers)
- [ ] Schema validation techniques
- [ ] Input sanitization patterns
- [ ] Type and range validation
- [ ] Business logic validation
- [ ] Security-focused validation
- [ ] Common validation anti-patterns
- [ ] Testing validation logic

---

## 📚 Overview

**Input validation** is your first line of defense against attacks. In A2A systems, every message from external agents must be validated before processing. Poor validation leads to:

- ❌ **Injection attacks** - SQL, command, code execution
- ❌ **Buffer overflows** - Crashes and memory corruption
- ❌ **DOS attacks** - Resource exhaustion
- ❌ **Data corruption** - Invalid state in your system
- ❌ **Business logic bypasses** - Unauthorized operations

**The Golden Rule**: **Never trust external input. Ever.**

---

## 🏗️ Defense-in-Depth Validation Strategy

### The 8-Layer Validation Model

Production A2A implementations should validate messages through **multiple independent layers**. Each layer catches different classes of issues:

![Alt text](/docs/images/diagrams/eight_layer_validation_model.png "Optional title")

**Why 8 layers?** Each layer is simple and focused. If one layer has a bug, others still protect you. This is **defense-in-depth**.

---

## 1️⃣ Layer 1: Size Validation

**Purpose**: Prevent resource exhaustion attacks before parsing

### Why This Matters

Without size limits, attackers can:
- Send gigabyte-sized messages to crash your server
- Exhaust memory by uploading huge files
- Cause disk exhaustion with unlimited storage

### Implementation Pattern

```python
class SizeValidator:
    """
    Layer 1: Size validation
    
    Validates BEFORE any parsing or processing
    """
    
    # Configuration
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_PAYLOAD_SIZE = 5 * 1024 * 1024   # 5MB
    MAX_FILE_SIZE = 10 * 1024 * 1024     # 10MB per file
    MAX_STRING_LENGTH = 10000            # 10K chars
    
    @staticmethod
    def validate_message_size(raw_message: bytes) -> None:
        """Validate total message size"""
        if len(raw_message) > SizeValidator.MAX_MESSAGE_SIZE:
            raise ValidationError(
                f"Message too large: {len(raw_message)} bytes "
                f"(max: {SizeValidator.MAX_MESSAGE_SIZE})"
            )
        
        if len(raw_message) == 0:
            raise ValidationError("Empty message not allowed")
    
    @staticmethod
    def validate_payload_size(payload: dict) -> None:
        """Validate payload size after parsing"""
        # Serialize to measure actual size
        payload_json = json.dumps(payload)
        payload_size = len(payload_json.encode('utf-8'))
        
        if payload_size > SizeValidator.MAX_PAYLOAD_SIZE:
            raise ValidationError(
                f"Payload too large: {payload_size} bytes "
                f"(max: {SizeValidator.MAX_PAYLOAD_SIZE})"
            )
    
    @staticmethod
    def validate_string_length(value: str, field_name: str) -> None:
        """Validate individual string lengths"""
        if len(value) > SizeValidator.MAX_STRING_LENGTH:
            raise ValidationError(
                f"{field_name} too long: {len(value)} chars "
                f"(max: {SizeValidator.MAX_STRING_LENGTH})"
            )
    
    @staticmethod
    def validate_array_size(arr: list, field_name: str, max_items: int) -> None:
        """Validate array lengths"""
        if len(arr) > max_items:
            raise ValidationError(
                f"{field_name} has too many items: {len(arr)} "
                f"(max: {max_items})"
            )

# Usage
try:
    SizeValidator.validate_message_size(raw_message)
    # Proceed to parse
except ValidationError as e:
    return error_response("PAYLOAD_TOO_LARGE", str(e))
```

### Real Example: Credit Report Agent (Stage 3)

```python
# From: a2a_examples/a2a_credit_report_example/secure/security/validation.py

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def validate_file(file_data: bytes, filename: str):
    # Layer 1: Size validation (FIRST!)
    if len(file_data) > MAX_FILE_SIZE:
        raise ValidationError(f"File too large: {len(file_data)} bytes")
    
    if len(file_data) == 0:
        raise ValidationError("File is empty")
    
    # Continue to other layers...
```

---

## 2️⃣ Layer 2: Format Validation

**Purpose**: Ensure message structure is valid before detailed parsing

### Why This Matters

Malformed messages can cause:
- Parser crashes
- Unexpected behavior
- Security vulnerabilities in parsers

### Implementation Pattern

```python
import json
import re
from datetime import datetime

class FormatValidator:
    """
    Layer 2: Format validation
    
    Validates structure and format before detailed checks
    """
    
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    
    ISO8601_PATTERN = re.compile(
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$'
    )
    
    @staticmethod
    def validate_json_structure(raw_message: bytes) -> dict:
        """Validate message is valid JSON"""
        try:
            message = json.loads(raw_message.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {str(e)}")
        except UnicodeDecodeError:
            raise ValidationError("Invalid UTF-8 encoding")
        
        if not isinstance(message, dict):
            raise ValidationError("Message must be a JSON object")
        
        return message
    
    @staticmethod
    def validate_uuid_format(value: str, field_name: str) -> None:
        """Validate UUID v4 format"""
        if not FormatValidator.UUID_PATTERN.match(value):
            raise ValidationError(
                f"{field_name} is not a valid UUID v4: {value}"
            )
    
    @staticmethod
    def validate_timestamp_format(value: str, field_name: str) -> datetime:
        """Validate ISO 8601 timestamp format"""
        if not FormatValidator.ISO8601_PATTERN.match(value):
            raise ValidationError(
                f"{field_name} is not valid ISO 8601 format: {value}"
            )
        
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as e:
            raise ValidationError(
                f"{field_name} has invalid date: {str(e)}"
            )
    
    @staticmethod
    def validate_agent_id_format(agent_id: str) -> None:
        """Validate agent_id format"""
        # Agent IDs should be alphanumeric with hyphens
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$', agent_id):
            raise ValidationError(f"Invalid agent_id format: {agent_id}")
        
        if len(agent_id) < 3 or len(agent_id) > 128:
            raise ValidationError(
                f"agent_id length must be 3-128 chars: {len(agent_id)}"
            )

# Usage
raw_message = receive_message()

# Layer 1: Size
SizeValidator.validate_message_size(raw_message)

# Layer 2: Format
message = FormatValidator.validate_json_structure(raw_message)
FormatValidator.validate_uuid_format(message['message_id'], 'message_id')
FormatValidator.validate_timestamp_format(message['timestamp'], 'timestamp')
```

---

## 3️⃣ Layer 3: Schema Validation

**Purpose**: Enforce message contract - all required fields present with correct structure

### Why This Matters

Schema validation ensures:
- ✅ All required fields are present
- ✅ No unexpected fields (prevents attacks via extra fields)
- ✅ Correct nesting and structure
- ✅ Consistent interface across agents

### Implementation Pattern A: Manual Validation

```python
class SchemaValidator:
    """
    Layer 3: Schema validation
    
    Validates message against A2A protocol schema
    """
    
    # Required fields for each message type
    BASE_REQUIRED_FIELDS = {
        'message_id', 'message_type', 'sender_id', 
        'recipient_id', 'timestamp', 'payload'
    }
    
    MESSAGE_TYPE_SCHEMAS = {
        'request': {
            'required': ['method', 'parameters'],
            'optional': []
        },
        'response': {
            'required': ['status'],
            'optional': ['data', 'error']
        },
        'handshake': {
            'required': ['agent_card'],
            'optional': []
        },
        'error': {
            'required': ['error'],
            'optional': []
        }
    }
    
    @staticmethod
    def validate_base_schema(message: dict) -> None:
        """Validate base message schema"""
        # Check all required fields present
        missing = SchemaValidator.BASE_REQUIRED_FIELDS - set(message.keys())
        if missing:
            raise ValidationError(
                f"Missing required fields: {', '.join(missing)}"
            )
        
        # Check no unexpected fields (security!)
        allowed = SchemaValidator.BASE_REQUIRED_FIELDS | {'correlation_id', 'auth'}
        unexpected = set(message.keys()) - allowed
        if unexpected:
            raise ValidationError(
                f"Unexpected fields: {', '.join(unexpected)}"
            )
    
    @staticmethod
    def validate_payload_schema(message_type: str, payload: dict) -> None:
        """Validate payload schema based on message type"""
        schema = SchemaValidator.MESSAGE_TYPE_SCHEMAS.get(message_type)
        if not schema:
            raise ValidationError(f"Unknown message_type: {message_type}")
        
        # Check required payload fields
        missing = set(schema['required']) - set(payload.keys())
        if missing:
            raise ValidationError(
                f"Missing required payload fields for {message_type}: "
                f"{', '.join(missing)}"
            )

# Usage
SchemaValidator.validate_base_schema(message)
SchemaValidator.validate_payload_schema(
    message['message_type'], 
    message['payload']
)
```

### Implementation Pattern B: JSON Schema (Recommended)

```python
from jsonschema import validate, ValidationError as JSONSchemaError

# Define complete schema
REQUEST_SCHEMA = {
    "type": "object",
    "required": ["message_id", "message_type", "sender_id", "recipient_id", "timestamp", "payload"],
    "properties": {
        "message_id": {
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        },
        "message_type": {
            "type": "string",
            "enum": ["request", "response", "handshake", "error"]
        },
        "sender_id": {
            "type": "string",
            "minLength": 3,
            "maxLength": 128,
            "pattern": "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"
        },
        "recipient_id": {
            "type": "string",
            "minLength": 3,
            "maxLength": 128
        },
        "timestamp": {
            "type": "string",
            "format": "date-time"
        },
        "payload": {
            "type": "object"
        },
        "correlation_id": {
            "type": ["string", "null"],
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        }
    },
    "additionalProperties": False  # CRITICAL: Reject unknown fields
}

def validate_with_json_schema(message: dict) -> None:
    """Validate using JSON Schema"""
    try:
        validate(instance=message, schema=REQUEST_SCHEMA)
    except JSONSchemaError as e:
        raise ValidationError(f"Schema validation failed: {e.message}")
```

### Real Example: Credit Report Agent (Stage 3)

```python
# From: a2a_examples/a2a_credit_report_example/secure/security/validation.py

def _validate_structure(report: dict):
    """Layer 7: Validate report has required structure"""
    
    # Required top-level fields
    required_fields = ["report_id", "subject", "credit_score"]
    for field in required_fields:
        if field not in report:
            raise ValidationError(f"Missing required field: {field}")
    
    # Validate report_id format
    report_id = report["report_id"]
    if not re.match(r'^CR-\d{4}-\d+$', report_id):
        raise ValidationError("report_id must match format: CR-YYYY-NNN")
    
    # Validate subject structure
    subject = report["subject"]
    if not isinstance(subject, dict):
        raise ValidationError("subject must be an object")
    
    required_subject_fields = ["ssn", "name"]
    for field in required_subject_fields:
        if field not in subject:
            raise ValidationError(f"Missing subject.{field}")
```

---

## 4️⃣ Layer 4: Type Validation

**Purpose**: Verify each field has the correct data type

### Why This Matters

Type mismatches can cause:
- Runtime errors and crashes
- Logic errors (treating string as number)
- Security vulnerabilities (type confusion attacks)

### Implementation Pattern

```python
class TypeValidator:
    """
    Layer 4: Type validation
    
    Validates data types match expectations
    """
    
    @staticmethod
    def validate_string(value: any, field_name: str) -> str:
        """Validate field is a string"""
        if not isinstance(value, str):
            raise ValidationError(
                f"{field_name} must be string, got {type(value).__name__}"
            )
        return value
    
    @staticmethod
    def validate_integer(value: any, field_name: str) -> int:
        """Validate field is an integer"""
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(
                f"{field_name} must be integer, got {type(value).__name__}"
            )
        return value
    
    @staticmethod
    def validate_float(value: any, field_name: str) -> float:
        """Validate field is a float (or int)"""
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValidationError(
                f"{field_name} must be number, got {type(value).__name__}"
            )
        return float(value)
    
    @staticmethod
    def validate_boolean(value: any, field_name: str) -> bool:
        """Validate field is a boolean"""
        if not isinstance(value, bool):
            raise ValidationError(
                f"{field_name} must be boolean, got {type(value).__name__}"
            )
        return value
    
    @staticmethod
    def validate_array(value: any, field_name: str) -> list:
        """Validate field is an array"""
        if not isinstance(value, list):
            raise ValidationError(
                f"{field_name} must be array, got {type(value).__name__}"
            )
        return value
    
    @staticmethod
    def validate_object(value: any, field_name: str) -> dict:
        """Validate field is an object"""
        if not isinstance(value, dict):
            raise ValidationError(
                f"{field_name} must be object, got {type(value).__name__}"
            )
        return value
    
    @staticmethod
    def validate_enum(value: any, field_name: str, allowed_values: set) -> any:
        """Validate field is one of allowed values"""
        if value not in allowed_values:
            raise ValidationError(
                f"{field_name} must be one of {allowed_values}, got {value}"
            )
        return value

# Usage example
message_type = TypeValidator.validate_string(message['message_type'], 'message_type')
message_type = TypeValidator.validate_enum(
    message_type, 
    'message_type', 
    {'request', 'response', 'handshake', 'error'}
)

# For nested structures
payload = TypeValidator.validate_object(message['payload'], 'payload')
method = TypeValidator.validate_string(payload['method'], 'payload.method')
params = TypeValidator.validate_object(payload['parameters'], 'payload.parameters')
```

### Type Coercion Anti-Pattern

**❌ Don't do this**:
```python
# BAD: Automatic type coercion hides errors
credit_score = int(report['credit_score'])  # "abc" → crash
amount = float(data['amount'])               # "1.2.3" → crash
```

**✅ Do this**:
```python
# GOOD: Explicit validation with clear errors
credit_score = TypeValidator.validate_integer(
    report['credit_score'], 
    'credit_score'
)
```

---

## 5️⃣ Layer 5: Range Validation

**Purpose**: Ensure numeric values are within acceptable bounds

### Why This Matters

Out-of-range values can cause:
- Business logic errors
- Integer overflow/underflow
- Buffer overflows in downstream systems
- Division by zero

### Implementation Pattern

```python
class RangeValidator:
    """
    Layer 5: Range validation
    
    Validates numeric values are within bounds
    """
    
    @staticmethod
    def validate_range(
        value: float, 
        field_name: str,
        min_value: float = None,
        max_value: float = None
    ) -> None:
        """Validate value is within range"""
        if min_value is not None and value < min_value:
            raise ValidationError(
                f"{field_name} is below minimum: {value} < {min_value}"
            )
        
        if max_value is not None and value > max_value:
            raise ValidationError(
                f"{field_name} exceeds maximum: {value} > {max_value}"
            )
    
    @staticmethod
    def validate_positive(value: float, field_name: str) -> None:
        """Validate value is positive"""
        if value <= 0:
            raise ValidationError(f"{field_name} must be positive: {value}")
    
    @staticmethod
    def validate_non_negative(value: float, field_name: str) -> None:
        """Validate value is non-negative"""
        if value < 0:
            raise ValidationError(f"{field_name} cannot be negative: {value}")
    
    @staticmethod
    def validate_percentage(value: float, field_name: str) -> None:
        """Validate value is a percentage (0-100)"""
        RangeValidator.validate_range(value, field_name, 0, 100)

# Usage example
RangeValidator.validate_range(
    credit_score, 
    'credit_score',
    min_value=300,
    max_value=850
)

RangeValidator.validate_positive(price, 'price')
RangeValidator.validate_percentage(interest_rate, 'interest_rate')
```

### Real Example: Credit Report Agent (Stage 3)

```python
# From: a2a_examples/a2a_credit_report_example/secure/security/validation.py

def _validate_ranges(report: dict) -> list:
    """Layer 8: Validate business logic and ranges"""
    warnings = []
    
    # Validate credit score range
    score = report["credit_score"]["score"]
    if score < 300 or score > 850:
        warnings.append(
            f"Credit score {score} outside valid range (300-850)"
        )
    
    # Validate account balances
    if "accounts" in report:
        for i, account in enumerate(report["accounts"]):
            balance = account.get("balance", 0)
            if balance < 0:
                warnings.append(f"Account[{i}] has negative balance")
            
            credit_limit = account.get("credit_limit", 0)
            if credit_limit < 0:
                warnings.append(f"Account[{i}] has negative credit limit")
            
            # Prevent division by zero
            if credit_limit > 0 and balance > credit_limit * 2:
                warnings.append(
                    f"Account[{i}] balance exceeds credit limit significantly"
                )
    
    return warnings
```

---

## 6️⃣ Layer 6: Sanitization

**Purpose**: Remove or escape dangerous characters that could cause injection attacks

### Why This Matters

Unsanitized input can lead to:
- **SQL Injection** - `'; DROP TABLE users;--`
- **Command Injection** - `; rm -rf /`
- **XSS Attacks** - `<script>alert('xss')</script>`
- **Log Injection** - Newlines in log messages
- **Path Traversal** - `../../etc/passwd`

### Implementation Pattern

```python
import html
import re
from pathlib import Path

class InputSanitizer:
    """
    Layer 6: Input sanitization
    
    Removes or escapes dangerous content
    """
    
    @staticmethod
    def sanitize_for_sql(value: str) -> str:
        """
        Sanitize for SQL queries
        
        NOTE: Use parameterized queries instead!
        This is a fallback defense layer.
        """
        # Remove SQL special characters
        dangerous = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        sanitized = value
        for char in dangerous:
            sanitized = sanitized.replace(char, '')
        return sanitized
    
    @staticmethod
    def sanitize_for_html(value: str) -> str:
        """Sanitize for HTML display (XSS prevention)"""
        return html.escape(value)
    
    @staticmethod
    def sanitize_for_logging(value: str, max_length: int = 100) -> str:
        """Sanitize for logging (prevent log injection)"""
        # Remove control characters and newlines
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', value)
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + '...'
        
        return sanitized
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename (path traversal prevention)
        
        Critical for file upload functionality
        """
        # Get basename only (removes path)
        safe = Path(filename).name
        
        # Remove dangerous characters
        safe = re.sub(r'[^\w\s.-]', '', safe)
        
        # Remove multiple dots (../ attempts)
        safe = re.sub(r'\.\.+', '.', safe)
        
        # Remove leading dots
        safe = safe.lstrip('.')
        
        # Limit length
        if len(safe) > 100:
            name, ext = Path(safe).stem, Path(safe).suffix
            safe = name[:95] + ext
        
        # Ensure we still have a name
        if not safe or safe == '.' or safe == '..':
            raise ValidationError("Invalid filename after sanitization")
        
        return safe
    
    @staticmethod
    def sanitize_for_shell(value: str) -> str:
        """
        Sanitize for shell commands
        
        NOTE: Never execute shell commands with user input!
        Use API/libraries instead. This is last resort.
        """
        # Whitelist approach: only allow alphanumeric
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            raise ValidationError(
                "Value contains disallowed characters for shell"
            )
        return value
    
    @staticmethod
    def remove_control_characters(value: str) -> str:
        """Remove non-printable control characters"""
        return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)

# Usage
safe_name = InputSanitizer.sanitize_filename(uploaded_filename)
log_msg = InputSanitizer.sanitize_for_logging(user_message)
display_text = InputSanitizer.sanitize_for_html(user_content)
```

### Real Example: Credit Report Agent (Stage 3)

```python
# From: a2a_examples/a2a_credit_report_example/secure/security/validation.py

def _sanitize_filename(filename: str) -> str:
    """Layer 5: Sanitize filename to prevent path traversal"""
    
    # Get basename (removes path)
    safe = os.path.basename(filename)
    
    # Remove dangerous characters
    safe = re.sub(r'[^\w\s.-]', '', safe)
    
    # Remove multiple dots
    safe = re.sub(r'\.\.+', '.', safe)
    
    # Remove leading dots
    safe = safe.lstrip('.')
    
    # Limit length
    if len(safe) > 100:
        name, ext = os.path.splitext(safe)
        safe = name[:95] + ext
    
    # Ensure we still have a name
    if not safe or safe == '.':
        safe = f"file_{uuid.uuid4().hex[:8]}"
    
    return safe
```

### Sanitization Anti-Patterns

**❌ Blacklist approach (incomplete)**:
```python
# BAD: Can't anticipate all dangerous patterns
def sanitize_bad(value):
    value = value.replace("'", "")
    value = value.replace(";", "")
    return value  # What about: '; or "/*" or "--"?
```

**✅ Whitelist approach (secure)**:
```python
# GOOD: Only allow known-safe patterns
def sanitize_good(value):
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        raise ValidationError("Contains disallowed characters")
    return value
```

---

## 7️⃣ Layer 7: Business Logic Validation

**Purpose**: Enforce domain-specific rules beyond structure and types

### Why This Matters

Business logic validation ensures:
- ✅ Data makes sense in your domain
- ✅ Invariants are maintained
- ✅ State transitions are valid
- ✅ References exist and are accessible

### Implementation Pattern

```python
class BusinessLogicValidator:
    """
    Layer 7: Business logic validation
    
    Validates domain-specific rules
    """
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    def validate_credit_report(self, report: dict) -> None:
        """Validate credit report business rules"""
        
        # Rule 1: Credit score consistent with rating
        score = report['credit_score']['score']
        rating = report['credit_score'].get('rating', '')
        
        if score >= 740 and rating != 'EXCELLENT':
            raise ValidationError(
                f"Score {score} should have EXCELLENT rating, got {rating}"
            )
        elif 670 <= score < 740 and rating != 'GOOD':
            raise ValidationError(
                f"Score {score} should have GOOD rating, got {rating}"
            )
        # ... other rating checks
        
        # Rule 2: Total balance vs total credit limit
        accounts = report.get('accounts', [])
        total_balance = sum(acc.get('balance', 0) for acc in accounts)
        total_limit = sum(acc.get('credit_limit', 0) for acc in accounts)
        
        if total_limit > 0:
            utilization = (total_balance / total_limit) * 100
            if utilization > 100:
                raise ValidationError(
                    f"Total utilization {utilization:.1f}% exceeds 100%"
                )
        
        # Rule 3: Account count reasonable
        if len(accounts) > 50:
            raise ValidationError(
                f"Too many accounts: {len(accounts)} (suspicious)"
            )
    
    def validate_references(self, message: dict) -> None:
        """Validate referenced entities exist"""
        
        # Check agent exists
        agent_id = message['sender_id']
        if not self.db.agent_exists(agent_id):
            raise ValidationError(f"Unknown agent: {agent_id}")
        
        # Check referenced resources exist
        if 'resource_id' in message['payload']:
            resource_id = message['payload']['resource_id']
            if not self.db.resource_exists(resource_id):
                raise ValidationError(f"Resource not found: {resource_id}")
    
    def validate_state_transition(
        self, 
        current_state: str, 
        requested_state: str
    ) -> None:
        """Validate state transition is allowed"""
        
        # Define valid transitions
        VALID_TRANSITIONS = {
            'draft': {'submitted', 'cancelled'},
            'submitted': {'approved', 'rejected'},
            'approved': {'completed'},
            'rejected': {},
            'completed': {},
            'cancelled': {}
        }
        
        allowed = VALID_TRANSITIONS.get(current_state, set())
        if requested_state not in allowed:
            raise ValidationError(
                f"Cannot transition from {current_state} to {requested_state}"
            )

# Usage
validator = BusinessLogicValidator(db)
validator.validate_credit_report(report)
validator.validate_references(message)
validator.validate_state_transition('draft', 'submitted')
```

### Real Example: Task Collaboration Agent (Stage 3)

```python
# From: a2a_examples/a2a_task_collab_example/stage3_secure/

def validate_task_assignment(project_id: str, worker_id: str):
    """Validate business rules for task assignment"""
    
    # Rule 1: Project must exist
    if project_id not in self.projects:
        raise ValidationError(f"Project not found: {project_id}")
    
    # Rule 2: Worker must be registered
    if worker_id not in self.registered_workers:
        raise ValidationError(f"Worker not registered: {worker_id}")
    
    # Rule 3: Worker must have required capability
    project = self.projects[project_id]
    required_skill = project.get('required_skill')
    worker_skills = self.registered_workers[worker_id]['skills']
    
    if required_skill and required_skill not in worker_skills:
        raise ValidationError(
            f"Worker {worker_id} lacks required skill: {required_skill}"
        )
    
    # Rule 4: Worker not already assigned to this project
    if worker_id in project.get('assigned_workers', []):
        raise ValidationError(
            f"Worker {worker_id} already assigned to project {project_id}"
        )
```

---

## 8️⃣ Layer 8: Security Validation

**Purpose**: Verify authentication, authorization, and security properties

### Why This Matters

Security validation ensures:
- ✅ Sender is authenticated (who they claim to be)
- ✅ Sender is authorized (allowed to perform action)
- ✅ Message is fresh (not replayed)
- ✅ Message hasn't been tampered with

### Implementation Pattern

```python
from datetime import datetime, timedelta

class SecurityValidator:
    """
    Layer 8: Security validation
    
    Validates authentication and authorization
    """
    
    def __init__(self, auth_manager, authz_manager):
        self.auth = auth_manager
        self.authz = authz_manager
        self.nonce_cache = set()  # Simple nonce tracking
    
    def validate_signature(self, message: dict) -> None:
        """Validate message signature"""
        if 'auth' not in message:
            raise SecurityError("Missing authentication tag")
        
        auth_tag = message['auth']
        
        # Verify signature
        if not self.auth.verify_signature(message, auth_tag['signature']):
            raise SecurityError("Invalid signature")
    
    def validate_timestamp_freshness(
        self, 
        timestamp: str,
        max_age_seconds: int = 300  # 5 minutes
    ) -> None:
        """Validate message timestamp is fresh"""
        msg_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        now = datetime.utcnow()
        age = (now - msg_time).total_seconds()
        
        if age < 0:
            raise SecurityError(
                f"Message timestamp is in the future: {timestamp}"
            )
        
        if age > max_age_seconds:
            raise SecurityError(
                f"Message too old: {age:.0f}s (max: {max_age_seconds}s)"
            )
    
    def validate_nonce(self, nonce: str) -> None:
        """Validate nonce hasn't been used (replay protection)"""
        if nonce in self.nonce_cache:
            raise SecurityError(f"Nonce reused (replay attack): {nonce}")
        
        # Mark nonce as used
        self.nonce_cache.add(nonce)
        
        # In production: expire old nonces from cache
        # after max_age_seconds has passed
    
    def validate_authorization(
        self, 
        agent_id: str, 
        action: str, 
        resource: str = None
    ) -> None:
        """Validate agent is authorized for action"""
        if not self.authz.is_authorized(agent_id, action, resource):
            raise SecurityError(
                f"Agent {agent_id} not authorized for {action}"
            )

# Usage - complete validation pipeline
def validate_message_security(message: dict):
    security = SecurityValidator(auth_manager, authz_manager)
    
    # 8.1: Verify signature
    security.validate_signature(message)
    
    # 8.2: Check timestamp freshness
    security.validate_timestamp_freshness(message['timestamp'])
    
    # 8.3: Validate nonce (if present)
    if 'auth' in message and 'nonce' in message['auth']:
        security.validate_nonce(message['auth']['nonce'])
    
    # 8.4: Check authorization
    action = message['payload'].get('method', 'unknown')
    security.validate_authorization(
        message['sender_id'],
        action
    )
```

### Real Example: Crypto Agent (Stage 3)

```python
# From: a2a_examples/a2a_crypto_example/security/validator.py

def validate_authentication(message: dict) -> None:
    """Validate message authentication"""
    
    # Verify signature
    if not verify_signature(message):
        raise SecurityError("Signature verification failed")
    
    # Check timestamp
    if not is_timestamp_fresh(message['timestamp'], max_age=300):
        raise SecurityError("Message timestamp expired")
    
    # Validate nonce (replay protection)
    nonce = message.get('auth', {}).get('nonce')
    if nonce and is_nonce_used(nonce):
        raise SecurityError("Nonce reused - replay attack detected")
    
    # Mark nonce as used
    if nonce:
        mark_nonce_used(nonce)
```

---

## 🔄 Complete Validation Pipeline

### Putting It All Together

```python
class MessageValidator:
    """
    Complete 8-layer validation pipeline
    
    Validates A2A messages through all layers
    """
    
    def __init__(self, db_connection, auth_manager, authz_manager):
        self.size = SizeValidator()
        self.format = FormatValidator()
        self.schema = SchemaValidator()
        self.type = TypeValidator()
        self.range = RangeValidator()
        self.sanitizer = InputSanitizer()
        self.business = BusinessLogicValidator(db_connection)
        self.security = SecurityValidator(auth_manager, authz_manager)
    
    def validate_message(self, raw_message: bytes) -> dict:
        """
        Validate message through all 8 layers
        
        Returns: Validated and sanitized message
        Raises: ValidationError or SecurityError
        """
        
        # Layer 1: Size validation
        self.size.validate_message_size(raw_message)
        
        # Layer 2: Format validation
        message = self.format.validate_json_structure(raw_message)
        self.format.validate_uuid_format(message['message_id'], 'message_id')
        self.format.validate_timestamp_format(message['timestamp'], 'timestamp')
        self.format.validate_agent_id_format(message['sender_id'])
        self.format.validate_agent_id_format(message['recipient_id'])
        
        # Layer 3: Schema validation
        self.schema.validate_base_schema(message)
        self.schema.validate_payload_schema(
            message['message_type'], 
            message['payload']
        )
        
        # Layer 4: Type validation
        message_type = self.type.validate_enum(
            message['message_type'],
            'message_type',
            {'request', 'response', 'handshake', 'error'}
        )
        payload = self.type.validate_object(message['payload'], 'payload')
        
        # Layer 5: Range validation (payload-specific)
        if message_type == 'request' and 'amount' in payload:
            self.range.validate_positive(payload['amount'], 'amount')
        
        # Layer 6: Sanitization
        # Sanitize string fields
        if 'description' in payload:
            payload['description'] = self.sanitizer.sanitize_for_html(
                payload['description']
            )
        
        # Layer 7: Business logic validation
        self.business.validate_references(message)
        
        # Layer 8: Security validation
        self.security.validate_signature(message)
        self.security.validate_timestamp_freshness(message['timestamp'])
        if 'auth' in message and 'nonce' in message['auth']:
            self.security.validate_nonce(message['auth']['nonce'])
        
        action = payload.get('method', 'unknown')
        self.security.validate_authorization(message['sender_id'], action)
        
        return message

# Usage
validator = MessageValidator(db, auth_manager, authz_manager)

try:
    validated_message = validator.validate_message(raw_message)
    # Process validated message
    process_message(validated_message)
    
except ValidationError as e:
    logger.warning(f"Validation failed: {e}")
    return error_response("VALIDATION_FAILED", str(e))
    
except SecurityError as e:
    logger.error(f"Security validation failed: {e}")
    return error_response("AUTHENTICATION_FAILED", "Security check failed")
```

---

## ❌ Common Validation Anti-Patterns

### Anti-Pattern 1: Validation After Processing

**❌ Don't do this**:
```python
# BAD: Processing before validation
def handle_message(raw_message):
    message = json.loads(raw_message)
    result = process_request(message)  # DANGER!
    
    # Validation too late!
    if not validate_message(message):
        return {"error": "Invalid"}
    
    return result
```

**✅ Do this**:
```python
# GOOD: Validation first
def handle_message(raw_message):
    # Validate FIRST
    message = validate_message(raw_message)
    
    # Process validated message
    result = process_request(message)
    return result
```

### Anti-Pattern 2: Silent Failure

**❌ Don't do this**:
```python
# BAD: Silently ignoring validation errors
def validate(message):
    try:
        check_schema(message)
    except ValidationError:
        pass  # Oops, ignored!
    
    return message
```

**✅ Do this**:
```python
# GOOD: Explicit error handling
def validate(message):
    try:
        check_schema(message)
        return message
    except ValidationError as e:
        logger.error(f"Validation failed: {e}")
        raise  # Propagate error
```

### Anti-Pattern 3: Trusting "Validated" Data

**❌ Don't do this**:
```python
# BAD: Assuming validation somewhere else
def process_payment(payment_data):
    # Assuming someone else validated this...
    amount = payment_data['amount']  # Could be anything!
    execute_payment(amount)
```

**✅ Do this**:
```python
# GOOD: Always validate at entry points
def process_payment(payment_data):
    # Validate even if "should be" validated
    amount = TypeValidator.validate_float(payment_data['amount'], 'amount')
    RangeValidator.validate_positive(amount, 'amount')
    execute_payment(amount)
```

### Anti-Pattern 4: Over-Trusting Types

**❌ Don't do this**:
```python
# BAD: Assuming type hints enforce validation
def process_score(score: int):  # Type hint doesn't validate!
    # score could be negative, zero, or huge
    return score / 100
```

**✅ Do this**:
```python
# GOOD: Explicit validation with runtime checks
def process_score(score: int):
    # Type hints are documentation, not enforcement
    RangeValidator.validate_range(score, 'score', 0, 850)
    return score / 100
```

### Anti-Pattern 5: Validation by Exception

**❌ Don't do this**:
```python
# BAD: Using exceptions for validation logic
def validate(value):
    try:
        int(value)  # Conversion as validation
        return True
    except:
        return False
```

**✅ Do this**:
```python
# GOOD: Explicit validation logic
def validate(value):
    if not isinstance(value, int):
        raise ValidationError(f"Expected int, got {type(value)}")
    return True
```

---

## 🧪 Testing Validation Logic

### Unit Tests for Validators

```python
import pytest

class TestSizeValidator:
    """Test suite for size validation"""
    
    def test_valid_message_size(self):
        """Test message within size limit"""
        message = b'{"message_id": "test"}' * 100
        # Should not raise
        SizeValidator.validate_message_size(message)
    
    def test_message_too_large(self):
        """Test message exceeding size limit"""
        message = b'x' * (11 * 1024 * 1024)  # 11MB
        with pytest.raises(ValidationError, match="too large"):
            SizeValidator.validate_message_size(message)
    
    def test_empty_message(self):
        """Test empty message rejected"""
        with pytest.raises(ValidationError, match="Empty"):
            SizeValidator.validate_message_size(b'')

class TestRangeValidator:
    """Test suite for range validation"""
    
    def test_valid_credit_score(self):
        """Test valid credit score"""
        RangeValidator.validate_range(750, 'score', 300, 850)
    
    def test_credit_score_too_low(self):
        """Test credit score below minimum"""
        with pytest.raises(ValidationError, match="below minimum"):
            RangeValidator.validate_range(200, 'score', 300, 850)
    
    def test_credit_score_too_high(self):
        """Test credit score above maximum"""
        with pytest.raises(ValidationError, match="exceeds maximum"):
            RangeValidator.validate_range(900, 'score', 300, 850)

class TestInputSanitizer:
    """Test suite for input sanitization"""
    
    def test_sanitize_filename_removes_path(self):
        """Test path traversal prevention"""
        unsafe = "../../etc/passwd"
        safe = InputSanitizer.sanitize_filename(unsafe)
        assert safe == "passwd"
        assert ".." not in safe
    
    def test_sanitize_filename_removes_dangerous_chars(self):
        """Test dangerous character removal"""
        unsafe = "file<>name?.txt"
        safe = InputSanitizer.sanitize_filename(unsafe)
        assert "<" not in safe
        assert ">" not in safe
        assert "?" not in safe
    
    def test_sanitize_for_logging_removes_newlines(self):
        """Test log injection prevention"""
        unsafe = "user input\nADMIN logged in"
        safe = InputSanitizer.sanitize_for_logging(unsafe)
        assert "\n" not in safe
        assert "ADMIN" in safe  # Content preserved, newline removed
```

### Integration Tests

```python
class TestValidationPipeline:
    """Test complete validation pipeline"""
    
    def test_valid_request_message(self):
        """Test valid message passes all layers"""
        message = create_valid_request_message()
        validator = MessageValidator(db, auth, authz)
        
        # Should not raise
        validated = validator.validate_message(message)
        assert validated['message_type'] == 'request'
    
    def test_invalid_signature_rejected(self):
        """Test invalid signature fails security layer"""
        message = create_message_with_invalid_signature()
        validator = MessageValidator(db, auth, authz)
        
        with pytest.raises(SecurityError, match="Invalid signature"):
            validator.validate_message(message)
    
    def test_replay_attack_detected(self):
        """Test replay attack prevented"""
        message = create_valid_request_message()
        validator = MessageValidator(db, auth, authz)
        
        # First attempt succeeds
        validator.validate_message(message)
        
        # Second attempt with same nonce fails
        with pytest.raises(SecurityError, match="Nonce reused"):
            validator.validate_message(message)
```

### Fuzz Testing

```python
import random
import string

def fuzz_test_validator(iterations=10000):
    """Fuzz test validator with random inputs"""
    validator = MessageValidator(db, auth, authz)
    
    for i in range(iterations):
        # Generate random message
        fuzz_message = generate_random_message()
        
        try:
            validator.validate_message(fuzz_message)
            # If it passes, verify it's actually valid
            assert is_truly_valid(fuzz_message)
        except (ValidationError, SecurityError):
            # Expected for invalid messages
            pass
        except Exception as e:
            # Unexpected error - validator crashed!
            pytest.fail(f"Validator crashed on iteration {i}: {e}")

def generate_random_message():
    """Generate random message for fuzzing"""
    return json.dumps({
        "message_id": random_string(36),
        "message_type": random.choice(['request', 'response', 'handshake', 'error', 'INVALID']),
        "sender_id": random_string(random.randint(0, 200)),
        "recipient_id": random_string(random.randint(0, 200)),
        "timestamp": random_timestamp(),
        "payload": random_object()
    }).encode()
```

---

## 📊 Validation Performance Considerations

### Optimization Tips

**1. Validate Early, Fail Fast**
```python
# Check cheap validations first
def validate_message(message):
    # Fast checks first
    validate_size(message)          # O(1)
    validate_format(message)        # O(n) where n = message size
    
    # Expensive checks last
    validate_signature(message)     # O(crypto)
    validate_business_logic(message) # O(database queries)
```

**2. Cache Validation Results**
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def validate_agent_exists(agent_id: str) -> bool:
    """Cache agent existence checks"""
    return db.query("SELECT 1 FROM agents WHERE id = %s", agent_id)
```

**3. Batch Validations**
```python
# Instead of N database queries
for item in items:
    if not db.exists(item.id):
        raise ValidationError()

# Do 1 query
item_ids = [item.id for item in items]
existing_ids = db.batch_check_existence(item_ids)
missing = set(item_ids) - existing_ids
if missing:
    raise ValidationError(f"Missing items: {missing}")
```

**4. Use Compiled Regexes**
```python
# Compile once at module level
UUID_PATTERN = re.compile(r'^[0-9a-f-]{36}$', re.IGNORECASE)

# Reuse compiled pattern
def validate_uuid(value):
    if not UUID_PATTERN.match(value):
        raise ValidationError()
```

---

## 🎓 Best Practices Summary

### ✅ DO

1. **Validate at boundaries** - Every external input
2. **Validate early** - Before any processing
3. **Fail explicitly** - Clear error messages
4. **Use whitelists** - Only allow known-good patterns
5. **Layer defenses** - Multiple independent checks
6. **Sanitize output** - Context-appropriate escaping
7. **Log validation failures** - Security monitoring
8. **Test thoroughly** - Unit + integration + fuzz
9. **Document assumptions** - What is being validated and why
10. **Keep it simple** - Complex validation has bugs

### ❌ DON'T

1. **Don't trust type hints** - They don't enforce at runtime
2. **Don't use blacklists** - Can't anticipate all attacks
3. **Don't validate after processing** - Too late!
4. **Don't catch and ignore** - Silent failures are dangerous
5. **Don't rely on client validation** - Always validate server-side
6. **Don't forget edge cases** - Empty, null, max int, etc.
7. **Don't leak info in errors** - Generic messages to clients
8. **Don't skip validation** - "It should be validated already"
9. **Don't auto-coerce types** - Hides errors
10. **Don't trust "validated" data** - Re-validate at boundaries

---

## 🔗 Related Documentation

- [Error Handling](./03_error_handling.md) - What to do when validation fails
- [Protocol Messages](./01_protocol_messages.md) - Message structure
- [Message Schemas](../05_REFERENCE/message_schemas.md) - Complete schemas
- [Security Best Practices](../03_SECURITY/04_security_best_practices.md) - Security context
- [Threat Model](../03_SECURITY/03_threat_model.md) - Attack scenarios

---

## 📚 Real-World Examples in Project

Study these implementations for practical patterns:

**Credit Report Agent (Stage 3)** - ✅ Best example
- Location: `a2a_examples/a2a_credit_report_example/secure/security/validation.py`
- Features: Complete 8-layer file validation
- Lines: 400+ lines of production validation code

**Task Collaboration Agent (Stage 3)** - ✅ Good example
- Location: `a2a_examples/a2a_task_collab_example/stage3_secure/security/validation.py`
- Features: Business logic validation, state validation

**Crypto Agent (Stage 3)** - ✅ Minimal but secure
- Location: `a2a_examples/a2a_crypto_example/security/validator.py`
- Features: Basic validation for simple queries

**Credit Report Agent (Stage 1)** - ❌ Anti-patterns
- Location: `a2a_examples/a2a_credit_report_example/insecure/`
- Study this to learn what NOT to do
- 26 validation vulnerabilities documented

---

## 💡 Key Takeaways

1. **Validation is not optional** - It's your first line of defense
2. **Layer your defenses** - 8 layers catch different issues
3. **Fail explicitly** - Clear errors help debugging and security
4. **Whitelist > Blacklist** - Can't anticipate all attacks
5. **Validate early** - Before any processing or side effects
6. **Test thoroughly** - Unit, integration, and fuzz testing
7. **Learn from examples** - Study Stage 3 implementations
8. **Avoid anti-patterns** - Validation after processing, silent failures
9. **Document validation** - Future maintainers need to understand
10. **Monitor failures** - Validation failures are security events

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Complete  
**Author**: Based on A2A Security Learning Project