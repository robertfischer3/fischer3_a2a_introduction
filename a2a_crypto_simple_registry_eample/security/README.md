# Security Module for Agent2Agent Protocol

## Overview

The security module provides a comprehensive, modular implementation of secure Agent Cards for the A2A protocol. It's designed with separation of concerns, making it easy to integrate, extend, and maintain.

## Module Structure

```
security/
├── __init__.py           # Module exports and version info
├── constants.py          # Security constants and enums
├── secure_agent_card.py  # SecureAgentCard class
├── validator.py          # AgentCardValidator class
├── manager.py           # SecureAgentCardManager class
└── audit_logger.py      # SecurityAuditLogger class
```

## Components

### 1. **constants.py** - Security Constants
- `SecurityLevel` enum: PUBLIC, TRUSTED, INTERNAL, ADMIN
- `CapabilityClass` enum: READ_ONLY, WRITE, STREAM, BATCH, ADMIN
- Security configuration constants (expiry times, thresholds, etc.)
- Whitelists and pattern definitions

### 2. **secure_agent_card.py** - Agent Card Model
- `SecureAgentCard`: Core data model with context-aware serialization
- Methods for capability checking and expiration validation
- Automatic sanitization of sensitive metadata

### 3. **validator.py** - Card Validation
- `AgentCardValidator`: Comprehensive validation framework
- Signature verification
- Capability whitelisting
- Injection detection
- Rate limiting
- Custom validator support

### 4. **manager.py** - Card Lifecycle Management
- `SecureAgentCardManager`: Manages card creation and exchange
- Nonce-based replay protection
- Reputation tracking
- Trust level calculation
- Card caching

### 5. **audit_logger.py** - Security Auditing
- `SecurityAuditLogger`: Comprehensive event logging
- Multiple severity levels
- Agent history tracking
- Statistics and reporting
- Alert generation for critical events

## Usage Examples

### Basic Usage

```python
from security import SecureAgentCardManager, SecurityLevel, CapabilityClass

# Create a manager
manager = SecureAgentCardManager("my-agent-001")

# Create a secure card
card = manager.create_secure_card(
    name="MyAgent",
    version="1.0.0",
    description="My secure agent",
    capabilities={
        CapabilityClass.READ_ONLY.value: ["read_data"],
        CapabilityClass.WRITE.value: ["write_data"]
    },
    metadata={"domain": "example.com"}
)

# Exchange cards with another agent
nonce = manager.generate_nonce()
success, remote_card, message = manager.exchange_cards(
    card,
    remote_card_data,
    nonce
)
```

### Context-Aware Serialization

```python
from security import SecureAgentCard, SecurityLevel

# Get different views of the card
public_view = card.to_dict(SecurityLevel.PUBLIC)     # Minimal info
trusted_view = card.to_dict(SecurityLevel.TRUSTED)   # Extended info
internal_view = card.to_dict(SecurityLevel.INTERNAL) # Full info
```

### Custom Validation

```python
from security import AgentCardValidator

validator = AgentCardValidator()

# Add custom validation logic
def validate_domain(card):
    if "domain" not in card.metadata:
        return ["Missing required domain metadata"]
    return []

validator.add_custom_validator(validate_domain)

# Validate a card
is_valid, issues = validator.validate_card(card)
```

### Security Auditing

```python
from security import SecurityAuditLogger

logger = SecurityAuditLogger()

# Log security events
logger.log_card_exchange("HANDSHAKE", local_id, remote_id, True)
logger.log_suspicious_activity(agent_id, "INJECTION", "SQL injection attempt")

# Get statistics
stats = logger.get_statistics()
print(f"Total events: {stats['total_events']}")

# Export audit log
logger.export_events("audit_log.json")
```

## Security Features

### 🔐 **Authentication & Identity**
- Cryptographic signatures on all cards
- Certificate fingerprinting
- Public key infrastructure support
- Issuer verification

### 🛡️ **Input Validation**
- Schema validation for all fields
- SQL/XSS injection prevention
- Pattern-based threat detection
- Length and format restrictions

### 🔄 **Replay Protection**
- Nonce-based replay prevention
- Time-based nonce expiration
- Automatic cleanup of expired nonces

### 📊 **Rate Limiting**
- Per-agent rate limiting
- Configurable thresholds
- Automatic blocking on violations

### 🏆 **Reputation System**
- Dynamic reputation scoring
- Automatic agent blocking
- Trust level calculation
- Historical tracking

### 📝 **Audit Logging**
- Comprehensive event logging
- Multiple severity levels
- Agent-specific history
- Statistical analysis
- Alert generation

## Integration with A2A Protocol

The security module is designed to integrate seamlessly with the A2A protocol:

```python
# In your A2A server
from security import SecureAgentCardManager, SecurityAuditLogger

class SecureA2AServer:
    def __init__(self):
        self.card_manager = SecureAgentCardManager(self.agent_id)
        self.audit_logger = SecurityAuditLogger()
        
    async def handle_handshake(self, message):
        # Validate and exchange cards securely
        success, remote_card, msg = self.card_manager.exchange_cards(
            self.local_card,
            message.payload["agent_card"],
            message.payload["nonce"]
        )
        
        # Log the exchange
        self.audit_logger.log_card_exchange(
            "HANDSHAKE",
            self.agent_id,
            remote_card.agent_id if remote_card else "unknown",
            success
        )
        
        return success, remote_card
```

## Configuration

### Environment Variables

```bash
# Security configuration
export A2A_MAX_VALIDATION_ATTEMPTS=10
export A2A_CARD_EXPIRY_DAYS=90
export A2A_REPUTATION_THRESHOLD=20
export A2A_NONCE_EXPIRY_SECONDS=300
```

### Programmatic Configuration

```python
from security import constants

# Modify security constants
constants.MAX_VALIDATION_ATTEMPTS_PER_MINUTE = 20
constants.DEFAULT_CARD_EXPIRY_DAYS = 180
constants.BLOCK_REPUTATION_THRESHOLD = 10
```

## Testing

Run the demonstration:

```bash
# Run the modular demo
python secure_demo.py

# Run with the crypto example
python secure_agent_card_demo.py
```

## Extending the Module

### Adding New Capability Classes

```python
# In constants.py
class CustomCapabilityClass(Enum):
    DATA_PROCESSING = "data_processing"
    ANALYTICS = "analytics"
```

### Adding Custom Validators

```python
def validate_custom_requirement(card):
    """Custom validation logic"""
    issues = []
    # Your validation logic here
    return issues

validator.add_custom_validator(validate_custom_requirement)
```

### Implementing Custom Loggers

```python
class CustomLogger(SecurityAuditLogger):
    def send_to_siem(self, event):
        """Send events to SIEM system"""
        # Your SIEM integration here
        pass
```

## Best Practices

1. **Always use nonces** for message exchanges to prevent replay attacks
2. **Validate all cards** before trusting them
3. **Use appropriate security contexts** when serializing cards
4. **Monitor reputation scores** and block low-reputation agents
5. **Regularly review audit logs** for suspicious patterns
6. **Keep the whitelist updated** with approved capabilities
7. **Implement custom validators** for domain-specific requirements
8. **Export and backup audit logs** regularly

## Migration Guide

To migrate from the monolithic `secure_agent_card_demo.py` to the modular structure:

1. **Update imports**:
```python
# Old
from secure_agent_card_demo import SecureAgentCard

# New
from security import SecureAgentCard
```

2. **Update file paths** if importing from outside the project:
```python
import sys
sys.path.append('/path/to/a2a_crypto_example')
from security import SecureAgentCardManager
```

3. **No API changes** - All classes maintain the same interfaces

## Performance Considerations

- **Card caching**: Validated cards are cached to reduce repeated validation
- **Lazy loading**: Components are initialized only when needed
- **Efficient cleanup**: Expired nonces and old events are automatically cleaned
- **Rate limiting**: Prevents DoS attacks through validation flooding

## Security Considerations

⚠️ **Important**: This is a demonstration implementation. For production use:

1. Replace simplified cryptography with proper libraries (e.g., `cryptography` package)
2. Implement real PKI infrastructure
3. Use secure key storage (HSM, Key Vault)
4. Integrate with enterprise security systems (SIEM, IDS)
5. Implement proper certificate chain validation
6. Add network-level security (TLS, mTLS)
7. Regular security audits and penetration testing

## License

This security module is provided as part of the A2A protocol example for educational purposes.