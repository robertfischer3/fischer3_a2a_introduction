# Agent Card Security Best Practices

## Overview

Agent Cards, while facilitating autonomous agent discovery and interaction, present unique security challenges in distributed multi-agent systems. This document outlines comprehensive security best practices for implementing, exchanging, and validating Agent Cards in production environments.

---

## 1. Identity and Authentication

### 1.1 Cryptographic Identity

**Best Practice**: Every Agent Card should include cryptographic proof of identity.

```python
class SecureAgentCard:
    def __init__(self):
        self.agent_id = str(uuid.uuid4())
        self.public_key = self.generate_public_key()
        self.certificate = self.get_x509_certificate()
        
    def sign_card(self, private_key):
        """Sign the agent card with private key"""
        card_data = self.to_json()
        signature = cryptographic_sign(card_data, private_key)
        return {
            "card": card_data,
            "signature": base64.encode(signature),
            "algorithm": "RS256"
        }
```

**Implementation Guidelines**:
- Use public key infrastructure (PKI) for agent identity
- Store private keys in secure hardware modules (HSM) or key vaults
- Implement certificate rotation before expiration
- Include certificate chain for validation

### 1.2 Mutual Authentication

**Best Practice**: Implement mutual TLS (mTLS) for agent-to-agent communication.

```python
# Example: Validating agent identity during handshake
async def validate_agent_handshake(agent_card, connection):
    # 1. Verify TLS certificate matches agent_id
    peer_cert = connection.get_peer_certificate()
    if not verify_cert_matches_agent(peer_cert, agent_card.agent_id):
        raise SecurityException("Certificate mismatch")
    
    # 2. Verify agent card signature
    if not verify_signature(agent_card):
        raise SecurityException("Invalid card signature")
    
    # 3. Check certificate revocation list (CRL)
    if is_certificate_revoked(peer_cert):
        raise SecurityException("Certificate revoked")
```

---

## 2. Capability Verification and Authorization

### 2.1 Capability Signing

**Best Practice**: Digitally sign capability declarations to prevent tampering.

```python
class CapabilityAttestation:
    def __init__(self, capabilities, issuer):
        self.capabilities = capabilities
        self.issuer = issuer  # Trusted authority
        self.issued_at = datetime.utcnow()
        self.expires_at = self.issued_at + timedelta(days=30)
        self.signature = None
    
    def verify_capabilities(self, agent_card):
        """Verify capabilities are properly attested"""
        # Check signature from trusted issuer
        if not verify_issuer_signature(self.signature, self.issuer):
            return False
        
        # Check expiration
        if datetime.utcnow() > self.expires_at:
            return False
        
        # Verify capabilities match card declaration
        return set(agent_card.capabilities).issubset(self.capabilities)
```

### 2.2 Principle of Least Privilege

**Best Practice**: Declare minimal required capabilities and request only necessary permissions.

```python
# Good: Specific, limited capabilities
agent_card = {
    "capabilities": ["read_public_prices", "cache_for_1hour"],
    "permissions": {
        "data_access": ["public_market_data"],
        "rate_limit": "100_requests_per_minute"
    }
}

# Bad: Overly broad capabilities
agent_card = {
    "capabilities": ["full_system_access", "unlimited_requests"],
    "permissions": {"data_access": ["*"]}
}
```

---

## 3. Data Validation and Sanitization

### 3.1 Schema Validation

**Best Practice**: Strictly validate all Agent Card fields against a defined schema.

```python
from jsonschema import validate, ValidationError

AGENT_CARD_SCHEMA = {
    "type": "object",
    "required": ["agent_id", "name", "version", "capabilities"],
    "properties": {
        "agent_id": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9-]{36}$"  # UUID format
        },
        "name": {
            "type": "string",
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_-]+$"  # Alphanumeric only
        },
        "version": {
            "type": "string",
            "pattern": "^\\d+\\.\\d+\\.\\d+$"  # Semantic versioning
        },
        "capabilities": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ALLOWED_CAPABILITIES  # Whitelist approach
            },
            "maxItems": 50
        }
    },
    "additionalProperties": False  # Reject unknown fields
}

def validate_agent_card(card_data):
    try:
        validate(card_data, AGENT_CARD_SCHEMA)
        return True
    except ValidationError as e:
        log_security_event(f"Invalid agent card: {e}")
        return False
```

### 3.2 Input Sanitization

**Best Practice**: Sanitize all string fields to prevent injection attacks.

```python
import re
import html

def sanitize_agent_card(card):
    """Sanitize agent card fields to prevent injection attacks"""
    # Escape HTML/XML entities
    card['description'] = html.escape(card.get('description', ''))
    
    # Remove potential SQL injection patterns
    card['name'] = re.sub(r'[;\'"\\]', '', card.get('name', ''))
    
    # Validate and sanitize URLs in metadata
    if 'metadata' in card and 'endpoint' in card['metadata']:
        url = card['metadata']['endpoint']
        if not is_valid_url(url) or not is_allowed_domain(url):
            del card['metadata']['endpoint']
    
    return card
```

---

## 4. Information Disclosure Prevention

### 4.1 Minimal Information Principle

**Best Practice**: Include only necessary information in Agent Cards.

```python
# Good: Minimal necessary information
public_agent_card = {
    "agent_id": "crypto-agent-001",
    "name": "CryptoPriceAgent",
    "version": "1.0.0",
    "capabilities": ["get_price", "get_currencies"],
    "endpoint": "https://api.example.com/agent"
}

# Bad: Excessive internal information
internal_agent_card = {
    "agent_id": "crypto-agent-001",
    "internal_ip": "192.168.1.100",  # Don't expose
    "database_host": "db.internal.com",  # Don't expose
    "api_keys": ["sk-1234..."],  # NEVER include
    "admin_contact": "admin@example.com",  # Don't expose
    "infrastructure": "AWS us-east-1a"  # Don't expose
}
```

### 4.2 Separate Public and Private Cards

**Best Practice**: Maintain separate versions for internal and external use.

```python
class AgentCardManager:
    def __init__(self):
        self.private_card = self._create_private_card()
        self.public_card = self._create_public_card()
    
    def get_card_for_context(self, requester):
        """Return appropriate card based on requester trust level"""
        if is_internal_agent(requester):
            return self.private_card
        elif is_trusted_partner(requester):
            return self._create_partner_card()
        else:
            return self.public_card
    
    def _create_public_card(self):
        """Minimal public-facing card"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "capabilities": self.public_capabilities
        }
```

---

## 5. Rate Limiting and Abuse Prevention

### 5.1 Capability-Based Rate Limiting

**Best Practice**: Implement rate limits based on declared capabilities.

```python
class RateLimitedAgent:
    def __init__(self):
        self.rate_limits = {
            "basic_query": (100, "per_minute"),
            "batch_processing": (10, "per_hour"),
            "admin_operation": (1, "per_minute")
        }
    
    def check_rate_limit(self, agent_card, operation):
        """Verify operation within rate limits"""
        capability = self.map_operation_to_capability(operation)
        
        if capability not in agent_card.capabilities:
            raise UnauthorizedException(f"Missing capability: {capability}")
        
        limit, period = self.rate_limits.get(capability, (10, "per_minute"))
        
        if not self.rate_limiter.allow(agent_card.agent_id, limit, period):
            raise RateLimitException(f"Rate limit exceeded: {limit}/{period}")
```

### 5.2 Dynamic Reputation System

**Best Practice**: Track agent behavior and adjust trust dynamically.

```python
class AgentReputationManager:
    def __init__(self):
        self.reputation_scores = {}
        self.behavior_log = []
    
    def update_reputation(self, agent_id, event):
        """Update agent reputation based on behavior"""
        score = self.reputation_scores.get(agent_id, 100)
        
        if event.type == "malformed_request":
            score -= 10
        elif event.type == "invalid_capability_claim":
            score -= 25
        elif event.type == "successful_interaction":
            score += 1
        elif event.type == "abuse_detected":
            score -= 50
        
        self.reputation_scores[agent_id] = max(0, min(100, score))
        
        # Block agents with low reputation
        if score < 20:
            self.block_agent(agent_id)
```

---

## 6. Secure Storage and Transmission

### 6.1 Card Storage

**Best Practice**: Encrypt Agent Cards at rest and implement access controls.

```python
class SecureCardStorage:
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key
        self.storage = {}
    
    def store_card(self, agent_card):
        """Securely store agent card"""
        # Encrypt sensitive fields
        encrypted_card = self.encrypt_sensitive_fields(agent_card)
        
        # Add integrity check
        encrypted_card['hmac'] = self.calculate_hmac(encrypted_card)
        
        # Store with access logging
        self.storage[agent_card.agent_id] = encrypted_card
        self.log_access("STORE", agent_card.agent_id)
    
    def retrieve_card(self, agent_id, requester):
        """Retrieve and decrypt card with access control"""
        if not self.has_permission(requester, agent_id):
            raise AccessDeniedException()
        
        encrypted_card = self.storage.get(agent_id)
        if not encrypted_card:
            return None
        
        # Verify integrity
        if not self.verify_hmac(encrypted_card):
            raise IntegrityException("Card tampered")
        
        # Decrypt and return
        return self.decrypt_sensitive_fields(encrypted_card)
```

### 6.2 Secure Transmission

**Best Practice**: Always use encrypted channels and implement replay protection.

```python
class SecureCardTransmission:
    def __init__(self):
        self.nonce_cache = TTLCache(maxsize=10000, ttl=300)
    
    def prepare_for_transmission(self, agent_card):
        """Prepare card for secure transmission"""
        nonce = generate_nonce()
        timestamp = datetime.utcnow().isoformat()
        
        envelope = {
            "card": agent_card.to_dict(),
            "nonce": nonce,
            "timestamp": timestamp,
            "expires": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }
        
        # Sign the envelope
        envelope["signature"] = self.sign_envelope(envelope)
        
        # Encrypt if containing sensitive data
        if self.contains_sensitive_data(agent_card):
            envelope = self.encrypt_envelope(envelope)
        
        return envelope
    
    def validate_received_card(self, envelope):
        """Validate received card envelope"""
        # Check replay attack
        if envelope["nonce"] in self.nonce_cache:
            raise SecurityException("Replay attack detected")
        
        # Check expiration
        if datetime.fromisoformat(envelope["expires"]) < datetime.utcnow():
            raise SecurityException("Card expired")
        
        # Verify signature
        if not self.verify_signature(envelope):
            raise SecurityException("Invalid signature")
        
        # Cache nonce to prevent replay
        self.nonce_cache[envelope["nonce"]] = True
        
        return envelope["card"]
```

---

## 7. Monitoring and Auditing

### 7.1 Security Event Logging

**Best Practice**: Log all security-relevant Agent Card operations.

```python
class AgentCardAuditor:
    def __init__(self):
        self.security_events = []
    
    def log_card_exchange(self, event_type, agent_id, remote_agent, result):
        """Log agent card exchange events"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,  # HANDSHAKE, VALIDATION, REJECTION
            "agent_id": agent_id,
            "remote_agent": remote_agent,
            "result": result,
            "ip_address": self.get_remote_ip(),
            "correlation_id": str(uuid.uuid4())
        }
        
        # Log based on severity
        if result == "REJECTED":
            self.log_security_alert(event)
        elif result == "SUSPICIOUS":
            self.log_warning(event)
        else:
            self.log_info(event)
        
        # Store for analysis
        self.security_events.append(event)
        
        # Real-time alerting for critical events
        if self.is_critical_event(event):
            self.send_security_alert(event)
```

### 7.2 Anomaly Detection

**Best Practice**: Implement behavioral analysis to detect suspicious patterns.

```python
class CardAnomalyDetector:
    def __init__(self):
        self.baseline_behavior = {}
        self.anomaly_threshold = 3.0  # Standard deviations
    
    def analyze_card_usage(self, agent_id, card_data):
        """Detect anomalies in agent card usage"""
        anomalies = []
        
        # Check capability changes
        if self.has_capability_escalation(agent_id, card_data):
            anomalies.append("CAPABILITY_ESCALATION")
        
        # Check version regression
        if self.has_version_regression(agent_id, card_data):
            anomalies.append("VERSION_REGRESSION")
        
        # Check metadata anomalies
        if self.has_metadata_anomaly(agent_id, card_data):
            anomalies.append("METADATA_ANOMALY")
        
        # Check request patterns
        if self.has_unusual_request_pattern(agent_id):
            anomalies.append("UNUSUAL_PATTERN")
        
        if anomalies:
            self.trigger_investigation(agent_id, anomalies)
        
        return len(anomalies) == 0
```

---

## 8. Security Checklist

### Pre-Deployment Checklist

- [ ] **Identity Verification**
  - [ ] Implement PKI-based agent identity
  - [ ] Configure mutual TLS for all connections
  - [ ] Set up certificate rotation schedule

- [ ] **Validation & Sanitization**
  - [ ] Schema validation for all card fields
  - [ ] Input sanitization for string fields
  - [ ] Whitelist allowed capabilities

- [ ] **Access Control**
  - [ ] Implement capability-based authorization
  - [ ] Configure rate limiting per capability
  - [ ] Set up reputation tracking

- [ ] **Data Protection**
  - [ ] Encrypt cards at rest
  - [ ] Use TLS 1.3+ for transmission
  - [ ] Implement replay protection

- [ ] **Monitoring**
  - [ ] Enable comprehensive audit logging
  - [ ] Configure anomaly detection
  - [ ] Set up security alerting

- [ ] **Incident Response**
  - [ ] Document card revocation process
  - [ ] Prepare agent blocking procedures
  - [ ] Test security incident runbooks

### Runtime Security Checks

```python
def perform_security_checks(agent_card):
    """Comprehensive security validation"""
    checks = [
        ("schema_valid", validate_schema),
        ("signature_valid", verify_signature),
        ("certificate_valid", verify_certificate),
        ("not_revoked", check_not_revoked),
        ("capabilities_authorized", verify_capabilities),
        ("rate_limit_ok", check_rate_limit),
        ("reputation_acceptable", check_reputation),
        ("no_anomalies", check_anomalies)
    ]
    
    results = {}
    for check_name, check_func in checks:
        try:
            results[check_name] = check_func(agent_card)
        except Exception as e:
            results[check_name] = False
            log_security_failure(check_name, e)
    
    return all(results.values()), results
```

---

## 9. Common Security Pitfalls

### Pitfall 1: Trusting Self-Declared Capabilities

**Problem**: Accepting capability claims without verification.

**Solution**: Always verify capabilities through attestation or testing.

```python
# Bad: Trust without verification
if "admin" in agent_card.capabilities:
    grant_admin_access()

# Good: Verify before trusting
if verify_capability_claim(agent_card, "admin"):
    grant_admin_access()
```

### Pitfall 2: Static Security Posture

**Problem**: Fixed security rules that don't adapt to threats.

**Solution**: Implement adaptive security based on threat intelligence.

```python
class AdaptiveSecurityPolicy:
    def update_from_threat_intel(self, threat_data):
        """Adjust security posture based on threats"""
        if threat_data.severity == "CRITICAL":
            self.require_additional_authentication = True
            self.reduce_rate_limits_by(50)
            self.enable_deep_packet_inspection()
```

### Pitfall 3: Insufficient Logging

**Problem**: Missing security events in logs.

**Solution**: Log all security-relevant operations with sufficient detail.

---

## 10. Future Security Enhancements

### Emerging Security Technologies

1. **Zero-Knowledge Proofs**: Verify capabilities without revealing sensitive information
2. **Homomorphic Encryption**: Process encrypted agent cards without decryption
3. **Blockchain Attestation**: Immutable capability attestation on distributed ledgers
4. **AI-Based Threat Detection**: Machine learning models for sophisticated anomaly detection
5. **Quantum-Resistant Cryptography**: Prepare for post-quantum security requirements

### Recommended Research Areas

- Federated identity management for agent ecosystems
- Privacy-preserving agent discovery protocols
- Automated security policy generation from capability declarations
- Cross-domain agent trust establishment
- Resilient agent reputation systems

---

## Conclusion

Security for Agent Cards requires a multi-layered approach combining cryptographic identity, strict validation, comprehensive monitoring, and adaptive defenses. By following these best practices, organizations can build robust and secure multi-agent systems that maintain the benefits of autonomous agent interaction while protecting against various threat vectors. Regular security audits and updates to these practices are essential as the threat landscape evolves.

Remember: **Security is not a feature, it's a fundamental design requirement for Agent Card implementations.**
