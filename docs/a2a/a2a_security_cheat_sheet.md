# Agent-to-Agent (A2A) Security Quick Reference Cheat Sheet

> **Purpose**: Fast reference for securing A2A systems with links to training examples  
> **Audience**: Developers building agent-to-agent communication systems  
> **Last Updated**: January 2025

---

## 🔐 Authentication & Authorization

### Strong Authentication ✅
**What**: Cryptographically verify agent identity  
**How**: 
- Use RSA-2048 or ECC P-256 signatures
- Include nonce (prevents replay attacks)
- Include timestamp (5-minute window)
- Validate signature before processing

**Example**: Credit Report Agent Stage 3  
Location: `secure/security/authentication.py` - `AuthenticationManager`

**Code Pattern**:
```python
auth_tag = {
    "agent_id": "agent-001",
    "timestamp": "2025-01-15T10:00:00Z",
    "nonce": "a1b2c3d4...",  # 32-char random, never reused
    "signature": "xyz789..."   # RSA signature of payload
}
```

**Common Mistakes**:
- ❌ Using shared secrets (HMAC) - Stage 2 shows why this fails
- ❌ No nonce - vulnerable to replay attacks (Stage 2)
- ❌ No timestamp - old messages accepted forever
- ❌ Weak crypto - MD5/SHA1 are broken

---

### Replay Attack Prevention ✅
**What**: Prevent reuse of captured valid requests  
**How**: Nonce cache with TTL (5-10 minutes)

**Example**: Credit Report Stage 3 vs Stage 2  
- Stage 2: `improved/` - NO nonce, replay vulnerable (client option 8 demos this!)
- Stage 3: `secure/security/authentication.py` - `NonceCache` class

**Implementation**:
```python
class NonceCache:
    def is_used(self, nonce: str) -> bool:
        # Check if nonce seen before
    
    def mark_used(self, nonce: str):
        # Mark as used, auto-expires after TTL
```

**Test**: Credit Report Stage 2, client option 8 - sends same request 3 times, all succeed!

---

### Authorization (RBAC) ✅
**What**: Control who can do what  
**How**: Role-Based Access Control

**Example**: Credit Report Stage 3  
Location: `secure/security/protection.py` - `AuthorizationManager`

**Roles Pattern**:
```python
ROLES = {
    "admin": ["upload", "view", "delete", "manage_users"],
    "analyst": ["upload", "view", "analyze"],
    "auditor": ["view", "audit_logs"],
    "viewer": ["view"]
}
```

**Check Before Action**:
```python
authz_manager.authorize(agent_id, "delete_report")
# Raises AuthorizationError if not permitted
```

---

## 📝 Input Validation

### 8-Layer File Validation ✅
**What**: Defense-in-depth for file uploads  
**Example**: Credit Report Stage 3  
Location: `secure/security/validation.py` - `FileValidator`

**The 8 Layers**:
1. **Size Validation** - Reject >5MB (DoS prevention)
2. **Extension Validation** - Whitelist only (.json, .csv)
3. **Content-Type Validation** - Verify HTTP header matches
4. **Magic Bytes** - Verify actual file content (prevents spoofing)
5. **Filename Sanitization** - Remove `../`, null bytes, control chars
6. **Structure Validation** - JSON schema checking
7. **Range Validation** - Business logic (e.g., credit score 300-850)
8. **Safe Parsing** - Recursion limits, reject NaN/Infinity

**Why Each Layer Matters**:
- Layer 1: Credit Report Stage 1 has NO limit → 10GB file crashes server
- Layer 2: Credit Report Stage 1 accepts .exe files
- Layer 4: Credit Report Stage 2 only checks extension → can be spoofed
- Layer 5: Credit Report Stage 1 vulnerable to path traversal (`../../../../etc/passwd`)

**Test**: Credit Report Stage 1 client - upload `fake_report.sh` (succeeds!), Stage 3 rejects it

---

### Path Traversal Prevention ✅
**What**: Prevent `../../etc/passwd` attacks  
**How**: Sanitize filenames before use

**Example**: Credit Report Stage 1 (vulnerable) vs Stage 2+ (fixed)  
Location: 
- Vulnerable: `insecure/server/insecure_credit_agent.py` line 176
- Fixed: `improved/server/improved_credit_agent.py` - `sanitize_filename()`

**Sanitization Pattern**:
```python
import os
import re

def sanitize_filename(filename: str) -> str:
    # Remove path components
    safe = os.path.basename(filename)
    
    # Remove dangerous characters
    safe = re.sub(r'[^\w\s.-]', '', safe)
    
    # Remove multiple dots
    safe = re.sub(r'\.\.+', '.', safe)
    
    return safe
```

---

### Schema Validation ✅
**What**: Validate message structure before processing  
**How**: Define expected schema, reject if doesn't match

**Example**: Credit Report Stage 3  
Location: `secure/security/validation.py` - `ReportValidator`

**Pattern**:
```python
# Required fields
required = ["report_id", "subject", "credit_score"]

# Nested requirements
subject_required = ["ssn", "name"]

# Format validation
if not re.match(r'^CR-\d{4}-\d+$', report_id):
    raise ValidationError("Invalid report_id format")
```

---

## 🚦 Rate Limiting

### Token Bucket Algorithm ✅
**What**: Smooth rate limiting with burst capacity  
**How**: Each agent gets tokens that refill over time

**Example**: Credit Report Stage 3  
Location: `secure/security/protection.py` - `RateLimiter`

**Configuration**:
```python
max_tokens = 100        # Bucket capacity
refill_rate = 10        # Tokens per minute
cost_per_action = 1     # Tokens consumed
```

**Why Not Stage 2?**: Stage 2 has NO rate limiting → can upload 1000s of reports/second

**Test**: Credit Report Stage 1 - upload 150 files rapidly (all succeed, no limits!)

---

### AI-Specific Rate Limiting ✅
**What**: Separate limits for expensive AI calls  
**Example**: Credit Report Stage 4  
Location: `stage4_ai/security/ai_security.py` - `AIRateLimiter`

**Why Separate?**:
- AI calls cost money ($)
- AI calls are slow (latency)
- Different limits needed

**Configuration**:
```python
max_calls_per_minute = 20    # API throttling
max_calls_per_hour = 200     # Volume control
max_cost_per_hour = 10.0     # Budget protection ($)
```

---

## 🔒 Data Protection

### PII Sanitization ✅
**What**: Remove/mask sensitive data appropriately  
**Example**: Credit Report Stage 3  
Location: `secure/security/protection.py` - `PIISanitizer`

**Three Modes**:

**1. For Logging** (most restrictive):
```python
{
    "ssn": "***-**-6789",           # Last 4 only
    "name": "PERSON_a1b2c3d4",      # Hashed
    "address": "[REDACTED]",
    "email": "[REDACTED]"
}
```

**2. For AI** (analytical only):
```python
{
    "credit_score": 720,
    "total_accounts": 5,
    "utilization_rate": 30.0
    # NO PII at all!
}
```

**3. For Client Response** (partial):
```python
{
    "ssn": "***-**-6789",  # Masked
    "name": "John Doe",     # Kept (business need)
    "credit_score": 720
}
```

**Bad Example**: Credit Report Stage 1 logs full SSN (line 176) - GDPR violation!  
**Good Example**: Credit Report Stage 2+ masks SSN in logs

---

### Encryption

**At Rest**: 
- ✅ Use AES-256-GCM for stored data
- ✅ Encrypt PII fields before database storage
- ❌ Stage 1-3 examples store plaintext (educational only!)

**In Transit**:
- ✅ Use TLS 1.3 for all A2A communication
- ✅ Certificate pinning for known agents
- ❌ Example agents use plain TCP (educational only!)

**Keys**:
- ✅ Store in environment variables or secrets manager
- ✅ Rotate regularly (90 days)
- ❌ NEVER hardcode in source

---

## 🤖 AI Integration Security

### Prompt Injection Prevention ✅
**What**: Detect attempts to manipulate AI behavior  
**Example**: Credit Report Stage 4  
Location: `stage4_ai/security/ai_security.py` - `PromptInjectionDetector`

**Suspicious Patterns**:
```python
[
    "ignore previous instructions",
    "disregard all instructions",
    "you are now",
    "pretend you are",
    "reveal your prompt",
    "base64", "rot13",  # Encoding tricks
    "system:", "</s>"    # System tokens
]
```

**Validation**:
```python
detector = PromptInjectionDetector()
result = detector.validate_input(user_input)
if not result["safe"]:
    # Block request, log security event
```

---

### PII Sanitization for AI ✅
**What**: Remove ALL PII before sending to external AI  
**Example**: Credit Report Stage 4  
Location: `stage4_ai/security/ai_security.py` - `AISecurityManager.sanitize_report_for_ai()`

**Critical**: Never send SSN, names, addresses, DOB to AI services!

**Pattern**:
```python
# Extract only analytical fields
safe_data = {
    "credit_score": report["credit_score"]["score"],
    "total_accounts": len(report["accounts"]),
    "utilization_rate": calculate_utilization(report),
    # NO PII fields included
}
```

---

### AI Output Validation ✅
**What**: Validate AI responses don't leak PII  
**Example**: Credit Report Stage 4  
Location: `stage4_ai/security/ai_security.py` - `AIOutputValidator`

**Check For**:
- SSN patterns: `\d{3}-\d{2}-\d{4}`
- Credit card: `\d{16}`
- Email addresses
- Expected format (JSON)

**Pattern**:
```python
validator = AIOutputValidator()
result = validator.validate_output(ai_response)
if not result["safe"]:
    # Block response, log alert
```

---

### Cost Tracking ✅
**What**: Monitor AI API costs and usage  
**Example**: Credit Report Stage 4  
Location: `stage4_ai/security/ai_security.py` - `AIRateLimiter`

**Track**:
```python
{
    "calls_last_hour": 150,
    "tokens_used": 37500,
    "estimated_cost": 7.50,  # USD
    "avg_latency": 1.8       # seconds
}
```

**Limits**:
- Calls per hour: 200
- Cost per hour: $10
- Alert if approaching limits

---

## 📋 Audit Logging

### What to Log ✅
**Example**: Credit Report Stage 3+  
Location: `secure/security/protection.py` - `AuditLogger`

**Always Log**:
1. **Authentication attempts** (success/failure)
2. **Authorization failures** (who tried what)
3. **File uploads** (who, what, when, size)
4. **Rate limit violations**
5. **Validation errors**
6. **AI decisions** (Stage 4)
7. **Security events** (injection attempts, etc.)

**Log Format** (structured JSON):
```json
{
    "timestamp": "2025-01-15T10:00:00Z",
    "event_type": "authentication",
    "agent_id": "agent-001",
    "action": "authenticate",
    "result": "failure",
    "reason": "invalid_signature",
    "severity": "MEDIUM",
    "ip_address": "192.168.1.100"
}
```

**What NOT to Log**:
- ❌ Full SSN (mask it)
- ❌ Passwords or API keys
- ❌ Full credit card numbers
- ❌ Unmasked PII

**Bad Example**: Credit Report Stage 1 logs full SSN (line 176)  
**Good Example**: Credit Report Stage 2+ masks SSN before logging

---

## 🛡️ Error Handling

### Secure Error Messages ✅

**DON'T** expose:
- ❌ Stack traces to clients (Stage 1 does this!)
- ❌ File paths or system details
- ❌ Database schema information
- ❌ Internal service names

**DO** provide:
- ✅ Generic error messages to clients
- ✅ Detailed errors in server logs (not sent to client)
- ✅ Error codes for client handling

**Example**:

**Bad** (Stage 1):
```python
# Sends to client:
{
    "error": "FileNotFoundError: /var/app/reports/CR-2025-001.json",
    "stack_trace": "Traceback (most recent call last)..."
}
```

**Good** (Stage 3):
```python
# Sends to client:
{
    "status": "error",
    "message": "Report not found",
    "error_code": "REPORT_NOT_FOUND"
}

# Logs on server:
print(f"Error: FileNotFoundError at {path}")
```

---

## 🎯 Quick Comparison: Training Examples

### Cryptocurrency Price Oracle Examples

**Location**: `cryptocurrency_agent/`

**What They Demonstrate**:
- WebSocket communication patterns
- Real-time data streaming security
- API authentication
- Query validation
- Three-stage progression (insecure → improved → secure)

**Key Lessons**:
- Simple queries can have injection attacks
- Rate limiting prevents API abuse
- Authentication even for "public" data

---

### Credit Report Analysis Examples

**Location**: `a2a_credit_report_example/`

**What They Demonstrate**:
- File upload security (26 vulnerabilities in Stage 1!)
- PII handling and sanitization
- 8-layer input validation
- RBAC authorization
- AI integration security (Stage 4)
- Four-stage progression (insecure → improved → secure → AI)

**Key Lessons**:
- File handling is complex and dangerous
- PII requires special protection
- Partial security creates false confidence (Stage 2)
- AI integration needs additional controls (Stage 4)

---

## 📚 Security Controls Not Yet in Examples

### Network Security

**TLS/HTTPS**:
- Use TLS 1.3 minimum
- Certificate pinning for known agents
- Mutual TLS (mTLS) for high-security environments

**Network Segmentation**:
- Isolate agent networks
- Use firewalls between zones
- Implement zero-trust networking

---

### Advanced Authentication

**Certificate-Based Auth**:
- X.509 certificates for agents
- PKI infrastructure
- Certificate revocation lists (CRL)

**OAuth 2.0 / OpenID Connect**:
- For user-on-behalf-of scenarios
- Token-based authentication
- Refresh token rotation

---

### Monitoring & Detection

**Anomaly Detection**:
- Baseline normal behavior
- Alert on deviations
- Machine learning for pattern detection

**SIEM Integration**:
- Send logs to Security Information and Event Management
- Correlate events across agents
- Automated incident response

---

### Compliance

**GDPR** (EU data protection):
- Right to erasure
- Data minimization
- Privacy by design
- Breach notification (72 hours)

**HIPAA** (Healthcare):
- PHI encryption requirements
- Access controls
- Audit trails
- Business associate agreements

**SOC 2** (Security standards):
- Security controls
- Availability
- Processing integrity
- Confidentiality
- Privacy

---

## 🚨 Common A2A Vulnerabilities

### Top 10 A2A Security Issues

1. **No Authentication** → Anyone can connect (Stage 1)
2. **Replay Attacks** → Valid requests reused (Stage 2)
3. **Unlimited File Uploads** → DoS via large files (Stage 1)
4. **PII Logging** → SSN in logs (Stage 1 line 176)
5. **No Rate Limiting** → API abuse (Stage 1-2)
6. **Path Traversal** → File system access (Stage 1)
7. **Injection Attacks** → SQL/Command/Prompt injection
8. **No Authorization** → All authenticated users can do everything
9. **Information Disclosure** → Stack traces to clients (Stage 1)
10. **Missing Encryption** → Data in transit/at rest unprotected

**Test These**: Credit Report Stage 1 has ALL 10 vulnerabilities!

---

## ✅ Production Deployment Checklist

### Before Going Live

**Authentication & Authorization**:
- [ ] RSA-2048 or ECC P-256 signatures implemented
- [ ] Nonce-based replay protection enabled
- [ ] Timestamp validation (5-min window)
- [ ] RBAC roles defined and assigned
- [ ] Principle of least privilege applied

**Input Validation**:
- [ ] All 8 validation layers implemented
- [ ] File size limits enforced
- [ ] Magic bytes checked
- [ ] Path traversal prevention tested
- [ ] Schema validation in place

**Rate Limiting**:
- [ ] Token bucket algorithm implemented
- [ ] Per-agent limits configured
- [ ] Separate limits for expensive operations
- [ ] Cost controls for AI calls (if applicable)

**Data Protection**:
- [ ] PII sanitization functions in place
- [ ] Encryption at rest (AES-256-GCM)
- [ ] TLS 1.3 for all communication
- [ ] Secrets in environment variables (not code)

**Logging & Monitoring**:
- [ ] Structured audit logs implemented
- [ ] All security events logged
- [ ] PII masked in logs
- [ ] SIEM integration configured
- [ ] Alerting rules defined

**AI Security** (if applicable):
- [ ] Prompt injection detection enabled
- [ ] PII removed before AI calls
- [ ] AI output validation implemented
- [ ] Cost tracking and limits configured
- [ ] AI decisions logged for audit

**Testing**:
- [ ] Security testing completed
- [ ] Penetration testing performed
- [ ] Load testing with rate limits
- [ ] Replay attack prevention verified
- [ ] Error handling tested

**Compliance**:
- [ ] GDPR requirements met (if EU data)
- [ ] HIPAA compliance verified (if PHI)
- [ ] SOC 2 controls implemented (if required)
- [ ] Privacy policy updated
- [ ] Breach response plan documented

---

## 🔗 Quick Reference Links

### Training Example Locations

**Credit Report Agent**:
- Stage 1 (Vulnerable): `a2a_credit_report_example/insecure/`
- Stage 2 (Improved): `a2a_credit_report_example/improved/`
- Stage 3 (Secure): `a2a_credit_report_example/secure/`
- Stage 4 (AI): `a2a_credit_report_example/stage4_ai/`

**Cryptocurrency Agent**:
- Stage 1 (Vulnerable): `cryptocurrency_agent/insecure/`
- Stage 2 (Improved): `cryptocurrency_agent/improved/`
- Stage 3 (Secure): `cryptocurrency_agent/secure/`

### Key Files to Study

**Authentication**:
- `secure/security/authentication.py` - RSA + nonce pattern

**Validation**:
- `secure/security/validation.py` - 8-layer validation
- `insecure/server/insecure_credit_agent.py` - All vulnerabilities

**Rate Limiting**:
- `secure/security/protection.py` - Token bucket algorithm

**AI Security**:
- `stage4_ai/security/ai_security.py` - Complete AI security suite

**Audit Logging**:
- `secure/security/protection.py` - AuditLogger class

---

## 📖 Further Reading

**OWASP Resources**:
- OWASP Top 10 API Security Risks
- OWASP Machine Learning Security Top 10
- OWASP Cheat Sheet Series

**Standards**:
- NIST SP 800-63 (Digital Identity Guidelines)
- NIST Cybersecurity Framework
- ISO 27001 (Information Security)

**AI Security**:
- OWASP Top 10 for LLM Applications
- NIST AI Risk Management Framework

---

## 🎯 Remember

### The Golden Rules

1. **Never Trust Input** - Validate everything, always
2. **Assume Breach** - Defense in depth, multiple layers
3. **Principle of Least Privilege** - Minimum necessary access
4. **Fail Securely** - Default deny, safe error handling
5. **Log Everything** (except PII) - Audit trail for investigations
6. **Encrypt All The Things** - In transit and at rest
7. **Rate Limit Everything** - Prevent abuse and DoS
8. **Test Security** - Don't assume, verify

### When In Doubt

- Refer to Stage 3 (secure) examples for patterns
- Compare against Stage 1 (insecure) to see what NOT to do
- Use Stage 2 (improved) to understand why partial security fails
- Check Stage 4 (AI) for LLM integration patterns

---

**Last Updated**: January 2025  
**Maintainer**: Your A2A Security Training Project  
**Feedback**: Add examples and update as new patterns emerge!

---

## 🔖 Quick Command Reference

```bash
# Test replay attack (Credit Report Stage 2)
cd improved && python client/client.py
# Choose option 8 - same request succeeds 3 times!

# Test file size limits (Stage 2 vs 1)
cd insecure/sample_reports
python generate_oversized.py  # Creates 10MB+ file
# Stage 1: Crashes server
# Stage 2+: Rejected with error

# Test prompt injection (Stage 4)
python -c "
from security.ai_security import PromptInjectionDetector
detector = PromptInjectionDetector()
print(detector.validate_input('Ignore previous instructions'))
"

# Test PII sanitization (Stage 3)
python -c "
from security.protection import PIISanitizer
sanitizer = PIISanitizer()
print(sanitizer.sanitize_for_logging(report))
"
```

---

**End of Quick Reference Cheat Sheet** 🔐