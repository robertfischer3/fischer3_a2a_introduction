# Agent-to-Agent (A2A) Security Cheat Sheet

> **Quick Reference Guide** for securing A2A systems  
> References training examples: Cryptocurrency Agent & Credit Report Agent

---

## 🔐 Authentication & Authorization

### Authentication Best Practices

| Control | Insecure ❌ | Secure ✅ | Example |
|---------|------------|----------|---------|
| **Method** | None / Shared secret | RSA-2048 or ECC | Credit Stage 3 |
| **Replay Protection** | No nonce | Unique nonce per request | Credit Stage 3 |
| **Timestamp** | Not validated | 5-minute window | Credit Stage 3 |
| **Key Management** | Hardcoded | Environment vars / HSM | Credit Stage 4 |

**Quick Check:**
```python
# ❌ BAD: No authentication
handle_request(message)

# ✅ GOOD: RSA signature + nonce + timestamp
auth_tag = {
    "agent_id": "agent-001",
    "timestamp": "2025-01-15T10:00:00Z",
    "nonce": "unique-32-char-hex",
    "signature": "RSA-signature"
}
if not verify_signature(message, auth_tag): reject()
if nonce_already_used(auth_tag["nonce"]): reject()
if timestamp_expired(auth_tag["timestamp"]): reject()
```

**See:** Credit Report Stage 3 (`authentication.py`)

---

### Authorization (RBAC)

**4 Standard Roles:**

```python
ROLES = {
    "viewer": ["read"],
    "analyst": ["read", "write"],
    "admin": ["read", "write", "delete", "manage_users"],
    "auditor": ["read", "view_logs"]
}
```

**Quick Check:**
```python
# ❌ BAD: No authorization
if authenticated: allow_action()

# ✅ GOOD: Check role permissions
if not has_permission(agent_id, action): reject()
```

**See:** Credit Report Stage 3 (`protection.py`)

---

## 🛡️ Input Validation

### 8-Layer Validation Framework

| Layer | Check | Example |
|-------|-------|---------|
| **1. Size** | Max file/message size | 5MB limit |
| **2. Type** | File extension / content-type | .json, .csv only |
| **3. Content** | Magic bytes validation | JSON starts with `{` |
| **4. Sanitization** | Path traversal, injection | Remove `../`, SQL chars |
| **5. Parsing** | Safe decode, limits | Recursion depth |
| **6. Schema** | Required fields, types | JSON schema |
| **7. Ranges** | Business logic validation | Score 300-850 |
| **8. Injection** | SQL, XSS, command injection | Parameterized queries |

**Quick Check:**
```python
# ❌ BAD: No validation
data = request.get("data")
process(data)

# ✅ GOOD: 8-layer validation
if len(data) > MAX_SIZE: reject()
if ext not in ALLOWED_TYPES: reject()
if not valid_magic_bytes(data): reject()
safe_filename = sanitize(filename)
parsed = safe_parse(data)
if not valid_schema(parsed): reject()
if not valid_ranges(parsed): reject()
sanitized = remove_injection_chars(parsed)
```

**See:** 
- Credit Report Stage 3 (`validation.py`)
- Credit Report Stage 1 (all vulnerabilities)

---

## 🚦 Rate Limiting

### Token Bucket Algorithm

**Standard Limits:**
- **General requests**: 100 tokens, refill 10/minute
- **AI requests**: 20/minute, 200/hour, $10/hour
- **File uploads**: Lower rate (e.g., 10/hour)

**Quick Check:**
```python
# ❌ BAD: No rate limiting
process_request(agent_id, request)

# ✅ GOOD: Token bucket
bucket = get_bucket(agent_id)
if bucket.tokens < cost: reject("Rate limited")
bucket.tokens -= cost
process_request(agent_id, request)
```

**See:** 
- Credit Report Stage 3 (`protection.py`)
- Credit Report Stage 4 (`ai_security.py` - AI-specific)

---

## 🔒 Data Privacy (PII Protection)

### PII Handling Modes

| Mode | SSN | Name | Address | Use Case |
|------|-----|------|---------|----------|
| **Logging** | ***-**-6789 | HASH_abc123 | [REDACTED] | Server logs |
| **AI Processing** | [REMOVED] | [REMOVED] | [REMOVED] | External APIs |
| **Client Response** | ***-**-6789 | John Doe | City, State | Business need |
| **Storage** | [ENCRYPTED] | [ENCRYPTED] | [ENCRYPTED] | Database |

**Quick Check:**
```python
# ❌ BAD: Log full PII
log(f"Processing SSN: {report['ssn']}")

# ✅ GOOD: Mask PII in logs
masked_ssn = f"***-**-{report['ssn'][-4:]}"
log(f"Processing SSN: {masked_ssn}")

# ✅ GOOD: Remove PII before AI
ai_data = {
    "credit_score": report["credit_score"],
    "total_accounts": len(report["accounts"])
    # No SSN, name, address!
}
```

**See:**
- Credit Report Stage 2 (partial masking)
- Credit Report Stage 3 (comprehensive)
- Credit Report Stage 4 (AI-specific sanitization)

---

## 🤖 AI-Specific Security

### Prompt Injection Prevention

**Dangerous Patterns:**
```python
BLOCK_PATTERNS = [
    "ignore previous instructions",
    "disregard all",
    "you are now",
    "reveal your prompt",
    "system:",
    "base64", "rot13"
]
```

**Quick Check:**
```python
# ❌ BAD: Send user input directly to AI
ai_response = gemini.generate(user_input)

# ✅ GOOD: Detect injection, use structured prompts
if detect_injection(user_input): reject()
sanitized = remove_pii(report)
prompt = f"Analyze this data: {sanitized}"
ai_response = gemini.generate(prompt)
```

**See:** Credit Report Stage 4 (`ai_security.py`)

---

### AI Output Validation

**Check Every AI Response:**
```python
# ❌ BAD: Return AI output directly
return ai_response

# ✅ GOOD: Validate output
if detect_pii_in_output(ai_response): reject()
if not valid_json(ai_response): reject()
if len(ai_response) > MAX_LENGTH: reject()
return ai_response
```

**See:** Credit Report Stage 4 (`ai_security.py`)

---

## 📊 Audit Logging

### Security Events to Log

| Event Type | Priority | Fields |
|------------|----------|--------|
| **Authentication** | HIGH | agent_id, result, reason, ip |
| **Authorization Failure** | HIGH | agent_id, action, reason |
| **Rate Limit Hit** | MEDIUM | agent_id, limit_type |
| **File Upload** | MEDIUM | agent_id, filename, size |
| **AI Call** | MEDIUM | agent_id, model, tokens, cost |
| **Prompt Injection** | CRITICAL | agent_id, pattern, payload_hash |
| **Data Access** | LOW | agent_id, resource_id |

**Quick Check:**
```python
# ❌ BAD: No logging
if authentication_failed: return error

# ✅ GOOD: Log security events
audit_log({
    "event": "auth_failure",
    "agent_id": agent_id,
    "reason": "invalid_signature",
    "timestamp": now(),
    "ip": request_ip
})
```

**See:** Credit Report Stage 3 & 4 (`protection.py`, `ai_security.py`)

---

## 💰 Financial Data Security

### Price Manipulation Prevention

**See:** Cryptocurrency Agent (all stages)

```python
# ❌ BAD: Accept any price
set_price(user_provided_price)

# ✅ GOOD: Validate against external sources
real_price = fetch_from_exchange()
if abs(user_price - real_price) > THRESHOLD:
    reject("Price manipulation detected")

# ✅ GOOD: Require multi-sig for large transactions
if amount > LARGE_THRESHOLD:
    if not multi_sig_verified(): reject()
```

**Key Controls:**
- External price validation
- Transaction size limits
- Multi-signature requirements
- Rate limiting on trades
- Audit trail of all transactions

---

## 🔢 Injection Attack Prevention

### Common Injection Types

| Type | Example Attack | Prevention |
|------|---------------|------------|
| **SQL** | `'; DROP TABLE--` | Parameterized queries |
| **Command** | `; rm -rf /` | Never shell out, whitelist |
| **Log** | `\nADMIN: granted` | Strip control chars |
| **Path** | `../../etc/passwd` | Basename only, whitelist |
| **XSS** | `<script>evil</script>` | HTML escape |
| **Prompt** | `Ignore instructions` | Pattern detection |

**Quick Check:**
```python
# ❌ BAD: Direct string interpolation
query = f"SELECT * FROM users WHERE name='{name}'"
os.system(f"process {filename}")

# ✅ GOOD: Parameterized / sanitized
query = "SELECT * FROM users WHERE name=?"
cursor.execute(query, (name,))

safe_filename = os.path.basename(filename)
# Don't use os.system at all!
```

**See:** Credit Report Stage 1 (vulnerabilities), Stage 3 (prevention)

---

## 🌐 Network Security

### Transport Security

```python
# ❌ BAD: Plain TCP
socket.connect((host, 9000))

# ✅ GOOD: TLS 1.3+
ssl_context = ssl.create_default_context()
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
socket = ssl_context.wrap_socket(socket)
```

**Not Yet in Examples** - Add TLS layer to all stages

---

### API Key Management

```python
# ❌ BAD: Hardcoded
API_KEY = "abc123secret"

# ✅ GOOD: Environment variable
API_KEY = os.getenv("API_KEY")
if not API_KEY: raise Error("API_KEY not set")

# ✅ BETTER: Secret management service
API_KEY = secrets_manager.get("api_key")
```

**See:** Credit Report Stage 4 (Gemini API key)

---

## 📁 File Upload Security

### Secure File Handling Checklist

```python
# ✅ 1. Size limit
if file_size > 5_MB: reject()

# ✅ 2. Type validation
if ext not in ['.json', '.csv']: reject()

# ✅ 3. Magic bytes
if not file.startswith(b'{'): reject()

# ✅ 4. Sanitize filename
safe = os.path.basename(filename)
safe = re.sub(r'[^\w\s.-]', '', safe)

# ✅ 5. Virus scan (not in examples yet)
if not virus_scan(file): reject()

# ✅ 6. Store outside web root
save_to('/var/data/uploads/', safe)  # Not /var/www/

# ✅ 7. Encrypt at rest
encrypted = encrypt_file(file, key)
save(encrypted)
```

**See:** Credit Report (all stages show progression)

---

## 🎯 Common Vulnerability Patterns

### Critical Mistakes to Avoid

| Vulnerability | Example | Fix | Reference |
|--------------|---------|-----|-----------|
| **No Auth** | Anyone can connect | RSA + nonce | Credit Stage 1→3 |
| **No Rate Limit** | DoS possible | Token bucket | Credit Stage 1→3 |
| **SSN in Logs** | GDPR violation | Mask to last 4 | Credit Stage 1→2 |
| **No Input Valid** | Injection attacks | 8-layer validation | Credit Stage 1→3 |
| **Replay Attacks** | Reuse requests | Nonce cache | Credit Stage 2→3 |
| **No Cost Control** | Runaway AI bills | Rate limit + budget | Credit Stage 4 |
| **PII to AI** | Data leakage | Sanitize before API | Credit Stage 4 |
| **No RBAC** | Unauthorized access | Role-based perms | Credit Stage 3 |

---

## 🚨 Incident Response

### Quick Response Guide

**Authentication Failure Spike:**
```bash
# Check logs
grep "auth_failure" audit.log | tail -100

# Block IP if needed
iptables -A INPUT -s <IP> -j DROP

# Rotate keys if compromised
./rotate_keys.sh
```

**Rate Limit Exceeded:**
```bash
# Identify offender
grep "rate_limit" audit.log | cut -d, -f2 | sort | uniq -c

# Temporary ban
ban_agent("agent-id", duration="1h")
```

**Prompt Injection Detected:**
```bash
# Alert security team
alert_security("prompt_injection", agent_id, payload_hash)

# Review logs
grep "prompt_injection" audit.log

# Update detection patterns if new attack
add_pattern("new_attack_pattern")
```

**Not Yet in Examples** - Add incident response module

---

## 📊 Security Metrics to Track

### Essential KPIs

```python
# Authentication
- Failed auth attempts / hour
- Unique agents / day
- Average auth latency

# Authorization  
- Permission denials / hour
- Role distribution

# Rate Limiting
- Rate limit hits / hour
- Top rate-limited agents

# File Uploads
- Files rejected / hour (by reason)
- Average file size
- File type distribution

# AI Security
- Prompt injection attempts / day
- AI cost / hour
- AI latency p95
- PII detections in output

# General
- Total requests / minute
- Error rate %
- Audit log volume
```

**Not Yet in Examples** - Add metrics dashboard

---

## 🔧 Security Configuration

### Recommended Settings

```python
# File Handling
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = ['.json', '.csv']
MAX_FILES_PER_HOUR = 100

# Rate Limiting
GENERAL_MAX_TOKENS = 100
GENERAL_REFILL_RATE = 10  # per minute
AI_MAX_CALLS_PER_MINUTE = 20
AI_MAX_CALLS_PER_HOUR = 200
AI_MAX_COST_PER_HOUR = 10.0  # dollars

# Authentication
NONCE_TTL = 300  # 5 minutes
TIMESTAMP_WINDOW = 300  # 5 minutes
KEY_SIZE = 2048  # RSA bits

# Privacy
SSN_LOG_FORMAT = "***-**-{last_4}"
PII_FIELDS = ["ssn", "name", "address", "dob", "email", "phone"]

# AI Security
MAX_PROMPT_LENGTH = 10000
MAX_OUTPUT_LENGTH = 5000
PROMPT_INJECTION_PATTERNS = [...]  # See Stage 4
```

---

## 📚 Quick Reference by Stage

### Stage 1 (Insecure) - Learn Vulnerabilities
- ❌ No authentication
- ❌ No rate limiting  
- ❌ No input validation
- ❌ PII in logs
- ❌ No file size limits
- **Use for:** Understanding what NOT to do

### Stage 2 (Improved) - Partial Security
- ✅ Basic auth (HMAC)
- ✅ File size limits
- ✅ SSN masking
- ⚠️ Still has 10 vulnerabilities
- **Use for:** Understanding why partial security fails

### Stage 3 (Secure) - Production Ready
- ✅ RSA + nonce auth
- ✅ 8-layer validation
- ✅ Token bucket rate limiting
- ✅ RBAC authorization
- ✅ Comprehensive PII protection
- ✅ Audit logging
- **Use for:** Production patterns

### Stage 4 (AI Integration) - AI Security
- ✅ All Stage 3 controls
- ✅ Prompt injection detection
- ✅ AI output validation
- ✅ Cost tracking
- ✅ PII sanitization for AI
- **Use for:** Secure AI integration

---

## 🎓 Security Principles

### Defense in Depth
- **Multiple layers**: Authentication + authorization + validation
- **Fail secure**: Deny by default
- **Least privilege**: Minimum permissions needed

### Zero Trust
- **Never trust**: Always verify
- **Assume breach**: Limit blast radius
- **Verify explicitly**: Check everything

### Privacy by Design
- **Data minimization**: Collect only what's needed
- **PII protection**: Multiple modes (log, AI, response, storage)
- **Audit trail**: Log all access to sensitive data

---

## 🔍 Security Checklist

### Pre-Deployment

- [ ] Authentication with nonce-based replay protection
- [ ] RBAC authorization implemented
- [ ] 8-layer input validation
- [ ] Rate limiting (general + AI if applicable)
- [ ] PII sanitization in all contexts
- [ ] Audit logging configured
- [ ] TLS/HTTPS enabled
- [ ] API keys in environment variables
- [ ] File upload size limits
- [ ] Error messages don't leak info
- [ ] Security headers set
- [ ] Monitoring and alerting configured

### Post-Deployment

- [ ] Monitor authentication failures
- [ ] Track rate limit violations
- [ ] Review audit logs daily
- [ ] Monitor AI costs (if applicable)
- [ ] Check for prompt injection attempts
- [ ] Verify PII protection working
- [ ] Performance metrics acceptable
- [ ] Incident response plan tested

---

## 📖 Example References

### Cryptocurrency Agent
- **Stage 1**: No auth, price manipulation, DoS
- **Stage 2**: Basic validation, still exploitable
- **Stage 3**: Production security (theoretical)

### Credit Report Agent  
- **Stage 1**: 26 documented vulnerabilities
- **Stage 2**: 27 improvements, 10 remaining issues
- **Stage 3**: Production security (9/10)
- **Stage 4**: + AI security (9/10)

**Modules to Reference:**
- `authentication.py` - RSA + nonce auth
- `validation.py` - 8-layer validation
- `protection.py` - Rate limiting, RBAC, PII, audit
- `ai_security.py` - AI-specific security

---

## 🚀 Quick Start Commands

```bash
# Stage 1 - See vulnerabilities
cd insecure && python server/insecure_agent.py
python client/client.py  # Try exploits

# Stage 2 - See improvements
cd improved && python server/improved_agent.py
python client/client.py  # Try remaining exploits

# Stage 3 - Production patterns
cd secure && python server/secure_agent.py
python client/client.py  # All exploits blocked

# Stage 4 - AI integration
cd stage4_ai
export GOOGLE_API_KEY='your-key'
python -c "from security.ai_security import *; test_security()"
```

---

## 📞 Need Help?

**Security Issues by Category:**
- **Authentication**: See Credit Stage 3 `authentication.py`
- **Input Validation**: See Credit Stage 3 `validation.py`
- **Rate Limiting**: See Credit Stage 3 `protection.py`
- **AI Security**: See Credit Stage 4 `ai_security.py`
- **All Vulnerabilities**: See Credit Stage 1 `SECURITY_ANALYSIS.md`

**General Pattern:** Look at Stage 1 for vulnerabilities, Stage 3 for fixes

---

**Security Rating Guide:**
- **0-3/10**: Critical vulnerabilities, do not deploy
- **4-6/10**: Improved but still risky
- **7-8/10**: Good for internal/low-risk use
- **9/10**: Production-ready (examples achieve this)
- **10/10**: Military-grade (requires HSM, formal verification, etc.)

---

*This cheat sheet covers A2A security patterns demonstrated in the training examples. For additional security concerns not yet covered, refer to OWASP Top 10 and industry security standards.*

**Last Updated:** 2025-01-15  
**Examples:** Cryptocurrency Agent, Credit Report Agent (Stages 1-4)
