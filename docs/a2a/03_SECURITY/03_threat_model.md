# Threat Model for Multi-Agent Systems

> **Learning Path**: Security  
> **Difficulty**: Advanced  
> **Prerequisites**: [Authentication Overview](./01_authentication_overview.md), [Authentication Tags](./02_authentication_tags.md)

## Navigation
← Previous: [Authentication Tags](./02_authentication_tags.md) | Next: [Security Best Practices](./04_security_best_practices.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

By the end of this document, you will understand:
- [ ] Common attack vectors in multi-agent systems
- [ ] How attackers exploit vulnerabilities
- [ ] Impact and likelihood of each threat
- [ ] Effective mitigations for each attack
- [ ] How to perform threat modeling for your systems

---

## 🏗️ Threat Modeling Framework

### STRIDE Model Applied to Agents

We use the STRIDE model to categorize threats:

| Category | Threat | Example |
|----------|--------|---------|
| **S**poofing | Identity forgery | Attacker impersonates admin agent |
| **T**ampering | Data modification | Modify agent card capabilities |
| **R**epudiation | Deny actions | Agent claims it didn't send message |
| **I**nformation Disclosure | Data leakage | Intercept sensitive agent data |
| **D**enial of Service | Resource exhaustion | Flood agent with requests |
| **E**levation of Privilege | Unauthorized access | Low-privilege agent gains admin rights |

---

## 🎭 Threat Actors

### Actor 1: External Attacker

**Profile**: Outside malicious party  
**Motivation**: Financial gain, disruption, espionage  
**Capabilities**: 
- Network access
- Common tools
- Public vulnerabilities

**Typical Attacks**:
- Impersonation
- Man-in-the-middle
- Denial of service

---

### Actor 2: Malicious Agent

**Profile**: Compromised or rogue agent in the system  
**Motivation**: Sabotage, data theft, privilege escalation  
**Capabilities**:
- Valid credentials
- Internal network access
- Knowledge of system

**Typical Attacks**:
- Privilege escalation
- Data exfiltration
- Lateral movement

---

### Actor 3: Insider Threat

**Profile**: Malicious employee or contractor  
**Motivation**: Revenge, financial gain, espionage  
**Capabilities**:
- Legitimate access
- Deep system knowledge
- Trust relationships

**Typical Attacks**:
- Data theft
- Backdoor creation
- Credential abuse

---

## 🔴 Critical Threats

### Threat 1: Agent Impersonation

**Description**: Attacker pretends to be a legitimate agent

**Attack Scenario**:
```python
# Attacker creates fake agent card
fake_admin_card = {
    "agent_id": "admin-super-user-001",
    "name": "SystemAdmin",
    "capabilities": ["admin", "delete_all", "full_access"],
    "security_level": "PRIVILEGED"
    # No signature! Or forged signature
}

# If server doesn't verify signature...
server.handle_handshake(fake_admin_card)  # ACCEPTED!

# Attacker now has full admin access
attacker.delete_all_agents()
attacker.exfiltrate_sensitive_data()
```

**Impact**: 🔴 **CRITICAL**
- Complete system compromise
- Data theft
- Service disruption
- Reputation damage

**Likelihood**: 🟡 **MEDIUM** (if authentication weak)

**Attack Tree**:
```
Agent Impersonation
├─ No signature verification
│  └─ Mitigation: Require signatures
├─ Weak signature algorithm
│  └─ Mitigation: Use RS256 or ES256
├─ No certificate validation
│  └─ Mitigation: Implement PKI
└─ Expired credentials accepted
   └─ Mitigation: Check expiration
```

**Mitigations**:

1. **Always verify signatures**:
```python
def authenticate_agent(agent_card):
    # ✅ REQUIRED: Verify cryptographic signature
    if not verify_signature(agent_card):
        raise AuthenticationError("Invalid signature")
    
    # ✅ REQUIRED: Check expiration
    if agent_card.is_expired():
        raise AuthenticationError("Card expired")
    
    # ✅ REQUIRED: Verify certificate chain
    if not verify_certificate_chain(agent_card):
        raise AuthenticationError("Invalid certificate")
    
    return True
```

2. **Use strong cryptographic algorithms** (RSA-2048+ or ECC-256+)
3. **Implement certificate pinning** for high-security agents
4. **Monitor for suspicious authentication patterns**

**Detection**:
```python
# Detect impersonation attempts
def detect_impersonation(agent_id, connection):
    # Check for suspicious patterns
    if connection.source_ip != get_known_ip(agent_id):
        alert("Agent connecting from new IP")
    
    if connection.tls_fingerprint != get_known_fingerprint(agent_id):
        alert("Agent TLS fingerprint changed")
    
    if get_failed_auth_count(agent_id) > 3:
        alert("Multiple failed auth attempts")
```

---

### Threat 2: Man-in-the-Middle (MITM)

**Description**: Attacker intercepts communication between agents

**Attack Scenario**:
```
Agent A                  Attacker                Agent B
   |                        |                       |
   |--[AgentCard + Data]--->|                       |
   |                        |--[Modified Data]----->|
   |                        |<--[Response]----------|
   |<--[Modified Response]--|                       |
   
Attacker can:
- Read all data (credentials, business data)
- Modify messages in transit
- Impersonate either party
- Replay captured messages
```

**Impact**: 🔴 **CRITICAL**
- Complete communication compromise
- Credential theft
- Data manipulation
- Undetected tampering

**Likelihood**: 🟢 **LOW** (if using TLS properly)

**Attack Tree**:
```
Man-in-the-Middle
├─ No encryption
│  └─ Mitigation: Use TLS 1.3
├─ Weak TLS configuration
│  └─ Mitigation: Strong cipher suites only
├─ Certificate validation skipped
│  └─ Mitigation: Enforce validation
└─ No certificate pinning
   └─ Mitigation: Pin certificates
```

**Mitigations**:

1. **Always use TLS 1.3**:
```python
# ✅ SECURE: TLS 1.3 with strong ciphers
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')

# ✅ SECURE: Require client certificates (mTLS)
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.load_verify_locations('trusted_ca.pem')
```

2. **Implement certificate pinning**:
```python
def verify_certificate_pin(peer_cert, expected_pin):
    """Verify certificate against known pin"""
    cert_pin = hashlib.sha256(peer_cert.public_bytes()).hexdigest()
    
    if cert_pin != expected_pin:
        raise SecurityError("Certificate pin mismatch - MITM attack?")
```

3. **Use message-level encryption** (defense in depth):
```python
def send_message(agent_card, message):
    # Encrypt message with recipient's public key
    encrypted = encrypt_with_public_key(
        message,
        agent_card.public_key
    )
    
    # Sign with our private key
    signature = sign_with_private_key(encrypted, our_private_key)
    
    return {
        "encrypted_message": encrypted,
        "signature": signature
    }
```

**Detection**:
```python
# Detect MITM attempts
def detect_mitm(connection):
    # Check for cert changes
    if connection.peer_cert_changed():
        alert("CRITICAL: Certificate changed mid-session")
        terminate_connection()
    
    # Check for unexpected renegotiation
    if connection.unexpected_renegotiation():
        alert("Suspicious TLS renegotiation")
        terminate_connection()
```

---

### Threat 3: Replay Attacks

**Description**: Attacker captures and retransmits legitimate messages

**Attack Scenario**:
```python
# 1. Legitimate transaction
legitimate_transfer = {
    "message_type": "REQUEST",
    "sender_id": "bank-agent-001",
    "method": "transfer_funds",
    "params": {
        "from": "account-123",
        "to": "merchant-456",
        "amount": 1000
    }
}

# 2. Attacker intercepts message
intercepted = capture_network_traffic()

# 3. Attacker replays message 100 times
for i in range(100):
    send_to_server(intercepted)

# Result: $100,000 transferred instead of $1,000!
```

**Impact**: 🔴 **CRITICAL**
- Financial loss
- Duplicate operations
- System state corruption
- Data integrity loss

**Likelihood**: 🟡 **MEDIUM** (if no replay protection)

**Attack Tree**:
```
Replay Attack
├─ No nonce validation
│  └─ Mitigation: Implement nonce tracking
├─ No timestamp validation
│  └─ Mitigation: Reject old messages
├─ Nonce reuse allowed
│  └─ Mitigation: Track used nonces
└─ Timestamp window too large
   └─ Mitigation: 5-minute window max
```

**Mitigations**:

1. **Implement nonce-based protection**:
```python
class ReplayProtection:
    def __init__(self):
        self.used_nonces = {}  # nonce -> timestamp
        self.nonce_window = timedelta(minutes=5)
    
    def validate_message(self, message):
        # ✅ REQUIRED: Check nonce hasn't been used
        if message.nonce in self.used_nonces:
            raise ReplayAttackError(f"Nonce {message.nonce} already used")
        
        # ✅ REQUIRED: Check timestamp freshness
        msg_time = datetime.fromisoformat(message.timestamp)
        if datetime.now() - msg_time > self.nonce_window:
            raise ReplayAttackError("Message too old")
        
        # Mark nonce as used
        self.used_nonces[message.nonce] = datetime.now()
        
        # Clean up old nonces
        self.cleanup_expired_nonces()
```

2. **Use short time windows**:
```python
MAX_MESSAGE_AGE = timedelta(minutes=5)

def validate_timestamp(message_timestamp):
    msg_time = datetime.fromisoformat(message_timestamp)
    age = datetime.now() - msg_time
    
    if age > MAX_MESSAGE_AGE:
        raise ValidationError("Message expired")
    
    if age < timedelta(seconds=-30):  # Allow 30s clock skew
        raise ValidationError("Message from future")
```

3. **Combine nonce + timestamp + sequence number**:
```python
def generate_secure_message_id():
    return f"{uuid.uuid4()}-{datetime.now().isoformat()}-{sequence_num}"
```

**Detection**:
```python
def detect_replay(message, agent_id):
    # Detect suspicious patterns
    recent_nonces = get_recent_nonces(agent_id, minutes=1)
    
    if len(recent_nonces) > 100:
        alert(f"Agent {agent_id} sending excessive requests")
    
    # Check for identical messages
    message_hash = hash_message(message)
    if message_hash in recent_message_hashes:
        alert(f"Identical message detected from {agent_id}")
```

---

## 🟡 High-Severity Threats

### Threat 4: Privilege Escalation

**Description**: Agent gains unauthorized elevated permissions

**Attack Scenario**:
```python
# Read-only agent modifies its own capabilities
low_privilege_card = {
    "agent_id": "reader-001",
    "capabilities": ["read_public_data"]  # Original capabilities
}

# Attacker modifies card
escalated_card = {
    "agent_id": "reader-001",
    "capabilities": ["read_public_data", "admin", "delete_all"]  # ESCALATED!
}

# If server doesn't verify capabilities...
if "admin" in received_card.capabilities:  # Trusts claimed capabilities
    grant_admin_access()  # VULNERABLE!
```

**Impact**: 🟡 **HIGH**
- Unauthorized access
- Data modification/deletion
- System compromise
- Compliance violations

**Likelihood**: 🟡 **MEDIUM**

**Mitigations**:

1. **Never trust claimed capabilities**:
```python
def verify_capabilities(agent_card):
    # ✅ SECURE: Verify against authoritative source
    authorized_capabilities = get_authorized_capabilities(agent_card.agent_id)
    
    # Check if claimed capabilities are subset of authorized
    claimed = set(agent_card.capabilities)
    authorized = set(authorized_capabilities)
    
    if not claimed.issubset(authorized):
        unauthorized = claimed - authorized
        raise PrivilegeEscalationError(
            f"Unauthorized capabilities: {unauthorized}"
        )
```

2. **Sign capabilities with CA**:
```python
def verify_capability_attestation(agent_card):
    # Capabilities must be signed by certificate authority
    cap_data = json.dumps(agent_card.capabilities, sort_keys=True)
    
    if not verify_ca_signature(cap_data, agent_card.capability_signature):
        raise ValidationError("Invalid capability signature")
```

3. **Implement RBAC with centralized policy**:
```python
class RBACEnforcer:
    def check_permission(self, agent_id, operation):
        role = get_agent_role(agent_id)  # From auth server
        permissions = get_role_permissions(role)  # From policy server
        
        if operation not in permissions:
            raise AuthorizationError(f"Role {role} cannot {operation}")
```

---

### Threat 5: Denial of Service (DOS)

**Description**: Attacker overwhelms system with requests

**Attack Scenarios**:

**Scenario A: Request Flooding**
```python
# Flood server with requests
while True:
    for i in range(10000):
        send_request({"method": "get_price", "params": {"currency": "BTC"}})
```

**Scenario B: Resource Exhaustion**
```python
# Send huge payloads
huge_payload = "A" * 100_000_000  # 100MB string
send_request({"method": "process", "data": huge_payload})
```

**Scenario C: Slow Loris**
```python
# Open connections but send data slowly
connection = open_connection()
for i in range(1000):
    send_partial_data(connection, 1_byte)
    time.sleep(10)  # Tie up connection for hours
```

**Impact**: 🟡 **HIGH**
- Service unavailability
- Revenue loss
- User frustration
- Operational costs

**Likelihood**: 🔴 **HIGH**

**Mitigations**:

1. **Rate limiting (token bucket)**:
```python
class RateLimiter:
    def __init__(self, rate=100, per=60):
        self.rate = rate  # requests
        self.per = per    # seconds
        self.allowance = {}
        self.last_check = {}
    
    def allow_request(self, agent_id):
        current = time.time()
        
        if agent_id not in self.last_check:
            self.allowance[agent_id] = self.rate
            self.last_check[agent_id] = current
        
        time_passed = current - self.last_check[agent_id]
        self.last_check[agent_id] = current
        
        # Add tokens based on time passed
        self.allowance[agent_id] += time_passed * (self.rate / self.per)
        
        if self.allowance[agent_id] > self.rate:
            self.allowance[agent_id] = self.rate
        
        if self.allowance[agent_id] < 1.0:
            return False  # Rate limited
        
        self.allowance[agent_id] -= 1.0
        return True
```

2. **Request size limits**:
```python
MAX_REQUEST_SIZE = 1_000_000  # 1MB

def validate_request_size(request):
    size = len(json.dumps(request))
    
    if size > MAX_REQUEST_SIZE:
        raise ValidationError(f"Request too large: {size} bytes")
```

3. **Connection limits per agent**:
```python
class ConnectionLimiter:
    def __init__(self, max_connections=10):
        self.max_connections = max_connections
        self.active_connections = {}
    
    def allow_connection(self, agent_id):
        count = self.active_connections.get(agent_id, 0)
        
        if count >= self.max_connections:
            return False
        
        self.active_connections[agent_id] = count + 1
        return True
```

4. **Timeouts**:
```python
# Request timeout
@timeout(seconds=30)
def handle_request(request):
    return process_request(request)

# Connection timeout
socket.settimeout(30)
```

**Detection**:
```python
def detect_dos(agent_id):
    metrics = get_agent_metrics(agent_id, window=60)
    
    # High request rate
    if metrics.requests_per_minute > 1000:
        alert(f"DOS: High request rate from {agent_id}")
    
    # Large requests
    if metrics.avg_request_size > 500_000:
        alert(f"DOS: Large requests from {agent_id}")
    
    # Many connections
    if metrics.connection_count > 100:
        alert(f"DOS: Many connections from {agent_id}")
```

---

### Threat 6: Injection Attacks

**Description**: Attacker injects malicious code/commands via input

**Attack Scenarios**:

**SQL Injection**:
```python
# Vulnerable code
currency = request.params["currency"]  # User input: "BTC'; DROP TABLE agents;--"
query = f"SELECT price FROM prices WHERE currency = '{currency}'"
db.execute(query)  # VULNERABLE!
```

**Command Injection**:
```python
# Vulnerable code
filename = request.params["file"]  # User input: "data.csv; rm -rf /"
os.system(f"cat {filename}")  # VULNERABLE!
```

**Code Injection**:
```python
# Vulnerable code
formula = request.params["formula"]  # User input: "__import__('os').system('evil')"
result = eval(formula)  # EXTREMELY VULNERABLE!
```

**Impact**: 🔴 **CRITICAL**
- Remote code execution
- Database compromise
- Data theft/destruction
- Complete system compromise

**Likelihood**: 🟡 **MEDIUM**

**Mitigations**:

1. **Input validation and sanitization**:
```python
def validate_currency(currency):
    # Whitelist validation
    ALLOWED_CURRENCIES = {"BTC", "ETH", "XRP"}
    
    if currency not in ALLOWED_CURRENCIES:
        raise ValidationError(f"Invalid currency: {currency}")
    
    return currency

def sanitize_string(value):
    # Remove dangerous characters
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "<", ">"]
    
    for char in dangerous_chars:
        if char in value:
            raise ValidationError(f"Dangerous character: {char}")
    
    return value
```

2. **Use parameterized queries**:
```python
# ✅ SECURE: Parameterized query
def get_price(currency):
    query = "SELECT price FROM prices WHERE currency = ?"
    return db.execute(query, (currency,))  # Parameterized
```

3. **Never use eval() or exec()**:
```python
# ❌ NEVER DO THIS
result = eval(user_input)

# ✅ Use safe alternatives
import ast
result = ast.literal_eval(safe_expression)  # Only literals, no code
```

4. **Input type validation**:
```python
from pydantic import BaseModel, validator

class PriceRequest(BaseModel):
    currency: str
    
    @validator('currency')
    def validate_currency(cls, v):
        if not v.isalpha() or len(v) != 3:
            raise ValueError('Invalid currency format')
        return v.upper()
```

**Detection**:
```python
def detect_injection(input_string):
    INJECTION_PATTERNS = [
        r"'; DROP TABLE",
        r"OR 1=1",
        r"__import__",
        r"<script",
        r"javascript:",
        r"\.\./",  # Path traversal
        r"cmd\.exe",
        r"/bin/bash"
    ]
    
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            raise InjectionAttemptError(f"Injection pattern detected: {pattern}")
```

---

## 🔵 Medium-Severity Threats

### Threat 7: Information Disclosure

**Description**: Sensitive data exposed to unauthorized parties

**Common Scenarios**:
- Verbose error messages
- Unencrypted logs
- Debug endpoints in production
- Overly detailed API responses

**Mitigations**:
```python
# ❌ BAD: Detailed error
try:
    result = process_payment()
except Exception as e:
    return {"error": str(e), "stack_trace": traceback.format_exc()}

# ✅ GOOD: Generic error, detailed logging
try:
    result = process_payment()
except Exception as e:
    log_detailed_error(e)  # Internal only
    return {"error": "Payment processing failed"}  # Generic to user
```

---

### Threat 8: Session Hijacking

**Description**: Attacker steals and uses valid session tokens

**Mitigations**:
```python
class SecureSessionManager:
    def create_session(self, agent_id):
        token = secrets.token_urlsafe(32)
        
        session = {
            "agent_id": agent_id,
            "token": token,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(hours=1),
            "source_ip": get_client_ip(),
            "tls_fingerprint": get_tls_fingerprint()
        }
        
        return token, session
    
    def validate_session(self, token):
        session = self.get_session(token)
        
        # Verify not expired
        if datetime.now() > session["expires_at"]:
            raise SessionExpiredError()
        
        # Verify same source IP
        if get_client_ip() != session["source_ip"]:
            raise SessionHijackingError("IP mismatch")
        
        # Verify same TLS fingerprint
        if get_tls_fingerprint() != session["tls_fingerprint"]:
            raise SessionHijackingError("TLS fingerprint mismatch")
```

---

## 📊 Threat Priority Matrix

| Threat | Impact | Likelihood | Risk | Priority |
|--------|--------|------------|------|----------|
| Agent Impersonation | Critical | Medium | 🔴 HIGH | P0 |
| MITM Attack | Critical | Low | 🟡 MEDIUM | P1 |
| Replay Attack | Critical | Medium | 🔴 HIGH | P0 |
| Privilege Escalation | High | Medium | 🟡 MEDIUM | P1 |
| Denial of Service | High | High | 🔴 HIGH | P0 |
| Injection Attacks | Critical | Medium | 🔴 HIGH | P0 |
| Info Disclosure | Medium | High | 🟡 MEDIUM | P2 |
| Session Hijacking | Medium | Low | 🟢 LOW | P3 |

**Priority Levels**:
- **P0** (Critical): Implement immediately
- **P1** (High): Implement in next sprint
- **P2** (Medium): Plan for upcoming release
- **P3** (Low): Backlog

---

## 🛡️ Defense in Depth Strategy

```
Layer 1: Network Security
  ├─ TLS 1.3
  ├─ Firewall rules
  └─ DDoS protection

Layer 2: Authentication
  ├─ Signature verification
  ├─ Certificate validation
  └─ Multi-factor if needed

Layer 3: Authorization
  ├─ RBAC enforcement
  ├─ Capability validation
  └─ Least privilege

Layer 4: Input Validation
  ├─ Schema validation
  ├─ Injection detection
  └─ Size limits

Layer 5: Rate Limiting
  ├─ Per-agent limits
  ├─ Global limits
  └─ Adaptive throttling

Layer 6: Monitoring
  ├─ Audit logging
  ├─ Anomaly detection
  └─ Alerting

Layer 7: Incident Response
  ├─ Automated blocking
  ├─ Forensics
  └─ Recovery procedures
```

---

## 🎯 Threat Modeling Exercise

### Your Turn: Analyze This Scenario

**Scenario**: A financial services company uses agents to process transactions.

**Questions**:
1. What are the top 3 threats?
2. What is the attacker's most likely entry point?
3. What mitigations would you prioritize?
4. How would you detect attacks?

<details>
<summary>Sample Analysis</summary>

**Top 3 Threats**:
1. Replay attacks (duplicate transactions)
2. Agent impersonation (unauthorized transfers)
3. DOS (service unavailability during critical times)

**Entry Points**:
- Weak authentication
- No replay protection
- Insufficient rate limiting

**Priority Mitigations**:
1. Implement nonce-based replay protection
2. Require cryptographic signatures
3. Deploy rate limiting
4. Add transaction monitoring

**Detection**:
- Monitor for duplicate transaction IDs
- Alert on unusual transfer patterns
- Track authentication failures
- Monitor request rates per agent

</details>

---

## 📚 Next Steps

1. **Apply to Your System**: Perform threat modeling for your specific use case
2. **Implement Mitigations**: Start with P0 threats
3. **Test Defenses**: Try to attack your own system
4. **Monitor**: Deploy detection mechanisms
5. **Iterate**: Update threat model as system evolves

### Related Documentation
- [Authentication Overview](./01_authentication_overview.md)
- [Security Best Practices](./04_security_best_practices.md)
- [Code Walkthrough](./05_code_walkthrough_comparison.md)

---

**Document Version**: 1.0  
**Last Updated**: November 2024  
**Part of**: A2A Security Learning Project

---

**Navigation**  
← Previous: [Authentication Tags](./02_authentication_tags.md) | Next: [Security Best Practices](./04_security_best_practices.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)