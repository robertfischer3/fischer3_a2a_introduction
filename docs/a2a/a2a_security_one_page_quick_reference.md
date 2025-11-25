# A2A Security One-Page Quick Reference

## 🔐 Authentication (Stage 3: `secure/security/authentication.py`)
```python
auth_tag = {
    "agent_id": "agent-001",
    "timestamp": "2025-01-15T10:00:00Z",  # 5-min window
    "nonce": "a1b2c3...",                  # Never reuse!
    "signature": "RSA-2048 signature"      # Verify before process
}
```
**✅ DO**: RSA/ECC, nonce, timestamp | **❌ DON'T**: HMAC, no nonce (Stage 2)

---

## 📝 Input Validation (Stage 3: `secure/security/validation.py`)
**8 Layers**: Size → Extension → Content-Type → Magic Bytes → Filename → Parse → Schema → Ranges

**Filename Sanitization**:
```python
safe = os.path.basename(filename)  # Remove ../
safe = re.sub(r'[^\w\s.-]', '', safe)  # Remove dangerous chars
```
**Test**: Stage 1 accepts `../../etc/passwd` ❌ | Stage 3 rejects ✅

---

## 🚦 Rate Limiting (Stage 3: `secure/security/protection.py`)
**Token Bucket**: 100 tokens max, refills 10/min
```python
rate_limiter.check_rate_limit(agent_id, cost=1)
```
**AI Separate**: 20/min, 200/hr, $10/hr limit (Stage 4)

---

## 🔒 PII Protection (Stage 3+4: `protection.py`, `ai_security.py`)
**For Logs**: `ssn: "***-**-6789"` | **For AI**: Remove ALL PII | **For Clients**: Partial mask

**Stage 1 Violation**: Logs full SSN (line 176) 🚨

---

## 🤖 AI Security (Stage 4: `stage4_ai/security/ai_security.py`)
**Prompt Injection**: Block "ignore previous instructions", "you are now", base64  
**PII for AI**: Send ZERO PII (only: score, totals, utilization)  
**Output Check**: Scan for SSN/email patterns, validate JSON  
**Cost Track**: Tokens, latency, $ per hour

---

## 📋 Audit Logging (Stage 3: `secure/security/protection.py`)
```json
{"timestamp": "...", "event_type": "auth", "agent_id": "...", 
 "action": "...", "result": "success/failure", "severity": "HIGH"}
```
**Log**: Auth attempts, authz failures, uploads, rate limits, AI calls  
**Don't Log**: Full SSN, passwords, API keys

---

## 🛡️ Error Handling
**To Client**: Generic messages only | **To Logs**: Detailed errors  
**❌ Stage 1**: Sends stack traces to client | **✅ Stage 3**: "Internal error" + log details

---

## 🎯 Training Examples Quick Map
| Security Control | Vulnerable (Stage 1) | Improved (Stage 2) | Secure (Stage 3) | AI (Stage 4) |
|------------------|----------------------|--------------------|--------------------|--------------|
| **File Uploads** | Credit Report insecure/ | Credit Report improved/ | Credit Report secure/ | - |
| **PII Handling** | Logs full SSN ❌ | Masks SSN ⚠️ | Full sanitization ✅ | + AI mode ✅ |
| **Authentication** | None ❌ | HMAC (weak) ⚠️ | RSA + nonce ✅ | Same ✅ |
| **Rate Limiting** | None ❌ | None ❌ | Token bucket ✅ | + AI limits ✅ |
| **AI Security** | - | - | - | Full suite ✅ |

---

## 🚨 Top 5 Vulnerabilities to Test
1. **Replay Attack**: Credit Report Stage 2, client option 8 (same request 3x)
2. **Path Traversal**: Credit Report Stage 1 accepts `../../etc/passwd`
3. **No Rate Limit**: Credit Report Stage 1, upload 150 files rapidly
4. **PII Logging**: Credit Report Stage 1, line 176 logs full SSN
5. **Prompt Injection**: Credit Report Stage 4, try "ignore previous instructions"

---

## ✅ Pre-Production Checklist
- [ ] RSA-2048 auth + nonce + timestamp
- [ ] 8-layer file validation
- [ ] Token bucket rate limiting (general + AI)
- [ ] PII sanitization (logs, AI, responses)
- [ ] RBAC authorization
- [ ] Structured audit logging
- [ ] TLS 1.3 in transit
- [ ] AES-256 at rest
- [ ] Prompt injection detection (if AI)
- [ ] AI output validation (if AI)
- [ ] Security testing complete

---

## 📂 Key Files
- **Auth**: `secure/security/authentication.py`
- **Validation**: `secure/security/validation.py`
- **Rate Limit**: `secure/security/protection.py`
- **AI Security**: `stage4_ai/security/ai_security.py`
- **All Vulns**: `insecure/server/insecure_credit_agent.py`

**Golden Rule**: When in doubt, check Stage 3 (secure) for patterns, Stage 1 (insecure) for anti-patterns.