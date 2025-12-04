# Session Security Quick Reference

> **One-page summary** of session management security for multi-agent systems  
> **Full Document**: [Session Management & State Security](./06_session_state_security.md)

---

## What is Session Security?

**Session**: A conversation between an agent and the system, tracked over time  
**State**: Information the system remembers about the session  
**Security Goal**: Ensure only the legitimate agent can use their session

---

## Core Threats

| Threat | What It Is | Impact |
|--------|-----------|--------|
| **Session Hijacking** | Attacker steals session token | Complete account takeover |
| **Session Fixation** | Attacker tricks victim into using known session | Unauthorized access |
| **Replay Attacks** | Attacker reuses captured requests | Duplicate transactions |
| **Stale State** | Outdated permissions persist | Unauthorized operations |

---

## Essential Security Controls

### 1. Secure Session Creation ✅

```python
# Generate cryptographically random ID
session_id = secrets.token_urlsafe(32)

# Bind to client characteristics
session = {
    "agent_id": agent_id,
    "source_ip": client_ip,
    "tls_fingerprint": tls_fp,
    "expires_at": now + timedelta(hours=8)
}
```

### 2. Validate Every Request ✅

```python
# Check: exists, not expired, bindings match
if not validate_session(session_id, client_ip, tls_fp):
    raise SecurityError("Invalid session")
```

### 3. Implement Timeouts ✅

- **Idle Timeout**: 15-30 minutes (no activity)
- **Absolute Timeout**: 1-8 hours (maximum lifetime)

### 4. Secure Termination ✅

```python
# On logout: destroy completely
del sessions[session_id]
invalidate_tokens(session_id)
clear_cache(session_id)
```

---

## Implementation Checklist

**Session Creation**:
- [ ] Cryptographically random session IDs
- [ ] New session ID on every login
- [ ] Bind to IP, user agent, TLS fingerprint
- [ ] Set idle and absolute timeouts

**Session Validation**:
- [ ] Validate on every single request
- [ ] Check expiration (idle + absolute)
- [ ] Verify security bindings
- [ ] Prevent replay attacks (nonce)

**Session Storage**:
- [ ] Minimize stored data
- [ ] Never store passwords
- [ ] Encrypt sensitive state
- [ ] Auto-expire old sessions

**Session Termination**:
- [ ] Explicit logout endpoint
- [ ] Complete cleanup
- [ ] Force-terminate on permission change
- [ ] Log termination events

**Monitoring**:
- [ ] Log all security events
- [ ] Alert on validation failures
- [ ] Track session metrics
- [ ] Monitor for anomalies

---

## Common Mistakes

❌ **Don't**:
- Use predictable session IDs
- Trust client-provided session IDs
- Skip validation on any request
- Have unlimited session lifetimes
- Store sensitive data unencrypted
- Forget to destroy sessions on logout

✅ **Do**:
- Generate random session IDs
- Create new sessions on login
- Validate every request
- Implement timeouts
- Encrypt sensitive data
- Completely destroy sessions

---

## Recommended Timeout Values

| Risk Level | Idle Timeout | Absolute Timeout |
|-----------|--------------|------------------|
| **High** (financial, admin) | 10 min | 1 hour |
| **Medium** (business) | 30 min | 8 hours |
| **Low** (read-only) | 60 min | 24 hours |

---

## Key References

1. **OWASP Session Management Cheat Sheet**  
   https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

2. **NIST Digital Identity Guidelines (SP 800-63B)**  
   https://pages.nist.gov/800-63-3/sp800-63b.html

3. **Full Documentation**  
   [Session Management & State Security](./06_session_state_security.md)

4. **Related A2A Docs**:
   - [Authentication Overview](./01_authentication_overview.md)
   - [Threat Model](./03_threat_model.md)
   - [Security Best Practices](./04_security_best_practices.md)

---

## Quick Decision Guide

**When to create new session?**
→ Every login, never reuse

**How long should sessions last?**
→ Balance security vs. usability (see table above)

**What to do on permission change?**
→ Force-terminate all sessions, require re-login

**Detected hijacking attempt?**
→ Terminate session immediately, alert security team

**How to handle reconnection?**
→ Validate security bindings, may require re-auth

---

**Remember**: Sessions are your security perimeter. Validate everything, expire aggressively, monitor constantly.

---

**Document**: Session Security Quick Reference  
**Version**: 1.0  
**Last Updated**: December 2025