# Task Collaboration Agent - Stage 2: Improved

> **Path**: `a2a_examples/a2a_task_collab_example/stage2_improved`

## Overview

Stage 2 demonstrates **partial security improvements** that are insufficient for production. This stage teaches that better does not equal secure in distributed multi-agent systems.

**Security Rating**: ⚠️ 4/10 - PARTIALLY SECURE

**Status**: ⚠️ Not Production Ready - Significant vulnerabilities remain

---

## Key Learning Focus

This stage focuses on understanding **why partial security measures fail** in multi-agent systems and the critical importance of **comprehensive, layered security**.

### What You'll Learn

- Why UUID4 session IDs aren't enough
- Limitations of password-only authentication
- Gaps in basic authorization
- Why no encryption still fails
- How attackers exploit remaining weaknesses
- The necessity of complete security

---

## Architecture

![Task Collaboration Agent - Stage 2](/docs/images/diagrams/task_collaboration_stage2_improved.jpg)

```
Client
  ↓ TCP (still no TLS)
Password Auth ✅
  ↓
Coordinator
  ├─ UUID4 sessions ✅
  ├─ Basic timeouts ✅
  ├─ Owner checks ⚠️
  └─ HMAC signatures ⚠️
  ↓
Worker Agents
  (Basic validation)
```

### Components

- **`task_coordinator.py`**: With SessionManager and AuthManager
- **`session_manager.py`**: UUID4 IDs, basic timeouts
- **`auth_manager.py`**: Password authentication (bcrypt)
- **`worker_agent.py`**: Basic task validation
- **`audit_agent.py`**: Improved logging
- **`client.py`**: Updated for authentication

---

## ✅ Improvements from Stage 1

### 1. **UUID4 Session IDs**

```python
import uuid

# ✅ Random session IDs
def create_session(user_id):
    session_id = str(uuid.uuid4())
    # Output: e3b0c442-98fc-1c14-b39f-92d1282e1f18
    
    sessions[session_id] = {
        'user_id': user_id,
        'created': time.time(),
        'last_activity': time.time()
    }
    return session_id
```

**Benefit**: Much harder to guess than sequential IDs

**But Still Vulnerable**: Can be sniffed (no TLS)

---

### 2. **Password Authentication**

```python
import bcrypt

# ✅ Password verification with bcrypt
class AuthManager:
    def authenticate(self, username, password):
        if username not in self.users:
            # Constant-time failure
            bcrypt.checkpw(b'dummy', bcrypt.gensalt())
            return None
        
        user = self.users[username]
        password_hash = user['password_hash'].encode()
        
        if bcrypt.checkpw(password.encode(), password_hash):
            return user['id']
        
        return None
```

**Benefit**: Can't impersonate without password

**But Still Vulnerable**: No MFA, no rate limiting

---

### 3. **Session Timeouts**

```python
# ✅ Idle timeout
IDLE_TIMEOUT = 30 * 60  # 30 minutes

def validate_session(session_id):
    if session_id not in sessions:
        return False
    
    session = sessions[session_id]
    
    # Check idle timeout
    idle_time = time.time() - session['last_activity']
    if idle_time > IDLE_TIMEOUT:
        del sessions[session_id]
        return False
    
    # Update activity
    session['last_activity'] = time.time()
    return True
```

**Benefit**: Sessions eventually expire

**But Still Vulnerable**: No absolute timeout, no binding

---

### 4. **Basic Authorization**

```python
# ✅ Check ownership
def create_task(session_id, project_id, task_data):
    # Validate session
    session = get_session(session_id)
    if not session:
        return {'error': 'Invalid session'}
    
    # Check if user owns project
    project = get_project(project_id)
    if project['owner_id'] != session['user_id']:
        return {'error': 'Access denied'}
    
    # Create task
    task = create_task_internal(project_id, task_data)
    return {'status': 'success', 'task': task}
```

**Benefit**: Basic permission checking

**But Still Vulnerable**: No role-based access, incomplete checks

---

### 5. **HMAC Message Signatures**

```python
import hmac
import hashlib

# ✅ Sign messages
SECRET_KEY = "shared-secret-key"  # ⚠️ Hardcoded!

def sign_message(message):
    message_bytes = json.dumps(message, sort_keys=True).encode()
    signature = hmac.new(
        SECRET_KEY.encode(),
        message_bytes,
        hashlib.sha256
    ).hexdigest()
    return signature

def verify_message(message, signature):
    expected = sign_message(message)
    return hmac.compare_digest(expected, signature)
```

**Benefit**: Detect message tampering

**But Still Vulnerable**: No nonce = replay attacks still work

---

## ⚠️ Remaining Vulnerabilities

Despite improvements, **10+ critical vulnerabilities remain**:

### 1. **No TLS Encryption** (CRITICAL)

```python
# ❌ Still plaintext TCP
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 8000))
# No TLS wrapper!
```

**Attack**:
```bash
# UUID4 sessions still visible in traffic
tcpdump -i any port 8000 -A | grep -E '[0-9a-f]{8}-[0-9a-f]{4}'
# Captures all session IDs
```

**Impact**: Session stealing via network sniffing

---

### 2. **No MFA** (HIGH)

```python
# ⚠️ Single-factor authentication
def login(username, password):
    user_id = auth_manager.authenticate(username, password)
    if user_id:
        return create_session(user_id)
    return None
```

**Attack**:
```python
# Stolen/weak password = full access
stolen_password = "password123"
session = login("victim", stolen_password)
# No second factor required
```

**Impact**: Compromised passwords = compromised accounts

---

### 3. **No Rate Limiting** (HIGH)

```python
# ❌ Still unlimited attempts
def handle_login(username, password):
    # No throttling
    # No attempt counting
    # No lockout
    return authenticate(username, password)
```

**Attack**:
```python
# Brute force passwords
passwords = load_wordlist()
for password in passwords:
    if login("target_user", password):
        print(f"Found: {password}")
        break
```

**Impact**: Brute force attacks succeed

---

### 4. **No Replay Protection** (HIGH)

```python
# ⚠️ HMAC signature but no nonce
def handle_message(data, signature):
    message = json.loads(data)
    
    # Verify signature
    if not verify_message(message, signature):
        return error("Invalid signature")
    
    # ❌ But same message can be replayed!
    return process_message(message)
```

**Attack**:
```python
# Capture signed message
captured = {
    'type': 'transfer_funds',
    'amount': 1000,
    'signature': 'abc123...'
}

# Replay it 100 times
for i in range(100):
    send_message(captured)
    # Each replay succeeds!
```

**Impact**: Replay attacks still work

---

### 5. **Incomplete Session Binding** (HIGH)

```python
# ⚠️ Only user_id binding, nothing else
def validate_session(session_id):
    if session_id not in sessions:
        return False
    
    session = sessions[session_id]
    
    # ❌ No IP address check
    # ❌ No user agent check
    # ❌ No certificate binding
    
    return check_timeout(session)
```

**Attack**:
```python
# Steal session, use from different IP/machine
stolen_session = sniff_session_id()
# Works from anywhere!
use_session(stolen_session)
```

**Impact**: Stolen sessions fully functional

---

### 6. **No State Encryption** (HIGH)

```python
# ⚠️ Sessions stored in plaintext
sessions = {
    'e3b0c442-...': {
        'user_id': 'user123',
        'permissions': ['admin'],  # Plaintext!
        'project_access': [1, 2, 3]
    }
}

def save_state():
    with open('sessions.json', 'w') as f:
        json.dump(sessions, f)  # ❌ Plaintext file
```

**Attack**:
```bash
# Read session file
cat sessions.json
# All sessions and permissions exposed
```

**Impact**: File system access = full session compromise

---

### 7. **Weak Secret Management** (HIGH)

```python
# ❌ Hardcoded secrets
SECRET_KEY = "shared-secret-key"  # In source code!
DATABASE_PASSWORD = "dbpass123"   # Committed to git!

# ❌ Shared secret across all agents
def init_agent():
    return HMACVerifier(SECRET_KEY)  # Same key everywhere
```

**Attack**:
- Secrets in version control
- Secrets in memory dumps
- Secrets in config files

**Impact**: Complete cryptographic bypass

---

### 8. **No Absolute Session Timeout** (MEDIUM)

```python
# ⚠️ Only idle timeout, no maximum lifetime
def validate_session(session_id):
    session = sessions.get(session_id)
    
    # Check idle timeout
    if time.time() - session['last_activity'] > IDLE_TIMEOUT:
        return False
    
    # ❌ No check of total session age
    # Session can live forever if kept active
    
    return True
```

**Attack**:
```python
# Keep session alive indefinitely
while True:
    keep_alive(session_id)
    time.sleep(29 * 60)  # Just under idle timeout
    # Session never expires!
```

**Impact**: Sessions can be kept alive forever

---

### 9. **Incomplete Audit Logging** (MEDIUM)

```python
# ⚠️ Some logging but not comprehensive
def handle_action(session_id, action):
    # Log action
    log(f"User {session['user_id']} performed {action}")
    
    # ❌ Missing:
    # - IP address
    # - Timestamp precision
    # - Request details
    # - Failure reasons
    # - Security events
```

**Attack**: Unauthorized actions not properly tracked

**Impact**: No forensics capability

---

### 10. **No Message Ordering** (MEDIUM)

```python
# ❌ Messages processed in any order
def handle_messages(messages):
    for message in messages:
        process(message)
        # No sequence checking
        # No dependency validation
```

**Attack**:
```python
# Send messages out of order
send_message({'seq': 3, 'action': 'delete'})
send_message({'seq': 2, 'action': 'create'})
send_message({'seq': 1, 'action': 'init'})
# All processed, wrong order causes corruption
```

**Impact**: State corruption via message reordering

---

## Attack Success Matrix

| Attack Type | Stage 1 | Stage 2 | Stage 3 |
|-------------|---------|---------|---------|
| **Session Guessing** | ✅ Succeeds | ❌ Blocked | ❌ Blocked |
| **Session Sniffing** | ✅ Succeeds | ✅ Succeeds | ❌ Blocked |
| **Identity Spoofing** | ✅ Succeeds | ❌ Blocked | ❌ Blocked |
| **Replay Attack** | ✅ Succeeds | ✅ Succeeds | ❌ Blocked |
| **Brute Force Login** | N/A | ✅ Succeeds | ❌ Blocked |
| **Session Theft** | ✅ Succeeds | ✅ Succeeds | ❌ Blocked |
| **Privilege Escalation** | ✅ Succeeds | ⚠️ Partial | ❌ Blocked |
| **Message Tampering** | ✅ Succeeds | ❌ Blocked | ❌ Blocked |
| **State Corruption** | ✅ Succeeds | ⚠️ Harder | ❌ Blocked |
| **DoS (No Rate Limit)** | ✅ Succeeds | ✅ Succeeds | ❌ Blocked |

**Legend**: ✅ = Succeeds, ⚠️ = Partially mitigated, ❌ = Blocked

---

## Attack Demonstrations

### Demo 1: Session Sniffing (Still Works)

```python
# demo_sniff_stage2.py
import socket
from scapy.all import sniff, TCP

def capture_sessions():
    """UUID4 sessions still visible without TLS"""
    packets = sniff(filter="tcp port 8000", count=100)
    
    sessions = []
    for packet in packets:
        if packet.haslayer(TCP):
            payload = str(packet[TCP].payload)
            # Look for UUID4 pattern
            import re
            uuids = re.findall(
                r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                payload
            )
            sessions.extend(uuids)
    
    return list(set(sessions))

# Run attack
captured = capture_sessions()
print(f"✅ Captured {len(captured)} sessions")
print(f"Sample: {captured[0]}")
```

**Expected Result**: Successfully captures UUID4 session IDs

---

### Demo 2: Replay Attack (Still Works)

```python
# demo_replay_stage2.py
def replay_attack():
    """HMAC signature doesn't prevent replay"""
    
    # Capture a legitimate signed message
    original = capture_message()
    # {
    #   'type': 'assign_task',
    #   'task_id': '123',
    #   'worker': 'worker1',
    #   'signature': 'abc123...'
    # }
    
    # Replay it multiple times
    for i in range(10):
        response = send_message(original)
        print(f"Replay {i}: {response['status']}")
        # All succeed - no nonce check!
    
    print("✅ Replay attack successful")

replay_attack()
```

**Expected Result**: All replays processed successfully

---

### Demo 3: Brute Force (Still Works)

```python
# demo_bruteforce_stage2.py
import time

def brute_force_login():
    """No rate limiting allows brute force"""
    
    passwords = [
        'password', 'Password1', '123456',
        'qwerty', 'letmein', 'admin'
    ]
    
    start = time.time()
    for password in passwords:
        response = try_login('target_user', password)
        if response.get('session_id'):
            elapsed = time.time() - start
            print(f"✅ Found password: {password}")
            print(f"Time: {elapsed:.2f}s")
            print(f"No throttling detected!")
            return
    
    print("Password not in list")

brute_force_login()
```

**Expected Result**: Successfully brute forces password

---

### Demo 4: Session Theft (Still Works)

```python
# demo_theft_stage2.py
def session_theft():
    """Stolen sessions work from anywhere"""
    
    # Attacker sniffs network
    victim_session = sniff_session()  # UUID4
    print(f"Sniffed session: {victim_session}")
    
    # Use from different machine/IP
    # No session binding prevents this!
    response = use_session_remotely(
        victim_session,
        from_ip='10.0.0.99',  # Different IP
        user_agent='AttackerBot'  # Different UA
    )
    
    if response.get('status') == 'success':
        print("✅ Session theft successful")
        print("No binding checks detected!")

session_theft()
```

**Expected Result**: Stolen session works remotely

---

## Key Differences from Stage 1

| Feature | Stage 1 | Stage 2 | Improvement |
|---------|---------|---------|-------------|
| **Session IDs** | Sequential | UUID4 | +95% |
| **Authentication** | None | Password (bcrypt) | +100% |
| **Authorization** | None | Basic ownership | +60% |
| **Message Integrity** | None | HMAC signatures | +80% |
| **Session Timeouts** | None | Idle timeout | +70% |
| **TLS Encryption** | None | None | 0% |
| **MFA** | None | None | 0% |
| **Rate Limiting** | None | None | 0% |
| **Replay Protection** | None | None | 0% |
| **State Encryption** | None | None | 0% |
| **Overall Security** | **0/10** | **4/10** | **+40%** |

**Conclusion**: Much better, but still fails in production

---

## Running the Example

### Setup

```bash
cd a2a_examples/a2a_task_collab_example/stage2_improved

# Install dependencies
pip install -r requirements.txt

# Generate password hashes (for test users)
python scripts/setup_users.py

# Start coordinator
python server/task_coordinator.py

# In separate terminals:
python server/worker_agent.py --port 8001
python server/worker_agent.py --port 8002
python server/audit_agent.py --port 8003
```

### Try the Attacks

```bash
# Terminal 1: Start all servers (see above)

# Terminal 2: Run Stage 2 specific attacks
python demos/demo_sniff_stage2.py       # Still works!
python demos/demo_replay_stage2.py      # Still works!
python demos/demo_bruteforce_stage2.py  # Still works!
python demos/demo_theft_stage2.py       # Still works!

# Compare with Stage 1 attacks
python demos/demo_hijack_stage1.py      # NOW FAILS!
python demos/demo_spoof_stage1.py       # NOW FAILS!
```

### What to Observe

- ❌ Session guessing now fails (UUID4)
- ❌ Identity spoofing now fails (passwords)
- ❌ Message tampering now fails (HMAC)
- ✅ But session sniffing still works (no TLS)
- ✅ But replay attacks still work (no nonce)
- ✅ But brute force still works (no rate limit)
- ✅ But session theft still works (no binding)

---

## Study Checklist

- [ ] Compare code with Stage 1
- [ ] Understand UUID4 improvements
- [ ] Test password authentication
- [ ] Verify HMAC signatures work
- [ ] Identify 10+ remaining vulnerabilities
- [ ] Successfully run attacks that still work
- [ ] Understand why partial security fails
- [ ] Ready for Stage 3 production patterns

---

## Key Takeaways

1. **UUID4 > Sequential**: But still vulnerable without encryption
2. **Password auth is essential**: But insufficient alone (need MFA)
3. **HMAC prevents tampering**: But doesn't prevent replay
4. **Partial improvements create false confidence**: "Better" ≠ "Secure"
5. **Defense-in-depth required**: Single layers fail
6. **Network encryption is critical**: Without TLS, everything visible
7. **Complete solutions needed**: Piecemeal security fails

---

## Next: Stage 3 (Secure)

Stage 3 implements production-grade security with comprehensive protections.

**Additional protections in Stage 3**:
- ✅ TLS 1.3 encryption
- ✅ 256-bit cryptographically random session IDs
- ✅ MFA enforcement (TOTP)
- ✅ Full session binding (IP, UA, cert)
- ✅ Nonce-based replay protection
- ✅ Token bucket rate limiting
- ✅ State encryption (AES-256-GCM)
- ✅ Comprehensive audit logging
- ✅ Full RBAC authorization
- ✅ Absolute + idle timeouts

**Time to Complete**: 8-12 hours  
**Difficulty**: ⭐⭐⭐ Advanced  
**Prerequisites**: Stage 1-2 complete, TLS basics, cryptography fundamentals

---

## Resources

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST Authentication Guidelines](https://pages.nist.gov/800-63-3/)
- [Stage 1: Insecure ←](./task-stage1.md)
- [Stage 3: Secure →](./task-stage3.md)

---

**Version**: 1.0  
**Last Updated**: January 2026  
**Status**: Educational - Not Production Ready
