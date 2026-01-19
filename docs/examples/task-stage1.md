# Task Collaboration Agent - Stage 1: Insecure

> **Path**: `examples/a2a_task_collab_example/stage1_insecure`

## Overview

Stage 1 demonstrates a **critically insecure** multi-agent task collaboration system. This stage is intentionally vulnerable to teach session management and multi-agent security through hands-on exploitation.

**Security Rating**: ⚠️ 0/10 - CRITICALLY INSECURE

**Status**: ❌ Educational Only - Never use in production

---

## Key Learning Focus

This stage focuses on **session management security** and **multi-agent coordination** vulnerabilities, showing how distributed systems can fail without proper security.

### What You'll Learn

- Session management fundamentals
- Why predictable session IDs are dangerous
- Authentication requirements for distributed systems
- Authorization in multi-agent environments
- The importance of message integrity
- Why encryption matters for sessions

---

## Architecture

```
Coordinator Agent
  ↓ (no security)
  ├─→ Worker Agent 1
  ├─→ Worker Agent 2
  └─→ Audit Agent

Session Management: Predictable IDs
Authentication: None
Authorization: None
Encryption: None
Message Integrity: None
```

### Components

- **`task_coordinator.py`**: Main coordinator with no security
- **`worker_agent.py`**: Task executor with no validation
- **`audit_agent.py`**: Logging agent (logs everything in plaintext)
- **`client.py`**: Test client showing attacks
- **`demo.py`**: Attack demonstrations

---

## Critical Vulnerabilities

### 1. **Predictable Session IDs** (CRITICAL)

```python
# ❌ Sequential session IDs
session_counter = 0

def create_session(client_id):
    global session_counter
    session_counter += 1
    session_id = f"session-{session_counter:04d}"
    # Output: session-0001, session-0002, session-0003...
    sessions[session_id] = {
        'client_id': client_id,
        'created': time.time()
    }
    return session_id
```

**Attack**:
```python
# Guess valid session IDs
for i in range(1, 10000):
    session_id = f"session-{i:04d}"
    # Try to use this session
    if hijack_session(session_id):
        print(f"Hijacked: {session_id}")
```

**Impact**: Complete session hijacking with trivial guessing

---

### 2. **No Authentication** (CRITICAL)

```python
# ❌ Trust whatever client claims
def handle_handshake(message):
    client_id = message.get("client_id")
    # No verification at all!
    session_id = create_session(client_id)
    return {
        'status': 'success',
        'session_id': session_id
    }
```

**Attack**:
```python
# Impersonate any user
fake_handshake = {
    'type': 'handshake',
    'client_id': 'admin'  # Claim to be admin
}
response = coordinator.handle(fake_handshake)
admin_session = response['session_id']
# Now have admin access!
```

**Impact**: Complete identity spoofing

---

### 3. **No Authorization** (CRITICAL)

```python
# ❌ Any session can do anything
def handle_create_project(message):
    session_id = message.get('session_id')
    
    # Check session exists
    if session_id not in sessions:
        return {'error': 'Invalid session'}
    
    # ❌ No check if user should create projects!
    project = create_project(message['project_data'])
    return {'status': 'created', 'project_id': project['id']}
```

**Attack**:
```python
# Any user can create/delete/modify anything
response = coordinator.create_project(
    session_id='session-0001',  # Any valid session
    project_data={'name': 'Malicious Project'}
)
# Success! No permission check
```

**Impact**: Complete authorization bypass

---

### 4. **No Session Binding** (CRITICAL)

```python
# ❌ Session not tied to client
def validate_session(session_id):
    return session_id in sessions
    # No check of:
    # - IP address
    # - User agent
    # - Client certificate
    # - Any binding factor
```

**Attack**:
```python
# Steal session ID and use from different machine/IP
stolen_session = "session-0042"
# Works from anywhere!
coordinator.execute_task(stolen_session, task_data)
```

**Impact**: Session theft is trivial

---

### 5. **No Encryption** (CRITICAL)

```python
# ❌ TCP without TLS
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 8000))
server.listen(5)

while True:
    client, addr = server.accept()
    # All communication in plaintext!
    data = client.recv(4096)
    # Session IDs, passwords, data all visible
```

**Attack**:
```bash
# Sniff network traffic
tcpdump -i any port 8000 -A
# See all session IDs, messages, credentials
```

**Impact**: Complete traffic interception

---

### 6. **No Message Integrity** (HIGH)

```python
# ❌ Trust all messages
def handle_message(data):
    message = json.loads(data)
    # No signature verification
    # No tampering detection
    action = message['type']
    return dispatch_action(action, message)
```

**Attack**:
```python
# Intercept and modify messages
original_message = {
    'type': 'assign_task',
    'task_id': '123',
    'worker': 'worker1'
}

# Modify in transit
modified_message = {
    'type': 'assign_task',
    'task_id': '123',
    'worker': 'attacker'  # Steal the task
}
```

**Impact**: Message tampering undetected

---

### 7. **No Replay Protection** (HIGH)

```python
# ❌ Messages can be replayed
def process_message(message):
    # No nonce
    # No timestamp check
    # Same message can be sent repeatedly
    return handle_action(message)
```

**Attack**:
```python
# Capture a "pay worker" message
payment_message = capture_message()

# Replay it 100 times
for i in range(100):
    send_message(payment_message)
    # Each replay succeeds!
```

**Impact**: Replay attacks succeed

---

### 8. **Plaintext State Storage** (HIGH)

```python
# ❌ Store everything in plaintext
def save_state():
    with open('state.json', 'w') as f:
        json.dump({
            'sessions': sessions,      # Session IDs exposed
            'projects': projects,      # All project data
            'tasks': tasks,           # All task details
            'permissions': permissions # Who can do what
        }, f)
```

**Attack**:
```bash
# Read state file
cat state.json
# All sessions, projects, permissions visible
```

**Impact**: State exposure on file access

---

### 9. **No Rate Limiting** (MEDIUM)

```python
# ❌ Unlimited requests
def handle_request(request):
    # No throttling
    # No request counting
    # No limits
    return process_request(request)
```

**Attack**:
```python
# Brute force session IDs
for i in range(1000000):
    try_session(f"session-{i:04d}")
```

**Impact**: DoS and brute force attacks

---

### 10. **No Timeout** (MEDIUM)

```python
# ❌ Sessions live forever
def create_session(client_id):
    session_id = generate_id()
    sessions[session_id] = {
        'client_id': client_id,
        'created': time.time()
        # No expiration time!
        # No idle timeout!
        # No absolute timeout!
    }
    return session_id
```

**Attack**:
```python
# Old stolen session still works
ancient_session = "session-0001"  # From months ago
# Still valid!
coordinator.execute_task(ancient_session, task)
```

**Impact**: Unlimited session lifetime

---

## Complete Vulnerability List

| # | Vulnerability | Severity | CWE | Impact |
|---|---------------|----------|-----|--------|
| 1 | Predictable Session IDs | CRITICAL | CWE-330 | Session hijacking |
| 2 | No Authentication | CRITICAL | CWE-287 | Identity spoofing |
| 3 | No Authorization | CRITICAL | CWE-862 | Privilege escalation |
| 4 | No Session Binding | CRITICAL | CWE-384 | Session theft |
| 5 | No Encryption (TLS) | CRITICAL | CWE-319 | Traffic interception |
| 6 | No Message Integrity | HIGH | CWE-345 | Message tampering |
| 7 | No Replay Protection | HIGH | CWE-294 | Replay attacks |
| 8 | Plaintext State | HIGH | CWE-312 | State exposure |
| 9 | No Rate Limiting | MEDIUM | CWE-770 | DoS/brute force |
| 10 | No Session Timeout | MEDIUM | CWE-613 | Stale sessions |
| 11 | No Input Validation | MEDIUM | CWE-20 | Injection attacks |
| 12 | No Audit Logging | MEDIUM | CWE-778 | No accountability |
| 13 | No Error Handling | LOW | CWE-209 | Info disclosure |
| 14 | Hardcoded Secrets | HIGH | CWE-798 | Credential exposure |
| 15 | No State Encryption | HIGH | CWE-311 | State compromise |
| 16 | Missing CSRF Protection | MEDIUM | CWE-352 | CSRF attacks |
| 17 | Weak Randomness | HIGH | CWE-338 | Prediction attacks |
| 18 | No Secure Deletion | LOW | CWE-226 | Data recovery |
| 19 | Race Conditions | MEDIUM | CWE-362 | State corruption |
| 20 | No Permission Checks | CRITICAL | CWE-863 | Unauthorized actions |
| 21 | No Multi-Agent Auth | CRITICAL | CWE-306 | Agent spoofing |
| 22 | No Task Validation | MEDIUM | CWE-20 | Malicious tasks |
| 23 | No Resource Limits | LOW | CWE-770 | Resource exhaustion |
| 24 | Cleartext Logging | MEDIUM | CWE-532 | Log exposure |
| 25 | No Network Segmentation | LOW | N/A | Lateral movement |

**Total**: 25+ exploitable vulnerabilities

---

## Attack Demonstrations

### Demo 1: Session Hijacking

```python
# demo_hijack.py
import socket
import json

def hijack_session():
    # Guess session IDs (predictable)
    for i in range(1, 100):
        session_id = f"session-{i:04d}"
        
        # Try to use guessed session
        message = {
            'type': 'list_projects',
            'session_id': session_id
        }
        
        response = send_to_coordinator(message)
        if response.get('status') == 'success':
            print(f"✅ Hijacked {session_id}")
            print(f"Projects: {response['projects']}")
            return session_id
    
    return None

# Run the attack
hijacked = hijack_session()
```

**Expected Result**: Successfully hijacks valid session

---

### Demo 2: Identity Spoofing

```python
# demo_spoof.py
def impersonate_admin():
    # Claim to be admin (no verification)
    handshake = {
        'type': 'handshake',
        'client_id': 'admin'  # No proof needed!
    }
    
    response = coordinator.handle(handshake)
    admin_session = response['session_id']
    
    # Now have admin powers
    result = coordinator.create_project(
        session_id=admin_session,
        project_data={'name': 'Malicious Project'}
    )
    
    print(f"✅ Created project as admin: {result}")

impersonate_admin()
```

**Expected Result**: Successfully impersonates admin

---

### Demo 3: Replay Attack

```python
# demo_replay.py
def replay_attack():
    # Capture a legitimate message
    legitimate_msg = capture_network_traffic()
    # Example: {'type': 'assign_task', 'task_id': '123', ...}
    
    # Replay it multiple times
    for i in range(10):
        response = send_message(legitimate_msg)
        print(f"Replay {i}: {response}")
    
    # All replays succeed!

replay_attack()
```

**Expected Result**: All replays processed successfully

---

### Demo 4: Man-in-the-Middle

```bash
# demo_mitm.sh

# Intercept traffic (no TLS)
sudo tcpdump -i any port 8000 -A -w capture.pcap

# View captured data
tcpdump -r capture.pcap -A | grep -A 10 "session-"

# Output shows all session IDs in plaintext:
# session-0042
# session-0043
# ...
```

**Expected Result**: All traffic visible in plaintext

---

## System Architecture

```
┌─────────────────┐
│ Client          │
│ (No Auth)       │
└────────┬────────┘
         │ TCP (plaintext)
         ↓
┌─────────────────┐
│ Coordinator     │
│ - Predictable   │
│   session IDs   │
│ - No validation │
│ - No encryption │
└────┬───┬───┬────┘
     │   │   │
     ↓   ↓   ↓
┌────┴┐ ┌┴──┐ ┌┴────┐
│Work1│ │Wk2│ │Audit│
└─────┘ └───┘ └─────┘
(All vulnerable)
```

---

## Running the Example

### Setup

```bash
cd examples/a2a_task_collab_example/stage1_insecure

# Install dependencies
pip install -r requirements.txt

# Start coordinator
python server/task_coordinator.py

# In separate terminals:
python server/worker_agent.py --port 8001
python server/worker_agent.py --port 8002
python server/audit_agent.py --port 8003
```

### Try the Attacks

```bash
# Terminal 1: Start all agents (see above)

# Terminal 2: Run attack demonstrations
python demos/demo_hijack.py
python demos/demo_spoof.py
python demos/demo_replay.py

# Terminal 3: Monitor traffic
sudo tcpdump -i lo port 8000 -A
```

### What to Observe

- ✅ Session hijacking succeeds
- ✅ Identity spoofing works
- ✅ Replay attacks processed
- ✅ All traffic visible in plaintext
- ✅ No security controls block attacks

---

## Key Concepts Demonstrated

### Session Management Basics

**What is a session?**
- Temporary state between client and server
- Maintains context across multiple requests
- Must be securely identified and validated

**Why sessions fail here:**
- Predictable IDs (guessable)
- No binding (stealable)
- No expiration (eternal)
- No encryption (visible)

---

### Multi-Agent Coordination

**Challenges:**
- Each agent needs authentication
- Agents must trust each other
- Shared state must be protected
- Message integrity required

**Failures in Stage 1:**
- No agent authentication
- No trust verification
- State exposed
- Message tampering possible

---

## Study Checklist

- [ ] Identify all 25+ vulnerabilities
- [ ] Successfully run session hijacking demo
- [ ] Successfully spoof identity
- [ ] Capture traffic and view session IDs
- [ ] Replay a captured message
- [ ] Understand why each vulnerability matters
- [ ] Ready to compare with Stage 2

---

## Comparison with Other Stages

| Feature | Stage 1 | Stage 2 | Stage 3 |
|---------|---------|---------|---------|
| **Session IDs** | `session-0001` | UUID4 | 256-bit random |
| **Authentication** | None | Password (bcrypt) | Password + MFA |
| **Encryption** | None | None | TLS 1.3 + AES-256 |
| **Authorization** | None | Basic checks | Full RBAC |
| **Replay Protection** | None | None | Nonce-based |
| **Rate Limiting** | None | None | Token bucket |
| **Session Binding** | None | Partial | Complete |
| **State Encryption** | None | None | AES-256-GCM |
| **Audit Logging** | Plaintext | Basic | Comprehensive |
| **Production Ready** | ❌ NO | ❌ NO | ✅ YES |

---

## Key Takeaways

After completing this stage, you should understand:

1. **Session IDs must be unpredictable**: Sequential IDs are instantly compromised
2. **Authentication is essential**: Never trust claimed identity
3. **Authorization prevents privilege escalation**: Check permissions on every action
4. **Encryption is mandatory**: Plaintext = complete exposure
5. **Sessions need binding**: Tie to client characteristics
6. **Defense requires layers**: Single protections are insufficient
7. **Multi-agent systems amplify risks**: Each agent is an attack surface

---

## Next: Stage 2 (Improved)

Stage 2 adds basic security but significant vulnerabilities remain.

**Improvements in Stage 2**:
- ✅ UUID4 session IDs (better randomness)
- ✅ Password authentication (bcrypt)
- ✅ Basic session timeouts
- ✅ Simple authorization checks
- ⚠️ But still 10+ critical issues

**Time to Complete**: 4-6 hours  
**Difficulty**: ⭐⭐ Intermediate  
**Prerequisites**: Stage 1 complete, understanding of hashing

---

## Resources

- [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)
- [Stage 2: Improved →](./task-stage2.md)

---

**Version**: 1.0  
**Last Updated**: January 2026  
**Status**: Educational Example - DO NOT USE IN PRODUCTION
