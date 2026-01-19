# Task Collaboration Agent - Stage 1: Insecure

**⚠️  WARNING: This code is INTENTIONALLY VULNERABLE for educational purposes.**  
**DO NOT USE IN PRODUCTION!**

## Overview

This is **Stage 1** of the Task Collaboration Agent learning project. It demonstrates a multi-agent task coordination system with **intentional security vulnerabilities** focused on session management and state security.

### The Scenario

Three types of agents collaborate to manage projects and execute tasks:

1. **Coordinator Agent** (`task_coordinator.py`) - Central coordinator that:
   - Manages projects and tasks
   - Assigns tasks to workers
   - Tracks session state
   - Maintains project context

2. **Worker Agent** (`task_worker.py`) - Specialized workers that:
   - Register their capabilities (data analysis, code review, testing, documentation)
   - Claim and execute assigned tasks
   - Report task completion

3. **Client** (`client.py` or `test_demo.py`) - Users who:
   - Create projects
   - Submit tasks
   - Monitor progress

## Learning Objectives

By completing Stage 1, you will understand:

✅ **Session Management Basics**
- What sessions are and why they're needed
- Session lifecycle (create → use → expire)
- Session state management

❌ **Critical Vulnerabilities** (25+ demonstrated):
- Predictable session IDs
- No session validation
- No authentication or authorization
- Session hijacking
- Task stealing
- Information disclosure
- State manipulation
- And many more...

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Basic understanding of sockets and JSON
- Terminal/command line access

### Installation

```bash
# Navigate to Stage 1 directory
cd examples/a2a_task_collab_example/stage1_insecure/

# No dependencies needed - uses only Python standard library
```

### Running the System

**Terminal 1: Start the Coordinator**
```bash
python server/task_coordinator.py
```

You should see:
```
╔═══════════════════════════════════════════════════╗
║   Task Coordinator - Stage 1: INSECURE            ║
║   ⚠️  For Educational Purposes Only               ║
╚═══════════════════════════════════════════════════╝

⚠️  WARNING: This code is INTENTIONALLY VULNERABLE
...
🚀 Coordinator started on localhost:9000
```

**Terminal 2 (Optional): Start a Worker**
```bash
python worker/task_worker.py
```

You should see:
```
╔═══════════════════════════════════════════════════╗
║   Task Worker Agent - Stage 1: INSECURE           ║
║   ⚠️  For Educational Purposes Only               ║
╚═══════════════════════════════════════════════════╝

🤖 Task Worker Initialized
   Worker ID: worker-XXXX
   Capabilities: data_analysis, code_review, testing, documentation
```

**Terminal 3: Run the Demo**
```bash
python test_demo.py
```

This will demonstrate:
1. Normal operation
2. Session hijacking attack
3. Task stealing attack

### Alternative: Interactive Client

For hands-on exploration:
```bash
python client/client.py
```

Menu options:
1. Create a project
2. Create a task
3. List projects
4. List tasks
5. Get session info
6. **Session hijacking attack**
7. **Task stealing attack**
8. **Session fixation attack**
9. Exit

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Client(s)                     │
│  - Creates projects                             │
│  - Submits tasks                                │
│  - Monitors progress                            │
└────────────┬────────────────────────────────────┘
             │
             │ Unencrypted TCP
             │ (Vulnerability!)
             │
┌────────────▼────────────────────────────────────┐
│          Task Coordinator                       │
│  - Manages sessions (❌ insecurely)             │
│  - Stores projects & tasks                      │
│  - Assigns tasks to workers                     │
│  - No authentication (❌)                       │
└────────────┬────────────────────────────────────┘
             │
             │ Unencrypted TCP
             │ (Vulnerability!)
             │
┌────────────▼────────────────────────────────────┐
│          Worker Agent(s)                        │
│  - Claim tasks (❌ no authorization)            │
│  - Execute tasks (❌ no sandboxing)             │
│  - Return results                               │
└─────────────────────────────────────────────────┘
```

## Key Vulnerabilities Demonstrated

### 1. Predictable Session IDs
```python
# ❌ Sequential, easily guessable
session_id = f"session-{self.session_counter:04d}"
```
**Impact**: Attackers can guess valid session IDs and hijack sessions.

### 2. No Session Validation
```python
# ❌ Accepts any session ID without checking
if session_id in self.sessions:
    session = self.sessions[session_id]
```
**Impact**: No verification that the session belongs to the requesting client.

### 3. No Authentication
```python
# ❌ Anyone can register as any client
def handle_handshake(self, message):
    client_id = message.get("client_id")
    # No credential check!
```
**Impact**: Attackers can impersonate legitimate clients.

### 4. No Authorization
```python
# ❌ Workers can claim any task
def handle_claim_task(self, message):
    task_id = payload.get("task_id")
    # No check if worker is authorized!
```
**Impact**: Malicious workers can steal sensitive tasks.

### 5. Information Disclosure
```python
# ❌ Returns all session data to anyone who asks
def handle_get_session_info(self, message):
    return {"session": self.sessions[session_id]}
```
**Impact**: Sensitive session state exposed to attackers.

### 6. No Session Timeout
```python
# ❌ Sessions never expire
self.sessions[session_id] = {...}
# No timeout mechanism
```
**Impact**: Stolen sessions remain valid indefinitely.

### 7. No Encryption
```python
# ❌ Plain TCP sockets, no TLS
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```
**Impact**: All traffic can be intercepted and read.

### 8. No Input Validation
```python
# ❌ Accepts any task data without validation
task_data = task.get("data", {})
# Process without checks
```
**Impact**: Malicious payloads could be injected.

**...and 17+ more vulnerabilities!**

## Attack Scenarios

### Scenario 1: Session Hijacking

**Attacker's Goal**: Access another user's projects and tasks

**Attack Steps**:
1. Observe session ID pattern: `session-0001`, `session-0002`, etc.
2. Connect to coordinator
3. Use guessed session ID in requests
4. Success! Can access victim's data

**Try it**:
```bash
python client/client.py
# Choose option 6: Session hijacking attack
```

### Scenario 2: Task Stealing

**Attacker's Goal**: Intercept and execute tasks meant for legitimate workers

**Attack Steps**:
1. Register as a worker with false capabilities
2. Monitor available tasks
3. Claim tasks before legitimate workers
4. Execute tasks and potentially exfiltrate data

**Try it**:
```bash
python client/client.py
# Choose option 7: Task stealing attack
```

### Scenario 3: Session Fixation

**Attacker's Goal**: Force a victim to use a known session ID

**Attack Steps**:
1. Create a session by connecting to coordinator
2. Trick victim into using this session ID
3. Both attacker and victim use the same session
4. Attacker sees all victim's actions

**Try it**:
```bash
python client/client.py
# Choose option 8: Session fixation attack
```

## Hands-On Exercises

### Exercise 1: Discover Vulnerabilities
1. Start the coordinator
2. Run the demo script
3. Observe what attacks succeed
4. List all vulnerabilities you notice

### Exercise 2: Session Hijacking
1. Start coordinator
2. Terminal 1: Run `client.py`, create a project, note session ID
3. Terminal 2: Run `client.py`, use option 6 with the session ID
4. Observe that you can access the other client's project

### Exercise 3: Trace Session Lifecycle
1. Add print statements to track session creation
2. Observe when sessions are created vs. used
3. Note that sessions never expire
4. Identify when validation should occur (but doesn't)

### Exercise 4: Read the Code
Go through each file and identify:
- Where sessions are created
- Where sessions are validated (or not!)
- Where authorization should happen
- What data is stored in sessions
- How session state is managed

## Files in This Stage

```
stage1_insecure/
├── README.md                    # This file
├── SECURITY_ANALYSIS.md         # Detailed vulnerability analysis
├── server/
│   └── task_coordinator.py      # Coordinator agent (vulnerable)
├── worker/
│   └── task_worker.py           # Worker agent (vulnerable)
├── client/
│   └── client.py                # Interactive client
└── test_demo.py                 # Automated demonstration
```

## What's Next?

After completing Stage 1, you should:

1. ✅ Understand what sessions are and why they matter
2. ✅ Recognize 25+ specific vulnerabilities
3. ✅ See how easily sessions can be hijacked
4. ✅ Understand the importance of authentication
5. ✅ Appreciate why input validation matters

**Move to Stage 2** to see how to fix these issues:
- Better session ID generation
- Basic authentication
- Session validation
- Authorization checks
- (Still has 10+ vulnerabilities - learning progression!)

## Study Time

- **Quick run**: 30 minutes (run demos, observe attacks)
- **Thorough study**: 3-4 hours (read code, try exercises, analyze vulnerabilities)
- **Deep dive**: 6-8 hours (modify code, create new attacks, document findings)

## Common Questions

**Q: Is this how real systems work?**  
A: No! This is intentionally vulnerable. Real systems use cryptographically secure session IDs, authentication, TLS, etc.

**Q: Can I use this code as a starting point?**  
A: No! Start with Stage 3 (secure) or use established frameworks.

**Q: Why learn the wrong way first?**  
A: Seeing attacks succeed helps you understand *why* security measures are necessary.

**Q: What if I find additional vulnerabilities?**  
A: Great! That means you're learning. Document them and compare with Stage 2/3.

## Disclaimer

**⚠️  EDUCATIONAL USE ONLY**

By using this code, you acknowledge:
- It contains intentional vulnerabilities
- It is not production-ready  
- You will not use it with real systems or data
- You understand the security risks demonstrated

**Intended Use**:
- Security training and education
- Vulnerability identification practice
- Learning session management security
- Understanding attack scenarios

**NOT Intended For**:
- Production deployments
- Real project management
- Actual agent coordination
- Any system handling real data

## Additional Resources

- **SECURITY_ANALYSIS.md** - Deep dive into each vulnerability
- **Stage 2** - See basic improvements (still has issues)
- **Stage 3** - Production-ready secure implementation
- **A2A Session Security Guide** - General session security principles

---

**Stage**: 1 (Insecure)  
**Security Rating**: 0/10 ❌  
**Vulnerabilities**: 25+  
**Study Time**: 3-4 hours  
**Next Stage**: [Stage 2 - Improved](../stage2_improved/README.md)

---

**Remember**: This is intentionally vulnerable code for learning. Never deploy to production!