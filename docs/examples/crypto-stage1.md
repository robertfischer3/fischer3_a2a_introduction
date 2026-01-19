# Crypto Agent - Stage 1: Vulnerable Implementation

> 🎯 **Goal**: Learn to recognize security vulnerabilities  
> ⏱️ **Time**: 2-3 hours  
> 📍 **You are here**: Stage 1 of 3  
> ⚠️ **Security Rating**: 0/10 - CRITICALLY VULNERABLE

## Navigation
← Back: [Crypto Example Overview](./crypto_agent_example.md) | Next: [Stage 2 - Improved →](./crypto-stage2.md)

---

## 👋 Welcome to Stage 1!

**Congratulations!** You're about to run your first Agent2Agent (A2A) protocol implementation. This is where your learning journey begins.

**But here's the twist**: This code is *intentionally vulnerable*. We're starting here because:
1. You need to recognize bad patterns before learning good ones
2. Understanding "what NOT to do" is just as important as "what to do"
3. Security makes more sense when you've seen the attacks firsthand

> 💡 **Important Mindset**: Don't feel bad if you don't spot all the vulnerabilities right away. That's what this stage is for - learning to develop your "security sense."

---

## 📖 What You'll Learn

By the end of this stage, you will be able to:

- ✅ Set up and run an A2A server and client
- ✅ Understand basic A2A protocol mechanics (requests, responses, streaming)
- ✅ Query cryptocurrency prices using the A2A protocol
- ✅ Identify at least 10 security vulnerabilities in code
- ✅ Understand why each vulnerability matters
- ✅ Explain how attackers could exploit these issues
- ✅ Be motivated to learn secure patterns in Stage 2 & 3

---

## 🎯 Learning Objectives

### Knowledge Goals
- Understand A2A message structure
- Learn agent identity and capabilities
- Recognize common security anti-patterns

### Skill Goals
- Run an A2A server
- Write A2A client queries
- Identify vulnerabilities through code review
- Test exploits safely

### Attitude Goals
- Appreciate the importance of security
- Develop healthy paranoia about user input
- Understand defense-in-depth principle

---

## 🚀 Quick Start (5 Minutes)

Let's get you up and running immediately!

### Prerequisites Check

```bash
# Check Python version (need 3.8+)
python3 --version

# Should show: Python 3.8.x or higher
```

**That's it!** Stage 1 has no external dependencies. Pure Python.

### Step 1: Navigate to Stage 1 Code

```bash
cd examples/a2a_crypto_example/insecure
ls
```

You should see:
```
crypto_price_server.py    # The vulnerable server
crypto_client.py          # Interactive test client
README.md                 # Technical documentation
```

### Step 2: Start the Server

**Terminal 1:**
```bash
python3 crypto_price_server.py
```

You'll see output like:
```
🚀 Starting Cryptocurrency Price Agent (Insecure Version)
================================================================================

⚠️  WARNING: This is Stage 1 - INTENTIONALLY VULNERABLE CODE
⚠️  DO NOT use in production or with real data
⚠️  For educational purposes only

🔓 Security Status: NONE (0/10)
   - No authentication
   - No input validation
   - No rate limiting
   - No audit logging
   - Intentional vulnerabilities for learning

📡 Server Configuration:
   Host: 0.0.0.0
   Port: 8080
   Protocol: HTTP (not HTTPS)
   
✅ Server is ready!
💰 Try querying: BTC, ETH, SOL, ADA, DOGE

Listening for requests...
```

> 💡 **Note the warnings**: The code is literally telling you it's insecure!

### Step 3: Run the Client

**Terminal 2:**
```bash
python3 crypto_client.py
```

You'll see:
```
================================================================================
        Cryptocurrency Price Query Client (Stage 1)
================================================================================

Connected to: http://localhost:8080

Available Commands:
  - Query prices: "What's the price of Bitcoin?"
  - Compare: "Compare BTC and ETH"
  - Stream: "Stream prices for BTC"
  - Quit: "quit" or "exit"

Enter your query:
```

### Step 4: Try Your First Query

```
Enter your query: What's the price of Bitcoin?
```

**Response:**
```
🤖 Agent Response:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The current price of Bitcoin (BTC) is $43,250.00

📊 Additional Information:
• 24h Change: +2.5%
• 24h Volume: $28.5B
• Market Cap: $845B

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**🎉 Congratulations!** You just made your first A2A protocol request!

---

## 🔍 Understanding What Just Happened

Let's break down that simple query:

### 1. The Client Request

```python
# Client sends an A2A protocol message
{
    "agent_id": "crypto-client-123",
    "capability": "query",
    "message": "What's the price of Bitcoin?",
    "timestamp": "2024-12-19T10:30:00Z"
}
```

### 2. The Server Processing

```python
# Server receives and processes
1. Parse the incoming message
2. Extract the cryptocurrency symbol (BTC)
3. Look up the price (from mock data)
4. Format the response
5. Send back to client
```

### 3. The Response

```python
# Server responds with A2A message
{
    "agent_id": "crypto-price-agent",
    "response_to": "crypto-client-123",
    "message": "The current price of Bitcoin...",
    "data": {
        "symbol": "BTC",
        "price": 43250.00,
        "change_24h": 2.5
    }
}
```

> 💡 **Key Insight**: The A2A protocol is just structured JSON messages. Simple, right? But there's a LOT that can go wrong with security!

---

## 🎮 Hands-On Exploration (30 Minutes)

Before we dive into vulnerabilities, spend some time playing with the system:

### Exercise 1: Basic Queries (5 min)

Try these queries:
```
What's the price of Ethereum?
Show me SOL price
How much is Dogecoin?
Compare BTC and ETH
```

**What to notice:**
- Response format
- How the agent interprets natural language
- What information is included

### Exercise 2: Streaming Responses (5 min)

```
Stream prices for BTC
```

**What to notice:**
- Real-time updates
- How streaming works in A2A
- When streaming stops

### Exercise 3: Error Handling (5 min)

Try these:
```
What's the price of INVALIDCOIN?
Show me 
[empty query]
```

**What to notice:**
- How errors are handled
- What information is revealed
- Whether the server crashes

### Exercise 4: Edge Cases (5 min)

Try these:
```
What's the price of BTC BTC BTC BTC?
Show me prices for 100 different coins
[Really long query with 1000 words]
```

**What to notice:**
- Does anything break?
- Are there any limits?
- What happens with unusual input?

### Exercise 5: Code Reading (10 min)

Open `crypto_price_server.py` in your editor:

```bash
code crypto_price_server.py
# or
nano crypto_price_server.py
# or
vim crypto_price_server.py
```

**Skim through and notice:**
- How requests are received (line ~50)
- How queries are parsed (line ~120)
- How responses are generated (line ~180)
- Any TODO comments or warnings

> 🎯 **Goal**: Get familiar with the code structure before the security analysis.

---

## 🔴 The Vulnerability Hunt

Now for the main event! Let's identify the security issues.

### Vulnerability #1: No Authentication

**Location**: Entire codebase  
**Severity**: CRITICAL  
**CVSS Score**: 9.1

**The Problem:**
```python
# crypto_price_server.py - Line 50
def handle_request(self, request):
    # No authentication check!
    # Anyone can send requests
    return self.process_query(request)
```

**Why This Matters:**
- Anyone can access the agent
- No way to identify who's making requests
- Can't enforce access controls
- Can't audit who did what

**Attack Scenario:**
```python
# Attacker's script
for i in range(10000):
    requests.post("http://server:8080", json={
        "query": "What's the price of BTC?"
    })
# Server crashes from overload
```

**Real-World Impact:**
- Unauthorized access
- Resource exhaustion
- No accountability
- Impossible to bill for usage

> 💡 **Lesson**: Always authenticate requests. Even "public" APIs need some form of identification.

### Vulnerability #2: No Input Validation

**Location**: `process_query()` function  
**Severity**: HIGH  
**CVSS Score**: 7.8

**The Problem:**
```python
# crypto_price_server.py - Line 120
def process_query(self, query):
    # No validation!
    coin = self.extract_coin_from_query(query)
    return self.get_price(coin)
```

**Why This Matters:**
```python
# What happens with these inputs?
query = "A" * 1000000  # 1 million characters
query = "<script>alert('xss')</script>"
query = "'; DROP TABLE prices; --"
query = "../../etc/passwd"
query = None  # Causes crash
```

**Attack Demonstration:**

Try this in the client:
```
Enter your query: AAAAAAAAAAAA[... 10,000 A's ...]AAAAAAAA
```

**What happens?**
- Server tries to process it
- Memory usage spikes
- Response is slow or crashes
- No limits enforced

**Real-World Impact:**
- Denial of Service (DoS)
- Memory exhaustion
- Server crashes
- Injection attacks

> 💡 **Lesson**: NEVER trust user input. Validate length, format, content, and type.

### Vulnerability #3: Information Disclosure

**Location**: Error handling  
**Severity**: MEDIUM  
**CVSS Score**: 5.3

**The Problem:**
```python
# crypto_price_server.py - Line 200
except Exception as e:
    return {
        "error": str(e),  # ⚠️ Reveals internals!
        "traceback": traceback.format_exc()  # ⚠️ Even worse!
    }
```

**Why This Matters:**

Trigger an error:
```
Enter your query: [some malformed input]
```

**Response reveals:**
```json
{
    "error": "KeyError: 'INVALIDCOIN'",
    "traceback": "File '/home/user/crypto_server.py', line 150...",
    "system": "Ubuntu 22.04",
    "python_version": "3.11.2"
}
```

**What attackers learn:**
- File paths (where code lives)
- Python version (known vulnerabilities?)
- System details
- Code structure
- Library versions

**Real-World Impact:**
- Reconnaissance for attackers
- Information leakage
- Easier to plan attacks
- Privacy violations

> 💡 **Lesson**: Generic error messages for users, detailed logs for admins (not in responses).

### Vulnerability #4: No Rate Limiting

**Location**: Request handler  
**Severity**: HIGH  
**CVSS Score**: 7.5

**The Problem:**
```python
# No limit on requests per second/minute/hour
def handle_request(self, request):
    return self.process_query(request)  # Called unlimited times
```

**Attack Demonstration:**

Create a simple attack script:
```python
# attacker.py
import requests

url = "http://localhost:8080"
while True:  # Infinite loop!
    requests.post(url, json={"query": "BTC price?"})
```

**What happens:**
- Server processes every request
- CPU usage hits 100%
- Legitimate users can't connect
- Server becomes unresponsive

**Real-World Impact:**
- Denial of Service
- Service degradation
- High hosting costs
- Poor user experience

> 💡 **Lesson**: Always implement rate limiting. Even generous limits are better than none.

### Vulnerability #5: Command Injection (Potential)

**Location**: Query processing  
**Severity**: CRITICAL  
**CVSS Score**: 9.8

**The Problem:**
```python
# crypto_price_server.py - Line 140
def extract_coin_from_query(self, query):
    # Dangerous pattern (simplified for example)
    coin = query.split()[-1].upper()
    
    # If this were used in a command:
    # os.system(f"get_price {coin}")  # ⚠️ Injection!
```

**Why This Matters:**

If coin is used in a system command:
```python
query = "BTC; rm -rf /"  # Malicious command
coin = "BTC; rm -rf /"
os.system(f"get_price {coin}")  # Executes: get_price BTC; rm -rf /
```

**Real-World Impact:**
- Arbitrary code execution
- Complete system compromise
- Data theft
- Ransomware deployment

> 💡 **Lesson**: Never execute user input as code or commands. Use parameterized queries and whitelists.

### Vulnerability #6: No Logging/Auditing

**Location**: Entire system  
**Severity**: MEDIUM  
**CVSS Score**: 4.3

**The Problem:**
```python
# No audit trail
def handle_request(self, request):
    # Who made this request? We don't know!
    # When? We don't know!
    # What did they ask? We don't know!
    return self.process_query(request)
```

**Why This Matters:**
- Can't detect attacks
- Can't investigate incidents
- Can't prove compliance
- Can't debug issues

**Attack Goes Unnoticed:**
```
[Attacker queries sensitive data]
[Attacker attempts injection]
[Attacker DoS attacks the server]

Server logs: [empty]
```

**Real-World Impact:**
- No security monitoring
- Compliance violations (GDPR, HIPAA)
- Can't detect breaches
- Can't prove what happened

> 💡 **Lesson**: Log everything (but not sensitive data). Logs are your security camera.

### Vulnerability #7: Weak Data Validation

**Location**: Price lookup  
**Severity**: MEDIUM  
**CVSS Score**: 5.9

**The Problem:**
```python
# crypto_price_server.py - Line 160
def get_price(self, coin):
    # No validation that coin is valid
    return self.prices.get(coin, "Unknown")
```

**Why This Matters:**

Try these queries:
```
What's the price of ../../database/passwords?
Show me ../config/api_keys
Price of __import__('os').system('ls')
```

**If paths aren't validated:**
- Directory traversal attacks
- Access to sensitive files
- Information disclosure

**Real-World Impact:**
- Data leakage
- Path traversal
- File inclusion vulnerabilities

> 💡 **Lesson**: Whitelist valid inputs. Only allow known-good values.

### Vulnerability #8: No HTTPS

**Location**: Server configuration  
**Severity**: HIGH  
**CVSS Score**: 7.4

**The Problem:**
```python
# Server runs on HTTP, not HTTPS
server = HTTPServer(('0.0.0.0', 8080), RequestHandler)
# No SSL/TLS!
```

**Why This Matters:**
```
Attacker on network:
┌──────────┐  "BTC price?" (PLAINTEXT)  ┌──────────┐
│  Client  │ ───────────────────────────> │  Server  │
└──────────┘ <─────────────────────────── └──────────┘
              "Price: $43,250" (PLAINTEXT)
                     ↑
              [Attacker intercepts]
```

**Attack Demonstration:**

Network sniffer sees:
```
POST /query HTTP/1.1
Host: server:8080
{
    "agent_id": "client-123",
    "query": "What's the price of BTC?",
    "api_key": "secret123"  ← Visible!
}
```

**Real-World Impact:**
- Eavesdropping
- Man-in-the-middle attacks
- Credential theft
- Data tampering

> 💡 **Lesson**: Always use HTTPS in production. Encrypt data in transit.

### Vulnerability #9: No Request Size Limits

**Location**: Request parsing  
**Severity**: MEDIUM  
**CVSS Score**: 6.5

**The Problem:**
```python
def do_POST(self):
    content_length = int(self.headers['Content-Length'])
    # No maximum size check!
    post_data = self.rfile.read(content_length)
```

**Attack Demonstration:**
```python
# Attacker sends 1GB request
huge_query = "A" * (1024 * 1024 * 1024)  # 1GB
requests.post(url, json={"query": huge_query})
```

**What happens:**
- Server tries to read 1GB into memory
- Memory exhaustion
- Server crashes or becomes unresponsive
- Affects all users

**Real-World Impact:**
- Denial of Service
- Memory exhaustion
- Server crashes
- Service unavailability

> 💡 **Lesson**: Set maximum request sizes. Reject oversized requests early.

### Vulnerability #10: Predictable Agent ID

**Location**: Agent identification  
**Severity**: LOW  
**CVSS Score**: 3.1

**The Problem:**
```python
agent_id = "crypto-price-agent"  # Same for all instances
```

**Why This Matters:**
- Can't distinguish between agent instances
- Can't do load balancing
- Can't trace requests to specific servers
- Easier for attackers to target

**Better Approach:**
```python
agent_id = f"crypto-price-agent-{uuid.uuid4()}"
# Results in: crypto-price-agent-a3d2c9f1-...
```

> 💡 **Lesson**: Use unique identifiers for each agent instance.

---

## 🎯 Vulnerability Summary Table

| # | Vulnerability | Severity | CVSS | Line | Fix in Stage |
|---|---------------|----------|------|------|--------------|
| 1 | No Authentication | CRITICAL | 9.1 | All | 2, 3 |
| 2 | No Input Validation | HIGH | 7.8 | 120 | 2, 3 |
| 3 | Information Disclosure | MEDIUM | 5.3 | 200 | 3 |
| 4 | No Rate Limiting | HIGH | 7.5 | All | 3 |
| 5 | Command Injection Risk | CRITICAL | 9.8 | 140 | 3 |
| 6 | No Logging | MEDIUM | 4.3 | All | 3 |
| 7 | Weak Data Validation | MEDIUM | 5.9 | 160 | 2, 3 |
| 8 | No HTTPS | HIGH | 7.4 | Config | 3 |
| 9 | No Request Limits | MEDIUM | 6.5 | Parser | 3 |
| 10 | Predictable Agent ID | LOW | 3.1 | 30 | 3 |

**Total Vulnerabilities**: 10 documented (15+ exist)  
**Average Severity**: HIGH  
**Stage 1 Security Rating**: 0/10 ❌

---

## 💪 Practice Exercises

### Exercise 1: Vulnerability Hunt (30 min)

**Task**: Find 3 vulnerabilities NOT listed above.

**Hints:**
- Look at error handling
- Check the streaming code
- Review the price data storage
- Examine the query parser

**Submit your findings:**
1. Vulnerability name
2. Code location (file & line)
3. Why it's dangerous
4. How to exploit it

### Exercise 2: Attack Simulation (30 min)

**Task**: Write a script that exploits vulnerability #4 (No Rate Limiting)

```python
# attack.py - Your code here
import requests
import time

# TODO: Send 1000 requests in 10 seconds
# TODO: Measure server response time degradation
# TODO: Prove DoS is possible
```

**Success Criteria:**
- Server response time increases
- Server CPU usage hits 100%
- Legitimate queries are delayed

### Exercise 3: Impact Analysis (20 min)

**Task**: For each vulnerability, write:
1. Who could exploit it? (attacker profile)
2. What's the worst-case outcome?
3. How likely is exploitation? (1-10)
4. Business impact (money, reputation, legal)

**Example:**
```
Vulnerability: No Authentication
Attacker: Anyone with network access
Worst case: Unauthorized data access + DoS
Likelihood: 10/10 (trivial to exploit)
Impact: $100K in losses, reputation damage, possible lawsuit
```

### Exercise 4: Security Checklist (30 min)

**Task**: Create a checklist for code review.

Based on what you learned, make a list:
- [ ] Authentication implemented?
- [ ] Input validation present?
- [ ] Rate limiting configured?
- [Add more items...]

Use this checklist on any code you review!

### Exercise 5: Fix One Thing (1 hour)

**Task**: Take Stage 1 code and fix JUST vulnerability #2 (Input Validation)

```python
# Your code in fixed_server.py
def process_query(self, query):
    # TODO: Add validation here
    # - Check query is a string
    # - Check length < 500 characters
    # - Check for dangerous characters
    # - Sanitize input
    
    if not self.validate_query(query):
        return {"error": "Invalid query"}
    
    return self.get_price(query)

def validate_query(self, query):
    # Your validation code here
    pass
```

**Test your fix:**
- Normal queries should work
- Malicious queries should be rejected
- Error messages should be safe

---

## ✅ Stage 1 Completion Checklist

Before moving to Stage 2, make sure you can:

### Understanding (Knowledge)
- [ ] Explain what the A2A protocol is
- [ ] Describe how requests and responses work
- [ ] Identify at least 10 security vulnerabilities
- [ ] Explain why each vulnerability matters
- [ ] Describe the attack scenarios

### Skills (Practical)
- [ ] Run the Stage 1 server
- [ ] Query prices using the client
- [ ] Read and understand the code
- [ ] Write a simple exploit script
- [ ] Use the security checklist

### Mindset (Attitude)
- [ ] Appreciate why security is critical
- [ ] Understand "secure by default" principle
- [ ] Recognize the cost of vulnerabilities
- [ ] Feel motivated to learn secure patterns
- [ ] Understand that "working" ≠ "secure"

### Ready for Stage 2?
- [ ] Completed all exercises (or attempted them)
- [ ] Read the full Stage 1 code
- [ ] Reviewed vulnerability table
- [ ] Understand the limitations

**If you checked most boxes**: You're ready for Stage 2! 🎉  
**If not**: That's okay! Review the sections you're unsure about.

---

## 🎓 Key Takeaways

### The Big Lessons

**1. Working ≠ Secure**
> Just because code runs doesn't mean it's safe. Stage 1 works perfectly... for attackers.

**2. Security is Hard**
> Did you spot all 10 vulnerabilities immediately? Probably not! That's why we need systematic approaches.

**3. Defense in Depth**
> Notice how vulnerabilities compound? No auth + no validation + no rate limiting = disaster.

**4. Attackers Only Need One**
> We need to fix ALL vulnerabilities. Attackers only need to exploit ONE.

**5. Security by Default**
> Starting insecure and adding security later (Stage 1 → 3) is harder than starting secure.

---

## 🚫 Important Reminders

### What NOT to Do

**❌ NEVER deploy Stage 1 code to:**
- Production servers
- Public networks
- Real systems
- Anywhere with actual data

**❌ NEVER use Stage 1 code with:**
- Real cryptocurrency APIs
- Actual financial data
- Customer information
- Any sensitive data

**❌ NEVER:**
- Copy-paste without understanding
- Skip the vulnerability analysis
- Assume "it works" means "it's secure"
- Use this as a template (use Stage 3 instead)

### What TO Do

**✅ DO use Stage 1 for:**
- Learning and education
- Security training
- Vulnerability practice
- Understanding attacks

**✅ DO:**
- Study every vulnerability
- Try the exploits (locally!)
- Read the security analysis
- Complete the exercises
- Move to Stage 2 when ready

---

## 📚 Additional Resources

### Deep Dive

Want to learn more about specific vulnerabilities?

- **No Authentication**: [OWASP Authentication Guide](https://owasp.org/www-project-authentication-cheat-sheet/)
- **Input Validation**: [OWASP Input Validation](https://owasp.org/www-community/vulnerabilities/Input_Validation)
- **Rate Limiting**: [Rate Limiting Best Practices](https://cloud.google.com/architecture/rate-limiting-strategies)
- **Command Injection**: [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### Related Documentation

- [A2A Overview](/docs/a2a/00_A2A_OVERVIEW.md) - Protocol basics
- [Security Best Practices](/docs/a2a/03_SECURITY/04_security_best_practices.md) - What to do instead
- [Threat Model](/docs/a2a/03_SECURITY/03_threat_model.md) - Understanding attackers
- [Authentication Overview](/docs/a2a/03_SECURITY/01_authentication_overview.md) - How to authenticate

### Code Files

- [Full Security Analysis](/examples/a2a_crypto_example/SECURITY_ANALYSIS.md) - All 15+ vulnerabilities
- [Stage 1 Server Code](/examples/a2a_crypto_example/insecure/crypto_price_server.py)
- [Stage 1 Client Code](/examples/a2a_crypto_example/insecure/crypto_client.py)

---

## ❓ FAQ

### "Should I memorize all the vulnerabilities?"

No! The goal is to understand the **patterns**. Once you see these patterns, you'll spot them everywhere.

### "I didn't find all 10 vulnerabilities. Am I bad at this?"

Not at all! Security is learned through practice. Keep at it, and it'll become second nature.

### "Can I fix these vulnerabilities myself?"

Absolutely! That's a great learning exercise. But also compare your fixes with Stage 2 & 3 to see different approaches.

### "When should I move to Stage 2?"

When you:
1. Understand how Stage 1 works
2. Can identify most vulnerabilities
3. Completed at least 3 exercises
4. Feel comfortable with the code

### "Is Stage 1 realistic? Would anyone write code this bad?"

Unfortunately, yes. Many real-world systems start like this and never get secured. That's why breaches happen!

### "How long should I spend on Stage 1?"

**Minimum**: 2-3 hours  
**Recommended**: 4-6 hours with exercises  
**Thorough**: 8-10 hours with all exercises and experimentation

Take your time! This foundation is important.

---

## 🎯 What's Next?

### Moving to Stage 2

Once you're comfortable with Stage 1:

**[Continue to Stage 2 - Improved →](./crypto-stage2.md)**

Stage 2 will show you:
- How to add agent registry and service discovery
- Basic authentication with HMAC
- Simple input validation
- **Why these improvements STILL aren't enough**

### Other Learning Paths

Want variety?
- [Credit Report Example](./credit_report_example.md) - File upload security
- [Task Collaboration Example](./task_collaboration_example.md) - Session management
- [MCP Fundamentals](/docs/mcp_fundamentals.md) - Learn Model Context Protocol

---

## 🎉 Congratulations!

You've completed Stage 1! You now:
- ✅ Understand the A2A protocol basics
- ✅ Can recognize security vulnerabilities
- ✅ Appreciate the importance of security
- ✅ Have hands-on experience with an A2A agent
- ✅ Are ready for more advanced topics

**This is a big milestone!** You've taken the first step toward building secure multi-agent systems.

---

**Document Version**: 1.0  
**Stage**: 1 of 3 (Vulnerable)  
**Last Updated**: December 2025  
**Maintained By**: Robert Fischer (robert@fischer3.net)  
**Code Location**: `/examples/a2a_crypto_example/insecure/`

---

**Ready for the next challenge?** [Let's improve this code in Stage 2 →](./crypto-stage2.md)

> 💪 **You've got this!** Remember: Every security expert started exactly where you are now. The difference is they kept learning. You're on the same path! 🚀