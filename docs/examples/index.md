# A2A Protocol Examples

> 🎓 **Learn by Doing**: Progressive security examples that take you from beginner to expert

---

## 👋 Welcome!

You're about to embark on a hands-on learning journey through the Agent2Agent (A2A) protocol. These examples are designed to teach you secure multi-agent systems through **progressive learning** - starting with vulnerable code and gradually building up to production-ready implementations.

**Why this approach?** Because understanding what's *wrong* is just as important as knowing what's *right*. By seeing vulnerabilities firsthand, you'll develop the security mindset needed for building real-world systems.

> 💡 **Learning Philosophy**: We believe the best way to learn security is to:
> 1. See what breaks
> 2. Understand why it breaks  
> 3. Learn how to fix it
> 4. Build it right from the start

---

## 🎯 Choose Your Learning Path

Each example follows a **3-stage progression** from vulnerable to secure. Pick the example that interests you most, or work through all of them for comprehensive coverage!

---

## 📚 Available Examples

### 🪙 Cryptocurrency Price Agent

**Focus**: Basic A2A Protocol, Query Security, Authentication  
**Difficulty**: ⭐ Beginner-Friendly  
**Time**: 6-8 hours (all stages)  
**Best For**: Your first A2A agent

**What You'll Learn**:
- A2A protocol fundamentals
- Request/response patterns
- Authentication evolution (none → HMAC → Ed25519)
- Replay attack prevention
- Rate limiting strategies

**The Journey**:
```
Stage 1: Vulnerable (0/10)    →  Stage 2: Improved (4/10)    →  Stage 3: Secure (9/10)
❌ No security                   ⚠️ Partial security             ✅ Production-ready
15+ vulnerabilities             Some fixes, still exploitable   Complete defense in depth
2-3 hours                        2-3 hours                       3-4 hours
```

**Start Here**: [Crypto Agent Overview](./crypto_agent_example.md)

**Quick Links**:
- [Stage 1 - Vulnerable](./crypto-stage1.md) - Learn to spot vulnerabilities
- [Stage 2 - Improved](./crypto-stage2.md) - Understand why partial security fails
- [Stage 3 - Secure](./crypto-stage3.md) - Build production-grade systems

**Why Start Here?**
- Simplest example (just price queries)
- No complex business logic
- Perfect for learning A2A basics
- Transferable patterns

---

### 💳 Credit Report Analysis Agent

**Focus**: File Upload Security, PII Protection, GDPR/HIPAA Compliance  
**Difficulty**: ⭐⭐ Intermediate  
**Time**: 8-12 hours (all stages + AI)  
**Best For**: Document processing, sensitive data handling

**What You'll Learn**:
- File upload security (magic bytes, size limits, path traversal)
- 8-layer validation framework
- PII protection and masking
- Regulatory compliance (GDPR, HIPAA)
- Secure AI integration (Stage 4 bonus!)

**The Journey**:
```
Stage 1: Insecure (0/10)  →  Stage 2: Improved (4/10)  →  Stage 3: Secure (9/10)  →  Stage 4: AI (9/10)
❌ Dangerous file handling   ⚠️ Basic validation         ✅ Production validation    ✅ Secure AI integration
26 vulnerabilities           Some fixes                  Complete security           Gemini AI + security
3-4 hours                    2-3 hours                   3-4 hours                   2-3 hours
```

**Start Here**: [Credit Report Example](./credit_report_example.md)

**Quick Links**:
- Stage 1 - Insecure (file upload dangers)
- Stage 2 - Improved (partial validation)
- Stage 3 - Secure (production file handling)
- Stage 4 - AI Enhanced (secure LLM integration)

**Why Choose This?**
- Real-world file handling patterns
- Compliance requirements
- PII protection techniques
- AI security (Stage 4)

---

### 🤝 Task Collaboration System

**Focus**: Session Management, Multi-Agent Coordination, State Management  
**Difficulty**: ⭐⭐⭐ Advanced  
**Time**: 12-16 hours (all stages)  
**Best For**: Multi-agent systems, stateful applications

**What You'll Learn**:
- Session management security
- Multi-agent coordination patterns
- Distributed systems (Redis)
- Web framework integration (Flask)
- State management security

**The Journey**:
```
Stage 1: Insecure     →  Stage 2: Improved     →  Stage 3: Secure        →  Stage 4: Distributed  →  Stage 5: Web Framework
❌ No session security   ⚠️ Basic improvements   ✅ SessionManager       ✅ Redis-backed         ✅ Flask + JWT
25+ vulnerabilities      20 fixes, 15 remain     All vulnerabilities     High availability       Production web app
3-4 hours                3-4 hours               3-4 hours               2-3 hours               2-3 hours
```

**Start Here**: [Task Collaboration Example](./task_collaboration_example.md)

**Quick Links**:
- Stage 1 - Insecure (session vulnerabilities)
- Stage 2 - Improved (partial fixes)
- Stage 3 - Secure (SessionManager pattern)
- Stage 4 - Distributed (Redis integration)
- Stage 5 - Web Framework (Flask + JWT + CSRF)

**Why Choose This?**
- Most comprehensive example
- Real distributed systems
- Web framework patterns
- Advanced coordination

---

## 🗺️ Learning Paths by Goal

### Path 1: Quick Start (Weekend Project)

**Goal**: Understand A2A basics and get something running

**Recommended**:
1. [Crypto Example - Stage 1](./crypto-stage1.md) (3 hours)
2. [Crypto Example - Stage 3](./crypto-stage3.md) (4 hours)
3. Build your own agent using Stage 3 as template (4 hours)

**Total**: ~11 hours  
**Outcome**: Working secure A2A agent

---

### Path 2: Security Focus (1 Week)

**Goal**: Master security patterns across different domains

**Recommended**:
1. Crypto Example (all stages) - 8 hours
2. Credit Report Example (stages 1-3) - 10 hours
3. Task Collaboration (stages 1-3) - 12 hours

**Total**: ~30 hours  
**Outcome**: Deep security expertise

---

### Path 3: Complete Mastery (2-3 Weeks)

**Goal**: Become an A2A security expert

**Recommended**:
1. All Crypto stages + exercises - 12 hours
2. All Credit Report stages (including AI) - 14 hours
3. All Task Collaboration stages - 16 hours
4. Build 2-3 your own secure agents - 20 hours

**Total**: ~62 hours  
**Outcome**: Expert-level knowledge

---

### Path 4: Specific Domain (Flexible)

**Goal**: Learn security for your specific use case

**Choose Based on Your Needs**:
- **API/Query Security** → Crypto Example
- **File Uploads/PII** → Credit Report Example
- **Sessions/State Management** → Task Collaboration Example
- **AI Integration** → Credit Report Stage 4
- **Distributed Systems** → Task Collaboration Stages 4-5

---

## 📊 Example Comparison Matrix

| Feature | Crypto | Credit Report | Task Collaboration |
|---------|--------|---------------|-------------------|
| **Difficulty** | ⭐ Beginner | ⭐⭐ Intermediate | ⭐⭐⭐ Advanced |
| **Time** | 6-8 hours | 8-12 hours | 12-16 hours |
| **Stages** | 3 | 4 | 5 |
| **Focus** | Authentication | File Security | Session Mgmt |
| **Best For** | First project | Document handling | Multi-agent systems |
| **Vulnerabilities** | 15+ | 26+ | 25+ |
| **Key Lessons** | Crypto, Replay attacks | PII, Validation | Sessions, Coordination |
| **Production Ready?** | Stage 3 ✅ | Stage 3 ✅ | Stage 3+ ✅ |
| **Code Lines** | ~2,000 | ~3,000 | ~4,000 |
| **Tests Included** | ✅ | ✅ | ✅ |
| **Docker Support** | ❌ | ❌ | ✅ |
| **AI Integration** | ❌ | ✅ (Stage 4) | ❌ |
| **Web Framework** | ❌ | ❌ | ✅ (Stage 5) |

---

## 🎓 What You'll Learn Across All Examples

### Core A2A Protocol
- Agent identity and capabilities
- Message structure and routing
- Request/response patterns
- Streaming events
- Service discovery
- Agent registry

### Authentication & Authorization
- No auth → HMAC → Ed25519 progression
- Shared secrets vs public-key crypto
- Signature verification
- Key management
- Client authorization
- Permission systems

### Attack Prevention
- Replay attacks (nonces + timestamps)
- Injection attacks (SQL, command, XSS)
- Path traversal
- Session hijacking/fixation
- CSRF attacks
- Rate limiting bypass
- DoS attacks

### Validation
- Type validation
- Size validation
- Format validation
- Content validation
- Semantic validation
- Business logic validation
- 8-layer defense in depth

### Secure Design Patterns
- Modular security architecture
- Separation of concerns
- Defense in depth
- Fail securely
- Principle of least privilege
- Secure by default

### Production Considerations
- TLS/HTTPS
- Monitoring and alerting
- Audit logging
- Error handling
- Key rotation
- Compliance (GDPR, HIPAA)
- Performance optimization
- Deployment strategies

---

## 🛠️ Prerequisites

### Required Knowledge
- **Python**: Intermediate level (functions, classes, async)
- **HTTP**: Basic understanding (requests, responses, headers)
- **JSON**: Comfortable reading and writing
- **Command Line**: Can navigate and run commands

### Nice to Have
- Basic cryptography concepts
- Experience with APIs
- Understanding of web security
- Docker knowledge (for some examples)

### System Requirements
- **Python 3.8+**
- **pip** for package management
- **Redis** (optional, can use mock)
- **Text Editor** or IDE
- **Terminal/Command Line**

### Time Commitment
- **Minimum**: 1-2 hours per stage
- **Recommended**: Take your time, do exercises
- **Ideal**: Spread learning over multiple sessions

---

## 💪 How to Use These Examples

### For Individual Learners

**Step 1: Choose Your Example**
Start with Crypto (easiest) or pick based on your domain.

**Step 2: Work Through Stages Sequentially**
Don't skip! Stage 1 → 2 → 3 builds understanding.

**Step 3: Do the Exercises**
Hands-on practice cements learning.

**Step 4: Build Your Own**
Apply patterns to a new domain.

### For Instructors

**Week 1: Introduction**
- Crypto Example Stage 1
- Live vulnerability demos
- Attack demonstrations

**Week 2: Improvements**
- Crypto Example Stage 2
- Why partial security fails
- Critical thinking exercises

**Week 3: Production Patterns**
- Crypto Example Stage 3
- Security module deep dives
- Code review practice

**Week 4: Advanced Topics**
- Choose Credit Report or Task Collaboration
- Domain-specific security
- Real-world scenarios

**Week 5: Capstone Project**
- Students build secure agents
- Peer code review
- Security presentations

### For Teams

**Sprint 1: Assessment**
- Everyone does Crypto Stage 1
- Team identifies vulnerabilities in existing systems
- Document findings

**Sprint 2: Planning**
- Review Crypto Stage 3 patterns
- Adapt to team's tech stack
- Create security roadmap

**Sprint 3: Implementation**
- Apply patterns to team's systems
- Use examples as reference
- Conduct peer reviews

**Sprint 4: Testing & Deployment**
- Security testing
- Penetration testing
- Deploy improvements

### For Self-Study

**Morning (Theory)**:
- Read the stage documentation
- Understand the concepts
- Review code examples

**Afternoon (Practice)**:
- Run the code
- Try the exercises
- Experiment with attacks

**Evening (Reflection)**:
- What did you learn?
- What surprised you?
- How would you apply this?

**Weekend (Build)**:
- Create your own agent
- Apply the patterns
- Share with community

---

## 🎯 Success Criteria

You'll know you've mastered an example when you can:

✅ **Explain** the vulnerabilities in Stage 1  
✅ **Demonstrate** attacks against Stage 1 code  
✅ **Critique** why Stage 2 improvements aren't enough  
✅ **Implement** Stage 3 security patterns  
✅ **Adapt** patterns to your own projects  
✅ **Teach** others using the examples  

---

## 📚 Additional Resources

### Before You Start
- [A2A Protocol Overview](/docs/a2a/00_A2A_OVERVIEW.md)
- [Core Concepts](/docs/a2a/01_FUNDAMENTALS/01_core_concepts.md)
- [Agent Identity](/docs/a2a/01_FUNDAMENTALS/02_agent_identity.md)

### Security Deep Dives
- [Authentication Overview](/docs/a2a/03_SECURITY/01_authentication_overview.md)
- [Authentication Tags](/docs/a2a/03_SECURITY/02_authentication_tags.md)
- [Threat Model](/docs/a2a/03_SECURITY/03_threat_model.md)
- [Security Best Practices](/docs/a2a/03_SECURITY/04_security_best_practices.md)

### Protocol Details
- [Protocol Messages](/docs/a2a/04_COMMUNICATION/01_protocol_messages.md)
- [Streaming Events](/docs/a2a/04_COMMUNICATION/02_streaming_events.md)
- [Agent Cards](/docs/a2a/02_DISCOVERY/01_agent_cards.md)
- [Agent Registry](/docs/a2a/02_DISCOVERY/02_agent_registry.md)

### Integration
- [MCP Fundamentals](/docs/mcp_fundamentals.md)
- [A2A + MCP Integration](/docs/integration_summary.md)

---

## 🤝 Community & Support

### Get Help

**Stuck on something?**
1. Re-read the relevant section
2. Check the FAQ in each stage
3. Review the code comments
4. Try the exercise again
5. Ask for help (details below)

**Found a bug?**
- Open an issue with reproduction steps
- Include error messages
- Share your environment details

**Have suggestions?**
- We'd love to hear them!
- What worked well?
- What was confusing?
- What should we add?

### Contribute

**Ways to Contribute**:
- Fix typos or improve clarity
- Add more exercises
- Create translations
- Share your implementations
- Help other learners

**Guidelines**:
- Keep the progressive learning approach
- Maintain the supportive tone
- Include practical examples
- Test all code changes

---

## ⚠️ Important Disclaimers

### Educational Use Only

**These examples are for learning.** Stage 1 and 2 code contains intentional vulnerabilities.

**DO**:
- ✅ Use for education and training
- ✅ Study the vulnerabilities
- ✅ Practice secure coding
- ✅ Use Stage 3 as template

**DON'T**:
- ❌ Deploy Stage 1 or 2 to production
- ❌ Use with real sensitive data
- ❌ Connect to public networks (Stages 1-2)
- ❌ Skip vulnerability analysis

### Legal Notice

This documentation and code are provided for educational purposes. The authors and contributors:
- Make no warranties about fitness for production use
- Are not liable for security breaches from misuse
- Recommend security audits before deployment
- Encourage responsible disclosure of vulnerabilities

**Use at your own risk.**

---

## 🎉 Ready to Start?

Choose your adventure:

### 🪙 [Start with Crypto Example →](./crypto_agent_example.md)
Perfect for beginners, covers A2A fundamentals

### 💳 [Try Credit Report Example →](./credit_report_example.md)
File security and PII protection

### 🤝 [Explore Task Collaboration →](./task_collaboration_example.md)
Advanced multi-agent patterns

---

## 📊 Your Progress

Track your learning journey:

```
Crypto Example:
[ ] Stage 1 - Vulnerable
[ ] Stage 2 - Improved
[ ] Stage 3 - Secure
[ ] Built my own secure agent

Credit Report Example:
[ ] Stage 1 - Insecure
[ ] Stage 2 - Improved
[ ] Stage 3 - Secure
[ ] Stage 4 - AI Enhanced

Task Collaboration Example:
[ ] Stage 1 - Insecure
[ ] Stage 2 - Improved
[ ] Stage 3 - Secure
[ ] Stage 4 - Distributed
[ ] Stage 5 - Web Framework

Mastery:
[ ] Can identify vulnerabilities quickly
[ ] Can explain security trade-offs
[ ] Can implement production patterns
[ ] Can teach others
[ ] Built 3+ secure agents
```

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Maintained By**: Robert Fischer (robert@fischer3.net)  
**Examples Location**: `/a2a_examples/`

---

**Let's build secure multi-agent systems together!** 🚀

> 💡 **Remember**: Security is learned, not innate. Everyone starts somewhere. You're in the right place! Happy learning! 🎓