# Stage 2 Demo Quick Start Guide

## 🚀 Quick Start

```bash
# Complete demonstration (recommended first time)
python demo_stage2.py

# Or choose specific mode:
python demo_stage2.py security     # Security features only
python demo_stage2.py legitimate   # Proper usage only
python demo_stage2.py attacks      # Attack demos only
python demo_stage2.py compare      # Side-by-side comparison
```

---

## 📋 Available Modes

### 1. Complete Demo (Default)
```bash
python demo_stage2.py all
# or just
python demo_stage2.py
```

**Duration**: 10-15 minutes  
**Includes**:
- Security features overview
- Legitimate worker demonstration
- All 4 attack demonstrations
- Side-by-side comparison
- Final summary

**Best for**: First-time users, comprehensive learning

---

### 2. Security Features Only
```bash
python demo_stage2.py security
```

**Duration**: 3-4 minutes  
**Shows**:
- JWT authentication demo
- RBAC authorization demo
- Schema validation demo
- What each feature blocks/allows

**Best for**: Understanding Stage 2's security layers

---

### 3. Legitimate Usage Only
```bash
python demo_stage2.py legitimate
```

**Duration**: 2-3 minutes  
**Shows**:
- Proper registration
- Correct token usage
- Benign message sending
- Normal task processing

**Best for**: Learning correct API usage

---

### 4. Attack Demonstrations Only
```bash
python demo_stage2.py attacks
```

**Duration**: 5-7 minutes  
**Shows**:
- Attack 1: Role Escalation (CVSS 9.1)
- Attack 2: Deep-Nested Exfiltration (CVSS 8.6)
- Attack 3: Token Replay (CVSS 8.1)
- Attack 4: Legitimate API Abuse (CVSS 7.5)

**Best for**: Security professionals, attack pattern study

---

### 5. Comparison Mode
```bash
python demo_stage2.py compare
```

**Duration**: 2-3 minutes  
**Shows**:
- Side-by-side legitimate vs malicious behavior
- Why attacks succeed
- Key lessons

**Best for**: Quick understanding of the differences

---

## 🎯 Recommended Learning Path

### For Beginners
1. Run complete demo: `python demo_stage2.py`
2. Review security features: `python demo_stage2.py security`
3. Study comparison: `python demo_stage2.py compare`

### For Security Professionals
1. Review attacks: `python demo_stage2.py attacks`
2. Analyze features: `python demo_stage2.py security`
3. Full walkthrough: `python demo_stage2.py`

### For Developers
1. See proper usage: `python demo_stage2.py legitimate`
2. Understand attacks: `python demo_stage2.py attacks`
3. Compare approaches: `python demo_stage2.py compare`

---

## 📊 What You'll See

### Security Features Demo Output
```
╔════════════════════════════════════════════════════════════════╗
║                    STAGE 2 SECURITY FEATURES                   ║
╚════════════════════════════════════════════════════════════════╝

Stage 2 added three security layers over Stage 1:

─────────────────────────────────────────────────────────────────
 1. JWT Authentication (HS256)
─────────────────────────────────────────────────────────────────

  Implementation:
    • Agents must register with password
    • Password hashed with bcrypt (cost factor 12)
    • JWT tokens issued with 24-hour expiration
    • All operations require valid token

  What it blocks:
    ✅ Anonymous access (100% prevented)
    ✅ Identity spoofing (100% prevented)
  
  [Interactive demonstrations...]
```

### Attack Demo Output
```
╔════════════════════════════════════════════════════════════════╗
║              ATTACK 1: Role Escalation                         ║
╚════════════════════════════════════════════════════════════════╝

🎯 Target: Unverified role assignment during registration
🔧 Technique: Request admin role, system grants it

[Step-by-step attack demonstration...]

╔════════════════════════════════════════╗
║  ✅ ATTACK SUCCESSFUL!                 ║
╚════════════════════════════════════════╝
   🎭 Granted role: admin
   [Impact assessment...]
```

---

## ⏸️ Interactive Features

The demo includes pause points:

```
⏸️  Press Enter to continue to Legitimate Usage...
⏸️  Press Enter to continue to Attack Demonstrations...
⏸️  Press Enter to see final comparison...
```

**Purpose**: 
- Gives time to read and understand each section
- Prevents information overload
- Allows note-taking

**Tip**: Take screenshots at each pause point for later review!

---

## 🎓 Learning Objectives

After completing the demo, you should understand:

### Security Concepts
- [ ] What JWT authentication provides (and doesn't)
- [ ] How RBAC works in practice
- [ ] Why schema validation must be comprehensive
- [ ] The difference between authentication and authorization

### Attack Techniques
- [ ] How role escalation works
- [ ] Data hiding in nested structures
- [ ] Token replay attack patterns
- [ ] Legitimate API abuse

### Design Lessons
- [ ] Why partial security creates false confidence
- [ ] What "defense in depth" means
- [ ] Why behavioral analysis is necessary
- [ ] How Stage 3 addresses Stage 2's gaps

---

## 📁 Related Files

After running the demo, explore:

```
stage2_improved/
├── demo_stage2.py              ← You are here
├── README.md                   ← Complete documentation
├── SECURITY_ANALYSIS.md        ← Detailed vulnerability analysis
├── agents/
│   ├── malicious_worker.py    ← Attack implementations
│   └── legitimate_worker.py   ← Proper usage example
└── [security modules...]
```

---

## 💡 Tips for Best Experience

### Before Running
1. **Read README.md first** - Get context
2. **Install dependencies** - `pip install -r requirements.txt`
3. **Clear your terminal** - Start with clean output
4. **Allocate time** - Complete demo takes 10-15 minutes

### While Running
1. **Read carefully** - Each section teaches important concepts
2. **Take notes** - Write down key vulnerabilities
3. **Ask questions** - Pause and research if confused
4. **Take screenshots** - Document attack successes

### After Running
1. **Review code** - Look at actual implementations
2. **Read analysis** - Study SECURITY_ANALYSIS.md
3. **Try modifications** - Experiment with the code
4. **Compare stages** - See Stage 1 and Stage 3

---

## 🔧 Troubleshooting

### Error: "No module named 'core'"
```bash
# Make sure you're in the stage2_improved directory
cd a2a_adversarial_agent_example/stage2_improved
python demo_stage2.py
```

### Error: "No module named 'jwt'"
```bash
# Install dependencies
pip install -r requirements.txt
```

### Demo runs too fast
```bash
# Use pauses to control pace
# Press Ctrl+S to pause terminal output
# Press Ctrl+Q to resume
```

### Want to save output
```bash
# Redirect to file
python demo_stage2.py | tee demo_output.txt
```

---

## 🎯 Next Steps

### After the Demo

1. **Read Documentation**
   - README.md - Complete user guide
   - SECURITY_ANALYSIS.md - Vulnerability details

2. **Study the Code**
   - malicious_worker.py - Attack implementations
   - legitimate_worker.py - Proper usage
   - Security modules - How defenses work

3. **Run Individual Components**
   ```bash
   python agents/malicious_worker.py    # Just attacks
   python agents/legitimate_worker.py   # Just proper usage
   ```

4. **Explore Stage 1**
   - See the completely vulnerable system
   - Compare attack techniques

5. **Preview Stage 3**
   - Learn about comprehensive security
   - See how all attacks are blocked

---

## 📚 Additional Resources

### In This Repository
- [Stage 1 Demo](../stage1_insecure/demo_attacks.py)
- [Stage 3 Implementation Plan](../stage3_secure/IMPLEMENTATION_PLAN.md)
- [8-Layer Validation Guide](../../docs/presentations/eight-layer-validation/)

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

## ❓ FAQ

**Q: How long does the complete demo take?**  
A: 10-15 minutes with pauses for reading.

**Q: Can I run it multiple times?**  
A: Yes! Each run creates fresh instances.

**Q: Do attacks actually work?**  
A: Yes! They succeed against Stage 2's partial security.

**Q: Is this safe to run?**  
A: Yes, everything is isolated and educational.

**Q: Can I modify the demo?**  
A: Absolutely! It's educational code - experiment!

**Q: What if I only want to see one attack?**  
A: Edit malicious_worker.py or run attacks mode and Ctrl+C after desired attack.

**Q: How do I share results with others?**  
A: Use `tee` to save output: `python demo_stage2.py | tee results.txt`

---

## 📞 Need Help?

- **Documentation**: See README.md
- **Issues**: Check GitHub Issues
- **Questions**: GitHub Discussions
- **Email**: robert@fischer3.net

---

**Last Updated**: January 2026  
**Version**: 2.0  
**Status**: Production-Ready