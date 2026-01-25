# Credit Report Analysis Agent - Stage 1: INSECURE Implementation

> ⚠️ **CRITICAL WARNING**: This code is INTENTIONALLY VULNERABLE for educational purposes.  
> **DO NOT USE IN PRODUCTION**. Contains 25+ security vulnerabilities.

## 🎯 Educational Purpose

This is **Stage 1** of a three-stage security learning journey. This implementation demonstrates **common security mistakes** in file upload and data handling systems. By studying these vulnerabilities, you'll learn to recognize and avoid them in your own code.

### Learning Objectives

After studying this code, you should be able to:
- ✅ Identify file upload vulnerabilities
- ✅ Recognize input validation failures
- ✅ Spot authentication and authorization gaps
- ✅ Understand DoS attack vectors
- ✅ See the dangers of logging sensitive data (PII)

---

## 🚨 Security Vulnerabilities

This implementation contains **25+ intentional vulnerabilities**:

### File Handling Vulnerabilities (Critical)
1. ❌ **No File Size Limits** - Can upload gigabyte files (DoS)
2. ❌ **No File Type Validation** - Accepts any file extension
3. ❌ **No Magic Byte Validation** - Doesn't verify actual file content
4. ❌ **No Filename Sanitization** - Path traversal possible (../../etc/passwd)
5. ❌ **Unbounded Storage** - No cleanup, no limits (disk exhaustion)
6. ❌ **No Streaming** - Loads entire file into memory

### Input Validation Vulnerabilities (Critical)
7. ❌ **No Schema Validation** - Accepts malformed JSON
8. ❌ **No Range Validation** - Credit scores can be negative or 999999
9. ❌ **No Sanitization** - SQL injection, command injection possible
10. ❌ **Direct Field Access** - KeyError crashes possible
11. ❌ **No Division by Zero Check** - Crashes on zero credit limit

### Authentication & Authorization (Critical)
12. ❌ **No Authentication** - Anyone can upload reports
13. ❌ **No Authorization** - No role-based access control
14. ❌ **No Rate Limiting** - Can upload thousands of files per second
15. ❌ **No Session Management** - No tracking of clients

### Data Privacy Vulnerabilities (Critical - GDPR)
16. ❌ **SSN in Logs** - Logs Social Security Numbers in plaintext
17. ❌ **PII in Responses** - Returns sensitive data without filtering
18. ❌ **No Encryption at Rest** - Stores reports in plaintext
19. ❌ **No Encryption in Transit** - Uses plain TCP (no TLS)
20. ❌ **PII in Error Messages** - Leaks data in error responses

### Error Handling Vulnerabilities
21. ❌ **Exposes Stack Traces** - Full error details to clients
22. ❌ **Reveals System Info** - File paths, structure details
23. ❌ **No Audit Logging** - Security events not tracked
24. ❌ **Generic Error Messages** - Helps attackers understand system

### Additional Vulnerabilities
25. ❌ **No Replay Protection** - Same request can be sent multiple times
26. ❌ **No Request Timeout** - Can hang indefinitely

---

## 🏗️ Architecture

```
Credit Report Agent (Stage 1 - Insecure)
│
├── Server (insecure_credit_agent.py)
│   ├── File Upload Handler ❌ (no validation)
│   ├── Report Analyzer ❌ (unsafe parsing)
│   ├── Storage Manager ❌ (unbounded)
│   └── Error Handler ❌ (exposes details)
│
├── Client (client.py)
│   └── Interactive Menu (testing tool)
│
└── Sample Reports
    ├── valid_report.json (legitimate test data)
    ├── malicious_report.json (injection attacks)
    ├── oversized_report.json (DoS test)
    ├── xml_bomb.xml (exponential expansion)
    └── fake_report.sh (wrong file type)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- No external dependencies (uses only stdlib)

### Installation

```bash
cd a2a_credit_report_example/insecure

# No pip install needed - uses only standard library
```

### Running the Agent

**Terminal 1 - Start Server:**
```bash
python server/insecure_credit_agent.py
```

**Terminal 2 - Run Client:**
```bash
python client/client.py
```

---

## 📋 Usage Examples

### 1. Upload Valid Report
```
Choose option 1 from the menu
Uploads: sample_reports/valid_report.json
Result: ✅ Successful upload with analysis
```

### 2. Test Injection Attack
```
Choose option 2 from the menu
Uploads: sample_reports/malicious_report.json
Demonstrates: SQL injection, command injection, log injection
```

### 3. Test DoS Attack
```
Choose option 6 from the menu
Generates and uploads: oversized_report.json (10MB+)
Demonstrates: Memory exhaustion, resource consumption
```

### 4. View All Reports
```
Choose option 4 from the menu
Shows: ❌ All reports with SSN and PII exposed
```

---

## 🔍 Vulnerability Deep Dive

### Example 1: No File Size Limits

**Vulnerable Code:**
```python
# insecure_credit_agent.py, line 119
data = await reader.read(1024 * 1024 * 20)  # Reads up to 20MB!
```

**Attack Scenario:**
```bash
# Attacker uploads 1GB file
curl -X POST http://localhost:9000/upload \
  --data-binary @massive_file.json

# Result: Server runs out of memory and crashes
```

**Impact:** DoS, service unavailability

---

### Example 2: SSN in Logs

**Vulnerable Code:**
```python
# insecure_credit_agent.py, line 176
print(f"   SSN: {report.get('subject', {}).get('ssn', 'Unknown')}")
```

**What Happens:**
```
Server logs show:
   Subject: John Doe
   SSN: 123-45-6789  ❌ EXPOSED IN LOGS!
   Credit Score: 720
```

**Impact:** GDPR violation, data breach, privacy violation

---

### Example 3: SQL Injection

**Vulnerable Code:**
```python
# insecure_credit_agent.py (hypothetical SQL query)
name = report["subject"]["name"]
query = f"SELECT * FROM reports WHERE name='{name}'"  # ❌ Vulnerable!
```

**Malicious Input:**
```json
{
  "subject": {
    "name": "John'; DROP TABLE reports; --"
  }
}
```

**Result:** Database table deleted!

---

### Example 4: Path Traversal

**Vulnerable Code:**
```python
# insecure_credit_agent.py, line 275
report_path = self.storage_dir / f"{report_id}.json"  # ❌ No sanitization
```

**Malicious Input:**
```json
{
  "report_id": "../../../../etc/passwd"
}
```

**Attack:** Could read sensitive system files

---

## 🎓 Learning Exercise

### Your Task: Find the Vulnerabilities

Before looking at SECURITY_ANALYSIS.md, try to:

1. **Read the code** - Study insecure_credit_agent.py
2. **Identify vulnerabilities** - Look for ❌ markers and comments
3. **Think about exploits** - How would you attack this?
4. **Document findings** - Write down each vulnerability
5. **Compare** - Check against SECURITY_ANALYSIS.md

### Questions to Consider

1. What happens if I upload a 10GB file?
2. How can I steal data from other reports?
3. Can I inject malicious code through the report data?
4. What sensitive data is exposed in logs?
5. Can I crash the server with malformed input?
6. How would I perform a DoS attack?

---

## 📊 Attack Scenarios

### Scenario 1: Data Exfiltration
```
1. Upload legitimate report
2. Call get_summary endpoint
3. Receive SSNs and PII of ALL reports
4. Exfiltrate sensitive data
```

### Scenario 2: Service Disruption
```
1. Generate 100GB file using generate_oversized.py
2. Upload file
3. Server runs out of memory
4. Service crashes
```

### Scenario 3: Log Injection
```
1. Create report with malicious name:
   "John Doe\n[ADMIN] Granted superuser access"
2. Upload report
3. Fake log entries appear in server logs
4. Cover tracks or create confusion
```

### Scenario 4: Storage Exhaustion
```
1. Upload 1000s of reports rapidly
2. No rate limiting stops uploads
3. Disk fills up
4. Server becomes unusable
```

---

## 📝 Next Steps

After understanding these vulnerabilities:

1. **Study SECURITY_ANALYSIS.md** - Detailed breakdown of each vulnerability
2. **Progress to Stage 2** - See partial security improvements
3. **Learn from Stage 3** - Production-ready secure implementation
4. **Apply lessons** - Avoid these mistakes in your own code

---

## 🔗 Related Documentation

- [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md) - Detailed vulnerability analysis
- [Stage 2 - Improved](../improved/README.md) - Partial security fixes
- [Stage 3 - Secure](../../../README.md) - Production-ready implementation

---

## ⚖️ Legal Notice

This code is provided for **educational purposes only**. 

- ❌ **DO NOT** use with real credit reports
- ❌ **DO NOT** deploy on production networks
- ❌ **DO NOT** use with real PII or sensitive data
- ✅ **DO** use for learning and security training
- ✅ **DO** study the vulnerabilities
- ✅ **DO** compare with secure implementations

**By using this code, you agree it is for educational purposes only.**

---

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

**Security Rating: 0/10** ❌  
**Status: VULNERABLE (Intentionally)**  
**Purpose: Educational - Learn by seeing what NOT to do**
