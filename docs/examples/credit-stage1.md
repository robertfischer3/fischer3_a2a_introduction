# Credit Report Agent - Stage 1: Insecure

> **Path**: `a2a_examples/a2a_credit_report_example/insecure`

## Overview

Stage 1 demonstrates a **critically insecure** implementation of a credit report processing agent. This stage is intentionally vulnerable to teach security fundamentals through hands-on exploitation.

**Security Rating**: ⚠️ 0/10 - CRITICALLY INSECURE

**Status**: ❌ Educational Only - Never use in production

---

## Key Learning Focus

This stage focuses on **file upload security** and **PII protection**, showing common vulnerabilities when handling sensitive financial documents.

### What You'll Learn

- File upload attack vectors (path traversal, malicious files)
- Why PII needs encryption at rest
- The importance of input validation
- FCRA and GDPR compliance failures
- Consequences of insecure document processing

---

## Architecture

```
Client
  ↓ (uploads credit report PDF)
Agent (no validation)
  ↓
PDF Parser (unsafe)
  ↓
Storage (plaintext)
  ↓
Analysis (no access control)
  ↓
Response (PII exposed)
```

### Components

- **`server.py`**: HTTP server with no authentication
- **`parser.py`**: PDF processor with no file validation
- **`storage.py`**: Plaintext file storage
- **`analyzer.py`**: Credit analysis with no authorization
- **`config.py`**: Hardcoded credentials

---

## Critical Vulnerabilities

### 1. **No File Validation** (CRITICAL)

```python
# ❌ Accepts any file
def upload_document(file):
    # No type checking, no size limits
    return save_file(file)
```

**Attack**: Upload malicious PDFs, executables, or oversized files

---

### 2. **Path Traversal** (CRITICAL)

```python
# ❌ User controls file path
def save_file(filename):
    path = f"uploads/{filename}"
    # Can write anywhere: ../../../etc/passwd
    with open(path, 'wb') as f:
        f.write(data)
```

**Attack**: Overwrite system files, access sensitive directories

---

### 3. **No PII Encryption** (CRITICAL)

```python
# ❌ Stores SSN, DOB, addresses in plaintext
def store_report(data):
    with open(f"data/{data['ssn']}.json", 'w') as f:
        json.dump(data, f)  # All PII readable
```

**Attack**: Database/filesystem breach = full PII exposure

---

### 4. **No Authentication** (CRITICAL)

```python
# ❌ Anyone can upload/access reports
@app.route('/upload', methods=['POST'])
def upload():
    return process_file(request.files['document'])
```

**Attack**: Unauthorized access to all credit reports

---

### 5. **PII in Logs** (HIGH)

```python
# ❌ Logs contain sensitive data
logger.info(f"Processing report for SSN: {ssn}")
```

**Attack**: Log files contain recoverable PII

---

### 6. **No Rate Limiting** (HIGH)

```python
# ❌ Unlimited uploads allowed
def upload():
    return save_file(request.files['document'])
```

**Attack**: DoS through massive file uploads

---

### 7. **Insecure Deserialization** (HIGH)

```python
# ❌ Unsafe pickle usage
def load_report(file):
    return pickle.load(open(file, 'rb'))
```

**Attack**: Remote code execution through crafted pickle files

---

### 8. **No Content-Type Validation** (MEDIUM)

```python
# ❌ Trusts client-provided MIME type
content_type = request.headers.get('Content-Type')
if content_type == 'application/pdf':
    process_file()  # Easily spoofed
```

**Attack**: Bypass restrictions by changing Content-Type header

---

## Complete Vulnerability Count

| Category | Count | Examples |
|----------|-------|----------|
| **File Handling** | 8 | Path traversal, no validation, size limits |
| **PII Protection** | 6 | No encryption, logs, exposed storage |
| **Authentication/Authorization** | 4 | No auth, no access control |
| **Input Validation** | 5 | No sanitization, unsafe parsing |
| **Compliance** | 10+ | FCRA, GDPR, GLBA violations |

**Total**: 30+ exploitable vulnerabilities

---

## Regulatory Violations

### Fair Credit Reporting Act (FCRA)
- ❌ §604: Providing reports to unauthorized persons
- ❌ §607: Inadequate security procedures
- ❌ §609: Improper disclosure

**Penalties**: Up to $1,000 per violation + criminal charges

### GDPR
- ❌ Article 5: Data minimization, accuracy
- ❌ Article 32: Security of processing
- ❌ Article 33: Breach notification

**Penalties**: Up to €20M or 4% of global revenue

---

## Attack Demonstrations

### Demo 1: Path Traversal
```bash
# Upload file to overwrite system files
curl -X POST http://localhost:8000/upload \
  -F "file=@malicious.pdf;filename=../../../tmp/exploit"
```

### Demo 2: Steal All Credit Reports
```python
# No authentication = access everything
for user_id in range(1000):
    report = requests.get(f'http://localhost:8000/report/{user_id}')
    print(report.json())  # Full PII exposed
```

### Demo 3: DoS via File Upload
```python
# No size limits or rate limiting
while True:
    requests.post('http://localhost:8000/upload', 
                  files={'file': 'x' * 1000000000})
```

---

## Running the Example

### Setup
```bash
cd a2a_examples/a2a_credit_report_example/insecure
pip install -r requirements.txt
python server.py
```

### Try the Attacks
```bash
# Terminal 1: Start server
python server.py

# Terminal 2: Run attack demos
python ../demos/attack_stage1.py
```

### What to Observe
- Files saved with user-controlled paths
- PII visible in logs and storage
- No authentication required
- All attacks succeed

---

## Study Checklist

- [ ] Identify all 30+ vulnerabilities in code
- [ ] Run path traversal demonstration
- [ ] Examine plaintext PII in storage
- [ ] Check logs for sensitive data
- [ ] Calculate FCRA/GDPR penalties
- [ ] Understand why each vuln is critical

---

## Key Takeaways

1. **File uploads are dangerous**: Require comprehensive validation
2. **PII must be encrypted**: Plaintext storage is unacceptable
3. **Compliance is mandatory**: FCRA/GDPR violations have severe consequences
4. **Defense in depth**: Single protections are insufficient
5. **Authentication is essential**: Especially for financial data

---

## Next: Stage 2 (Improved)

Stage 2 adds basic security measures but still has significant vulnerabilities. Compare to understand why partial security fails.

**Improvements in Stage 2**:
- ✅ Basic file type validation
- ✅ Some PII encryption
- ✅ Simple authentication
- ⚠️ But still 15+ critical issues remain

**Time to Complete**: 3-4 hours  
**Difficulty**: ⭐ Beginner  
**Prerequisites**: Basic Python, understanding of file I/O

---

## Resources

- [FCRA Full Text](https://www.ftc.gov/legal-library/browse/statutes/fair-credit-reporting-act)
- [GDPR Guidelines](https://gdpr.eu/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Stage 2: Improved →](./credit-stage2.md)
