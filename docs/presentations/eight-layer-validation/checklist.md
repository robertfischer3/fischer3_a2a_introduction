# Eight-Layer Input Validation Security Checklist
## For Non-Technical Security Professionals

**Purpose**: This checklist guides conversations between Security, Architecture, and Development teams to ensure comprehensive input validation is deployed in agent-to-agent communication systems, particularly those using Google Gemini.

**How to Use**: 
- Use this during architecture reviews, pre-deployment security assessments, and security audits
- Check each box only when you have verified evidence (code, tests, documentation)
- For each unchecked item, create an action item with assigned owner and deadline
- Review this checklist at each major release milestone

---

## Pre-Review Conversation Starters

Before diving into the technical checklist, use these questions to establish baseline understanding:

### Discovery Questions

1. **"Walk me through what happens when your agent receives a message from an external agent."**
   - Purpose: Understand the data flow and identify validation points
   - Listen for: Mention of validation layers, error handling, logging

2. **"Where does external input enter your system?"**
   - Purpose: Identify all agent boundaries that need validation
   - Listen for: API endpoints, message queues, file uploads, webhooks

3. **"How do you currently protect against malicious input?"**
   - Purpose: Assess current validation maturity
   - Listen for: Specific layers mentioned, or vague "we validate everything"

4. **"Show me your validation documentation."**
   - Purpose: Verify validation is documented and maintainable
   - Red flag: "It's mostly in the code..." or "Let me find that..."

5. **"Have you had any security incidents related to input validation?"**
   - Purpose: Learn from past failures
   - Follow-up: "What validation would have prevented it?"

---

## Layer 1: Size Validation

**Purpose**: Prevent denial-of-service attacks by limiting message and payload sizes before processing

### Verification Checklist

- [ ] **Maximum message size is defined and documented**
  - Evidence needed: Configuration file or documentation showing exact limits
  - Typical values: 10MB for messages, 5MB for payloads
  - Ask: "What's our maximum message size and where is it documented?"

- [ ] **Maximum payload size is defined for JSON/XML bodies**
  - Evidence needed: Separate limit for message body content
  - Ask: "Is the payload size limit different from total message size?"

- [ ] **Maximum file upload size is enforced**
  - Evidence needed: File upload handler with size checks
  - Ask: "Can someone upload a 1GB file? Show me where we prevent this."

- [ ] **Maximum string length for individual fields is defined**
  - Evidence needed: Field-level validation rules
  - Ask: "What's the maximum length for text fields like 'description' or 'notes'?"

- [ ] **Size validation occurs BEFORE parsing or processing**
  - Evidence needed: Code showing size check as first step
  - Critical: Size check must happen before `json.loads()`, `xml.parse()`, etc.
  - Ask: "Show me the order of operations when a message arrives."

- [ ] **Oversized requests return appropriate error codes**
  - Evidence needed: HTTP 413 (Payload Too Large) responses
  - Ask: "What error code do we return for oversized messages?"

- [ ] **Size limits are configurable (not hardcoded)**
  - Evidence needed: Configuration file with size limits
  - Ask: "Can we change size limits without modifying code?"

### Questions for Developers

- "What happens if an agent sends a 1GB message?"
  - Expected: "It's rejected immediately with 413 error before parsing."
  - Red flag: "We parse it first and then check..."

- "Where in the code do we check message sizes?"
  - Expected: Shows validation function at entry point
  - Red flag: "Let me search for that..."

- "Show me the size validation test cases."
  - Expected: Tests with messages at limit, above limit, zero-length
  - Red flag: "We don't have specific tests for that."

### Evidence to Request

- [ ] Configuration file showing all size limits
- [ ] Code snippet showing validation at entry point
- [ ] Test suite with boundary tests (at limit, above limit, edge cases)
- [ ] Monitoring dashboard showing size rejection metrics

### Risk Assessment

**If this layer is missing:**
- Attackers can crash agents with huge messages
- Memory exhaustion and disk space depletion
- Denial of service to legitimate users
- API quota exhaustion (for services like Gemini)

**Severity if missing**: HIGH

---

## Layer 2: Extension Validation

**Purpose**: Verify file extensions match expected types using a whitelist approach

### Verification Checklist

- [ ] **Allowed file extensions are whitelisted (not blacklisted)**
  - Evidence needed: Explicit whitelist of allowed extensions
  - Critical: Whitelist approach (allow `.json`, `.csv`) not blacklist (block `.exe`)
  - Ask: "Show me the list of allowed file extensions."

- [ ] **Whitelist is maintained in configuration, not scattered in code**
  - Evidence needed: Single source of truth for allowed extensions
  - Ask: "Where is the extension whitelist defined?"

- [ ] **Extension validation is case-insensitive**
  - Evidence needed: Handles `.JSON`, `.Json`, `.json` identically
  - Ask: "What happens if someone uploads `file.JSON` vs `file.json`?"

- [ ] **Double extensions are handled correctly**
  - Evidence needed: Detects and blocks `file.jpg.exe`
  - Ask: "How do we handle files like `malware.exe.json`?"

- [ ] **Files without extensions are explicitly handled**
  - Evidence needed: Decision to allow or reject extensionless files
  - Ask: "Can someone upload a file named just `report` with no extension?"

- [ ] **Rejected files return clear error messages**
  - Evidence needed: Error messages indicate which extension was rejected
  - Ask: "What error message does a user see if they upload a .exe file?"

### Questions for Developers

- "What file types do we accept? Where is this list?"
  - Expected: Shows configuration file with explicit whitelist
  - Red flag: "We accept most file types except executables..."

- "How do we handle `malware.exe` renamed to `data.csv`?"
  - Expected: "We check extension against whitelist, then validate with magic bytes."
  - Red flag: "The extension says CSV, so we treat it as CSV."

- "Show me test cases for invalid extensions."
  - Expected: Tests with .exe, .bat, .dll, .sh, .app files
  - Red flag: "We mainly test the happy path..."

### Evidence to Request

- [ ] Whitelist configuration file
- [ ] Code showing extension validation logic  
- [ ] Test cases with blocked extensions (.exe, .bat, .dll, .sh)
- [ ] Error message examples

### Risk Assessment

**If this layer is missing:**
- Attackers can upload disguised malware
- Executables treated as data files
- Potential for remote code execution

**Severity if missing**: HIGH

---

## Layer 3: Content-Type Validation

**Purpose**: Verify the claimed content type (HTTP header) matches the actual file type

### Verification Checklist

- [ ] **HTTP Content-Type headers are validated**
  - Evidence needed: Code that checks Content-Type header
  - Ask: "Do we validate the Content-Type header?"

- [ ] **Content-Type validation matches expected file type**
  - Evidence needed: Mapping of extensions to expected Content-Types
  - Example: `.json` should have `application/json`
  - Ask: "What Content-Type do we expect for JSON files?"

- [ ] **Mismatches between Content-Type and actual content are rejected**
  - Evidence needed: Validation that catches mismatches
  - Ask: "What happens if Content-Type says JSON but file is PDF?"

- [ ] **Missing Content-Type headers are handled appropriately**
  - Evidence needed: Decision to require or infer Content-Type
  - Ask: "Can someone upload a file without a Content-Type header?"

- [ ] **Content-Type validation occurs before file processing**
  - Evidence needed: Content-Type check before parsing
  - Ask: "When do we check Content-Type in the validation pipeline?"

### Questions for Developers

- "Do we trust the Content-Type header or verify it?"
  - Expected: "We verify it against the actual file content."
  - Red flag: "We use whatever the header says."

- "What happens if Content-Type says JSON but file is PDF?"
  - Expected: "Request rejected, error logged."
  - Red flag: "We'd try to parse it and probably fail..."

- "Show me the Content-Type validation logic."
  - Expected: Code that compares header to actual content
  - Red flag: "We don't really check that..."

### Evidence to Request

- [ ] Code showing Content-Type header validation
- [ ] Mapping of extensions to expected Content-Types
- [ ] Test cases with Content-Type mismatches
- [ ] Error handling for missing Content-Type headers

### Risk Assessment

**If this layer is missing:**
- Attackers can send malicious files with fake Content-Type headers
- Content parsing vulnerabilities can be exploited
- Type confusion vulnerabilities

**Severity if missing**: MEDIUM

---

## Layer 4: Magic Byte Validation

**Purpose**: Inspect the first bytes of a file to verify its true type (file signature)

### Verification Checklist

- [ ] **File signatures (magic bytes) are checked**
  - Evidence needed: Code that inspects file headers
  - Ask: "Do we check the actual file signature (magic bytes)?"

- [ ] **Magic byte database is maintained for supported file types**
  - Evidence needed: List of known signatures for each file type
  - Examples: PDF (`%PDF`), ZIP (`PK`), JPEG (`0xFF 0xD8 0xFF`)
  - Ask: "What magic bytes do we check for each file type?"

- [ ] **Validation occurs after Content-Type but before full parsing**
  - Evidence needed: Magic byte check in correct order
  - Ask: "When does magic byte validation happen in the pipeline?"

- [ ] **Mismatches between magic bytes and declared type are rejected**
  - Evidence needed: Validation that catches disguised files
  - Ask: "What happens if magic bytes say PDF but extension says JSON?"

- [ ] **Unknown file types are rejected by default**
  - Evidence needed: Fail-closed approach for unrecognized signatures
  - Ask: "What do we do with files that have unrecognized magic bytes?"

### Questions for Developers

- "How do we detect a PDF disguised as JSON?"
  - Expected: "We check the magic bytes and compare to expected signature."
  - Red flag: "We trust the file extension."

- "What's our magic byte validation library?"
  - Expected: Names specific library (python-magic, file-type, etc.)
  - Red flag: "We wrote our own..." or "We don't do that."

- "Show me test cases for disguised file types."
  - Expected: Tests with PDF as .json, EXE as .csv, etc.
  - Red flag: "We don't test for that."

### Evidence to Request

- [ ] Code showing magic byte validation
- [ ] Database/list of magic byte signatures
- [ ] Library used for file type detection
- [ ] Test cases with disguised files

### Risk Assessment

**If this layer is missing:**
- Sophisticated attackers can bypass extension and Content-Type validation
- Disguised malware can be uploaded
- Exploit files can masquerade as legitimate data

**Severity if missing**: HIGH

---

## Layer 5: Filename Sanitization

**Purpose**: Remove dangerous characters from filenames to prevent path traversal attacks

### Verification Checklist

- [ ] **Path traversal characters are removed (`../`, `..\\`)**
  - Evidence needed: Sanitization that strips directory traversal sequences
  - Ask: "How do we handle filenames like `../../../../etc/passwd`?"

- [ ] **Absolute paths are converted to relative paths**
  - Evidence needed: Stripping of leading `/` or `C:\`
  - Ask: "What happens if someone uploads `/etc/shadow` as a filename?"

- [ ] **Special characters are sanitized or rejected**
  - Evidence needed: Removal or escaping of special characters
  - Characters: `;`, `|`, `&`, `$`, `` ` ``, `<`, `>`, `(`, `)`
  - Ask: "What characters do we allow in filenames?"

- [ ] **Unicode characters in filenames are handled safely**
  - Evidence needed: Unicode normalization or rejection
  - Ask: "Can someone upload a file with emoji or non-ASCII characters in the name?"

- [ ] **Null bytes in filenames are blocked**
  - Evidence needed: Detection and rejection of `\0` in filenames
  - Ask: "Do we check for null bytes in filenames?"

- [ ] **Maximum filename length is enforced**
  - Evidence needed: Length limit (typically 255 characters)
  - Ask: "What's the maximum filename length we allow?"

- [ ] **Files are saved only to designated directories**
  - Evidence needed: Hardcoded base path for file storage
  - Ask: "Where do uploaded files get saved? Can this be changed by input?"

### Questions for Developers

- "How do we prevent `../../../../etc/passwd` attacks?"
  - Expected: "We strip all path separators and traversal sequences."
  - Red flag: "We sanitize the path..." (path should not be used at all)

- "Where do uploaded files get saved?"
  - Expected: "Always in `/uploads/` directory, nowhere else."
  - Red flag: "Depends on the filename..." or "In the path specified..."

- "Show me the filename sanitization function."
  - Expected: Clear sanitization code removing dangerous characters
  - Red flag: "We use the filename as provided..."

### Evidence to Request

- [ ] Filename sanitization code
- [ ] Test cases with path traversal attempts
- [ ] Test cases with special characters
- [ ] Documentation of allowed filename characters

### Risk Assessment

**If this layer is missing:**
- Attackers can write files anywhere on the filesystem
- Overwrite critical system or application files
- Read sensitive files via path traversal
- Remote code execution via overwriting executables or libraries

**Severity if missing**: CRITICAL

---

## Layer 6: Input Sanitization (Injection Prevention)

**Purpose**: Remove or escape characters that could trigger injection attacks (SQL, command, XSS, prompt)

### Verification Checklist

#### General Injection Prevention

- [ ] **SQL injection patterns are detected and blocked**
  - Evidence needed: Detection of SQL keywords and special characters
  - Patterns: `'; DROP TABLE`, `OR 1=1`, `UNION SELECT`, `--`
  - Ask: "How do we protect against SQL injection?"

- [ ] **Command injection patterns are detected and blocked**
  - Evidence needed: Detection of shell metacharacters
  - Patterns: `;`, `|`, `&`, `$()`, `` ` ``, `$(`, `>`
  - Ask: "Can someone inject shell commands through our inputs?"

- [ ] **XSS patterns are detected and blocked (if HTML rendering occurs)**
  - Evidence needed: Detection of HTML/JavaScript tags
  - Patterns: `<script>`, `javascript:`, `onerror=`, `<iframe>`
  - Ask: "Do we render any user input as HTML? How is it sanitized?"

- [ ] **LDAP injection patterns are blocked**
  - Evidence needed: Escaping of LDAP special characters
  - Ask: "Do we query LDAP directories? How are inputs sanitized?"

#### AI-Specific Injection Prevention (CRITICAL)

- [ ] **Prompt injection patterns are detected for AI agents**
  - Evidence needed: Detection of manipulation phrases
  - Patterns: 
    - `ignore all previous instructions`
    - `disregard all previous`
    - `new instructions:`
    - `system message:`
    - `admin override`
    - `your new purpose is`
  - Ask: "How do we protect Gemini from prompt injection?"

- [ ] **Input sanitization occurs BEFORE AI model processing**
  - Evidence needed: Sanitization step before Gemini API call
  - Critical: Must happen before prompt construction
  - Ask: "Show me where we sanitize inputs before sending to Gemini."

#### Database and Logging

- [ ] **Log injection patterns (newlines) are sanitized**
  - Evidence needed: Stripping or escaping of `\n`, `\r`
  - Ask: "Can someone inject newlines into log messages?"

- [ ] **Parameterized queries are used (SQL injection defense)**
  - Evidence needed: Use of prepared statements, not string concatenation
  - Ask: "Show me a database query. Do we use parameterized queries?"

- [ ] **Input sanitization occurs before database queries**
  - Evidence needed: Sanitization even with parameterized queries (defense-in-depth)
  - Ask: "Do we sanitize inputs even though we use parameterized queries?"

### Questions for Developers (AI-Specific)

- "How do we protect against prompt injection in Gemini?"
  - Expected: Shows sanitization function that detects manipulation patterns
  - Red flag: "Gemini has built-in safety features..." (not enough)

- "Show me the input sanitization for AI prompts."
  - Expected: Code that scans for and blocks injection patterns
  - Red flag: "We just pass the input to Gemini as-is."

- "What happens if someone inputs: `'; DROP TABLE users;--`?"
  - Expected: "Injection pattern detected, request blocked, incident logged."
  - Red flag: "That would depend on where it's used..."

- "Do we use parameterized queries for databases?"
  - Expected: "Yes, always. Never string concatenation."
  - Red flag: "We build queries dynamically..." or "Sometimes..."

### Evidence to Request

- [ ] Prompt injection detection code
- [ ] List of blocked patterns (SQL, command, XSS, prompt)
- [ ] Database query code (should use parameterized queries)
- [ ] Test cases with injection attempts
- [ ] Incident logs showing blocked injections
- [ ] Sanitization library or functions used

### Risk Assessment

**If this layer is missing:**
- SQL injection: Database destruction, data theft
- Command injection: Remote code execution
- XSS: Session hijacking, credential theft
- Prompt injection: AI behavior manipulation, policy bypasses
- Log injection: Log forgery, monitoring evasion

**Severity if missing**: CRITICAL

**Note**: This is the most important layer for AI agent security.

---

## Layer 7: Schema Validation

**Purpose**: Validate that JSON/XML structure matches expected format

### Verification Checklist

- [ ] **JSON/XML schemas are formally defined and documented**
  - Evidence needed: Schema definition files (JSON Schema, XSD, OpenAPI)
  - Ask: "Where are our message schemas defined?"

- [ ] **All required fields are validated**
  - Evidence needed: List of required fields in schema
  - Ask: "What fields are required in each message type?"

- [ ] **Field types are validated**
  - Evidence needed: Type checking (string, integer, boolean, array, object)
  - Ask: "How do we validate field types?"

- [ ] **Nested object structures are validated recursively**
  - Evidence needed: Schema validation for nested objects
  - Ask: "Do we validate nested JSON structures?"

- [ ] **Array lengths are validated**
  - Evidence needed: Minimum and maximum array sizes
  - Ask: "Can someone send an array with 1 million items?"

- [ ] **Unknown fields are handled appropriately**
  - Evidence needed: Decision to reject strict or ignore additional fields
  - Ask: "What happens if a message contains unexpected fields?"

- [ ] **Schema validation occurs after sanitization but before business logic**
  - Evidence needed: Correct ordering in validation pipeline
  - Ask: "When does schema validation happen relative to other checks?"

- [ ] **Schema validation errors provide clear messages**
  - Evidence needed: Error messages indicate which field failed validation
  - Ask: "What error message does a user see for schema validation failures?"

- [ ] **Error messages don't leak sensitive information**
  - Evidence needed: Generic errors for external users, detailed errors in logs
  - Ask: "Do our error messages expose internal field names or structure?"

### Questions for Developers

- "Where are our message schemas defined?"
  - Expected: Shows schema definition files (JSON Schema, OpenAPI, etc.)
  - Red flag: "They're kind of implicit in the code..."

- "What happens if a required field is missing?"
  - Expected: "Validation fails immediately with specific error message."
  - Red flag: "We have default values..." or "The code handles nulls..."

- "Do we validate nested JSON structures?"
  - Expected: "Yes, recursively to all levels."
  - Red flag: "We validate the top level..."

- "Show me the schema validation test suite."
  - Expected: Comprehensive tests for missing fields, wrong types, etc.
  - Red flag: "We test the main cases..."

### Evidence to Request

- [ ] Schema definition files
- [ ] Schema validation library in use (ajv, jsonschema, etc.)
- [ ] Test cases with:
  - Missing required fields
  - Wrong field types
  - Invalid nested structures
  - Extra unknown fields
  - Arrays exceeding limits
- [ ] Documentation of error messages

### Risk Assessment

**If this layer is missing:**
- Application crashes from missing fields
- Type confusion vulnerabilities
- Buffer overflows from oversized arrays
- Logic errors from malformed data
- Denial of service from deeply nested structures

**Severity if missing**: HIGH

---

## Layer 8: Business Logic Validation

**Purpose**: Validate that data makes sense in business context, beyond technical correctness

### Verification Checklist

#### Numeric Validation

- [ ] **Numeric ranges are validated**
  - Evidence needed: Validation of min/max values
  - Examples: Credit scores (300-850), percentages (0-100), amounts (>0)
  - Ask: "How do we validate that numeric values are realistic?"

- [ ] **Currency amounts are validated**
  - Evidence needed: No negative prices, reasonable ranges
  - Ask: "Can someone submit a negative price or amount?"

#### Date and Time Validation

- [ ] **Date ranges are validated**
  - Evidence needed: No future dates for past events, reasonable ranges
  - Ask: "Can someone claim a birth date in the future?"

- [ ] **Temporal consistency is checked**
  - Evidence needed: Start dates before end dates, etc.
  - Ask: "Do we check that start dates come before end dates?"

#### Cross-Field Validation

- [ ] **Business rules are enforced**
  - Evidence needed: Complex validations across multiple fields
  - Examples: Balance ≤ credit limit, age ≥ 18 for contracts
  - Ask: "What business rules do we enforce beyond data types?"

- [ ] **Cross-field consistency is checked**
  - Evidence needed: Validations that compare multiple fields
  - Ask: "Do we validate relationships between fields?"

#### Referential Integrity

- [ ] **Referential integrity is validated**
  - Evidence needed: Foreign keys exist, references are valid
  - Ask: "Do we verify that referenced entities exist?"

- [ ] **Workflow state transitions are validated**
  - Evidence needed: Only valid state transitions allowed
  - Example: Can't go from "pending" to "completed" without "in_progress"
  - Ask: "Can someone skip workflow states?"

#### Error Handling

- [ ] **Business rule violations return meaningful errors**
  - Evidence needed: Errors explain what business rule was violated
  - Ask: "What error message does someone get for invalid business logic?"

### Questions for Developers

- "How do we validate that credit scores are realistic?"
  - Expected: "We check they're in the 300-850 range."
  - Red flag: "We validate it's a number..."

- "What business rules are enforced beyond data types?"
  - Expected: Lists specific business logic validations
  - Red flag: "We trust the data if it parses..."

- "Show me validation for cross-field consistency."
  - Expected: Code checking relationships between fields
  - Red flag: "Each field is validated independently..."

- "What happens with logically impossible data?"
  - Expected: "It's rejected with a clear error message."
  - Red flag: "We'd probably catch it later in processing..."

### Evidence to Request

- [ ] Documentation of business rules
- [ ] Business logic validation code
- [ ] Test cases with:
  - Out-of-range values
  - Negative amounts where not allowed
  - Invalid state transitions
  - Inconsistent cross-field data
  - Missing references
- [ ] Examples of business rule error messages

### Risk Assessment

**If this layer is missing:**
- Incorrect business decisions based on nonsense data
- Financial losses from invalid transactions
- Compliance violations
- Data corruption
- Workflow bypasses

**Severity if missing**: MEDIUM to HIGH (depends on application)

---

## Google Gemini-Specific Security

**Additional validation requirements for Gemini-powered agents**

### Prompt Security

- [ ] **System prompts are stored securely (not in message history)**
  - Evidence needed: System prompts in configuration, not conversation
  - Ask: "Where are Gemini system prompts stored?"

- [ ] **User inputs are sanitized before inclusion in prompts**
  - Evidence needed: Sanitization before prompt construction
  - Ask: "Show me how we build prompts. Where is input sanitized?"

- [ ] **Prompt injection patterns are detected and blocked**
  - Evidence needed: Layer 6 sanitization applied to all AI inputs
  - Ask: "How do we prevent prompt injection specifically?"

- [ ] **Conversation context is validated at each turn**
  - Evidence needed: Validation of previous messages in conversation
  - Ask: "Do we validate the entire conversation history or just new messages?"

- [ ] **Hard limits on prompt length are enforced**
  - Evidence needed: Maximum token/character limits
  - Ask: "What's the maximum prompt length we allow?"

- [ ] **Safety settings are configured appropriately**
  - Evidence needed: Gemini safety settings configuration
  - Ask: "What safety settings do we use for Gemini API calls?"

### API Security

- [ ] **API keys are stored in secure vaults, not code**
  - Evidence needed: Secrets management system (AWS Secrets Manager, HashiCorp Vault)
  - Ask: "Where are Gemini API keys stored?"

- [ ] **API rate limits are monitored and enforced locally**
  - Evidence needed: Local rate limiting before hitting API limits
  - Ask: "How do we prevent exhausting Gemini API rate limits?"

- [ ] **API quota exhaustion is handled gracefully**
  - Evidence needed: Error handling for quota exceeded
  - Ask: "What happens if we exceed Gemini API quota?"

- [ ] **Error responses from Gemini are parsed safely**
  - Evidence needed: Safe parsing of API error responses
  - Ask: "How do we handle errors from Gemini API?"

- [ ] **Retry logic includes exponential backoff**
  - Evidence needed: Retry with increasing delays
  - Ask: "Do we retry failed Gemini API calls? How?"

- [ ] **All API calls are logged for audit**
  - Evidence needed: Logging of all Gemini interactions
  - Ask: "Do we log all calls to Gemini API?"

### Output Validation

- [ ] **Gemini outputs are parsed and validated**
  - Evidence needed: Validation of AI responses before use
  - Ask: "Do we validate Gemini's responses before acting on them?"

- [ ] **JSON outputs are schema-validated before use**
  - Evidence needed: Schema validation (Layer 7) applied to AI outputs
  - Ask: "If Gemini generates JSON, do we validate it?"

- [ ] **Function calling parameters are validated before execution**
  - Evidence needed: Validation of parameters Gemini suggests
  - Ask: "If Gemini suggests calling a function, do we validate the parameters?"

- [ ] **Hallucinated data is detected and rejected**
  - Evidence needed: Validation that catches nonsense outputs
  - Ask: "How do we detect when Gemini hallucinates?"

- [ ] **Gemini responses are sanitized before display to users**
  - Evidence needed: Sanitization of AI output (XSS prevention)
  - Ask: "Do we sanitize Gemini's responses before showing them to users?"

- [ ] **Maximum output length is enforced**
  - Evidence needed: Truncation or rejection of oversized responses
  - Ask: "Can Gemini return an unlimited amount of text?"

### Evidence to Request

- [ ] Gemini API integration code
- [ ] Prompt construction code
- [ ] API key storage configuration
- [ ] Safety settings configuration
- [ ] Output validation code
- [ ] Function calling validation code
- [ ] Error handling for API failures
- [ ] Audit logs of Gemini interactions

### Risk Assessment

**If Gemini-specific validation is missing:**
- Prompt injection manipulates AI behavior
- API quota exhaustion (DoS)
- Execution of hallucinated or malicious function calls
- Exposure of sensitive data in prompts
- XSS via unsanitized AI outputs

**Severity if missing**: CRITICAL

---

## Testing and Verification

### Test Coverage Requirements

- [ ] **All eight layers have automated tests**
  - Evidence needed: Test suite covering each validation layer
  - Ask: "Show me tests for each validation layer."

- [ ] **Tests include both positive and negative cases**
  - Positive: Valid inputs that should pass
  - Negative: Invalid inputs that should be rejected
  - Ask: "Do we test both valid and invalid inputs?"

- [ ] **Tests cover boundary conditions**
  - Evidence needed: Tests at limits (max size, min/max values)
  - Ask: "Do we test edge cases and boundaries?"

- [ ] **Security tests are part of CI/CD pipeline**
  - Evidence needed: Security tests run automatically on every commit
  - Ask: "Do security tests run automatically?"

- [ ] **Penetration testing includes injection attacks**
  - Evidence needed: Regular pentesting with injection attempts
  - Ask: "When was the last penetration test? What did it cover?"

### Monitoring Requirements

- [ ] **Validation failures are logged**
  - Evidence needed: Logs showing which layer rejected which requests
  - Ask: "Can we see logs of validation failures?"

- [ ] **Metrics are collected for each layer**
  - Evidence needed: Dashboard showing rejection counts by layer
  - Ask: "Show me validation metrics."

- [ ] **Alerts are configured for suspicious patterns**
  - Evidence needed: Alerts for repeated failures, injection attempts
  - Ask: "Do we get alerts for validation anomalies?"

- [ ] **Logs include enough context for investigation**
  - Evidence needed: Logs with agent ID, timestamp, layer, reason
  - Ask: "If an attack is blocked, do we have enough info to investigate?"

- [ ] **Logs don't expose sensitive data**
  - Evidence needed: Sanitized or redacted content in logs
  - Ask: "Do our logs contain PII or sensitive data?"

### Documentation Requirements

- [ ] **Validation rules are documented**
  - Evidence needed: Documentation of all validation layers
  - Ask: "Where is validation logic documented?"

- [ ] **Error codes are documented**
  - Evidence needed: List of error codes and their meanings
  - Ask: "Do we have a list of validation error codes?"

- [ ] **Security runbooks exist for validation failures**
  - Evidence needed: Procedures for responding to suspicious validation failures
  - Ask: "What do we do when we detect an attack attempt?"

---

## Common Gaps and Red Flags

### Red Flags in Responses

When you hear these, dig deeper:

- ❌ **"We haven't thought about that..."** - Basic security missing
- ❌ **"The AI handles that automatically..."** - Over-reliance on AI safety
- ❌ **"We trust our internal agents..."** - No internal validation
- ❌ **"That's an edge case we'll handle later..."** - Security is postponed
- ❌ **"We validate where it makes sense..."** - Incomplete validation
- ❌ **"Let me find that code..."** - Validation might not exist
- ❌ **"We built our own validation..."** - NIH syndrome, likely has gaps
- ❌ **"That's on the roadmap..."** - Not currently implemented

### Green Flags in Responses

When you hear these, you're on the right track:

- ✅ **Shows you code and configuration immediately**
- ✅ **Has comprehensive test suites**
- ✅ **Monitoring and alerting in place**
- ✅ **Clear, up-to-date documentation**
- ✅ **Regular security reviews scheduled**
- ✅ **Metrics dashboard available**
- ✅ **Can walk through validation pipeline in detail**

### Common Missing Layers

Based on common gaps in production systems:

1. **Layer 1 (Size) often missing**: Many assume framework handles this
2. **Layer 4 (Magic Bytes) frequently skipped**: Considered "overkill"
3. **Layer 6 (Injection) incomplete**: Only SQL covered, not prompt injection
4. **Layer 8 (Business Logic) rarely comprehensive**: Only basic checks

---

## Action Item Template

When you find gaps, use this template to track remediation:

### Gap: [Layer Name] - [Specific Issue]

**Severity**: [Critical / High / Medium / Low]

**Current State**: [What exists now]

**Gap**: [What's missing]

**Risk**: [What could happen without this]

**Remediation**:
- [ ] Task 1: [Specific action]
- [ ] Task 2: [Specific action]
- [ ] Task 3: [Specific action]

**Owner**: [Name]

**Due Date**: [Date]

**Verification**: [How will we verify this is fixed?]

**Follow-up Review**: [Date to re-check]

---

## Example: Completed Checklist Section

Here's how a completed section should look:

### Layer 6: Input Sanitization ✓ VERIFIED

- [x] SQL injection patterns detected
  - **Evidence**: Code review of `security/sanitizer.py` line 145-178
  - **Test coverage**: `tests/test_sql_injection.py` with 25 test cases
  - **Last verified**: 2024-03-15 by J. Smith

- [x] Prompt injection patterns detected
  - **Evidence**: `ai/prompt_guard.py` blocks 15 manipulation patterns
  - **Test coverage**: `tests/test_prompt_injection.py` with 32 test cases
  - **Last verified**: 2024-03-15 by J. Smith

- [x] Sanitization before AI processing
  - **Evidence**: `ai/gemini_client.py` line 67 calls sanitizer
  - **Test coverage**: Integration tests verify order
  - **Last verified**: 2024-03-15 by J. Smith

**Overall Layer 6 Status**: ✅ PASS - All requirements met

---

## Summary Assessment

### Overall Security Posture

After completing this checklist, provide an overall assessment:

**Layers Fully Implemented**: ___ / 8

**Critical Gaps Identified**: ___

**High-Priority Gaps**: ___

**Medium-Priority Gaps**: ___

**Overall Risk Rating**: [Low / Medium / High / Critical]

**Recommendation**: [Approve for deployment / Conditional approval / Require remediation before deployment]

### Required Actions Before Deployment

List critical items that MUST be addressed:

1. [Critical item 1]
2. [Critical item 2]
3. [Critical item 3]

### Nice-to-Have Improvements

List items that would improve security but aren't blockers:

1. [Improvement 1]
2. [Improvement 2]
3. [Improvement 3]

---

## Checklist Maintenance

### Review Schedule

- [ ] **Monthly**: Review validation metrics
- [ ] **Quarterly**: Update checklist based on new threats
- [ ] **Annually**: Full security audit with external pentesting
- [ ] **Per Release**: Complete checklist for major releases
- [ ] **Post-Incident**: Review and update after any security incident

### Version History

- Version 1.0 - Initial checklist (YYYY-MM-DD)
- Version 1.1 - Added Gemini-specific items (YYYY-MM-DD)
- Version 1.2 - Updated based on OWASP changes (YYYY-MM-DD)

---

## Contact Information

**Security Team Contact**: [email@company.com]

**Architecture Review Requests**: [process/URL]

**Security Incident Reporting**: [incident-response@company.com]

**Questions About This Checklist**: [security-questions@company.com]

---

**END OF CHECKLIST**

**Remember**: This checklist is a conversation tool, not a compliance checkbox. Use it to ensure genuine security, not just paper compliance.