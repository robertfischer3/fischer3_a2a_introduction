# Contributing to Agent2Agent (A2A) Protocol

Thank you for your interest in contributing to the Agent2Agent Protocol project! We're excited to have you join our community of developers working to advance secure multi-agent communication.

This document provides guidelines for contributing to this project. By participating, you agree to abide by these guidelines and help us maintain a welcoming, productive community.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Contribution Workflow](#contribution-workflow)
- [Contribution Guidelines](#contribution-guidelines)
- [Security Considerations](#security-considerations)
- [Style Guidelines](#style-guidelines)
- [Review Process](#review-process)
- [Recognition](#recognition)
- [Questions or Need Help?](#questions-or-need-help)

---

## 🤝 Code of Conduct

This project and everyone participating in it is expected to uphold our standards of respectful, professional conduct. We are committed to providing a welcoming and inclusive environment for all contributors.

**Our Standards:**
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

**Unacceptable Behavior:**
- Harassment or discriminatory language
- Trolling, insulting comments, or personal attacks
- Public or private harassment
- Publishing others' private information
- Other conduct that would be considered inappropriate in a professional setting

If you experience or witness unacceptable behavior, please report it to: **robert@fischer3.net**

---

## 🎯 How Can I Contribute?

We welcome several types of contributions:

### 1. 📖 Documentation Contributions

**We especially encourage:**
- Writing tutorials and how-to guides
- Creating markdown articles explaining A2A concepts
- Improving existing documentation clarity
- Adding diagrams and visual aids
- Translating documentation
- Fixing typos and grammatical errors

**High-value documentation areas:**
- Security best practices guides
- Integration tutorials
- Troubleshooting guides
- Real-world use case examples
- Architecture decision records

### 2. 💻 Code Examples

**We're looking for:**
- New agent implementations demonstrating A2A patterns
- Security-focused examples showing proper implementation
- Integration examples (A2A + MCP, A2A + other protocols)
- Tool and utility scripts
- Testing utilities and frameworks

**Important:** All code examples should follow our security guidelines (see below).

### 3. 🔒 Security Reviews

**Critical contributions:**
- Reviewing existing code for vulnerabilities
- Suggesting security improvements
- Creating security analysis documents
- Developing security testing tools
- Writing security-focused documentation

**Note:** If you discover a security vulnerability, please report it responsibly to **robert@fischer3.net** rather than opening a public issue.

### 4. 🐛 Bug Reports

Help us improve by reporting:
- Documentation errors or inconsistencies
- Broken links or missing resources
- Issues with example code
- Security concerns (report privately)

### 5. 💡 Feature Suggestions

We welcome ideas for:
- New security patterns
- Additional documentation topics
- Example scenarios
- Tool improvements

---

## 🚀 Getting Started

### Prerequisites

Before contributing, please:

1. **Read the core documentation:**
   - [A2A Overview](docs/a2a/00_A2A_OVERVIEW.md)
   - [Security Best Practices](docs/a2a/03_SECURITY/04_security_best_practices.md)
   - [Threat Model](docs/a2a/03_SECURITY/03_threat_model.md)

2. **Review existing examples:**
   - [Crypto Price Agent](a2a_examples/a2a_crypto_example/)
   - [Credit Report Agent](a2a_examples/a2a_credit_report_example/)
   - [Task Collaboration Agent](a2a_examples/a2a_task_collab_example/)

3. **Set up your development environment:**
   ```bash
   # Clone the repository
   git clone https://github.com/robertfischer3/fischer3_a2a_introduction.git
   cd fischer3_a2a_introduction

   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install dependencies (example-specific)
   pip install -r requirements.txt
   ```

---

## 🔄 Contribution Workflow

We use a standard GitHub fork-and-pull-request workflow:

### Step 1: Fork the Repository

1. Navigate to the [repository](https://github.com/robertfischer3/fischer3_a2a_introduction)
2. Click the "Fork" button in the top-right corner
3. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/fischer3_a2a_introduction.git
   cd fischer3_a2a_introduction
   ```

### Step 2: Create a Branch

Create a descriptive branch for your contribution:

```bash
# For documentation
git checkout -b docs/improve-security-guide

# For code examples
git checkout -b example/weather-agent

# For bug fixes
git checkout -b fix/broken-link-in-readme

# For features
git checkout -b feature/add-prometheus-metrics
```

**Branch naming conventions:**
- `docs/` - Documentation changes
- `example/` - New code examples
- `fix/` - Bug fixes
- `feature/` - New features
- `security/` - Security improvements

### Step 3: Make Your Changes

**For documentation:**
- Write in clear, concise markdown
- Use proper heading hierarchy
- Include code examples where helpful
- Add diagrams if they clarify concepts
- Check spelling and grammar

**For code examples:**
- Follow security best practices (see below)
- Include comprehensive README.md
- Add inline comments explaining security decisions
- Include security analysis if demonstrating vulnerabilities
- Provide setup and usage instructions

**For security contributions:**
- Document the security issue clearly
- Explain the impact and severity
- Provide remediation steps
- Include test cases if applicable

### Step 4: Test Your Changes

**For documentation:**
- Preview markdown rendering
- Check all links work
- Verify code examples are correct
- Ensure formatting is consistent

**For code examples:**
- Test all functionality
- Verify security controls work as intended
- Run any existing tests
- Document any dependencies

### Step 5: Commit Your Changes

Write clear, descriptive commit messages:

```bash
# Good commit messages
git commit -m "docs: add session management security guide"
git commit -m "example: create weather agent with OAuth2 auth"
git commit -m "fix: correct broken link in authentication overview"
git commit -m "security: add input validation to credit report agent"

# Poor commit messages (avoid these)
git commit -m "update"
git commit -m "fix stuff"
git commit -m "changes"
```

**Commit message format:**
```
<type>: <brief description>

<optional detailed description>

<optional footer: references to issues, breaking changes, etc.>
```

**Types:**
- `docs:` - Documentation changes
- `example:` - Code examples
- `fix:` - Bug fixes
- `feature:` - New features
- `security:` - Security improvements
- `refactor:` - Code refactoring
- `test:` - Test additions or modifications

### Step 6: Push to Your Fork

```bash
git push origin your-branch-name
```

### Step 7: Open a Pull Request

1. Navigate to your fork on GitHub
2. Click "Compare & pull request"
3. Fill out the pull request template (see below)
4. Submit the pull request

---

## 📝 Contribution Guidelines

### Documentation Contributions

**✅ DO:**
- Start with an executive summary
- Use clear headings and structure
- Include practical examples
- Reference related documentation
- Keep language accessible (avoid unnecessary jargon)
- Use diagrams and visuals where helpful
- Provide "Why" context, not just "How"

**❌ DON'T:**
- Copy content from other sources without attribution
- Use overly technical language without explanation
- Create documentation without examples
- Skip proofreading

**Markdown style:**
```markdown
# Main Title (H1 - one per document)

Brief introduction paragraph.

## Section (H2)

Content here.

### Subsection (H3)

More specific content.

**Bold** for emphasis.
*Italic* for terminology.
`code` for inline code.
```

### Code Example Contributions

**✅ DO:**
- Include a comprehensive README.md
- Document all security considerations
- Add inline comments for complex logic
- Provide clear setup instructions
- Include example usage
- Follow existing project structure
- Add requirements.txt or equivalent
- Test thoroughly before submitting

**❌ DON'T:**
- Submit code with known security vulnerabilities (unless explicitly demonstrating a vulnerability for educational purposes)
- Include sensitive data (API keys, credentials, etc.)
- Commit large binary files
- Add dependencies without justification

**Example structure:**
```
your_example/
├── README.md                 # Comprehensive documentation
├── requirements.txt          # Dependencies
├── SECURITY_ANALYSIS.md     # Security considerations
├── server/
│   └── agent_server.py
├── client/
│   └── client.py
└── tests/
    └── test_agent.py
```

**README.md should include:**
```markdown
# Your Agent Name

Brief description.

## What This Demonstrates

- Security pattern X
- Integration with Y
- Proper handling of Z

## Security Features

- ✅ Input validation
- ✅ Authentication
- ✅ Rate limiting
- etc.

## Setup

Step-by-step instructions.

## Usage

Example commands and expected output.

## Security Considerations

Important notes about security.
```

### Article Contributions

**We welcome articles on:**
- A2A implementation experiences
- Security analysis and best practices
- Integration patterns
- Case studies
- Performance optimization
- Troubleshooting guides

**Article format:**
```markdown
# Article Title

**Author:** Your Name  
**Date:** YYYY-MM-DD  
**Tags:** security, authentication, tutorial

## Introduction

Hook the reader.

## Main Content

Well-organized sections.

## Conclusion

Key takeaways.

## References

- Links to related resources
```

---

## 🔒 Security Considerations

**This is a security-focused project.** All contributions must prioritize security.

### Security Review Checklist

Before submitting code, ensure:

- [ ] **Input Validation**: All inputs are validated and sanitized
- [ ] **Authentication**: Proper authentication mechanisms are implemented
- [ ] **Authorization**: Access controls are in place
- [ ] **Encryption**: Sensitive data is encrypted (in transit and at rest if applicable)
- [ ] **Error Handling**: Errors don't leak sensitive information
- [ ] **Logging**: Security-relevant events are logged (but NOT sensitive data)
- [ ] **Rate Limiting**: Protection against abuse
- [ ] **No Hardcoded Secrets**: No API keys, passwords, or tokens in code
- [ ] **Dependencies**: No known vulnerabilities in dependencies
- [ ] **Documentation**: Security considerations are documented

### Required Security Documentation

For code examples, include:

1. **Security Features**: What security controls are implemented
2. **Security Limitations**: What this example doesn't protect against
3. **Threat Model**: What attacks this defends against
4. **Assumptions**: What security assumptions are made

**Example:**
```markdown
## Security Features

✅ RSA-based authentication
✅ Nonce-based replay protection
✅ Input validation using JSON Schema
✅ Rate limiting (100 requests/minute)
✅ Audit logging

## Security Limitations

⚠️ This example does not include:
- TLS/HTTPS configuration (assumes reverse proxy handles this)
- Distributed rate limiting (single-instance only)
- Certificate revocation checking

## Threat Model

**Defends Against:**
- Replay attacks
- Man-in-the-middle (with TLS)
- Injection attacks
- Brute force

**Does NOT Defend Against:**
- Physical access to server
- Compromised dependencies
- Zero-day vulnerabilities
```

### Reporting Security Vulnerabilities

**Found a security issue?** Please report it responsibly:

1. **DO NOT** open a public issue
2. **DO** email details to: **robert@fischer3.net**
3. **DO** provide:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

We will:
- Acknowledge receipt within 48 hours
- Provide a timeline for fix
- Credit you in the security advisory (if desired)
- Notify you when the fix is released

---

## 🎨 Style Guidelines

### Python Code Style

**Follow PEP 8** with these specifics:

```python
# Imports: standard library, third-party, local
import os
import sys

import httpx
from fastapi import FastAPI

from . import utils


# Type hints
def validate_message(msg: dict, schema: dict) -> bool:
    """Validate message against schema.
    
    Args:
        msg: Message to validate
        schema: JSON schema
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails
    """
    pass


# Classes: CamelCase
class AgentRegistry:
    """Central registry for agent discovery."""
    
    def __init__(self):
        self.agents = {}
    
    def register(self, agent: Agent) -> bool:
        """Register an agent."""
        pass


# Functions and variables: snake_case
def create_agent_card(name: str, capabilities: list) -> dict:
    """Create agent card."""
    pass


# Constants: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30
```

### Documentation Style

**Markdown formatting:**
- Use ATX-style headers (`#` not underlines)
- One blank line before and after headers
- Code blocks with language specification
- Tables for structured data
- Lists for unordered items
- Ordered lists for sequential steps

**Code blocks:**
````markdown
```python
# Good: language specified
def example():
    pass
```

```
# Avoid: no language (unless plain text)
generic code
```
````

**Links:**
```markdown
<!-- Good: descriptive text -->
See the [authentication guide](docs/auth.md) for details.

<!-- Avoid: "click here" -->
For more information, click [here](docs/auth.md).
```

---

## 👀 Review Process

### What to Expect

1. **Initial Review** (1-3 days):
   - Automated checks run (linting, link checking)
   - Maintainer does initial review
   - May request changes or clarifications

2. **Discussion** (varies):
   - Back-and-forth on changes
   - Refinement of approach
   - Security review if applicable

3. **Approval** (after all feedback addressed):
   - Maintainer approves PR
   - Changes are merged
   - Your contribution is live!

### Review Criteria

We evaluate contributions based on:

**For Documentation:**
- ✅ Accuracy and correctness
- ✅ Clarity and readability
- ✅ Completeness
- ✅ Consistency with existing docs
- ✅ Proper formatting

**For Code:**
- ✅ Security best practices followed
- ✅ Code quality and readability
- ✅ Proper documentation
- ✅ Tests (if applicable)
- ✅ Follows project conventions

**For Security Contributions:**
- ✅ Accurate threat analysis
- ✅ Effective mitigation
- ✅ Clear documentation
- ✅ No introduction of new vulnerabilities

### Addressing Review Feedback

When reviewers request changes:

1. **Read feedback carefully**
2. **Ask questions** if anything is unclear
3. **Make requested changes**
4. **Push updates** to your branch (PR updates automatically)
5. **Respond to comments** explaining your changes
6. **Request re-review** when ready

**Example response:**
```markdown
Thanks for the feedback! I've made the following changes:

1. ✅ Added input validation as suggested
2. ✅ Improved error messages
3. ✅ Added security analysis section
4. ❓ Question: Should rate limiting be per-IP or per-agent-ID?

Ready for another look!
```

---

## 🏆 Recognition

We value all contributions! Contributors will be recognized in the following ways:

### Attribution

- All merged pull requests include attribution
- Contributors are listed in project documentation
- Security researchers who responsibly disclose vulnerabilities are credited (with their permission)

### Hall of Fame

Outstanding contributors may be featured in our documentation:
- Significant documentation improvements
- Major security enhancements
- Valuable code examples
- Active community support

### References

When appropriate, we'll cite contributors in:
- Documentation pages
- Security advisories
- Release notes
- Conference presentations or papers

---

## ❓ Questions or Need Help?

### Getting Help

**Before asking:**
1. Check the [documentation](docs/a2a/INDEX.md)
2. Search [existing issues](https://github.com/robertfischer3/fischer3_a2a_introduction/issues)
3. Review [examples](a2a_examples/)

**Where to ask:**
- **General questions**: Open a [Discussion](https://github.com/robertfischer3/fischer3_a2a_introduction/discussions)
- **Bug reports**: Open an [Issue](https://github.com/robertfischer3/fischer3_a2a_introduction/issues)
- **Security concerns**: Email **robert@fischer3.net**
- **Contribution help**: Comment on your PR or open a Discussion

### Contact

**Project Maintainer:** Robert Fischer  
**Email:** robert@fischer3.net  
**GitHub:** [@robertfischer3](https://github.com/robertfischer3)

### Communication Guidelines

When seeking help:
- ✅ Be specific about your question or problem
- ✅ Provide context (what you're trying to do)
- ✅ Include relevant code or documentation references
- ✅ Share what you've already tried
- ✅ Be patient and respectful

---

## 📄 Pull Request Template

When opening a PR, please include:

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Documentation (typos, new content, etc.)
- [ ] Code example (new example or improvement)
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] Security improvement
- [ ] Feature (new functionality)

## Checklist

- [ ] I have read the CONTRIBUTING.md guidelines
- [ ] My changes follow the project's style guidelines
- [ ] I have performed a self-review of my code/documentation
- [ ] I have commented my code where necessary
- [ ] I have updated documentation as needed
- [ ] My changes do not introduce new security vulnerabilities
- [ ] I have tested my changes (if applicable)
- [ ] All links in documentation are working (if applicable)

## Security Considerations

<!-- For code contributions, describe security implications -->

- [ ] This contribution includes security controls
- [ ] Security analysis is documented
- [ ] No sensitive data is included
- [ ] Dependencies are secure

## Related Issues

Closes #(issue number)
Related to #(issue number)

## Additional Context

Any other relevant information.
```

---

## 🙏 Thank You!

Your contributions make this project better for everyone. We appreciate your time, effort, and expertise in advancing secure multi-agent communication.

**Key Reminders:**
1. 🔒 **Security first** - Always consider security implications
2. 📖 **Document thoroughly** - Help others understand your work
3. 🤝 **Be respectful** - We're all learning together
4. ✅ **Follow guidelines** - Makes review faster and easier

**Happy Contributing!** 🚀

---

## 📚 Additional Resources

### Essential Reading
- [A2A Overview](docs/a2a/00_A2A_OVERVIEW.md)
- [Security Best Practices](docs/a2a/03_SECURITY/04_security_best_practices.md)
- [Threat Model](docs/a2a/03_SECURITY/03_threat_model.md)
- [Code Walkthrough](docs/a2a/03_SECURITY/05_code_walkthrough_comparison.md)

### Example Projects
- [Crypto Price Agent](a2a_examples/a2a_crypto_example/)
- [Credit Report Agent](a2a_examples/a2a_credit_report_example/)
- [Task Collaboration Agent](a2a_examples/a2a_task_collab_example/)

### External Resources
- [GitHub Flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Writing Good Commit Messages](https://chris.beams.io/posts/git-commit/)
- [Markdown Guide](https://www.markdownguide.org/)
- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)

---

**Document Version:** 1.0  
**Last Updated:** December 2025  
**Maintained By:** Robert Fischer (robert@fischer3.net)