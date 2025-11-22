# Agent Identity in Multi-Agent Systems

> **Learning Path**: Fundamentals  
> **Difficulty**: Beginner  
> **Prerequisites**: [Core Concepts](./01_core_concepts.md)

## Navigation
← Previous: [Core Concepts](./01_core_concepts.md) | Next: [Message Types](./03_message_types.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)

---

## 🎯 What You'll Learn

By the end of this document, you will understand:
- [ ] What makes an agent's identity unique
- [ ] How agent IDs are structured and generated
- [ ] The difference between identity and authentication
- [ ] Agent identity lifecycle management
- [ ] Security considerations for agent identities

---

## 🆔 What is Agent Identity?

**Agent Identity** is the unique, persistent identifier that distinguishes one agent from all others in a multi-agent system.

### The Human Analogy

Think of agent identity like your social security number or passport number:
- **Unique**: No two people have the same number
- **Persistent**: It doesn't change over your lifetime
- **Verifiable**: Can be checked against authoritative records
- **Portable**: Recognized across different systems

For agents:
```python
agent_identity = {
    "agent_id": "550e8400-e29b-41d4-a716-446655440000",  # Like SSN
    "name": "CryptoPriceAgent",                          # Like your name
    "public_key": "MIIBIjANBgkq...",                    # Like your fingerprint
}
```

---

## 🔑 Components of Agent Identity

### 1. Agent ID (Required)

**The Unique Identifier**

```python
agent_id = "550e8400-e29b-41d4-a716-446655440000"
```

**Properties**:
- ✅ **Globally unique** - No two agents share the same ID
- ✅ **Immutable** - Never changes during agent's lifetime
- ✅ **Opaque** - Doesn't encode sensitive information
- ✅ **URL-safe** - Can be used in APIs and URLs

**Best Practice**: Use UUIDv4

```python
import uuid

def generate_agent_id():
    """Generate a globally unique agent ID"""
    return str(uuid.uuid4())

# Example output:
# "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

**Why UUID?**
- **Guaranteed uniqueness** - Collision probability: 1 in 5.3 × 10³⁶
- **No central coordination** - Can be generated independently
- **Standard format** - Recognized across languages and platforms
- **Cryptographically random** - No predictable patterns

---

### 2. Human-Readable Name (Optional but Recommended)

```python
name = "CryptoPriceAgent"
```

**Properties**:
- ✅ **Descriptive** - Indicates agent's purpose
- ⚠️ **Not unique** - Multiple agents can have the same name
- ✅ **Changeable** - Can be updated without breaking identity
- ✅ **Human-friendly** - Used in logs, UIs, and debugging

**Naming Conventions**:
```python
# Good names (descriptive, clear purpose)
"WeatherDataAgent"
"CustomerServiceBot"
"PriceMonitorAgent"
"DocumentAnalyzer"

# Poor names (vague, not descriptive)
"Agent1"
"MyAgent"
"Test"
"AgentXYZ"
```

---

### 3. Version (Important for Compatibility)

```python
version = "1.2.3"  # Semantic versioning
```

**Format**: MAJOR.MINOR.PATCH

```
1.2.3
│ │ └─ Patch: Bug fixes, no functionality changes
│ └─── Minor: New features, backwards compatible
└───── Major: Breaking changes
```

**Example Evolution**:
```python
# Initial release
agent_v1 = {"agent_id": "123", "version": "1.0.0"}

# Added new feature (backward compatible)
agent_v1_1 = {"agent_id": "123", "version": "1.1.0"}

# Breaking change (protocol updated)
agent_v2 = {"agent_id": "123", "version": "2.0.0"}
```

**Why Versioning Matters**:
```python
def can_communicate(agent_a, agent_b):
    """Check if agents can communicate"""
    
    a_major = int(agent_a.version.split('.')[0])
    b_major = int(agent_b.version.split('.')[0])
    
    if a_major != b_major:
        return False  # Incompatible major versions
    
    return True  # Compatible
```

---

### 4. Description (Helpful for Discovery)

```python
description = "Provides real-time cryptocurrency price data from multiple exchanges"
```

**Good Description**:
- Explains agent's purpose
- Lists key capabilities
- Mentions data sources or limitations
- 1-2 sentences max

**Example**:
```python
good_description = "AI agent that analyzes customer feedback and generates sentiment reports. Supports English and Spanish."

poor_description = "An agent."  # Too vague
```

---

## 🏗️ Complete Agent Identity Structure

```python
from dataclasses import dataclass
from typing import Dict, Any
import uuid

@dataclass
class AgentIdentity:
    """Complete agent identity structure"""
    
    # Required fields
    agent_id: str                    # UUID v4
    name: str                        # Human-readable name
    version: str                     # Semantic version
    description: str                 # Purpose description
    
    # Optional but recommended
    organization: str = None         # Owning organization
    contact_email: str = None        # Support contact
    created_at: str = None          # ISO timestamp
    metadata: Dict[str, Any] = None # Additional info
    
    @classmethod
    def create_new(cls, name: str, description: str, **kwargs):
        """Factory method to create new agent identity"""
        return cls(
            agent_id=str(uuid.uuid4()),
            name=name,
            version="1.0.0",
            description=description,
            **kwargs
        )

# Usage
crypto_agent = AgentIdentity.create_new(
    name="CryptoPriceAgent",
    description="Provides cryptocurrency prices",
    organization="FinTech Corp",
    contact_email="agents@fintech.com"
)

print(crypto_agent.agent_id)
# Output: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

---

## 🔒 Identity vs. Authentication

**Critical Distinction**:

| Aspect | Identity | Authentication |
|--------|----------|----------------|
| **What it is** | Who you claim to be | Proof of who you are |
| **Example** | "I am agent-001" | "Here's my signature" |
| **Static/Dynamic** | Static (doesn't change) | Dynamic (per request) |
| **Trust** | Claimed | Verified |

### Identity: The Claim

```python
# Agent CLAIMS an identity
agent_card = {
    "agent_id": "crypto-agent-001",
    "name": "CryptoPriceAgent"
}

# Anyone can CLAIM to be any agent!
fake_card = {
    "agent_id": "crypto-agent-001",  # Impersonation!
    "name": "CryptoPriceAgent"
}
```

### Authentication: The Proof

```python
# Agent PROVES identity with signature
def prove_identity(agent_id, private_key):
    """Generate proof of identity"""
    
    # Create message to sign
    message = f"I am {agent_id} at {datetime.now().isoformat()}"
    
    # Sign with private key (only real agent has this!)
    signature = sign_with_private_key(message, private_key)
    
    return {
        "agent_id": agent_id,
        "message": message,
        "signature": signature  # PROOF!
    }

def verify_identity(proof, public_key):
    """Verify proof of identity"""
    
    # Verify signature with public key
    is_valid = verify_signature(
        proof["message"],
        proof["signature"],
        public_key
    )
    
    if is_valid:
        return True  # Identity PROVEN
    else:
        return False  # Identity NOT PROVEN (imposter!)
```

**Key Point**: Identity can be claimed by anyone. Authentication proves the claim is true.

---

## 🔄 Agent Identity Lifecycle

```
┌─────────────────────────────────────────────┐
│ 1. CREATION                                 │
│    - Generate UUID                          │
│    - Assign name and version                │
│    - Generate key pair                      │
│    - Register in system                     │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 2. REGISTRATION                             │
│    - Submit to registry                     │
│    - Obtain certificate (if PKI)            │
│    - Become discoverable                    │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 3. ACTIVE USE                               │
│    - Authenticate to other agents           │
│    - Perform operations                     │
│    - Update capabilities                    │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 4. VERSION UPDATES                          │
│    - Increment version number               │
│    - Maintain same agent_id                 │
│    - Announce capabilities                  │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 5. KEY ROTATION                             │
│    - Generate new key pair                  │
│    - Maintain same agent_id                 │
│    - Update public key in registry          │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│ 6. DECOMMISSIONING                          │
│    - Revoke certificates                    │
│    - Remove from registry                   │
│    - Archive audit logs                     │
│    - Never reuse agent_id                   │
└─────────────────────────────────────────────┘
```

---

## 🔐 Security Considerations

### 1. Agent ID Must Be Unpredictable

```python
# ❌ BAD: Sequential IDs
agent_id = f"agent-{counter}"  # Predictable! Attacker can guess IDs
# agent-1, agent-2, agent-3...

# ❌ BAD: Timestamp-based
agent_id = f"agent-{datetime.now().timestamp()}"  # Predictable!

# ✅ GOOD: UUID v4 (cryptographically random)
agent_id = str(uuid.uuid4())  # Unpredictable!
# "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

**Why Unpredictability Matters**:
- Prevents enumeration attacks
- Hides system size
- Protects agent privacy

---

### 2. Never Encode Sensitive Data in IDs

```python
# ❌ BAD: Encoding sensitive info
agent_id = "org-fintech-user-john-dept-accounting-001"
# Reveals: Organization, user, department

# ❌ BAD: Encoding capabilities
agent_id = "admin-privileged-full-access-001"
# Reveals: Permission level

# ✅ GOOD: Opaque identifier
agent_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
# Reveals: Nothing useful to attacker
```

---

### 3. Protect Agent Identity Information

```python
class AgentIdentity:
    def to_dict(self, security_level="PUBLIC"):
        """Context-aware serialization"""
        
        # Public information (safe for anyone)
        public_data = {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "description": self.description
        }
        
        if security_level == "INTERNAL":
            # Internal information (same organization)
            public_data.update({
                "organization": self.organization,
                "contact_email": self.contact_email
            })
        
        if security_level == "PRIVILEGED":
            # Sensitive information (admin only)
            public_data.update({
                "created_at": self.created_at,
                "metadata": self.metadata
            })
        
        return public_data
```

---

### 4. Never Reuse Agent IDs

```python
# ❌ BAD: Reusing ID after decommissioning
old_agent = decommission_agent("agent-001")
new_agent = create_agent(agent_id="agent-001")  # DANGEROUS!

# Why bad:
# - Old permissions might still be cached
# - Logs become confusing (which agent-001?)
# - Certificates might still be trusted

# ✅ GOOD: Always generate new ID
new_agent = create_agent(agent_id=str(uuid.uuid4()))
```

---

## 🎯 Best Practices Checklist

### Identity Generation
- [ ] Use UUID v4 for agent IDs
- [ ] Generate cryptographically secure IDs
- [ ] Never encode sensitive data in IDs
- [ ] Make IDs URL-safe
- [ ] Document ID format in system

### Identity Management
- [ ] Store IDs immutably
- [ ] Never reuse decommissioned IDs
- [ ] Maintain agent ID registry
- [ ] Track identity lifecycle
- [ ] Archive decommissioned agent data

### Identity Presentation
- [ ] Include version in identity
- [ ] Provide clear description
- [ ] Use semantic versioning
- [ ] Context-aware information disclosure
- [ ] Sanitize names and descriptions

### Identity Verification
- [ ] Always verify claimed identities
- [ ] Use cryptographic authentication
- [ ] Check identity against registry
- [ ] Validate identity freshness
- [ ] Log all identity validations

---

## 📊 Common Identity Patterns

### Pattern 1: Hierarchical Identity

```python
# Useful for organizational structure
agent_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
metadata = {
    "organization_id": "org-123",
    "department": "trading",
    "team": "crypto-analytics"
}
```

### Pattern 2: Role-Based Identity

```python
# Identity includes role information
agent_identity = {
    "agent_id": "f47ac10b...",
    "role": "price-provider",
    "capabilities": ["read_prices", "stream_updates"]
}
```

### Pattern 3: Federated Identity

```python
# Identity from external provider
agent_identity = {
    "agent_id": "f47ac10b...",
    "issuer": "https://idp.partner.com",
    "issuer_agent_id": "partner-agent-xyz"
}
```

---

## 🔍 Troubleshooting Identity Issues

### Issue: Identity Collision

**Symptom**: Two agents have the same ID

**Cause**: Not using proper UUID generation

**Solution**:
```python
# Use uuid.uuid4(), not uuid.uuid1()
import uuid

# ✅ CORRECT
agent_id = str(uuid.uuid4())  # Random-based

# ❌ WRONG
agent_id = str(uuid.uuid1())  # Time-based, can collide
```

---

### Issue: Identity Not Recognized

**Symptom**: Agent rejected even with valid ID

**Cause**: Not registered in system

**Solution**:
```python
def ensure_registered(agent_identity):
    """Ensure agent is registered before use"""
    
    if not is_registered(agent_identity.agent_id):
        register_agent(agent_identity)
    
    return agent_identity
```

---

### Issue: Lost Identity After Restart

**Symptom**: Agent gets new ID after restart

**Cause**: Generating new ID on each startup

**Solution**:
```python
class PersistentAgent:
    def __init__(self, storage_path):
        self.storage_path = storage_path
        self.identity = self.load_or_create_identity()
    
    def load_or_create_identity(self):
        """Load existing identity or create new"""
        
        if os.path.exists(self.storage_path):
            # Load existing identity
            with open(self.storage_path) as f:
                data = json.load(f)
                return AgentIdentity(**data)
        else:
            # Create new identity and persist
            identity = AgentIdentity.create_new(
                name="MyAgent",
                description="Agent description"
            )
            self.save_identity(identity)
            return identity
    
    def save_identity(self, identity):
        """Persist identity to disk"""
        with open(self.storage_path, 'w') as f:
            json.dump(identity.to_dict(), f)
```

---

## 📚 Next Steps

Now that you understand agent identity:

1. **[Message Types](./03_message_types.md)** - Learn how agents communicate
2. **[Authentication Overview](../03_SECURITY/01_authentication_overview.md)** - Learn how agents prove identity
3. **[Agent Cards](../02_DISCOVERY/01_agent_cards.md)** - Full identity structure with capabilities

---

## 🎓 Check Your Understanding

1. **What makes an agent ID unique?**
   <details><summary>Answer</summary>Using UUID v4 ensures global uniqueness through cryptographic randomness</details>

2. **Can two agents have the same name?**
   <details><summary>Answer</summary>Yes, names are not unique. Only agent_id must be unique.</details>

3. **Should you reuse agent IDs?**
   <details><summary>Answer</summary>Never! Reusing IDs causes security and operational issues.</details>

4. **What's the difference between identity and authentication?**
   <details><summary>Answer</summary>Identity is who you claim to be. Authentication is proof of that claim.</details>

---

**Document Version**: 1.0  
**Last Updated**: November 2025  
**Part of**: A2A Security Learning Project

---

**Navigation**  
← Previous: [Core Concepts](./01_core_concepts.md) | Next: [Message Types](./03_message_types.md) →  
↑ Up: [A2A Overview](../00_A2A_OVERVIEW.md)