# Agent Card Authentication Tags

## Overview

Agent Card Authentication Tags are cryptographic and metadata fields that establish the identity, authenticity, and trustworthiness of agents in the A2A protocol. These tags enable secure agent-to-agent communication and prevent impersonation, tampering, and unauthorized access.

---

## Core Authentication Tags

### 1. **agent_id** 
**Type:** String (UUID recommended)  
**Required:** Yes  
**Purpose:** Unique identifier for the agent

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Security Notes:**
- Must be globally unique (use UUIDv4)
- Immutable across agent lifetime
- Used as primary key in registries and logs

---

### 2. **public_key**
**Type:** Base64-encoded string  
**Required:** Yes (for secure implementations)  
**Purpose:** Public half of asymmetric key pair for signature verification

```json
{
  "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}
```

**Security Notes:**
- Corresponding private key never transmitted
- Used to verify agent signatures
- Should be at least 2048-bit RSA or 256-bit ECC
- Rotated periodically (recommended: every 90 days)

**Usage:**
```python
# Verify agent card signature using public key
public_key = load_public_key(agent_card.public_key)
is_valid = verify_signature(
    data=agent_card.to_bytes(),
    signature=agent_card.signature,
    public_key=public_key
)
```

---

### 3. **signature**
**Type:** Base64-encoded string  
**Required:** Yes (for tamper protection)  
**Purpose:** Cryptographic signature of the entire agent card

```json
{
  "signature": "a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t9u8v7w6x5y4z3...",
  "signature_algorithm": "RS256"
}
```

**What is Signed:**
All agent card fields except the signature itself, serialized deterministically.

**Security Notes:**
- Proves card issued by holder of private key
- Detects any tampering with card contents
- Must be verified before trusting any card data

**Example Signing Process:**
```python
def sign_card(agent_card, private_key):
    # 1. Create canonical representation (excluding signature)
    card_data = {
        "agent_id": agent_card.agent_id,
        "name": agent_card.name,
        "capabilities": agent_card.capabilities,
        "issued_at": agent_card.issued_at,
        # ... all other fields except signature
    }
    
    # 2. Serialize deterministically (sorted keys)
    canonical_json = json.dumps(card_data, sort_keys=True)
    
    # 3. Sign with private key
    signature = rsa_sign(canonical_json.encode(), private_key)
    
    # 4. Encode signature
    return base64.b64encode(signature).decode()
```

---

### 4. **certificate_fingerprint**
**Type:** SHA-256 hash (hex string)  
**Required:** Recommended for PKI systems  
**Purpose:** References X.509 certificate for identity verification

```json
{
  "certificate_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

**Security Notes:**
- Links agent to X.509 certificate
- Enables certificate chain validation
- Checked against Certificate Revocation Lists (CRLs)
- Provides non-repudiation

**Validation Flow:**
```python
def validate_certificate(agent_card):
    # 1. Retrieve certificate by fingerprint
    cert = get_certificate(agent_card.certificate_fingerprint)
    
    # 2. Verify certificate chain
    if not verify_chain(cert, trusted_root_certs):
        return False
    
    # 3. Check revocation status
    if is_revoked(cert):
        return False
    
    # 4. Verify cert matches public key in card
    if cert.public_key != agent_card.public_key:
        return False
    
    return True
```

---

### 5. **issuer**
**Type:** String  
**Required:** Yes (for trust hierarchies)  
**Purpose:** Identifies the trusted authority that issued/certified the agent

```json
{
  "issuer": "trust-authority-production-01",
  "issuer_signature": "9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2h1g0f9e8d7c6b5a4..."
}
```

**Trust Models:**
- **Self-Issued**: Agent signs its own card (lowest trust)
- **Organization-Issued**: Company CA issues agent certificates
- **Third-Party CA**: External certificate authority
- **Federated Trust**: Multiple issuers in trust network

**Security Notes:**
- Issuer must be in receiver's trusted issuer list
- Enables delegation of trust
- Allows revocation at issuer level

---

### 6. **issued_at** & **expires_at**
**Type:** ISO 8601 timestamp  
**Required:** Yes  
**Purpose:** Time-bound validity of agent card

```json
{
  "issued_at": "2025-01-15T10:30:00Z",
  "expires_at": "2025-04-15T10:30:00Z"
}
```

**Security Notes:**
- Limits window of exposure if card compromised
- Forces periodic re-authentication
- Prevents replay of old cards
- Recommended lifetime: 30-90 days

**Validation:**
```python
def is_card_valid(agent_card):
    now = datetime.utcnow()
    issued = datetime.fromisoformat(agent_card.issued_at)
    expires = datetime.fromisoformat(agent_card.expires_at)
    
    if now < issued:
        return False  # Not yet valid
    
    if now > expires:
        return False  # Expired
    
    return True
```

---

## Additional Authentication Tags

### 7. **nonce** (for replay protection)
**Type:** String  
**Required:** For sensitive operations  
**Purpose:** One-time value preventing replay attacks

```json
{
  "nonce": "550e8400-e29b-41d4-a716-446655440000",
  "nonce_expires_at": "2025-01-15T10:35:00Z"
}
```

**Security Notes:**
- Must be unique per request
- Typically valid for 5-10 minutes
- Server tracks used nonces and rejects duplicates

---

### 8. **security_level**
**Type:** Enum/String  
**Required:** Recommended  
**Purpose:** Indicates trust level of agent

```json
{
  "security_level": "TRUSTED"
}
```

**Levels:**
- `BOOTSTRAP`: Initial registration (limited capabilities)
- `UNTRUSTED`: Unknown agent (restricted access)
- `VERIFIED`: Identity confirmed (standard access)
- `TRUSTED`: Fully vetted (elevated permissions)
- `PRIVILEGED`: System-level agent (admin access)

---

### 9. **allowed_domains**
**Type:** Array of strings (domain patterns)  
**Required:** Recommended  
**Purpose:** Restricts where agent can operate

```json
{
  "allowed_domains": [
    "*.mycompany.com",
    "trusted-partner.net"
  ]
}
```

**Security Notes:**
- Prevents agent from being used outside authorized networks
- Supports wildcards for subdomains
- Validated during connection establishment

---

### 10. **revocation_list_url**
**Type:** URL string  
**Required:** Optional  
**Purpose:** Points to certificate revocation list

```json
{
  "revocation_list_url": "https://pki.example.com/crl/agents.crl"
}
```

**Security Notes:**
- Enables real-time revocation checking
- Should be checked before accepting card
- Falls back to cached CRL if URL unreachable

---

## Authentication Tag Validation Flow

```
┌─────────────────────────────────────────────┐
│ 1. Receive Agent Card                       │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 2. Verify Signature                         │
│    - Extract public_key                     │
│    - Verify signature matches card data     │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 3. Check Certificate (if PKI)               │
│    - Validate certificate_fingerprint       │
│    - Check certificate chain                │
│    - Verify not revoked                     │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 4. Validate Issuer                          │
│    - Check issuer in trusted list           │
│    - Verify issuer_signature if present     │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 5. Check Time Validity                      │
│    - issued_at <= now <= expires_at         │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 6. Validate Nonce (if present)              │
│    - Check not previously used              │
│    - Verify not expired                     │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 7. Check Security Level                     │
│    - Meets minimum required level           │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ 8. Validate Domain Restrictions              │
│    - Connection from allowed_domains        │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│ ✅ Agent Authenticated                       │
└─────────────────────────────────────────────┘
```

---
![A2A Processes Diagram](../../images/security/A2AProcesses-Page-2.drawio.png)

## Complete Example: Secure Agent Card

```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "CryptoPriceAgent",
  "version": "1.0.0",
  "description": "Cryptocurrency price data provider",
  
  "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArW8...",
  "certificate_fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature": "a8b7c6d5e4f3g2h1i0j9k8l7m6n5o4p3q2r1s0t9u8v7w6x5y4z3...",
  "signature_algorithm": "RS256",
  
  "issued_at": "2025-01-15T10:30:00Z",
  "expires_at": "2025-04-15T10:30:00Z",
  "issuer": "trust-authority-production-01",
  "issuer_signature": "9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2h1g0f9e8d7c6b5a4...",
  
  "security_level": "TRUSTED",
  "allowed_domains": ["*.crypto-exchange.com", "api.pricedata.net"],
  "revocation_list_url": "https://pki.crypto-exchange.com/crl/agents.crl",
  
  "capabilities": ["get_price", "list_currencies"],
  "metadata": {
    "supported_currencies": ["BTC", "ETH", "XRP"]
  }
}
```

---

## Security Best Practices

### ✅ DO

- **Always verify signatures** before trusting card data
- **Check expiration** on every card use
- **Validate issuer** against trusted authority list
- **Use nonces** for sensitive operations
- **Rotate keys** every 90 days
- **Check revocation lists** regularly
- **Log all validation failures** for security monitoring
- **Use TLS/mTLS** for card transmission

### ❌ DON'T

- **Never transmit private keys**
- **Don't trust self-signed cards** in production
- **Don't skip signature verification** for "trusted" agents
- **Don't reuse nonces**
- **Don't hardcode trusted issuers** (use configuration)
- **Don't ignore expired cards**
- **Don't log sensitive key material**

---

## Implementation Example

```python
class AuthenticatedAgentCard:
    """Agent Card with full authentication tag support"""
    
    def __init__(self, **kwargs):
        # Core identity
        self.agent_id = kwargs['agent_id']
        self.name = kwargs['name']
        
        # Authentication tags
        self.public_key = kwargs['public_key']
        self.signature = kwargs.get('signature')
        self.certificate_fingerprint = kwargs.get('certificate_fingerprint')
        
        # Time validity
        self.issued_at = kwargs['issued_at']
        self.expires_at = kwargs['expires_at']
        
        # Trust
        self.issuer = kwargs['issuer']
        self.security_level = kwargs.get('security_level', 'UNTRUSTED')
        
        # Authorization
        self.allowed_domains = kwargs.get('allowed_domains', [])
        
    def verify_authenticity(self, trusted_issuers, trusted_certs):
        """Verify all authentication tags"""
        
        # 1. Check not expired
        if self.is_expired():
            return False, "Card expired"
        
        # 2. Verify signature
        if not self.verify_signature():
            return False, "Invalid signature"
        
        # 3. Check issuer
        if self.issuer not in trusted_issuers:
            return False, "Untrusted issuer"
        
        # 4. Validate certificate if present
        if self.certificate_fingerprint:
            if not self.verify_certificate(trusted_certs):
                return False, "Certificate validation failed"
        
        return True, "Authenticated"
    
    def verify_signature(self):
        """Verify card signature using public key"""
        # Implementation depends on crypto library
        pass
    
    def verify_certificate(self, trusted_certs):
        """Verify certificate chain and revocation status"""
        # Implementation depends on PKI setup
        pass
    
    def is_expired(self):
        """Check if card is within valid time window"""
        now = datetime.utcnow()
        issued = datetime.fromisoformat(self.issued_at)
        expires = datetime.fromisoformat(self.expires_at)
        return now < issued or now > expires
```

---

## Security Levels Explained

| Level | Trust | Use Case | Capabilities |
|-------|-------|----------|--------------|
| **BOOTSTRAP** | None | Initial registration | Register only |
| **UNTRUSTED** | Low | Unknown agents | Public read-only |
| **VERIFIED** | Medium | Identity confirmed | Standard operations |
| **TRUSTED** | High | Fully vetted | Sensitive operations |
| **PRIVILEGED** | Highest | System agents | Administrative |

**Progression:**
```
BOOTSTRAP → UNTRUSTED → VERIFIED → TRUSTED → PRIVILEGED
   (registration)  (basic auth)  (PKI cert)  (audit pass)  (admin approval)
```

---

## Common Attack Vectors & Mitigations

### 1. **Card Tampering**
**Attack:** Modify capabilities after issuance  
**Mitigation:** Signature verification detects any changes

### 2. **Replay Attacks**
**Attack:** Reuse intercepted card  
**Mitigation:** Nonces + expiration timestamps

### 3. **Impersonation**
**Attack:** Create fake card with stolen agent_id  
**Mitigation:** Signature requires private key possession

### 4. **Man-in-the-Middle**
**Attack:** Intercept and modify card in transit  
**Mitigation:** TLS/mTLS encryption + signature verification

### 5. **Certificate Revocation Bypass**
**Attack:** Use compromised cert after revocation  
**Mitigation:** Check CRL/OCSP before accepting card

---

## Summary

Authentication tags transform Agent Cards from simple metadata into cryptographically-secured identity documents. Key principles:

1. **Identity**: `agent_id` + `public_key` uniquely identify agent
2. **Authenticity**: `signature` proves card issued by private key holder
3. **Trust**: `issuer` + `certificate_fingerprint` enable trust chains
4. **Validity**: `issued_at` + `expires_at` provide time boundaries
5. **Authorization**: `security_level` + `allowed_domains` control access

**Result:** Secure, trustworthy agent-to-agent communication in distributed systems.

---

## Additional Resources

- **Agent Card Security Best Practices** - See `agent_card_security.md`
- **A2A Protocol Specification** - See protocol documentation
- **PKI Fundamentals** - X.509 certificates, CRLs, OCSP
- **Cryptographic Standards** - RS256, ES256, EdDSA
- **Zero Trust Architecture** - Never trust, always verify