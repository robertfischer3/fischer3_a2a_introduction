# Configuration Files - Stage 2

## Users

The `users.json` file contains test user accounts for Stage 2 demonstrations.

### Test User Credentials

⚠️  **FOR TESTING/LEARNING ONLY - DO NOT USE IN PRODUCTION**

| Username | Password | Roles | Description |
|----------|----------|-------|-------------|
| alice | AlicePass123 | user | Standard user account |
| bob | BobPass456 | user, coordinator | User with coordinator privileges |
| admin | AdminPass789 | user, admin | Administrator account |

### Password Hashing

Passwords are hashed using bcrypt with cost factor 12:

```python
import bcrypt

password = "AlicePass123"
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

**Security Note**: 
- Cost factor 12 is appropriate for 2024 hardware
- Bcrypt automatically includes random salt
- Each hash is unique even for identical passwords
- Verification is constant-time (prevents timing attacks)

### Creating New Users

You can create new users in two ways:

#### 1. Using the SimpleAuthProvider

```python
from security import SimpleAuthProvider

provider = SimpleAuthProvider("config/users.json")

success, user_id, error = provider.create_user(
    "carol",
    {"password": "CarolPass123"},
    {
        "email": "carol@example.com",
        "name": "Carol Chen",
        "roles": ["user"]
    }
)
```

#### 2. Manual Password Hash Generation

```python
import bcrypt
import json

# Generate hash
password = "NewPass123"
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Create user entry
user = {
    "username": "newuser",
    "password_hash": password_hash.decode(),
    "email": "newuser@example.com",
    "name": "New User",
    "roles": ["user"],
    "created_at": "2024-12-29T10:00:00",
    "last_login": None,
    "mfa_enabled": False
}

# Add to users.json
with open("config/users.json", "r") as f:
    users = json.load(f)

users["newuser"] = user

with open("config/users.json", "w") as f:
    json.dump(users, f, indent=2)
```

### User Roles

**Available Roles**:

- **user**: Basic role for all authenticated users
- **coordinator**: Can coordinate tasks and projects
- **admin**: Full administrative access

**Role Implementation**:
- Stage 2: Roles stored but not fully enforced
- Stage 3: Full RBAC implementation with real-time checks

### File Format

```json
{
  "username": {
    "username": "alice",
    "password_hash": "$2b$12$...",
    "email": "alice@example.com",
    "name": "Alice Anderson",
    "roles": ["user"],
    "created_at": "2024-01-01T10:00:00",
    "last_login": null,
    "mfa_enabled": false
  }
}
```

### Security Considerations

**Stage 2 Implementation**:
- ✅ bcrypt password hashing
- ✅ Constant-time comparison
- ✅ Random salts per password
- ✅ Appropriate cost factor

**Still Missing (Stage 3)**:
- ❌ MFA/2FA support (mfa_enabled flag ready)
- ❌ Password reset flow
- ❌ Account lockout
- ❌ Password history
- ❌ Force password change on first login

### Production Recommendations

⚠️  **DO NOT use file-based user storage in production!**

Instead:
- Use external Identity Providers (Auth0, Okta, etc.)
- Store users in database with encryption
- Implement proper password policies
- Enable MFA
- Use OAuth/OIDC flows

See Stage 4 for external IdP integration examples.

---

**Stage**: 2 (Improved)  
**Security**: Learning implementation only  
**Production**: See Stage 3 & 4