"""
Simple Authentication Provider - Stage 2

Password-based authentication using bcrypt for hashing.

⚠️  FOR LEARNING PURPOSES ONLY
This implementation is secure for its scope, but production systems
should use external Identity Providers (Auth0, Okta, etc.).
See Stage 4 for production patterns.

Security Features (Stage 2):
✅ bcrypt password hashing (slow, salted)
✅ Constant-time password comparison
✅ User storage with JSON file
✅ Password validation rules

Still Missing (Fixed in Stage 3/4):
❌ No MFA support (added in Stage 3)
❌ No OAuth/OIDC (added in Stage 4)
❌ No account lockout
❌ No password reset flow
"""

import bcrypt
import json
import os
from datetime import datetime
from typing import Dict, Optional, Tuple
from pathlib import Path

from .auth_provider import (
    AuthProvider,
    InvalidCredentialsError,
    UserNotFoundError,
    AuthResult,
    MFAResult
)


class SimpleAuthProvider(AuthProvider):
    """
    Simple password-based authentication
    
    Features:
    - bcrypt password hashing (cost factor 12)
    - JSON file-based user storage
    - Basic password validation
    - Constant-time comparison
    
    Usage:
        provider = SimpleAuthProvider("config/users.json")
        
        # Authenticate
        success, user_id, error = provider.authenticate(
            "alice",
            {"password": "secret123"}
        )
        
        # Create user
        success, user_id, error = provider.create_user(
            "bob",
            {"password": "newsecret456"},
            {"email": "bob@example.com"}
        )
    """
    
    def __init__(self, users_file: str = "config/users.json"):
        """
        Initialize simple auth provider
        
        Args:
            users_file: Path to JSON file storing user data
        """
        self.users_file = Path(users_file)
        self.users: Dict[str, Dict] = {}
        
        # ✅ Load users from file
        self._load_users()
        
        # ✅ Password requirements
        self.min_password_length = 8
        self.bcrypt_cost_factor = 12  # Appropriate for 2024
    
    def authenticate(
        self,
        username: str,
        credentials: Dict[str, str]
    ) -> AuthResult:
        """
        Authenticate user with password
        
        ✅ Security features:
        - Constant-time username lookup defense
        - bcrypt comparison (inherently constant-time)
        - No information disclosure (generic error)
        """
        password = credentials.get("password")
        
        if not password:
            return False, None, "Password required"
        
        # ✅ Constant-time failure if user doesn't exist
        # Always hash something to prevent timing attacks
        if username not in self.users:
            # Perform dummy bcrypt check to match timing
            bcrypt.checkpw(b"dummy_password", bcrypt.gensalt())
            return False, None, "Invalid credentials"
        
        user = self.users[username]
        password_hash = user["password_hash"].encode()
        
        # ✅ bcrypt.checkpw is constant-time
        try:
            if bcrypt.checkpw(password.encode(), password_hash):
                # Update last login
                user["last_login"] = datetime.now().isoformat()
                self._save_users()
                
                return True, username, None
            else:
                return False, None, "Invalid credentials"
        except Exception as e:
            # Log error but don't expose details
            print(f"⚠️  Authentication error: {e}")
            return False, None, "Authentication error"
    
    def verify_mfa(
        self,
        user_id: str,
        mfa_token: str
    ) -> MFAResult:
        """
        MFA not supported in Stage 2
        
        ❌ Returns False (no MFA support yet)
        
        Note: MFA will be added in Stage 3
        """
        return False, "MFA not supported in Stage 2"
    
    def supports_mfa(self) -> bool:
        """
        Stage 2: No MFA support
        
        Returns:
            False (MFA added in Stage 3)
        """
        return False
    
    def create_user(
        self,
        username: str,
        credentials: Dict[str, str],
        user_data: Optional[Dict] = None
    ) -> AuthResult:
        """
        Create a new user account
        
        ✅ Security features:
        - Password validation (length, complexity)
        - bcrypt hashing with appropriate cost factor
        - Duplicate username prevention
        
        Args:
            username: Desired username
            credentials: Must contain "password"
            user_data: Optional data (email, name, etc.)
        
        Returns:
            (success, user_id, error_message)
        """
        password = credentials.get("password")
        
        if not password:
            return False, None, "Password required"
        
        # ✅ Check if user already exists
        if username in self.users:
            return False, None, "Username already exists"
        
        # ✅ Validate password
        valid, error = self._validate_password(password)
        if not valid:
            return False, None, error
        
        # ✅ Hash password with bcrypt
        try:
            password_hash = bcrypt.hashpw(
                password.encode(),
                bcrypt.gensalt(rounds=self.bcrypt_cost_factor)
            )
        except Exception as e:
            print(f"⚠️  Password hashing error: {e}")
            return False, None, "Failed to create user"
        
        # ✅ Create user record
        now = datetime.now().isoformat()
        self.users[username] = {
            "username": username,
            "password_hash": password_hash.decode(),
            "created_at": now,
            "last_login": None,
            "email": user_data.get("email") if user_data else None,
            "name": user_data.get("name") if user_data else None,
            "roles": user_data.get("roles", ["user"]) if user_data else ["user"],
            "mfa_enabled": False  # For Stage 3
        }
        
        # ✅ Save to file
        self._save_users()
        
        return True, username, None
    
    def can_create_users(self) -> bool:
        """
        Simple auth manages its own users
        
        Returns:
            True (can create users locally)
        """
        return True
    
    def get_user_info(self, user_id: str) -> Optional[Dict]:
        """
        Get user information
        
        Args:
            user_id: Username
        
        Returns:
            User info dict (without password hash)
        """
        if user_id not in self.users:
            return None
        
        user = self.users[user_id].copy()
        
        # ✅ Never return password hash
        user.pop("password_hash", None)
        
        return user
    
    def provider_name(self) -> str:
        """Get provider name"""
        return "SimpleAuth"
    
    def _validate_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password meets requirements
        
        ✅ Requirements:
        - Minimum length (8 characters)
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        
        Args:
            password: Password to validate
        
        Returns:
            (valid, error_message)
        """
        if len(password) < self.min_password_length:
            return False, f"Password must be at least {self.min_password_length} characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        return True, None
    
    def _load_users(self):
        """
        Load users from JSON file
        
        Creates empty file if doesn't exist
        """
        if not self.users_file.exists():
            # Create directory if needed
            self.users_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create empty users file
            self.users = {}
            self._save_users()
            return
        
        try:
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        except json.JSONDecodeError as e:
            print(f"⚠️  Error loading users file: {e}")
            print("   Starting with empty user database")
            self.users = {}
        except Exception as e:
            print(f"⚠️  Unexpected error loading users: {e}")
            self.users = {}
    
    def _save_users(self):
        """
        Save users to JSON file
        
        ✅ Atomic write (write to temp, then rename)
        """
        try:
            # Write to temporary file first
            temp_file = self.users_file.with_suffix('.tmp')
            
            with open(temp_file, 'w') as f:
                json.dump(self.users, f, indent=2)
            
            # Atomic rename
            temp_file.replace(self.users_file)
            
        except Exception as e:
            print(f"⚠️  Error saving users: {e}")
    
    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Change user password
        
        Args:
            username: Username
            old_password: Current password (for verification)
            new_password: New password
        
        Returns:
            (success, error_message)
        """
        # Verify old password
        success, user_id, error = self.authenticate(
            username,
            {"password": old_password}
        )
        
        if not success:
            return False, "Current password is incorrect"
        
        # Validate new password
        valid, error = self._validate_password(new_password)
        if not valid:
            return False, error
        
        # Hash new password
        try:
            password_hash = bcrypt.hashpw(
                new_password.encode(),
                bcrypt.gensalt(rounds=self.bcrypt_cost_factor)
            )
        except Exception as e:
            print(f"⚠️  Password hashing error: {e}")
            return False, "Failed to change password"
        
        # Update user
        self.users[username]["password_hash"] = password_hash.decode()
        self._save_users()
        
        return True, None


def create_default_users(users_file: str = "config/users.json") -> SimpleAuthProvider:
    """
    Create a SimpleAuthProvider with default test users
    
    Default users:
    - alice / AlicePass123
    - bob / BobPass456
    - admin / AdminPass789
    
    ⚠️  FOR TESTING ONLY - DO NOT USE IN PRODUCTION
    
    Returns:
        Configured SimpleAuthProvider
    """
    provider = SimpleAuthProvider(users_file)
    
    # Create default users if none exist
    if not provider.users:
        print("Creating default test users...")
        
        test_users = [
            {
                "username": "alice",
                "password": "AlicePass123",
                "email": "alice@example.com",
                "name": "Alice Anderson",
                "roles": ["user"]
            },
            {
                "username": "bob",
                "password": "BobPass456",
                "email": "bob@example.com",
                "name": "Bob Brown",
                "roles": ["user", "coordinator"]
            },
            {
                "username": "admin",
                "password": "AdminPass789",
                "email": "admin@example.com",
                "name": "Admin User",
                "roles": ["user", "admin"]
            }
        ]
        
        for user in test_users:
            username = user.pop("username")
            password = user.pop("password")
            
            success, user_id, error = provider.create_user(
                username,
                {"password": password},
                user
            )
            
            if success:
                print(f"✅ Created user: {username}")
            else:
                print(f"❌ Failed to create {username}: {error}")
    
    return provider


if __name__ == "__main__":
    """
    Test the SimpleAuthProvider
    
    Usage:
        python -m security.simple_auth_provider
    """
    print("=" * 60)
    print("SimpleAuthProvider Test")
    print("=" * 60)
    
    # Create provider with test users
    provider = create_default_users("test_users.json")
    
    print("\n--- Testing Authentication ---")
    
    # Test valid login
    print("\nTest 1: Valid credentials")
    success, user_id, error = provider.authenticate(
        "alice",
        {"password": "AlicePass123"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test invalid password
    print("\nTest 2: Invalid password")
    success, user_id, error = provider.authenticate(
        "alice",
        {"password": "WrongPassword"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test non-existent user
    print("\nTest 3: Non-existent user")
    success, user_id, error = provider.authenticate(
        "charlie",
        {"password": "AnyPassword"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test user creation
    print("\n--- Testing User Creation ---")
    success, user_id, error = provider.create_user(
        "carol",
        {"password": "CarolPass123"},
        {"email": "carol@example.com", "name": "Carol Chen"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test duplicate username
    print("\nTest: Duplicate username")
    success, user_id, error = provider.create_user(
        "alice",
        {"password": "AnyPassword123"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test weak password
    print("\nTest: Weak password")
    success, user_id, error = provider.create_user(
        "dave",
        {"password": "weak"}
    )
    print(f"Result: {success}, User: {user_id}, Error: {error}")
    
    # Test get user info
    print("\n--- Testing User Info ---")
    user_info = provider.get_user_info("alice")
    print(f"User info: {user_info}")
    
    print("\n" + "=" * 60)
    print("Test complete!")
