"""
Authentication Manager - Stage 2

Manages authentication using pluggable AuthProvider implementations.

This demonstrates the Strategy Pattern - the AuthManager doesn't care
which AuthProvider is used, it just calls the interface methods.

Stage 2: Uses SimpleAuthProvider
Stage 3: Adds MFA support
Stage 4: Can swap to OAuth providers (Auth0, Okta, etc.)

Key Benefits:
✅ Easy to test (use mock providers)
✅ Easy to swap implementations
✅ Separation of concerns
✅ Future-proof design
"""

from typing import Dict, Optional, Tuple
from datetime import datetime

from .auth_provider import (
    AuthProvider,
    AuthenticationError,
    InvalidCredentialsError,
    MFARequiredError,
    RateLimitError
)


class AuthManager:
    """
    Authentication manager with pluggable providers
    
    This class coordinates the authentication process without
    being tied to a specific authentication method.
    
    Usage:
        # Stage 2: Simple auth
        from security.simple_auth_provider import SimpleAuthProvider
        
        provider = SimpleAuthProvider("config/users.json")
        auth_manager = AuthManager(provider)
        
        success, session_data = auth_manager.login("alice", "AlicePass123")
        
        # Stage 4: Swap to OAuth (no code changes needed!)
        from security.oauth_provider import Auth0Provider
        
        provider = Auth0Provider(domain="...", client_id="...")
        auth_manager = AuthManager(provider)  # Same interface!
        
        success, session_data = auth_manager.login("alice", "AlicePass123")
    """
    
    def __init__(self, provider: AuthProvider):
        """
        Initialize auth manager with a provider
        
        Args:
            provider: Authentication provider implementation
        """
        self.provider = provider
        
        # Track failed login attempts for rate limiting
        # ❌ Stage 2: Basic tracking (in-memory)
        # ✅ Stage 3: Will add proper rate limiting
        self.failed_attempts: Dict[str, list] = {}
        
        print(f"✅ AuthManager initialized with {provider.provider_name()}")
    
    def login(
        self,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        client_info: Optional[Dict] = None
    ) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Authenticate user and create session data
        
        Args:
            username: Username
            password: Password
            mfa_token: MFA token (if provider supports MFA)
            client_info: Client information (IP, user-agent, etc.)
        
        Returns:
            Tuple of (success, session_data, error_message)
            
            session_data contains:
            - user_id: User identifier
            - username: Username
            - roles: List of user roles
            - provider: Provider name
            - mfa_verified: Whether MFA was verified
            - login_time: When user logged in
        
        Example:
            success, session, error = auth_manager.login(
                "alice",
                "AlicePass123"
            )
            
            if success:
                print(f"Welcome {session['username']}!")
                print(f"Roles: {session['roles']}")
        """
        # ⚠️ Stage 2: Basic rate limiting (will improve in Stage 3)
        if self._is_rate_limited(username):
            return False, None, "Too many failed attempts. Please try again later."
        
        # Step 1: Authenticate with password
        print(f"🔐 Authenticating {username} with {self.provider.provider_name()}...")
        
        success, user_id, error = self.provider.authenticate(
            username,
            {"password": password}
        )
        
        if not success:
            self._record_failed_attempt(username)
            print(f"❌ Authentication failed: {error}")
            return False, None, error
        
        print(f"✅ Password verified for {username}")
        
        # Step 2: Check if MFA is required
        if self.provider.supports_mfa():
            if not mfa_token:
                # MFA supported but token not provided
                print("⚠️  MFA required but not provided")
                return False, None, "MFA token required"
            
            # Verify MFA token
            print(f"🔐 Verifying MFA token...")
            mfa_success, mfa_error = self.provider.verify_mfa(user_id, mfa_token)
            
            if not mfa_success:
                self._record_failed_attempt(username)
                print(f"❌ MFA verification failed: {mfa_error}")
                return False, None, mfa_error
            
            print(f"✅ MFA verified")
            mfa_verified = True
        else:
            mfa_verified = False
        
        # Step 3: Get user information
        user_info = self.provider.get_user_info(user_id)
        
        if not user_info:
            return False, None, "Failed to retrieve user information"
        
        # Step 4: Create session data
        session_data = {
            "user_id": user_id,
            "username": user_info.get("username", user_id),
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "roles": user_info.get("roles", ["user"]),
            "provider": self.provider.provider_name(),
            "mfa_verified": mfa_verified,
            "login_time": datetime.now().isoformat(),
            "client_ip": client_info.get("ip") if client_info else None,
            "user_agent": client_info.get("user_agent") if client_info else None
        }
        
        # Clear failed attempts on successful login
        if username in self.failed_attempts:
            del self.failed_attempts[username]
        
        print(f"✅ Login successful for {username}")
        
        return True, session_data, None
    
    def create_user(
        self,
        username: str,
        password: str,
        user_data: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Create a new user account
        
        Args:
            username: Desired username
            password: Password
            user_data: Additional user data (email, name, roles)
        
        Returns:
            Tuple of (success, user_id, error_message)
        
        Note:
            Not all providers support user creation (e.g., OAuth providers)
        
        Example:
            success, user_id, error = auth_manager.create_user(
                "bob",
                "BobPass456",
                {"email": "bob@example.com", "name": "Bob Brown"}
            )
        """
        # Check if provider supports user creation
        if not self.provider.can_create_users():
            return False, None, f"{self.provider.provider_name()} does not support user creation"
        
        print(f"👤 Creating user {username}...")
        
        success, user_id, error = self.provider.create_user(
            username,
            {"password": password},
            user_data
        )
        
        if success:
            print(f"✅ User {username} created successfully")
        else:
            print(f"❌ User creation failed: {error}")
        
        return success, user_id, error
    
    def get_user_info(self, user_id: str) -> Optional[Dict]:
        """
        Get user information
        
        Args:
            user_id: User identifier
        
        Returns:
            User information dictionary, or None if not found
        """
        return self.provider.get_user_info(user_id)
    
    def supports_mfa(self) -> bool:
        """
        Check if current provider supports MFA
        
        Returns:
            True if MFA is supported
        """
        return self.provider.supports_mfa()
    
    def _is_rate_limited(self, username: str) -> bool:
        """
        Check if user is rate limited
        
        ⚠️  Stage 2: Basic implementation (in-memory)
        ❌  Issues:
        - Lost on restart
        - Not distributed
        - Simple time window
        
        ✅  Stage 3: Will use proper rate limiter
        
        Args:
            username: Username to check
        
        Returns:
            True if rate limited
        """
        if username not in self.failed_attempts:
            return False
        
        # ⚠️ Simple rule: 5 failures = rate limited
        return len(self.failed_attempts[username]) >= 5
    
    def _record_failed_attempt(self, username: str):
        """
        Record a failed login attempt
        
        ⚠️  Stage 2: Simple in-memory tracking
        
        Args:
            username: Username that failed
        """
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append(datetime.now())
        
        # ⚠️ Keep only last 10 attempts
        self.failed_attempts[username] = self.failed_attempts[username][-10:]


if __name__ == "__main__":
    """
    Test the AuthManager with SimpleAuthProvider
    
    Usage:
        python -m security.auth_manager
    """
    from .simple_auth_provider import create_default_users
    
    print("=" * 60)
    print("AuthManager Test")
    print("=" * 60)
    
    # Create provider with default test users
    provider = create_default_users("test_users.json")
    
    # Create auth manager
    auth_manager = AuthManager(provider)
    
    print("\n--- Test 1: Successful Login ---")
    success, session, error = auth_manager.login("alice", "AlicePass123")
    
    if success:
        print(f"✅ Login successful!")
        print(f"   User: {session['username']}")
        print(f"   Roles: {session['roles']}")
        print(f"   Provider: {session['provider']}")
        print(f"   MFA Verified: {session['mfa_verified']}")
    else:
        print(f"❌ Login failed: {error}")
    
    print("\n--- Test 2: Invalid Password ---")
    success, session, error = auth_manager.login("alice", "WrongPassword")
    print(f"Result: {success}, Error: {error}")
    
    print("\n--- Test 3: Non-existent User ---")
    success, session, error = auth_manager.login("charlie", "AnyPassword")
    print(f"Result: {success}, Error: {error}")
    
    print("\n--- Test 4: Create New User ---")
    success, user_id, error = auth_manager.create_user(
        "dave",
        "DavePass123",
        {
            "email": "dave@example.com",
            "name": "Dave Davis",
            "roles": ["user"]
        }
    )
    print(f"Result: {success}, User ID: {user_id}, Error: {error}")
    
    if success:
        print("\n--- Test 5: Login with New User ---")
        success, session, error = auth_manager.login("dave", "DavePass123")
        if success:
            print(f"✅ New user logged in successfully!")
            print(f"   User: {session['username']}")
    
    print("\n--- Test 6: Rate Limiting ---")
    print("Attempting 6 failed logins...")
    for i in range(6):
        success, session, error = auth_manager.login("bob", "WrongPassword")
        print(f"  Attempt {i+1}: {error}")
    
    print("\n" + "=" * 60)
    print("Test complete!")