"""
Authentication Provider Interface - Stage 2

This module defines the authentication provider interface that allows
swapping between different authentication implementations.

Stage 2: Uses SimpleAuthProvider (password + bcrypt)
Stage 3: Adds MFA to SimpleAuthProvider
Stage 4: Adds OAuth/OIDC providers (Auth0, Okta, etc.)

⚠️  Educational Implementation
This shows proper interface design, but the simple implementation
is for learning only. Production systems should use external IdPs
(see Stage 4).
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple


class AuthProvider(ABC):
    """
    Abstract authentication provider interface
    
    This interface allows the system to support multiple authentication
    backends without changing the core authentication logic.
    
    Design Pattern: Strategy Pattern
    Benefits:
    - Easy to swap authentication methods
    - Test with mock providers
    - Support multiple auth types
    - Future-proof architecture
    """
    
    @abstractmethod
    def authenticate(
        self,
        username: str,
        credentials: Dict[str, str]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticate a user with provided credentials
        
        Args:
            username: User identifier
            credentials: Authentication credentials (varies by provider)
                        For password auth: {"password": "..."}
                        For OAuth: {"code": "...", "redirect_uri": "..."}
        
        Returns:
            Tuple of (success, user_id, error_message)
            - success: True if authentication succeeded
            - user_id: User identifier if successful, None otherwise
            - error_message: Error description if failed, None otherwise
        
        Example:
            success, user_id, error = provider.authenticate(
                "alice",
                {"password": "secret123"}
            )
            
            if success:
                print(f"User {user_id} authenticated")
            else:
                print(f"Authentication failed: {error}")
        """
        pass
    
    @abstractmethod
    def verify_mfa(
        self,
        user_id: str,
        mfa_token: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify multi-factor authentication token
        
        Args:
            user_id: User identifier
            mfa_token: MFA token (TOTP code, SMS code, etc.)
        
        Returns:
            Tuple of (success, error_message)
            - success: True if MFA verification succeeded
            - error_message: Error description if failed, None otherwise
        
        Note:
            This method is only called if supports_mfa() returns True
        
        Example:
            success, error = provider.verify_mfa("alice", "123456")
            if success:
                print("MFA verified")
        """
        pass
    
    @abstractmethod
    def supports_mfa(self) -> bool:
        """
        Check if this provider supports multi-factor authentication
        
        Returns:
            True if MFA is supported, False otherwise
        
        Example:
            if provider.supports_mfa():
                # Prompt for MFA token
                mfa_token = input("Enter MFA code: ")
                provider.verify_mfa(user_id, mfa_token)
        """
        pass
    
    @abstractmethod
    def create_user(
        self,
        username: str,
        credentials: Dict[str, str],
        user_data: Optional[Dict] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Create a new user account
        
        Args:
            username: Desired username
            credentials: Initial credentials (e.g., password)
            user_data: Additional user data (email, name, etc.)
        
        Returns:
            Tuple of (success, user_id, error_message)
        
        Note:
            Not all providers support user creation (e.g., OAuth providers)
            Check can_create_users() first
        """
        pass
    
    @abstractmethod
    def can_create_users(self) -> bool:
        """
        Check if this provider allows creating users
        
        Returns:
            True if user creation is supported
        
        Note:
            SimpleAuthProvider: True (manages its own users)
            OAuth providers: False (users managed externally)
        """
        pass
    
    @abstractmethod
    def get_user_info(self, user_id: str) -> Optional[Dict]:
        """
        Get user information
        
        Args:
            user_id: User identifier
        
        Returns:
            Dictionary with user info, or None if user not found
            
        Common fields:
            - username: User's username
            - email: User's email
            - name: User's full name
            - roles: List of assigned roles
            - created_at: Account creation timestamp
        """
        pass
    
    @abstractmethod
    def provider_name(self) -> str:
        """
        Get the name of this authentication provider
        
        Returns:
            Provider name (e.g., "SimpleAuth", "Auth0", "Okta")
        
        Example:
            print(f"Using {provider.provider_name()} for authentication")
        """
        pass


class AuthenticationError(Exception):
    """
    Base exception for authentication errors
    
    Usage:
        raise AuthenticationError("Invalid credentials")
    """
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when provided credentials are invalid"""
    pass


class UserNotFoundError(AuthenticationError):
    """Raised when user does not exist"""
    pass


class MFARequiredError(AuthenticationError):
    """Raised when MFA is required but not provided"""
    pass


class MFAVerificationError(AuthenticationError):
    """Raised when MFA verification fails"""
    pass


class RateLimitError(AuthenticationError):
    """Raised when rate limit is exceeded"""
    pass


# Type hints for better IDE support
AuthResult = Tuple[bool, Optional[str], Optional[str]]
MFAResult = Tuple[bool, Optional[str]]