"""
Security Package - Stage 2

Provides pluggable authentication and session management.

Modules:
- auth_provider: Abstract interface for authentication providers
- simple_auth_provider: Password-based authentication (learning only)
- auth_manager: Coordinates authentication process
- session_manager: Session management (to be implemented next)

Usage:
    from security import AuthManager, SimpleAuthProvider
    
    provider = SimpleAuthProvider("config/users.json")
    auth_manager = AuthManager(provider)
    
    success, session, error = auth_manager.login("alice", "password123")
"""

from .auth_provider import (
    AuthProvider,
    AuthenticationError,
    InvalidCredentialsError,
    UserNotFoundError,
    MFARequiredError,
    MFAVerificationError,
    RateLimitError,
    AuthResult,
    MFAResult
)

from .simple_auth_provider import (
    SimpleAuthProvider,
    create_default_users
)

from .auth_manager import AuthManager
from .session_manager import SessionManager

__all__ = [
    # Interfaces
    'AuthProvider',
    
    # Providers
    'SimpleAuthProvider',
    'create_default_users',
    
    # Managers
    'AuthManager',
    'SessionManager',
    
    # Exceptions
    'AuthenticationError',
    'InvalidCredentialsError',
    'UserNotFoundError',
    'MFARequiredError',
    'MFAVerificationError',
    'RateLimitError',
    
    # Type hints
    'AuthResult',
    'MFAResult'
]

__version__ = '2.0.0'  # Stage 2