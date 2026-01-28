"""
Authentication Module - Stage 3

Provides comprehensive authentication with:
- RSA keypair management (key_manager.py)
- Nonce-based replay protection (nonce_validator.py)
- HMAC request signing (request_signer.py)
- JWT RS256 authentication (auth_manager.py)
"""

from .key_manager import KeyManager
from .nonce_validator import NonceValidator
from .request_signer import RequestSigner, SignedRequestBuilder, SignedRequest

# Import auth_manager if it exists
try:
    from .auth_manager import AuthManager
except ImportError:
    AuthManager = None

__all__ = [
    'KeyManager',
    'NonceValidator',
    'RequestSigner',
    'SignedRequestBuilder',
    'SignedRequest',
]

# Add AuthManager if available
if AuthManager is not None:
    __all__.append('AuthManager')

__version__ = '3.0.0'