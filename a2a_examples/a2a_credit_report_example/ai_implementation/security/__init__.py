"""
Security Module - Stage 3 (Production Security)

Comprehensive security controls for credit report agent:
- Strong authentication (RSA-style with nonce)
- 8-layer input validation
- Rate limiting (token bucket)
- RBAC authorization
- PII sanitization
- Audit logging
"""

from .authentication import (
    AuthenticationManager,
    AuthenticationError,
    create_auth_tag,
    generate_demo_keypair
)

from .validation import (
    FileValidator,
    ReportValidator,
    InputSanitizer,
    ValidationError
)

from .protection import (
    RateLimiter,
    RateLimitError,
    PIISanitizer,
    AuditLogger,
    AuthorizationManager,
    AuthorizationError
)

__all__ = [
    # Authentication
    'AuthenticationManager',
    'AuthenticationError',
    'create_auth_tag',
    'generate_demo_keypair',
    
    # Validation
    'FileValidator',
    'ReportValidator',
    'InputSanitizer',
    'ValidationError',
    
    # Protection
    'RateLimiter',
    'RateLimitError',
    'PIISanitizer',
    'AuditLogger',
    'AuthorizationManager',
    'AuthorizationError',
]
