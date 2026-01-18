"""
Security Enums and Constants
Defines security levels and capability classifications
"""

from enum import Enum


class SecurityLevel(Enum):
    """Security levels for agent interactions"""
    PUBLIC = "public"
    TRUSTED = "trusted"
    INTERNAL = "internal"
    ADMIN = "admin"


class CapabilityClass(Enum):
    """Standardized capability classifications"""
    READ_ONLY = "read_only"
    WRITE = "write"
    STREAM = "stream"
    BATCH = "batch"
    ADMIN = "admin"


# Security constants
DEFAULT_TOKEN_BYTES = 32
DEFAULT_NONCE_EXPIRY_SECONDS = 300  # 5 minutes
DEFAULT_CARD_EXPIRY_DAYS = 90
MAX_VALIDATION_ATTEMPTS_PER_MINUTE = 10
MIN_REPUTATION_SCORE = 0
MAX_REPUTATION_SCORE = 100
DEFAULT_REPUTATION_SCORE = 50
BLOCK_REPUTATION_THRESHOLD = 20

# Trusted certificate authorities
TRUSTED_ISSUERS = [
    "trust-authority-1",
    "trust-authority-2",
    "internal-ca"
]

# Whitelisted capabilities
CAPABILITY_WHITELIST = {
    "price_query",
    "get_status",
    "list_items",
    "process_batch",
    "stream_updates",
    "admin_control",
    "get_price",
    "list_currencies",
    "price_stream",
    "configure_sources"
}

# Suspicious patterns for security scanning
SUSPICIOUS_KEY_PATTERNS = [
    "password",
    "secret",
    "token",
    "private",
    "credentials",
    "api_key",
    "access_key"
]

INJECTION_PATTERNS = [
    "<script",
    "javascript:",
    "onclick=",  # XSS patterns
    "' OR '1'='1",
    "DROP TABLE",  # SQL injection
    "../",
    "file://",
    "\x00",  # Path traversal
    "${",
    "#{",
    "{{",  # Template injection
]