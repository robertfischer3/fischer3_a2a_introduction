"""
Security Module for Agent2Agent Protocol
Provides secure Agent Card implementation with comprehensive security features
"""

from .constants import (
    SecurityLevel,
    CapabilityClass,
    TRUSTED_ISSUERS,
    CAPABILITY_WHITELIST,
    DEFAULT_CARD_EXPIRY_DAYS,
    DEFAULT_REPUTATION_SCORE,
    BLOCK_REPUTATION_THRESHOLD
)

from .secure_agent_card import SecureAgentCard
from .validator import AgentCardValidator
from .manager import SecureAgentCardManager
from .audit_logger import (
    SecurityAuditLogger,
    SecurityEventType,
    SecuritySeverity
)

__all__ = [
    # Core classes
    'SecureAgentCard',
    'AgentCardValidator',
    'SecureAgentCardManager',
    'SecurityAuditLogger',
    
    # Enums
    'SecurityLevel',
    'CapabilityClass',
    'SecurityEventType',
    'SecuritySeverity',
    
    # Constants
    'TRUSTED_ISSUERS',
    'CAPABILITY_WHITELIST',
    'DEFAULT_CARD_EXPIRY_DAYS',
    'DEFAULT_REPUTATION_SCORE',
    'BLOCK_REPUTATION_THRESHOLD'
]

# Version info
__version__ = '1.0.0'
__author__ = 'Robert Fischer'