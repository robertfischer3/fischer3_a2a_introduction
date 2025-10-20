"""
Secure Agent Card Model
Implements the secure agent card with context-aware serialization
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime

from .constants import SecurityLevel, CapabilityClass


@dataclass
class SecureAgentCard:
    """
    Secure Agent Card with built-in security features
    
    This card implements context-aware serialization, exposing different
    levels of information based on the security context of the request.
    """
    
    # Core identity fields
    agent_id: str
    name: str
    version: str
    description: str
    
    # Security fields
    public_key: str
    certificate_fingerprint: str
    issued_at: str
    expires_at: str
    issuer: str
    
    # Capabilities with classification
    capabilities: Dict[str, List[str]]  # {capability_class: [specific_capabilities]}
    
    # Metadata with security constraints
    metadata: Dict[str, Any]
    
    # Security metadata
    security_level: SecurityLevel
    allowed_domains: List[str]
    rate_limits: Dict[str, int]
    
    # Card signature
    signature: Optional[str] = None
    
    def to_dict(self, security_context: SecurityLevel = SecurityLevel.PUBLIC) -> Dict:
        """
        Convert to dictionary based on security context
        
        Args:
            security_context: The security level of the requesting party
            
        Returns:
            Dictionary with appropriate fields based on security context
        """
        if security_context == SecurityLevel.PUBLIC:
            # Return minimal public information
            return {
                "agent_id": self.agent_id,
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "capabilities": self._get_public_capabilities(),
                "expires_at": self.expires_at,
                "signature": self.signature
            }
        elif security_context == SecurityLevel.TRUSTED:
            # Include additional information for trusted partners
            return {
                "agent_id": self.agent_id,
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "public_key": self.public_key,
                "certificate_fingerprint": self.certificate_fingerprint,
                "capabilities": self.capabilities,
                "metadata": self._get_sanitized_metadata(),
                "expires_at": self.expires_at,
                "rate_limits": self.rate_limits,
                "signature": self.signature
            }
        else:
            # Full card for internal use
            return asdict(self)
    
    def _get_public_capabilities(self) -> List[str]:
        """
        Extract only public-safe capabilities
        
        Returns:
            List of capabilities safe for public exposure
        """
        public_caps = []
        for cap_class, caps in self.capabilities.items():
            # Only expose read-only and streaming capabilities publicly
            if cap_class in [CapabilityClass.READ_ONLY.value, CapabilityClass.STREAM.value]:
                public_caps.extend(caps)
        return public_caps
    
    def _get_sanitized_metadata(self) -> Dict:
        """
        Remove sensitive metadata fields
        
        Returns:
            Metadata dictionary with sensitive fields removed
        """
        from .constants import SUSPICIOUS_KEY_PATTERNS
        
        sanitized = {}
        
        for key, value in self.metadata.items():
            # Check if key contains any suspicious patterns
            if not any(pattern in key.lower() for pattern in SUSPICIOUS_KEY_PATTERNS):
                sanitized[key] = value
        
        return sanitized
    
    def is_expired(self) -> bool:
        """
        Check if the card has expired
        
        Returns:
            True if card is expired, False otherwise
        """
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.utcnow() > expires
        except (ValueError, AttributeError):
            # If we can't parse the date, consider it expired for safety
            return True
    
    def get_capability_classes(self) -> List[str]:
        """
        Get list of capability classes this agent supports
        
        Returns:
            List of capability class names
        """
        return list(self.capabilities.keys())
    
    def has_capability(self, capability: str) -> bool:
        """
        Check if agent has a specific capability
        
        Args:
            capability: The capability to check for
            
        Returns:
            True if agent has the capability, False otherwise
        """
        for caps in self.capabilities.values():
            if capability in caps:
                return True
        return False
    
    def __repr__(self) -> str:
        """String representation of the agent card"""
        return (
            f"SecureAgentCard(id={self.agent_id}, "
            f"name={self.name}, "
            f"version={self.version}, "
            f"expires={self.expires_at})"
        )