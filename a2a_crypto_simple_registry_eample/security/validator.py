"""
Agent Card Validator
Validates Agent Cards against security policies
"""

import hashlib
import hmac
import json
import time
from typing import List, Set, Dict, Tuple
from datetime import datetime

from .secure_agent_card import SecureAgentCard
from .constants import (
    TRUSTED_ISSUERS,
    CAPABILITY_WHITELIST,
    MAX_VALIDATION_ATTEMPTS_PER_MINUTE,
    SUSPICIOUS_KEY_PATTERNS,
    INJECTION_PATTERNS
)


class AgentCardValidator:
    """
    Validates Agent Cards against security policies
    
    This validator performs comprehensive security checks including
    signature verification, capability validation, and injection detection.
    """
    
    def __init__(self):
        """Initialize the validator with security configurations"""
        self.revoked_certificates: Set[str] = set()
        self.trusted_issuers: List[str] = TRUSTED_ISSUERS.copy()
        self.capability_whitelist: Set[str] = CAPABILITY_WHITELIST.copy()
        
        # Track validation attempts for rate limiting
        self.validation_attempts: Dict[str, List[float]] = {}
        self.max_attempts_per_minute = MAX_VALIDATION_ATTEMPTS_PER_MINUTE
        
        # Custom validators can be added
        self.custom_validators = []
    
    def validate_card(self, card: SecureAgentCard) -> Tuple[bool, List[str]]:
        """
        Comprehensive validation of agent card
        
        Args:
            card: The SecureAgentCard to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # 1. Check expiration
        if not self._check_expiration(card):
            issues.append("Card expired")
        
        # 2. Verify signature
        if not self._verify_signature(card):
            issues.append("Invalid signature")
        
        # 3. Check certificate status
        if card.certificate_fingerprint in self.revoked_certificates:
            issues.append("Certificate revoked")
        
        # 4. Validate issuer
        if card.issuer not in self.trusted_issuers:
            issues.append(f"Untrusted issuer: {card.issuer}")
        
        # 5. Validate capabilities
        invalid_caps = self._validate_capabilities(card)
        if invalid_caps:
            issues.append(f"Invalid capabilities: {invalid_caps}")
        
        # 6. Check rate limiting on validation attempts
        if not self._check_validation_rate_limit(card.agent_id):
            issues.append("Validation rate limit exceeded")
        
        # 7. Validate metadata structure
        metadata_issues = self._validate_metadata(card)
        if metadata_issues:
            issues.extend(metadata_issues)
        
        # 8. Run custom validators
        for validator in self.custom_validators:
            custom_issues = validator(card)
            if custom_issues:
                issues.extend(custom_issues)
        
        return len(issues) == 0, issues
    
    def _check_expiration(self, card: SecureAgentCard) -> bool:
        """
        Check if card is expired
        
        Args:
            card: The card to check
            
        Returns:
            True if card is valid (not expired), False otherwise
        """
        return not card.is_expired()
    
    def _verify_signature(self, card: SecureAgentCard) -> bool:
        """
        Verify card signature (simplified for demo)
        
        In production, use proper cryptographic verification with
        the actual public key and a real signature algorithm.
        
        Args:
            card: The card to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not card.signature:
            return False
        
        # Create canonical representation of card data
        card_data = json.dumps({
            "agent_id": card.agent_id,
            "name": card.name,
            "version": card.version,
            "capabilities": card.capabilities
        }, sort_keys=True)
        
        # In production, use proper cryptographic verification
        # This is a simplified demonstration
        expected_signature = hashlib.sha256(
            f"{card_data}{card.public_key}".encode()
        ).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(card.signature[:64], expected_signature)
    
    def _validate_capabilities(self, card: SecureAgentCard) -> List[str]:
        """
        Check capabilities against whitelist
        
        Args:
            card: The card to validate
            
        Returns:
            List of invalid capabilities
        """
        invalid = []
        for cap_class, capabilities in card.capabilities.items():
            for capability in capabilities:
                if capability not in self.capability_whitelist:
                    invalid.append(capability)
        return invalid
    
    def _check_validation_rate_limit(self, agent_id: str) -> bool:
        """
        Check if agent is within validation rate limits
        
        Args:
            agent_id: The agent ID to check
            
        Returns:
            True if within limits, False if rate limit exceeded
        """
        current_time = time.time()
        window_start = current_time - 60  # 1 minute window
        
        if agent_id not in self.validation_attempts:
            self.validation_attempts[agent_id] = []
        
        # Clean old attempts outside the window
        self.validation_attempts[agent_id] = [
            t for t in self.validation_attempts[agent_id] if t > window_start
        ]
        
        # Check if we're at the limit
        if len(self.validation_attempts[agent_id]) >= self.max_attempts_per_minute:
            return False
        
        # Record this attempt
        self.validation_attempts[agent_id].append(current_time)
        return True
    
    def _validate_metadata(self, card: SecureAgentCard) -> List[str]:
        """
        Validate metadata doesn't contain dangerous content
        
        Args:
            card: The card to validate
            
        Returns:
            List of validation issues found
        """
        issues = []
        
        if not isinstance(card.metadata, dict):
            issues.append("Metadata must be a dictionary")
            return issues
        
        # Check for suspicious keys
        for key in card.metadata.keys():
            if any(pattern in key.lower() for pattern in SUSPICIOUS_KEY_PATTERNS):
                issues.append(f"Suspicious metadata key: {key}")
        
        # Check for injection attempts in values
        for key, value in card.metadata.items():
            if isinstance(value, str):
                if self._contains_injection_attempt(value):
                    issues.append(f"Potential injection in metadata field '{key}'")
        
        return issues
    
    def _contains_injection_attempt(self, value: str) -> bool:
        """
        Check for common injection patterns
        
        Args:
            value: The string value to check
            
        Returns:
            True if injection patterns detected, False otherwise
        """
        value_lower = value.lower()
        return any(pattern.lower() in value_lower for pattern in INJECTION_PATTERNS)
    
    def add_revoked_certificate(self, fingerprint: str):
        """
        Add a certificate to the revocation list
        
        Args:
            fingerprint: The certificate fingerprint to revoke
        """
        self.revoked_certificates.add(fingerprint)
    
    def add_trusted_issuer(self, issuer: str):
        """
        Add a trusted certificate issuer
        
        Args:
            issuer: The issuer identifier to trust
        """
        self.trusted_issuers.append(issuer)
    
    def add_custom_validator(self, validator_func):
        """
        Add a custom validation function
        
        Args:
            validator_func: Function that takes a SecureAgentCard and returns list of issues
        """
        self.custom_validators.append(validator_func)
    
    def clear_validation_history(self, agent_id: str = None):
        """
        Clear validation attempt history
        
        Args:
            agent_id: Specific agent to clear, or None to clear all
        """
        if agent_id:
            self.validation_attempts.pop(agent_id, None)
        else:
            self.validation_attempts.clear()