"""
Secure Agent Card Manager
Manages secure creation, storage, and exchange of Agent Cards
"""

import base64
import hashlib
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any

from .secure_agent_card import SecureAgentCard
from .validator import AgentCardValidator
from .constants import (
    SecurityLevel,
    CapabilityClass,
    DEFAULT_TOKEN_BYTES,
    DEFAULT_NONCE_EXPIRY_SECONDS,
    DEFAULT_CARD_EXPIRY_DAYS,
    DEFAULT_REPUTATION_SCORE,
    MIN_REPUTATION_SCORE,
    MAX_REPUTATION_SCORE,
    BLOCK_REPUTATION_THRESHOLD,
    TRUSTED_ISSUERS
)


class SecureAgentCardManager:
    """
    Manages secure creation, storage, and exchange of Agent Cards
    
    This manager handles the full lifecycle of agent cards including
    creation, validation, exchange, and reputation tracking.
    """
    
    def __init__(self, agent_id: str):
        """
        Initialize the manager for a specific agent
        
        Args:
            agent_id: The ID of the local agent using this manager
        """
        self.agent_id = agent_id
        self.validator = AgentCardValidator()
        self.card_cache: Dict[str, Dict[str, Any]] = {}
        self.reputation_scores: Dict[str, int] = {}
        
        # Nonce tracking for replay protection
        self.used_nonces = set()
        self.nonce_expiry: Dict[str, float] = {}  # nonce -> expiry_time
        
        # Local card storage
        self.local_card: Optional[SecureAgentCard] = None
    
    def create_secure_card(
        self,
        name: str,
        version: str,
        description: str,
        capabilities: Dict[str, list],
        metadata: Dict[str, Any],
        security_level: SecurityLevel = SecurityLevel.TRUSTED,
        allowed_domains: list = None,
        rate_limits: Dict[str, int] = None,
        expires_in_days: int = DEFAULT_CARD_EXPIRY_DAYS
    ) -> SecureAgentCard:
        """
        Create a new secure agent card
        
        Args:
            name: Agent name
            version: Agent version (semantic versioning recommended)
            description: Human-readable description
            capabilities: Dictionary of capability classes to capability lists
            metadata: Additional metadata
            security_level: Security level for this card
            allowed_domains: List of allowed domains for this agent
            rate_limits: Rate limiting configuration
            expires_in_days: Days until card expiration
            
        Returns:
            A new SecureAgentCard instance
        """
        
        # Generate secure random values
        agent_id = str(uuid.uuid4())
        public_key = base64.b64encode(secrets.token_bytes(DEFAULT_TOKEN_BYTES)).decode()
        
        # Create certificate fingerprint (simplified for demo)
        cert_data = f"{agent_id}{public_key}{datetime.utcnow().isoformat()}"
        certificate_fingerprint = hashlib.sha256(cert_data.encode()).hexdigest()
        
        # Set expiration
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(days=expires_in_days)
        
        # Set defaults
        if allowed_domains is None:
            allowed_domains = ["*.example.com"]
        if rate_limits is None:
            rate_limits = {"requests_per_minute": 100, "burst_size": 20}
        
        # Create the card
        card = SecureAgentCard(
            agent_id=agent_id,
            name=name,
            version=version,
            description=description,
            public_key=public_key,
            certificate_fingerprint=certificate_fingerprint,
            issued_at=issued_at.isoformat(),
            expires_at=expires_at.isoformat(),
            issuer=TRUSTED_ISSUERS[0],  # Use first trusted issuer as default
            capabilities=capabilities,
            metadata=metadata,
            security_level=security_level,
            allowed_domains=allowed_domains,
            rate_limits=rate_limits
        )
        
        # Sign the card
        card.signature = self._sign_card(card)
        
        # Store as local card
        self.local_card = card
        
        return card
    
    def _sign_card(self, card: SecureAgentCard) -> str:
        """
        Sign the agent card (simplified for demo)
        
        In production, use proper cryptographic signing with private key.
        
        Args:
            card: The card to sign
            
        Returns:
            Signature string
        """
        card_data = json.dumps({
            "agent_id": card.agent_id,
            "name": card.name,
            "version": card.version,
            "capabilities": card.capabilities
        }, sort_keys=True)
        
        signature = hashlib.sha256(
            f"{card_data}{card.public_key}".encode()
        ).hexdigest()
        
        return signature
    
    def exchange_cards(
        self,
        local_card: SecureAgentCard,
        remote_card_data: Dict,
        nonce: str
    ) -> Tuple[bool, Optional[SecureAgentCard], str]:
        """
        Securely exchange agent cards
        
        Args:
            local_card: The local agent's card
            remote_card_data: The remote agent's card data
            nonce: Nonce for replay protection
            
        Returns:
            Tuple of (success, remote_card, message)
        """
        
        # Check replay attack
        if not self._verify_nonce(nonce):
            return False, None, "Invalid or reused nonce"
        
        # Parse remote card
        try:
            remote_card = self._parse_remote_card(remote_card_data)
        except Exception as e:
            return False, None, f"Failed to parse remote card: {e}"
        
        # Validate remote card
        is_valid, issues = self.validator.validate_card(remote_card)
        if not is_valid:
            self._update_reputation(remote_card.agent_id, -10)
            return False, None, f"Card validation failed: {', '.join(issues)}"
        
        # Check if agent is blocked
        if self._is_agent_blocked(remote_card.agent_id):
            return False, None, "Agent is blocked due to low reputation"
        
        # Update reputation positively for successful exchange
        self._update_reputation(remote_card.agent_id, 1)
        
        # Cache the validated card
        self.card_cache[remote_card.agent_id] = {
            "card": remote_card,
            "validated_at": datetime.utcnow(),
            "trust_level": self._calculate_trust_level(remote_card)
        }
        
        return True, remote_card, "Card exchange successful"
    
    def _verify_nonce(self, nonce: str) -> bool:
        """
        Verify nonce for replay protection
        
        Args:
            nonce: The nonce to verify
            
        Returns:
            True if nonce is valid and unused, False otherwise
        """
        current_time = time.time()
        
        # Clean expired nonces
        expired = [n for n, exp in self.nonce_expiry.items() if exp < current_time]
        for n in expired:
            self.used_nonces.discard(n)
            del self.nonce_expiry[n]
        
        # Check if nonce is already used
        if nonce in self.used_nonces:
            return False
        
        # Add nonce with expiry
        self.used_nonces.add(nonce)
        self.nonce_expiry[nonce] = current_time + DEFAULT_NONCE_EXPIRY_SECONDS
        
        return True
    
    def _parse_remote_card(self, card_data: Dict) -> SecureAgentCard:
        """
        Parse and sanitize remote card data
        
        Args:
            card_data: Raw card data from remote agent
            
        Returns:
            Parsed SecureAgentCard instance
        """
        # Sanitize strings to prevent injection
        for key in ["name", "description", "agent_id"]:
            if key in card_data and isinstance(card_data[key], str):
                # Remove potentially dangerous characters
                card_data[key] = "".join(
                    c for c in card_data[key] 
                    if c.isalnum() or c in "-_. "
                )[:100]  # Limit length
        
        # Ensure required fields with defaults
        return SecureAgentCard(
            agent_id=card_data.get("agent_id", "unknown"),
            name=card_data.get("name", "Unknown Agent"),
            version=card_data.get("version", "0.0.0"),
            description=card_data.get("description", ""),
            public_key=card_data.get("public_key", ""),
            certificate_fingerprint=card_data.get("certificate_fingerprint", ""),
            issued_at=card_data.get("issued_at", datetime.utcnow().isoformat()),
            expires_at=card_data.get("expires_at", datetime.utcnow().isoformat()),
            issuer=card_data.get("issuer", "unknown"),
            capabilities=card_data.get("capabilities", {}),
            metadata=card_data.get("metadata", {}),
            security_level=SecurityLevel.PUBLIC,
            allowed_domains=card_data.get("allowed_domains", []),
            rate_limits=card_data.get("rate_limits", {}),
            signature=card_data.get("signature")
        )
    
    def _update_reputation(self, agent_id: str, delta: int):
        """
        Update agent reputation score
        
        Args:
            agent_id: The agent to update
            delta: Change in reputation (positive or negative)
        """
        current = self.reputation_scores.get(agent_id, DEFAULT_REPUTATION_SCORE)
        new_score = max(MIN_REPUTATION_SCORE, min(MAX_REPUTATION_SCORE, current + delta))
        self.reputation_scores[agent_id] = new_score
    
    def _is_agent_blocked(self, agent_id: str) -> bool:
        """
        Check if agent is blocked based on reputation
        
        Args:
            agent_id: The agent to check
            
        Returns:
            True if agent should be blocked, False otherwise
        """
        reputation = self.reputation_scores.get(agent_id, DEFAULT_REPUTATION_SCORE)
        return reputation < BLOCK_REPUTATION_THRESHOLD
    
    def _calculate_trust_level(self, card: SecureAgentCard) -> str:
        """
        Calculate trust level for an agent
        
        Args:
            card: The agent's card
            
        Returns:
            Trust level string: "HIGH", "MEDIUM", or "LOW"
        """
        reputation = self.reputation_scores.get(card.agent_id, DEFAULT_REPUTATION_SCORE)
        
        if card.issuer in self.validator.trusted_issuers and reputation > 80:
            return "HIGH"
        elif reputation > 50:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_cached_card(self, agent_id: str) -> Optional[SecureAgentCard]:
        """
        Get a cached agent card
        
        Args:
            agent_id: The agent ID to look up
            
        Returns:
            The cached card or None if not found
        """
        cached = self.card_cache.get(agent_id)
        if cached:
            return cached["card"]
        return None
    
    def get_agent_reputation(self, agent_id: str) -> int:
        """
        Get the current reputation score for an agent
        
        Args:
            agent_id: The agent to check
            
        Returns:
            Reputation score (0-100)
        """
        return self.reputation_scores.get(agent_id, DEFAULT_REPUTATION_SCORE)
    
    def clear_cache(self):
        """Clear all cached cards"""
        self.card_cache.clear()
    
    def generate_nonce(self) -> str:
        """
        Generate a secure nonce for message exchange
        
        Returns:
            Hex string nonce
        """
        return secrets.token_hex(16)