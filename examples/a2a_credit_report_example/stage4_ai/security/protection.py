"""
Rate Limiting and PII Protection - Stage 3 (Production Security)

Includes:
- Token bucket rate limiting
- PII sanitization and encryption
- Audit logging helpers
"""

import time
import hashlib
import copy
from datetime import datetime
from typing import Dict, Any, Optional


class RateLimiter:
    """
    Token bucket rate limiting
    
    Prevents DoS attacks by limiting request rate per agent.
    Each agent gets a bucket of tokens that refills over time.
    """
    
    def __init__(self, max_tokens: int = 100, refill_rate: int = 10):
        """
        Initialize rate limiter
        
        Args:
            max_tokens: Maximum tokens in bucket
            refill_rate: Tokens added per minute
        """
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per minute
        self.buckets: Dict[str, Dict[str, Any]] = {}
    
    def check_rate_limit(self, agent_id: str, cost: int = 1) -> bool:
        """
        Check if agent can perform action
        
        Args:
            agent_id: Agent making request
            cost: Token cost of action (default 1)
        
        Returns:
            True if allowed, False if rate limited
        
        Raises:
            RateLimitError if rate limit exceeded
        """
        bucket = self._get_bucket(agent_id)
        
        # Check if enough tokens
        if bucket["tokens"] < cost:
            raise RateLimitError(
                f"Rate limit exceeded for {agent_id}. "
                f"Current tokens: {bucket['tokens']:.1f}, required: {cost}"
            )
        
        # Consume tokens
        bucket["tokens"] -= cost
        return True
    
    def _get_bucket(self, agent_id: str) -> Dict[str, Any]:
        """Get or create token bucket for agent"""
        if agent_id not in self.buckets:
            self.buckets[agent_id] = {
                "tokens": float(self.max_tokens),
                "last_refill": time.time()
            }
        
        # Refill tokens based on time elapsed
        bucket = self.buckets[agent_id]
        now = time.time()
        elapsed = now - bucket["last_refill"]
        
        # Calculate tokens to add
        tokens_to_add = (elapsed / 60.0) * self.refill_rate
        
        # Add tokens (up to max)
        bucket["tokens"] = min(
            self.max_tokens,
            bucket["tokens"] + tokens_to_add
        )
        bucket["last_refill"] = now
        
        return bucket
    
    def get_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current rate limit status for agent"""
        bucket = self._get_bucket(agent_id)
        return {
            "agent_id": agent_id,
            "current_tokens": round(bucket["tokens"], 2),
            "max_tokens": self.max_tokens,
            "refill_rate": self.refill_rate
        }


class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    pass


class PIISanitizer:
    """
    PII sanitization and protection
    
    Handles:
    - SSN masking
    - Name hashing
    - Address redaction
    - DOB protection
    """
    
    @staticmethod
    def sanitize_for_logging(report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove all PII from report for safe logging
        
        Returns sanitized copy (original unchanged)
        """
        safe = copy.deepcopy(report)
        
        if "subject" in safe:
            subject = safe["subject"]
            
            # Mask SSN (show last 4 only)
            if "ssn" in subject:
                ssn = subject["ssn"]
                if len(ssn) >= 4:
                    subject["ssn"] = f"***-**-{ssn[-4:]}"
                else:
                    subject["ssn"] = "***"
            
            # Hash name (one-way, for correlation)
            if "name" in subject:
                name_hash = hashlib.sha256(
                    subject["name"].encode()
                ).hexdigest()[:8]
                subject["name"] = f"PERSON_{name_hash}"
            
            # Redact address
            if "address" in subject:
                subject["address"] = "[REDACTED]"
            
            # Redact DOB
            if "dob" in subject:
                subject["dob"] = "[REDACTED]"
            
            # Redact email
            if "email" in subject:
                subject["email"] = "[REDACTED]"
            
            # Redact phone
            if "phone" in subject:
                subject["phone"] = "[REDACTED]"
        
        return safe
    
    @staticmethod
    def sanitize_for_response(report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize report for client response
        
        Less aggressive than logging (clients need some data)
        """
        safe = copy.deepcopy(report)
        
        if "subject" in safe:
            subject = safe["subject"]
            
            # Mask SSN
            if "ssn" in subject:
                ssn = subject["ssn"]
                if len(ssn) >= 4:
                    subject["ssn"] = f"***-**-{ssn[-4:]}"
                else:
                    subject["ssn"] = "***"
            
            # Keep name but sanitize
            # Keep other fields as needed for business logic
        
        return safe
    
    @staticmethod
    def encrypt_pii(report: Dict[str, Any], encryption_key: str) -> Dict[str, Any]:
        """
        Encrypt PII fields for storage
        
        In production, use proper encryption library:
        - Fernet (symmetric)
        - AES-256-GCM
        - Age encryption
        
        This is a simplified demo.
        """
        encrypted = copy.deepcopy(report)
        
        if "subject" in encrypted:
            subject = encrypted["subject"]
            
            # In production: use actual encryption
            # For demo: mark as encrypted
            if "ssn" in subject:
                subject["ssn"] = f"[ENCRYPTED:{hashlib.sha256(subject['ssn'].encode()).hexdigest()[:16]}]"
            
            if "address" in subject:
                subject["address"] = f"[ENCRYPTED:{hashlib.sha256(subject['address'].encode()).hexdigest()[:16]}]"
        
        return encrypted


class AuditLogger:
    """
    Structured audit logging
    
    Logs security-relevant events with:
    - Timestamp
    - Event type
    - Agent ID
    - Action
    - Result
    - Context
    """
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file
    
    def log_event(self, event_type: str, agent_id: str, 
                  action: str, result: str, **kwargs):
        """
        Log security event
        
        Args:
            event_type: Category (auth, upload, access, etc.)
            agent_id: Who performed action
            action: What was done
            result: success/failure/error
            **kwargs: Additional context
        """
        import json
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_type": event_type,
            "agent_id": agent_id,
            "action": action,
            "result": result,
            **kwargs
        }
        
        # In production: use structured logging library
        # (structlog, python-json-logger, etc.)
        log_line = json.dumps(log_entry)
        
        # Print to console
        print(f"📋 AUDIT: {log_line}")
        
        # Write to file if configured
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(log_line + '\n')
    
    def log_authentication(self, agent_id: str, success: bool, reason: str = ""):
        """Log authentication attempt"""
        self.log_event(
            event_type="authentication",
            agent_id=agent_id,
            action="authenticate",
            result="success" if success else "failure",
            reason=reason
        )
    
    def log_file_upload(self, agent_id: str, filename: str, 
                       size: int, success: bool):
        """Log file upload attempt"""
        self.log_event(
            event_type="file_upload",
            agent_id=agent_id,
            action="upload",
            result="success" if success else "failure",
            filename=filename,
            size=size
        )
    
    def log_rate_limit(self, agent_id: str, action: str):
        """Log rate limit exceeded"""
        self.log_event(
            event_type="rate_limit",
            agent_id=agent_id,
            action=action,
            result="blocked",
            severity="MEDIUM"
        )
    
    def log_authorization_failure(self, agent_id: str, action: str, reason: str):
        """Log authorization failure"""
        self.log_event(
            event_type="authorization",
            agent_id=agent_id,
            action=action,
            result="denied",
            reason=reason,
            severity="HIGH"
        )
    
    def log_validation_error(self, agent_id: str, error_type: str, details: str):
        """Log validation error"""
        self.log_event(
            event_type="validation",
            agent_id=agent_id,
            action="validate",
            result="error",
            error_type=error_type,
            details=details
        )


class AuthorizationManager:
    """
    Role-Based Access Control (RBAC)
    
    Defines roles and their permissions
    """
    
    ROLES = {
        "analyst": {
            "permissions": [
                "upload_report",
                "view_report",
                "analyze_report",
                "list_reports"
            ],
            "description": "Can upload and analyze reports"
        },
        "admin": {
            "permissions": [
                "upload_report",
                "view_report",
                "analyze_report",
                "list_reports",
                "delete_report",
                "manage_users",
                "view_audit_logs"
            ],
            "description": "Full system access"
        },
        "auditor": {
            "permissions": [
                "view_report",
                "list_reports",
                "view_audit_logs"
            ],
            "description": "Read-only access with audit logs"
        },
        "viewer": {
            "permissions": [
                "view_report",
                "list_reports"
            ],
            "description": "Read-only access"
        }
    }
    
    def __init__(self):
        self.agent_roles: Dict[str, str] = {}
    
    def assign_role(self, agent_id: str, role: str):
        """Assign role to agent"""
        if role not in self.ROLES:
            raise ValueError(f"Unknown role: {role}")
        self.agent_roles[agent_id] = role
        print(f"✅ Assigned role '{role}' to {agent_id}")
    
    def authorize(self, agent_id: str, action: str) -> bool:
        """
        Check if agent is authorized for action
        
        Returns True if authorized
        Raises AuthorizationError if not
        """
        # Get agent's role
        role = self.agent_roles.get(agent_id)
        if not role:
            raise AuthorizationError(f"No role assigned to {agent_id}")
        
        # Get role's permissions
        permissions = self.ROLES.get(role, {}).get("permissions", [])
        
        # Check permission
        if action not in permissions:
            raise AuthorizationError(
                f"Role '{role}' not authorized for action '{action}'"
            )
        
        return True
    
    def get_agent_permissions(self, agent_id: str) -> list[str]:
        """Get list of permissions for agent"""
        role = self.agent_roles.get(agent_id)
        if not role:
            return []
        return self.ROLES.get(role, {}).get("permissions", [])


class AuthorizationError(Exception):
    """Raised when authorization fails"""
    pass
