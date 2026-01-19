"""
Message Validation

Stage 2: IMPROVED - Basic input validation

IMPROVEMENTS OVER STAGE 1:
✅ Schema validation on messages
✅ Type checking
✅ Pattern detection for sensitive data
✅ Field whitelisting

REMAINING VULNERABILITIES:
⚠️ Only validates TOP-LEVEL fields
⚠️ No deep nested structure validation
⚠️ Limited content sanitization
⚠️ No semantic validation
⚠️ No size limits on nested data
⚠️ Easily bypassed by nesting data deeper
"""

import re
from typing import Dict, Tuple, Any, Set

class MessageValidator:
    """
    Validates incoming messages
    
    Stage 2: Basic schema and pattern validation
    """
    
    # Maximum sizes for top-level fields
    MAX_STRING_LENGTH = 1000
    MAX_LIST_LENGTH = 100
    
    # Message schemas
    SCHEMAS = {
        "register": {
            "required": ["agent_id", "password"],
            "optional": ["requested_role"],
            "types": {
                "agent_id": str,
                "password": str,
                "requested_role": str
            }
        },
        "login": {
            "required": ["agent_id", "password"],
            "types": {
                "agent_id": str,
                "password": str
            }
        },
        "status_update": {
            "required": ["agent_id", "task_id", "status", "auth_token"],
            "optional": ["progress", "details"],
            "types": {
                "agent_id": str,
                "task_id": str,
                "status": str,
                "auth_token": str,
                "progress": (int, float),
                "details": dict
            }
        },
        "task_complete": {
            "required": ["agent_id", "task_id", "result", "auth_token"],
            "optional": ["metrics"],
            "types": {
                "agent_id": str,
                "task_id": str,
                "result": (str, dict),
                "auth_token": str,
                "metrics": dict
            }
        },
        "task_assignment": {
            "required": ["task_id", "description", "assigned_to", "auth_token"],
            "optional": ["priority"],
            "types": {
                "task_id": str,
                "description": str,
                "assigned_to": str,
                "auth_token": str,
                "priority": str
            }
        }
    }
    
    # Patterns that indicate sensitive data
    SENSITIVE_PATTERNS = [
        (r'password\s*[:=]', 'password'),
        (r'passwd\s*[:=]', 'password'),
        (r'api[_-]?key\s*[:=]', 'api_key'),
        (r'secret\s*[:=]', 'secret'),
        (r'token\s*[:=]', 'token'),
        (r'credential', 'credential'),
        (r'sk_live_[a-zA-Z0-9]+', 'stripe_key'),
        (r'AKIA[A-Z0-9]{16}', 'aws_key'),
        (r'\d{3}-\d{2}-\d{4}', 'ssn'),
        (r'\d{13,19}', 'credit_card'),
    ]
    
    def __init__(self):
        """Initialize validator"""
        self.validation_stats = {
            "total_validated": 0,
            "passed": 0,
            "failed": 0,
            "suspicious_detected": 0
        }
        print(f"✅ MessageValidator initialized")
    
    def validate_message(self, message: Dict) -> Tuple[bool, str]:
        """
        Validate message structure and content
        
        Stage 2: ✅ Validates schema and types
        ⚠️ CRITICAL: Only checks TOP-LEVEL fields
        ⚠️ Nested data (e.g., details.metadata.nested.data) NOT CHECKED
        
        Args:
            message: Message to validate
        
        Returns:
            (is_valid, error_message)
        """
        self.validation_stats["total_validated"] += 1
        
        # Get message type
        msg_type = message.get("type")
        
        if msg_type not in self.SCHEMAS:
            self.validation_stats["failed"] += 1
            return False, f"Unknown message type: {msg_type}"
        
        schema = self.SCHEMAS[msg_type]
        
        # Check required fields
        for field in schema["required"]:
            if field not in message:
                self.validation_stats["failed"] += 1
                return False, f"Missing required field: {field}"
        
        # Check field types
        for field, expected_type in schema["types"].items():
            if field in message:
                if not isinstance(message[field], expected_type):
                    self.validation_stats["failed"] += 1
                    return False, f"Invalid type for {field}: expected {expected_type}"
        
        # ⚠️ VULNERABILITY: Only validates top-level strings
        # Nested dictionaries are NOT recursively validated!
        for key, value in message.items():
            if isinstance(value, str):
                # Check string length
                if len(value) > self.MAX_STRING_LENGTH:
                    self.validation_stats["failed"] += 1
                    return False, f"String too long in {key}"
                
                # Check for sensitive patterns in top-level only
                suspicious = self._check_suspicious_patterns({key: value})
                if suspicious:
                    self.validation_stats["suspicious_detected"] += 1
                    return False, suspicious
        
        # ⚠️ CRITICAL VULNERABILITY: 
        # If message has 'details' dict, we DON'T validate its contents!
        # Attackers can hide data in: details.metadata.nested.deep.stolen_data
        
        self.validation_stats["passed"] += 1
        return True, "Valid"
    
    def _check_suspicious_patterns(self, data: Dict, depth: int = 0) -> str:
        """
        Check for suspicious content patterns
        
        Stage 2: ⚠️ Only checks provided dict (usually top-level)
        ⚠️ NOT called recursively on nested structures
        
        Args:
            data: Dictionary to check
            depth: Current nesting depth (unused in Stage 2)
        
        Returns:
            Error message if suspicious, empty string if OK
        """
        for key, value in data.items():
            if isinstance(value, str):
                # Check key names
                for pattern, pattern_name in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, key, re.IGNORECASE):
                        # Allow certain legitimate fields
                        if key not in ["password", "auth_token", "new_password"]:
                            return f"Suspicious field name: {key} (matches {pattern_name})"
                    
                    # Check values
                    if re.search(pattern, value):
                        return f"Suspicious content in {key} (matches {pattern_name})"
        
        # ⚠️ Stage 2: Doesn't recurse into nested dicts!
        # Stage 3 will add recursive validation
        
        return ""
    
    def sanitize_status_details(self, details: Dict) -> Dict:
        """
        Sanitize status update details field
        
        Stage 2: ✅ Whitelists allowed top-level fields
        ⚠️ CRITICAL: Doesn't recursively sanitize nested dicts
        
        Args:
            details: Details dictionary from status update
        
        Returns:
            Sanitized dictionary (top-level only)
        """
        # Whitelist of allowed top-level fields
        allowed_fields = {
            "message",
            "progress_notes",
            "timestamp",
            "metrics",
            "metadata"  # ⚠️ Allowed but not sanitized!
        }
        
        sanitized = {}
        for field in allowed_fields:
            if field in details:
                # ⚠️ VULNERABILITY: Just copies the value, doesn't validate
                # If it's a dict, that dict's contents are NOT checked!
                sanitized[field] = details[field]
        
        # ⚠️ Example bypass:
        # details = {
        #     "message": "Working...",  # ✅ Allowed
        #     "metadata": {  # ✅ Allowed
        #         "nested": {  # ⚠️ Not checked!
        #             "stolen_data": {...}  # ❌ Malicious content hidden
        #         }
        #     }
        # }
        
        return sanitized
    
    def validate_agent_id(self, agent_id: str) -> Tuple[bool, str]:
        """
        Validate agent ID format
        
        Stage 2: ✅ Basic format checking
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            (is_valid, error_message)
        """
        if not agent_id:
            return False, "Agent ID cannot be empty"
        
        if len(agent_id) > 100:
            return False, "Agent ID too long"
        
        # Check format: alphanumeric, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', agent_id):
            return False, "Agent ID contains invalid characters"
        
        return True, "Valid"
    
    def validate_task_id(self, task_id: str) -> Tuple[bool, str]:
        """
        Validate task ID format
        
        Args:
            task_id: Task identifier
        
        Returns:
            (is_valid, error_message)
        """
        if not task_id:
            return False, "Task ID cannot be empty"
        
        if len(task_id) > 100:
            return False, "Task ID too long"
        
        # Check format
        if not re.match(r'^[a-zA-Z0-9_-]+$', task_id):
            return False, "Task ID contains invalid characters"
        
        return True, "Valid"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.validation_stats.copy()

# Stage 2 Summary:
# 
# ✅ Improvements:
# - Schema validation on all message types
# - Type checking on fields
# - Pattern detection for obvious sensitive data
# - Field whitelisting on status details
# - Basic format validation
# 
# ⚠️ CRITICAL VULNERABILITIES:
# 1. Only validates TOP-LEVEL fields
# 2. Nested dictionaries NOT recursively validated
# 3. Attacker can hide data in: details.metadata.nested.deep.stolen
# 4. No size limits on nested structures
# 5. No semantic validation (doesn't understand context)
# 6. Pattern matching easily bypassed
# 7. No validation of data relationships
# 8. Whitelist approach incomplete
# 
# BYPASS TECHNIQUE (works in Stage 2):
# ```python
# # This passes validation:
# status_update = {
#     "type": "status_update",
#     "task_id": "task-001",
#     "status": "in_progress",  # ✅ Valid
#     "details": {  # ✅ Allowed field
#         "message": "Processing...",  # ✅ Looks innocent
#         "metadata": {  # ✅ Allowed but not deeply checked
#             "technical": {  # ⚠️ Not validated
#                 "debug_info": {  # ⚠️ Not validated
#                     "customer_records": [...],  # ❌ Hidden data
#                     "credentials": {...}  # ❌ Exfiltration!
#                 }
#             }
#         }
#     }
# }
# ```
# 
# These will be fixed in Stage 3 with recursive deep validation!