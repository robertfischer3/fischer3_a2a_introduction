"""
Deep Recursive Validator - Stage 3

Blocks VULN-S2-002: Deep-Nested Data Exfiltration

This validator recursively checks ALL nesting levels, preventing attackers
from hiding malicious data deep in nested structures.

Stage 2 Problem:
    Validator only checked top-level fields, attackers hid stolen data
    5+ levels deep where validation didn't reach.

Stage 3 Solution:
    Recursive validation at every level with strict limits on:
    - Maximum nesting depth (5 levels)
    - Dictionary size (100 keys max)
    - List size (50 items max)
    - String length (1000 chars max)
    - Pattern detection at ALL levels
"""

import re
from typing import Any, Tuple, Dict, List, Set

class DeepValidator:
    """
    Comprehensive recursive validator that checks data at ALL nesting levels
    
    Prevents data exfiltration by:
    1. Limiting nesting depth
    2. Limiting structure sizes
    3. Detecting sensitive patterns at every level
    4. Validating data types recursively
    """
    
    # Structural limits
    MAX_DEPTH = 5
    MAX_DICT_SIZE = 100      # Maximum keys per dictionary
    MAX_LIST_SIZE = 50       # Maximum items per list
    MAX_STRING_SIZE = 1000   # Maximum characters per string
    MAX_TOTAL_SIZE = 10000   # Maximum total data size (bytes)
    
    # Sensitive pattern detection
    SENSITIVE_PATTERNS = {
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'credit_card': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'api_key': re.compile(r'\b[A-Za-z0-9_-]{20,}\b'),
        'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b'),
        'password': re.compile(r'\b(password|passwd|pwd)\s*[:=]\s*[^\s]+', re.IGNORECASE),
        'secret': re.compile(r'\b(secret|token|key)\s*[:=]\s*[^\s]+', re.IGNORECASE),
    }
    
    # Forbidden field names (case-insensitive)
    FORBIDDEN_FIELDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 
        'private_key', 'access_token', 'refresh_token', 'ssn', 
        'social_security', 'credit_card', 'cvv', 'pin'
    }
    
    def __init__(self):
        self.validation_errors = []
        self.warnings = []
        
    def validate(self, data: Any, context: str = "root") -> Tuple[bool, List[str]]:
        """
        Validate data with comprehensive recursive checks
        
        Args:
            data: Data to validate (any type)
            context: Current context path for error messages
            
        Returns:
            (is_valid, list_of_errors)
        """
        self.validation_errors = []
        self.warnings = []
        
        # Check total size first
        total_size = len(str(data))
        if total_size > self.MAX_TOTAL_SIZE:
            self.validation_errors.append(
                f"Total data size ({total_size} bytes) exceeds limit ({self.MAX_TOTAL_SIZE} bytes)"
            )
            return False, self.validation_errors
        
        # Start recursive validation
        is_valid = self._validate_recursive(data, depth=0, context=context)
        
        return is_valid, self.validation_errors
    
    def _validate_recursive(self, data: Any, depth: int, context: str) -> bool:
        """
        Recursively validate data at all nesting levels
        
        Args:
            data: Current data to validate
            depth: Current nesting depth
            context: Path to current data (for error messages)
            
        Returns:
            True if valid, False otherwise (errors stored in self.validation_errors)
        """
        # Check depth limit
        if depth > self.MAX_DEPTH:
            self.validation_errors.append(
                f"Maximum nesting depth ({self.MAX_DEPTH}) exceeded at {context}"
            )
            return False
        
        # Validate based on type
        if isinstance(data, dict):
            return self._validate_dict(data, depth, context)
        elif isinstance(data, list):
            return self._validate_list(data, depth, context)
        elif isinstance(data, str):
            return self._validate_string(data, depth, context)
        elif isinstance(data, (int, float, bool, type(None))):
            return True  # Primitives are safe
        else:
            self.validation_errors.append(
                f"Unsupported data type {type(data).__name__} at {context}"
            )
            return False
    
    def _validate_dict(self, data: Dict, depth: int, context: str) -> bool:
        """Validate dictionary recursively"""
        is_valid = True
        
        # Check size
        if len(data) > self.MAX_DICT_SIZE:
            self.validation_errors.append(
                f"Dictionary at {context} has {len(data)} keys, exceeds limit of {self.MAX_DICT_SIZE}"
            )
            return False
        
        # Check each key-value pair
        for key, value in data.items():
            # Validate key
            if not isinstance(key, str):
                self.validation_errors.append(
                    f"Dictionary key at {context} must be string, got {type(key).__name__}"
                )
                is_valid = False
                continue
            
            # Check for forbidden field names
            if key.lower() in self.FORBIDDEN_FIELDS:
                self.validation_errors.append(
                    f"Forbidden field name '{key}' detected at {context}"
                )
                is_valid = False
                continue
            
            # Recursively validate value
            new_context = f"{context}.{key}"
            if not self._validate_recursive(value, depth + 1, new_context):
                is_valid = False
        
        return is_valid
    
    def _validate_list(self, data: List, depth: int, context: str) -> bool:
        """Validate list recursively"""
        is_valid = True
        
        # Check size
        if len(data) > self.MAX_LIST_SIZE:
            self.validation_errors.append(
                f"List at {context} has {len(data)} items, exceeds limit of {self.MAX_LIST_SIZE}"
            )
            return False
        
        # Check each item
        for i, item in enumerate(data):
            new_context = f"{context}[{i}]"
            if not self._validate_recursive(item, depth + 1, new_context):
                is_valid = False
        
        return is_valid
    
    def _validate_string(self, data: str, depth: int, context: str) -> bool:
        """Validate string including pattern detection"""
        is_valid = True
        
        # Check length
        if len(data) > self.MAX_STRING_SIZE:
            self.validation_errors.append(
                f"String at {context} has {len(data)} characters, exceeds limit of {self.MAX_STRING_SIZE}"
            )
            return False
        
        # Check for sensitive patterns
        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            if pattern.search(data):
                self.validation_errors.append(
                    f"Sensitive pattern '{pattern_name}' detected in string at {context}"
                )
                is_valid = False
        
        return is_valid
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get summary of validation results
        
        Returns:
            Dictionary with validation statistics
        """
        return {
            "is_valid": len(self.validation_errors) == 0,
            "error_count": len(self.validation_errors),
            "warning_count": len(self.warnings),
            "errors": self.validation_errors,
            "warnings": self.warnings
        }


class DeepValidationError(Exception):
    """Raised when deep validation fails"""
    pass


# Example usage
if __name__ == "__main__":
    validator = DeepValidator()
    
    # Test 1: Valid shallow data
    print("Test 1: Valid shallow data")
    valid_data = {
        "message": "Task completed",
        "progress": 100,
        "details": {
            "info": "Everything went well"
        }
    }
    is_valid, errors = validator.validate(valid_data)
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    if errors:
        for error in errors:
            print(f"    - {error}")
    print()
    
    # Test 2: Too deep nesting (should fail)
    print("Test 2: Deep nesting (6 levels)")
    deep_data = {
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "level6": "too deep!"  # Exceeds MAX_DEPTH=5
                        }
                    }
                }
            }
        }
    }
    is_valid, errors = validator.validate(deep_data)
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (CORRECTLY BLOCKED)'}")
    if errors:
        for error in errors:
            print(f"    - {error}")
    print()
    
    # Test 3: Sensitive data hidden deep (should fail)
    print("Test 3: Stolen data hidden at level 5")
    malicious_data = {
        "message": "Processing",
        "metadata": {
            "technical": {
                "debug": {
                    "internal": {
                        "stolen_ssn": "123-45-6789"  # Should be detected!
                    }
                }
            }
        }
    }
    is_valid, errors = validator.validate(malicious_data)
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (CORRECTLY BLOCKED)'}")
    if errors:
        for error in errors:
            print(f"    - {error}")
    print()
    
    # Test 4: Forbidden field name (should fail)
    print("Test 4: Forbidden field name")
    forbidden_data = {
        "message": "Task update",
        "details": {
            "password": "secret123"  # Forbidden field!
        }
    }
    is_valid, errors = validator.validate(forbidden_data)
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (CORRECTLY BLOCKED)'}")
    if errors:
        for error in errors:
            print(f"    - {error}")
    print()
    
    print("=" * 60)
    print("🎓 LESSON: Deep validation checks EVERY level")
    print("   Stage 2's shallow validation missed data at level 5+")
    print("   Stage 3's recursive validation catches it all!")
    print("=" * 60)