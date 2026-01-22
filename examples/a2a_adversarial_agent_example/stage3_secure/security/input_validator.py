"""
Input Validator - Stage 3: Production Security

Pluggable input validation interface with multiple implementations.

✅ Stage 3: Comprehensive input validation
❌ Stage 2: Size checks only

Architecture:
- Abstract InputValidator interface
- Multiple validator implementations
- Easy to add new validators (Google Model Armor, OWASP, etc.)
- Composable validators

Usage:
    # Use basic validator
    validator = BasicInputValidator()
    
    # Or use AI-based validator
    validator = AIInputValidator()
    
    # Or compose multiple validators
    validator = CompositeValidator([
        BasicInputValidator(),
        AIInputValidator(),
        OWASPValidator()
    ])
    
    # Validate input
    valid, sanitized, errors = validator.validate_input(
        value="some input",
        input_type="string",
        context={"field": "username"}
    )
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import re


class InputType(Enum):
    """Input types for validation"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    EMAIL = "email"
    URL = "url"
    USERNAME = "username"
    PASSWORD = "password"
    JSON = "json"
    UUID = "uuid"
    ENUM = "enum"
    ARRAY = "array"
    OBJECT = "object"


class ValidationResult:
    """
    Structured validation result
    
    Attributes:
        valid: Whether input is valid
        sanitized: Sanitized/normalized value
        errors: List of validation errors
        warnings: List of warnings (non-fatal issues)
        metadata: Additional metadata from validator
    """
    
    def __init__(
        self,
        valid: bool,
        sanitized: Any = None,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ):
        self.valid = valid
        self.sanitized = sanitized
        self.errors = errors or []
        self.warnings = warnings or []
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "valid": self.valid,
            "sanitized": self.sanitized,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata
        }


class InputValidator(ABC):
    """
    Abstract base class for input validators
    
    This interface allows plugging in different validation implementations:
    - BasicInputValidator: Built-in validation rules
    - AIInputValidator: AI/ML-based validation
    - OWASPValidator: OWASP validation library
    - GoogleModelArmorValidator: Google's Model Armor
    - CompositeValidator: Multiple validators combined
    
    Implementations must provide:
    - validate_input(): Validate and sanitize input
    - get_validator_name(): Return validator name
    - supports_type(): Check if type is supported
    """
    
    @abstractmethod
    def validate_input(
        self,
        value: Any,
        input_type: InputType,
        constraints: Optional[Dict] = None,
        context: Optional[Dict] = None
    ) -> ValidationResult:
        """
        Validate and sanitize input
        
        Args:
            value: Input value to validate
            input_type: Type of input (string, email, etc.)
            constraints: Validation constraints (min_length, max_length, etc.)
            context: Additional context (field name, user info, etc.)
        
        Returns:
            ValidationResult with validation outcome
        
        Example:
            result = validator.validate_input(
                value="john@example.com",
                input_type=InputType.EMAIL,
                constraints={"max_length": 100},
                context={"field": "email"}
            )
            
            if result.valid:
                use_value(result.sanitized)
            else:
                return_errors(result.errors)
        """
        pass
    
    @abstractmethod
    def get_validator_name(self) -> str:
        """
        Get validator name/identifier
        
        Returns:
            String identifier for this validator
        """
        pass
    
    @abstractmethod
    def supports_type(self, input_type: InputType) -> bool:
        """
        Check if validator supports this input type
        
        Args:
            input_type: Type to check
        
        Returns:
            True if this validator can handle this type
        """
        pass
    
    def validate_batch(
        self,
        inputs: List[Dict]
    ) -> List[ValidationResult]:
        """
        Validate multiple inputs
        
        Args:
            inputs: List of input dictionaries with 'value', 'input_type', etc.
        
        Returns:
            List of ValidationResult objects
        
        Example:
            results = validator.validate_batch([
                {"value": "alice", "input_type": InputType.USERNAME},
                {"value": "alice@example.com", "input_type": InputType.EMAIL}
            ])
        """
        results = []
        
        for input_dict in inputs:
            result = self.validate_input(
                value=input_dict.get("value"),
                input_type=input_dict.get("input_type"),
                constraints=input_dict.get("constraints"),
                context=input_dict.get("context")
            )
            results.append(result)
        
        return results


class CompositeValidator(InputValidator):
    """
    Composite validator that runs multiple validators
    
    Runs all validators and combines results. Input is valid only if
    ALL validators approve it.
    
    Usage:
        validator = CompositeValidator([
            BasicInputValidator(),
            AIInputValidator(),
            CustomValidator()
        ])
        
        # All three validators will check the input
        result = validator.validate_input(...)
    """
    
    def __init__(self, validators: List[InputValidator]):
        """
        Initialize composite validator
        
        Args:
            validators: List of validators to run
        """
        self.validators = validators
        print(f"✅ CompositeValidator initialized with {len(validators)} validators")
        for v in validators:
            print(f"   - {v.get_validator_name()}")
    
    def validate_input(
        self,
        value: Any,
        input_type: InputType,
        constraints: Optional[Dict] = None,
        context: Optional[Dict] = None
    ) -> ValidationResult:
        """
        Run all validators
        
        Returns combined result. Valid only if all validators pass.
        """
        all_errors = []
        all_warnings = []
        all_metadata = {}
        sanitized_value = value
        
        # Run each validator
        for validator in self.validators:
            # Skip if validator doesn't support this type
            if not validator.supports_type(input_type):
                continue
            
            result = validator.validate_input(
                value=sanitized_value,
                input_type=input_type,
                constraints=constraints,
                context=context
            )
            
            # Collect errors and warnings
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)
            
            # Use sanitized value for next validator
            if result.valid and result.sanitized is not None:
                sanitized_value = result.sanitized
            
            # Collect metadata
            validator_name = validator.get_validator_name()
            all_metadata[validator_name] = result.metadata
            
            # If any validator fails, short-circuit
            if not result.valid:
                # Continue checking to collect all errors
                pass
        
        # Valid only if no errors
        is_valid = len(all_errors) == 0
        
        return ValidationResult(
            valid=is_valid,
            sanitized=sanitized_value if is_valid else None,
            errors=all_errors,
            warnings=all_warnings,
            metadata=all_metadata
        )
    
    def get_validator_name(self) -> str:
        """Get composite validator name"""
        names = [v.get_validator_name() for v in self.validators]
        return f"Composite[{', '.join(names)}]"
    
    def supports_type(self, input_type: InputType) -> bool:
        """Composite supports a type if any validator supports it"""
        return any(v.supports_type(input_type) for v in self.validators)
    
    def add_validator(self, validator: InputValidator):
        """Add a validator to the composite"""
        self.validators.append(validator)
        print(f"✅ Added validator: {validator.get_validator_name()}")
    
    def remove_validator(self, validator_name: str) -> bool:
        """Remove a validator by name"""
        for i, v in enumerate(self.validators):
            if v.get_validator_name() == validator_name:
                del self.validators[i]
                print(f"✅ Removed validator: {validator_name}")
                return True
        return False


class BasicInputValidator(InputValidator):
    """
    Basic built-in input validator
    
    Provides standard validation rules:
    - Length checks
    - Pattern matching
    - Type validation
    - Common injection prevention
    - Character whitelisting
    
    This is the default validator included with Stage 3.
    """
    
    def __init__(self):
        """Initialize basic validator"""
        # ✅ Dangerous patterns to detect
        self.dangerous_patterns = {
            "sql_injection": re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b|--|;|/\*|\*/)", re.IGNORECASE),
            "xss": re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE),
            "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e)"),
            "command_injection": re.compile(r"(;|\||&&|\$\(|\`)", re.IGNORECASE),
            "ldap_injection": re.compile(r"(\*|\(|\)|\||&)", re.IGNORECASE)
        }
        
        # ✅ Valid patterns
        self.valid_patterns = {
            InputType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
            InputType.USERNAME: re.compile(r"^[a-zA-Z0-9_-]{3,32}$"),
            InputType.UUID: re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),
            InputType.URL: re.compile(r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$")
        }
        
        print("✅ BasicInputValidator initialized")
    
    def validate_input(
        self,
        value: Any,
        input_type: InputType,
        constraints: Optional[Dict] = None,
        context: Optional[Dict] = None
    ) -> ValidationResult:
        """Validate input with basic rules"""
        constraints = constraints or {}
        context = context or {}
        errors = []
        warnings = []
        
        # 1. Type validation
        if not self._validate_type(value, input_type):
            errors.append(f"Invalid type: expected {input_type.value}")
            return ValidationResult(valid=False, errors=errors)
        
        # 2. Null check
        if value is None:
            if constraints.get("required", False):
                errors.append("Value is required")
                return ValidationResult(valid=False, errors=errors)
            else:
                return ValidationResult(valid=True, sanitized=None)
        
        # Convert to string for string-based validation
        value_str = str(value)
        
        # 3. Length validation
        if "min_length" in constraints:
            if len(value_str) < constraints["min_length"]:
                errors.append(f"Minimum length is {constraints['min_length']}")
        
        if "max_length" in constraints:
            if len(value_str) > constraints["max_length"]:
                errors.append(f"Maximum length is {constraints['max_length']}")
        
        # 4. Pattern validation
        if input_type in self.valid_patterns:
            if not self.valid_patterns[input_type].match(value_str):
                errors.append(f"Invalid format for {input_type.value}")
        
        # 5. Injection detection
        for attack_type, pattern in self.dangerous_patterns.items():
            if pattern.search(value_str):
                errors.append(f"Potential {attack_type} detected")
                warnings.append(f"Input contains patterns similar to {attack_type}")
        
        # 6. Range validation (for numbers)
        if input_type in [InputType.INTEGER, InputType.FLOAT]:
            try:
                num_value = float(value)
                
                if "min" in constraints and num_value < constraints["min"]:
                    errors.append(f"Value must be >= {constraints['min']}")
                
                if "max" in constraints and num_value > constraints["max"]:
                    errors.append(f"Value must be <= {constraints['max']}")
            except (ValueError, TypeError):
                errors.append(f"Invalid number: {value}")
        
        # 7. Enum validation
        if input_type == InputType.ENUM:
            allowed_values = constraints.get("allowed_values", [])
            if value not in allowed_values:
                errors.append(f"Value must be one of: {allowed_values}")
        
        # 8. Sanitization
        sanitized = self._sanitize(value, input_type)
        
        is_valid = len(errors) == 0
        
        return ValidationResult(
            valid=is_valid,
            sanitized=sanitized if is_valid else None,
            errors=errors,
            warnings=warnings,
            metadata={
                "validator": "BasicInputValidator",
                "input_type": input_type.value
            }
        )
    
    def _validate_type(self, value: Any, input_type: InputType) -> bool:
        """Validate Python type matches expected input type"""
        if value is None:
            return True
        
        type_map = {
            InputType.STRING: str,
            InputType.INTEGER: int,
            InputType.FLOAT: (int, float),
            InputType.EMAIL: str,
            InputType.URL: str,
            InputType.USERNAME: str,
            InputType.PASSWORD: str,
            InputType.UUID: str,
            InputType.ENUM: (str, int),
            InputType.ARRAY: list,
            InputType.OBJECT: dict
        }
        
        expected_type = type_map.get(input_type, str)
        return isinstance(value, expected_type)
    
    def _sanitize(self, value: Any, input_type: InputType) -> Any:
        """Sanitize value"""
        if value is None:
            return None
        
        if input_type == InputType.STRING:
            # Strip whitespace
            value = str(value).strip()
            # Remove null bytes
            value = value.replace('\x00', '')
            return value
        
        if input_type in [InputType.EMAIL, InputType.USERNAME]:
            # Lowercase and strip
            return str(value).lower().strip()
        
        if input_type == InputType.INTEGER:
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        
        if input_type == InputType.FLOAT:
            try:
                return float(value)
            except (ValueError, TypeError):
                return None
        
        return value
    
    def get_validator_name(self) -> str:
        """Get validator name"""
        return "BasicInputValidator"
    
    def supports_type(self, input_type: InputType) -> bool:
        """Basic validator supports all types"""
        return True


if __name__ == "__main__":
    """Test the input validator interface"""
    print("=" * 70)
    print("Input Validator Interface Test")
    print("=" * 70)
    
    # Create basic validator
    basic_validator = BasicInputValidator()
    
    print("\n--- Test 1: Valid Email ---")
    result = basic_validator.validate_input(
        value="alice@example.com",
        input_type=InputType.EMAIL,
        constraints={"max_length": 100}
    )
    print(f"Valid: {result.valid}")
    print(f"Sanitized: {result.sanitized}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 2: Invalid Email ---")
    result = basic_validator.validate_input(
        value="not-an-email",
        input_type=InputType.EMAIL
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 3: SQL Injection Detection ---")
    result = basic_validator.validate_input(
        value="'; DROP TABLE users; --",
        input_type=InputType.STRING
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    
    print("\n--- Test 4: XSS Detection ---")
    result = basic_validator.validate_input(
        value="<script>alert('xss')</script>",
        input_type=InputType.STRING
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 5: Length Constraints ---")
    result = basic_validator.validate_input(
        value="ab",
        input_type=InputType.USERNAME,
        constraints={"min_length": 3, "max_length": 32}
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 6: Number Range ---")
    result = basic_validator.validate_input(
        value=150,
        input_type=InputType.INTEGER,
        constraints={"min": 1, "max": 100}
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 7: Enum Validation ---")
    result = basic_validator.validate_input(
        value="red",
        input_type=InputType.ENUM,
        constraints={"allowed_values": ["red", "green", "blue"]}
    )
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    
    print("\n--- Test 8: Batch Validation ---")
    results = basic_validator.validate_batch([
        {"value": "alice", "input_type": InputType.USERNAME},
        {"value": "alice@example.com", "input_type": InputType.EMAIL},
        {"value": "invalid@@", "input_type": InputType.EMAIL}
    ])
    
    for i, result in enumerate(results):
        print(f"Input {i+1}: valid={result.valid}, errors={result.errors}")
    
    print("\n--- Test 9: Composite Validator ---")
    # You could add more validators here
    composite = CompositeValidator([
        basic_validator
        # AIInputValidator(),  # Would add if available
        # GoogleModelArmorValidator(),  # Would add if available
    ])
    
    result = composite.validate_input(
        value="test@example.com",
        input_type=InputType.EMAIL
    )
    print(f"Composite result: valid={result.valid}")
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ Input validator interface is ready for plugins")
    print("   - Abstract interface defined")
    print("   - BasicInputValidator implemented")
    print("   - CompositeValidator for multiple validators")
    print("   - Ready to plug in AI validators, OWASP, etc.")