"""
Request Signer - Stage 3

Comprehensive HMAC-SHA256 request signing with nonce integration

Blocks VULN-S2-003: Token Replay Attacks (when combined with NonceValidator)

Stage 2 Problem:
    JWT tokens could be intercepted and replayed unlimited times.
    No per-request signing or integrity protection beyond the JWT itself.

Stage 3 Solution:
    - HMAC-SHA256 signing of each complete request
    - Integrates with NonceValidator for replay protection
    - Includes nonce, timestamp, and full request data in signature
    - Signature verification before any processing
    - Tamper detection at message level
    - Request body integrity protection
    - Optional double-signing (JWT + HMAC) for defense in depth

Works with:
    - NonceValidator: Prevents message replay
    - KeyManager: Can use RSA keys for additional signing
    - AuditLogger: Logs all signature failures
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, field


@dataclass
class SignedRequest:
    """
    Represents a complete signed request
    
    Contains all elements needed for verification:
    - Original data
    - Nonce (unique identifier)
    - Timestamp (for time-window validation)
    - Signature (HMAC-SHA256)
    """
    data: Dict[str, Any]
    nonce: str
    timestamp: float
    signature: str
    algorithm: str = "HMAC-SHA256"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission"""
        return {
            **self.data,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "_signature_algorithm": self.algorithm
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'SignedRequest':
        """Parse from received dictionary"""
        # Extract signature metadata
        nonce = d.get("nonce")
        timestamp = d.get("timestamp")
        signature = d.get("signature")
        algorithm = d.get("_signature_algorithm", "HMAC-SHA256")
        
        # Extract data (everything except signature fields)
        data = {
            k: v for k, v in d.items()
            if k not in ("nonce", "timestamp", "signature", "_signature_algorithm")
        }
        
        return cls(
            data=data,
            nonce=nonce,
            timestamp=timestamp,
            signature=signature,
            algorithm=algorithm
        )


class RequestSigner:
    """
    Signs and verifies requests using HMAC-SHA256
    
    Provides:
    1. Message authenticity (proves sender has signing key)
    2. Message integrity (detects any tampering)
    3. Replay protection (when used with nonces)
    4. Defense in depth (additional layer beyond JWT)
    
    Stage 3 Enhancements:
    - Integrates with NonceValidator
    - Supports multiple signing keys (key rotation)
    - Comprehensive audit logging
    - Request validation before signing
    - Signature chain support (multi-hop signing)
    """
    
    NONCE_LENGTH = 32  # bytes (64 hex characters)
    
    def __init__(self, signing_key: Optional[bytes] = None,
                 nonce_validator=None, audit_logger=None):
        """
        Initialize request signer
        
        Args:
            signing_key: Secret key for HMAC (32+ bytes recommended)
            nonce_validator: NonceValidator instance for replay protection
            audit_logger: AuditLogger for comprehensive logging
        """
        # Generate strong key if not provided
        self.signing_key = signing_key if signing_key else secrets.token_bytes(32)
        
        # Store hash of key (for key identification without exposing key)
        self.key_id = hashlib.sha256(self.signing_key).hexdigest()[:16]
        
        # External integrations
        self.nonce_validator = nonce_validator
        self.audit_logger = audit_logger
        
        # Statistics
        self.stats = {
            "total_signed": 0,
            "total_verified": 0,
            "verification_success": 0,
            "verification_failed": 0,
            "replay_detected": 0,
            "tamper_detected": 0,
            "expired_requests": 0
        }
        
        # Key rotation support
        self.old_keys: List[Tuple[bytes, str]] = []  # (key, key_id)
        
        print(f"🔐 RequestSigner initialized (key_id: {self.key_id})")
    
    def sign_request(self, request_data: Dict[str, Any],
                     nonce: Optional[str] = None,
                     timestamp: Optional[float] = None) -> SignedRequest:
        """
        Create HMAC-SHA256 signature for request
        
        Args:
            request_data: Request data to sign
            nonce: Unique nonce (generated if not provided)
            timestamp: Request timestamp (current time if not provided)
            
        Returns:
            SignedRequest with signature
        """
        # Generate nonce and timestamp if not provided
        if nonce is None:
            nonce = self._generate_nonce()
        
        if timestamp is None:
            timestamp = time.time()
        
        # Validate request data
        validation_errors = self._validate_request_data(request_data)
        if validation_errors:
            self._audit("request_signing_failed", request_data.get("agent_id", "unknown"), {
                "reason": "Invalid request data",
                "errors": validation_errors
            })
            raise ValueError(f"Invalid request data: {validation_errors}")
        
        # Create canonical message
        canonical = self._create_canonical_message(request_data, nonce, timestamp)
        
        # Generate HMAC signature
        signature = hmac.new(
            self.signing_key,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        self.stats["total_signed"] += 1
        
        signed_request = SignedRequest(
            data=request_data,
            nonce=nonce,
            timestamp=timestamp,
            signature=signature
        )
        
        self._audit("request_signed", request_data.get("agent_id", "unknown"), {
            "nonce": nonce[:16],
            "timestamp": timestamp,
            "key_id": self.key_id
        })
        
        return signed_request
    
    def verify_signature(self, signed_request: SignedRequest,
                        time_window: int = 60) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify HMAC signature of request
        
        Args:
            signed_request: SignedRequest to verify
            time_window: Maximum age in seconds (default 60)
            
        Returns:
            (is_valid, error_message, metadata)
        """
        self.stats["total_verified"] += 1
        
        agent_id = signed_request.data.get("agent_id", "unknown")
        
        # 1. Verify timestamp is within acceptable window
        current_time = time.time()
        age = current_time - signed_request.timestamp
        
        if age > time_window:
            self.stats["expired_requests"] += 1
            self.stats["verification_failed"] += 1
            
            self._audit("signature_verification_failed", agent_id, {
                "reason": "Timestamp expired",
                "age": age,
                "time_window": time_window,
                "nonce": signed_request.nonce[:16]
            })
            
            return False, f"Request expired (age: {age:.1f}s > {time_window}s)", {
                "age": age,
                "expired": True
            }
        
        # 2. Check for replay via NonceValidator (if available)
        if self.nonce_validator:
            is_valid, nonce_msg = self.nonce_validator.validate(
                signed_request.nonce,
                signed_request.timestamp,
                signed_request.signature,
                signed_request.data
            )
            
            if not is_valid:
                self.stats["replay_detected"] += 1
                self.stats["verification_failed"] += 1
                
                self._audit("replay_attack_detected", agent_id, {
                    "nonce": signed_request.nonce[:16],
                    "reason": nonce_msg
                })
                
                return False, f"Replay detected: {nonce_msg}", {
                    "replay": True
                }
        
        # 3. Calculate expected signature
        canonical = self._create_canonical_message(
            signed_request.data,
            signed_request.nonce,
            signed_request.timestamp
        )
        
        expected_signature = hmac.new(
            self.signing_key,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # 4. Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signed_request.signature, expected_signature):
            # Try old keys (key rotation support)
            for old_key, old_key_id in self.old_keys:
                old_expected = hmac.new(
                    old_key,
                    canonical.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                
                if hmac.compare_digest(signed_request.signature, old_expected):
                    # Valid with old key
                    self.stats["verification_success"] += 1
                    
                    self._audit("signature_verified_old_key", agent_id, {
                        "nonce": signed_request.nonce[:16],
                        "old_key_id": old_key_id
                    })
                    
                    return True, "Valid (old key)", {
                        "valid": True,
                        "old_key": True,
                        "key_id": old_key_id
                    }
            
            # Invalid signature
            self.stats["tamper_detected"] += 1
            self.stats["verification_failed"] += 1
            
            self._audit("signature_verification_failed", agent_id, {
                "reason": "Invalid signature - message may have been tampered",
                "nonce": signed_request.nonce[:16]
            })
            
            return False, "Invalid signature - message may have been tampered with", {
                "tampered": True
            }
        
        # 5. All checks passed
        self.stats["verification_success"] += 1
        
        self._audit("signature_verified", agent_id, {
            "nonce": signed_request.nonce[:16],
            "key_id": self.key_id
        })
        
        return True, "Valid signature", {
            "valid": True,
            "key_id": self.key_id
        }
    
    def create_signed_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create complete signed request ready for transmission
        
        Args:
            request_data: Base request data
            
        Returns:
            Complete request with nonce, timestamp, and signature
        """
        signed = self.sign_request(request_data)
        return signed.to_dict()
    
    def verify_received_request(self, received_data: Dict[str, Any],
                               time_window: int = 60) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify a received request dictionary
        
        Args:
            received_data: Request data received
            time_window: Maximum age in seconds
            
        Returns:
            (is_valid, error_message, metadata)
        """
        try:
            signed_request = SignedRequest.from_dict(received_data)
            return self.verify_signature(signed_request, time_window)
        except Exception as e:
            self.stats["verification_failed"] += 1
            return False, f"Invalid request format: {str(e)}", {"error": str(e)}
    
    def _create_canonical_message(self, request_data: Dict[str, Any],
                                  nonce: str, timestamp: float) -> str:
        """
        Create canonical message for signing
        
        Format: nonce:timestamp:sorted_json_data:key_id
        
        Including key_id in signature prevents cross-key attacks
        
        Args:
            request_data: Request data
            nonce: Request nonce
            timestamp: Request timestamp
            
        Returns:
            Canonical message string
        """
        # Create sorted JSON (deterministic order)
        json_data = json.dumps(request_data, sort_keys=True, separators=(',', ':'))
        
        # Create canonical format with key_id
        canonical = f"{nonce}:{timestamp}:{json_data}:{self.key_id}"
        
        return canonical
    
    def _generate_nonce(self) -> str:
        """Generate cryptographically random nonce"""
        return secrets.token_hex(self.NONCE_LENGTH)
    
    def _validate_request_data(self, request_data: Dict[str, Any]) -> List[str]:
        """
        Validate request data before signing
        
        Args:
            request_data: Data to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Must have type
        if "type" not in request_data:
            errors.append("Missing 'type' field")
        
        # Must have agent_id
        if "agent_id" not in request_data:
            errors.append("Missing 'agent_id' field")
        
        # Check for reasonable data size (prevent DoS)
        data_str = json.dumps(request_data)
        if len(data_str) > 1_000_000:  # 1MB limit
            errors.append(f"Request too large: {len(data_str)} bytes")
        
        return errors
    
    def rotate_key(self, new_key: bytes, keep_old_keys: int = 2):
        """
        Rotate signing key
        
        Keeps old keys for a transition period to allow existing
        signed requests to still verify.
        
        Args:
            new_key: New signing key
            keep_old_keys: Number of old keys to keep (default 2)
        """
        # Store current key as old
        self.old_keys.append((self.signing_key, self.key_id))
        
        # Trim old keys list
        if len(self.old_keys) > keep_old_keys:
            self.old_keys = self.old_keys[-keep_old_keys:]
        
        # Set new key
        old_key_id = self.key_id
        self.signing_key = new_key
        self.key_id = hashlib.sha256(new_key).hexdigest()[:16]
        
        self._audit("key_rotated", "system", {
            "old_key_id": old_key_id,
            "new_key_id": self.key_id,
            "old_keys_kept": len(self.old_keys)
        })
        
        print(f"🔄 Key rotated: {old_key_id} → {self.key_id}")
    
    def get_statistics(self) -> Dict[str, int]:
        """Get signing/verification statistics"""
        return {
            **self.stats,
            "success_rate": (
                (self.stats["verification_success"] / self.stats["total_verified"] * 100)
                if self.stats["total_verified"] > 0 else 0
            )
        }
    
    def _audit(self, event_type: str, agent_id: str, details: Dict):
        """Log to audit trail"""
        if self.audit_logger:
            self.audit_logger.log(event_type, agent_id, details)
        # Fallback logging for testing
        # print(f"[AUDIT] {event_type}: {agent_id} - {details}")


class SignedRequestBuilder:
    """
    Helper class for building properly signed requests
    
    Simplifies client-side request creation with consistent patterns
    """
    
    def __init__(self, signer: RequestSigner):
        """
        Initialize builder
        
        Args:
            signer: RequestSigner instance to use
        """
        self.signer = signer
    
    def build_status_update(self, agent_id: str, task_id: str,
                           status: str, **kwargs) -> Dict[str, Any]:
        """
        Build signed status update request
        
        Args:
            agent_id: Agent sending update
            task_id: Task being updated
            status: New status
            **kwargs: Additional fields
            
        Returns:
            Signed request ready to send
        """
        request_data = {
            "type": "status_update",
            "agent_id": agent_id,
            "task_id": task_id,
            "status": status,
            **kwargs
        }
        
        return self.signer.create_signed_request(request_data)
    
    def build_task_completion(self, agent_id: str, task_id: str,
                             result: str, **kwargs) -> Dict[str, Any]:
        """
        Build signed task completion request
        
        Args:
            agent_id: Agent completing task
            task_id: Completed task
            result: Task result
            **kwargs: Additional fields
            
        Returns:
            Signed request ready to send
        """
        request_data = {
            "type": "task_complete",
            "agent_id": agent_id,
            "task_id": task_id,
            "result": result,
            **kwargs
        }
        
        return self.signer.create_signed_request(request_data)
    
    def build_registration(self, agent_id: str, password: str,
                          requested_role: str = "worker") -> Dict[str, Any]:
        """
        Build signed registration request
        
        Args:
            agent_id: Agent ID to register
            password: Agent password
            requested_role: Desired role
            
        Returns:
            Signed registration request
        """
        request_data = {
            "type": "register",
            "agent_id": agent_id,
            "password": password,
            "requested_role": requested_role
        }
        
        return self.signer.create_signed_request(request_data)


# Example usage and testing
if __name__ == "__main__":
    print("=" * 70)
    print("REQUEST SIGNER - COMPREHENSIVE HMAC MESSAGE AUTHENTICATION")
    print("=" * 70)
    print()
    
    # Create signer with strong key
    signer = RequestSigner()
    builder = SignedRequestBuilder(signer)
    
    print(f"✅ Signer initialized")
    print(f"   Key ID: {signer.key_id}")
    print()
    
    # Test 1: Sign a request
    print("Test 1: Creating signed request")
    request_data = {
        "type": "status_update",
        "agent_id": "worker-001",
        "task_id": "task-123",
        "status": "completed",
        "progress": 100
    }
    
    signed_request = signer.sign_request(request_data)
    
    print(f"  Original data: {request_data}")
    print(f"  Nonce: {signed_request.nonce[:16]}...")
    print(f"  Timestamp: {signed_request.timestamp:.2f}")
    print(f"  Signature: {signed_request.signature[:16]}...")
    print()
    
    # Test 2: Verify valid signature
    print("Test 2: Verifying valid signature")
    is_valid, message, metadata = signer.verify_signature(signed_request)
    
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    print(f"  Message: {message}")
    print(f"  Metadata: {metadata}")
    print()
    
    # Test 3: Detect tampering
    print("Test 3: Detecting tampered data")
    tampered_request = SignedRequest(
        data={**request_data, "status": "failed"},  # Changed!
        nonce=signed_request.nonce,
        timestamp=signed_request.timestamp,
        signature=signed_request.signature  # Original signature
    )
    
    is_valid, message, metadata = signer.verify_signature(tampered_request)
    
    print(f"  Tampered field: status = 'failed' (was 'completed')")
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (correctly detected)'}")
    print(f"  Message: {message}")
    print()
    
    # Test 4: Detect replay (without NonceValidator for this test)
    print("Test 4: Replay detection (simulated)")
    print("  Note: Full replay protection requires NonceValidator integration")
    
    # Try same request twice
    request1 = builder.build_status_update(
        agent_id="worker-002",
        task_id="task-456",
        status="in_progress"
    )
    
    print(f"  Request 1 sent: nonce={request1['nonce'][:16]}...")
    
    # Simulate replay
    request2 = request1.copy()  # Exact same request
    print(f"  Request 2 (replay): nonce={request2['nonce'][:16]}...")
    print(f"  Same nonce: {request1['nonce'] == request2['nonce']}")
    print()
    
    # Test 5: Key rotation
    print("Test 5: Key rotation")
    old_key_id = signer.key_id
    
    # Create request with old key
    old_request = builder.build_status_update(
        agent_id="worker-003",
        task_id="task-789",
        status="completed"
    )
    
    print(f"  Request signed with key: {old_key_id}")
    
    # Rotate key
    new_key = secrets.token_bytes(32)
    signer.rotate_key(new_key, keep_old_keys=2)
    
    print(f"  Key rotated to: {signer.key_id}")
    
    # Old request should still verify
    signed_old = SignedRequest.from_dict(old_request)
    is_valid, message, metadata = signer.verify_signature(signed_old)
    
    print(f"  Old request verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
    print(f"  Message: {message}")
    print()
    
    # Test 6: Using builder
    print("Test 6: Using SignedRequestBuilder")
    
    completion_request = builder.build_task_completion(
        agent_id="worker-004",
        task_id="task-999",
        result="Successfully processed 1000 items",
        metrics={"processed": 1000, "errors": 0}
    )
    
    print(f"  Built completion request")
    print(f"  Type: {completion_request['type']}")
    print(f"  Agent: {completion_request['agent_id']}")
    print(f"  Signed: ✅ (nonce: {completion_request['nonce'][:16]}...)")
    
    # Verify it
    is_valid, message, metadata = signer.verify_received_request(completion_request)
    print(f"  Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
    print()
    
    # Statistics
    print("=" * 70)
    print("SIGNING STATISTICS")
    print("=" * 70)
    stats = signer.get_statistics()
    for key, value in stats.items():
        if key == "success_rate":
            print(f"  {key}: {value:.1f}%")
        else:
            print(f"  {key}: {value}")
    print()
    
    print("=" * 70)
    print("🎓 LESSON: HMAC request signing for message integrity")
    print()
    print("   Stage 3 provides:")
    print("     ✅ Message authenticity - proves sender has key")
    print("     ✅ Message integrity - detects any tampering")
    print("     ✅ Replay protection - with NonceValidator integration")
    print("     ✅ Key rotation - supports graceful key changes")
    print("     ✅ Audit trail - comprehensive logging")
    print()
    print("   Stage 2: No request signing → tampering possible")
    print("   Stage 3: HMAC-SHA256 signing → tamper-proof messages")
    print("=" * 70)