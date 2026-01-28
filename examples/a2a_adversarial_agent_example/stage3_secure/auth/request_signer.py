"""
Request Signer - Stage 3

HMAC-SHA256 request signing for message authenticity

Works with NonceValidator to provide comprehensive replay protection:
- NonceValidator: Prevents reuse of messages
- RequestSigner: Proves message authenticity and integrity

Stage 2 Problem:
    JWT tokens could be intercepted and replayed.
    No per-request signing or integrity protection.

Stage 3 Solution:
    - HMAC-SHA256 signing of each request
    - Includes nonce, timestamp, and full request data
    - Signature verification before processing
    - Tamper detection
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Any, Tuple


class RequestSigner:
    """
    Signs and verifies requests using HMAC-SHA256
    
    Provides:
    1. Message authenticity (proves sender has signing key)
    2. Message integrity (detects tampering)
    3. Replay protection (when used with nonces)
    """
    
    def __init__(self, signing_key: bytes = None):
        """
        Initialize request signer
        
        Args:
            signing_key: Secret key for HMAC (32+ bytes recommended)
        """
        self.signing_key = signing_key if signing_key else secrets.token_bytes(32)
    
    def sign_request(self, request_data: Dict[str, Any], nonce: str, 
                     timestamp: float) -> str:
        """
        Create HMAC-SHA256 signature for request
        
        Args:
            request_data: Request data to sign
            nonce: Unique nonce for this request
            timestamp: Request timestamp
            
        Returns:
            Hex-encoded HMAC signature
        """
        # Create canonical message
        message = self._create_canonical_message(request_data, nonce, timestamp)
        
        # Generate HMAC signature
        signature = hmac.new(
            self.signing_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, request_data: Dict[str, Any], nonce: str,
                        timestamp: float, signature: str) -> Tuple[bool, str]:
        """
        Verify HMAC signature of request
        
        Args:
            request_data: Request data that was signed
            nonce: Nonce from request
            timestamp: Timestamp from request
            signature: Signature to verify
            
        Returns:
            (is_valid, error_message)
        """
        # Calculate expected signature
        expected_signature = self.sign_request(request_data, nonce, timestamp)
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature, expected_signature):
            return False, "Invalid signature - message may have been tampered with"
        
        return True, "Signature valid"
    
    def create_signed_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create complete signed request with nonce and timestamp
        
        Args:
            request_data: Base request data
            
        Returns:
            Request with nonce, timestamp, and signature added
        """
        # Generate nonce and timestamp
        nonce = self._generate_nonce()
        timestamp = time.time()
        
        # Create signature
        signature = self.sign_request(request_data, nonce, timestamp)
        
        # Return complete signed request
        return {
            **request_data,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature
        }
    
    def _create_canonical_message(self, request_data: Dict[str, Any],
                                  nonce: str, timestamp: float) -> str:
        """
        Create canonical message for signing
        
        Format: nonce:timestamp:sorted_json_data
        
        Args:
            request_data: Request data
            nonce: Request nonce
            timestamp: Request timestamp
            
        Returns:
            Canonical message string
        """
        # Create sorted JSON (deterministic order)
        # Exclude nonce, timestamp, signature from data to sign
        data_to_sign = {
            k: v for k, v in request_data.items()
            if k not in ('nonce', 'timestamp', 'signature')
        }
        
        json_data = json.dumps(data_to_sign, sort_keys=True, separators=(',', ':'))
        
        # Create canonical format
        canonical = f"{nonce}:{timestamp}:{json_data}"
        
        return canonical
    
    def _generate_nonce(self) -> str:
        """Generate cryptographically random nonce"""
        return secrets.token_hex(32)  # 64 character hex string
    
    def rotate_key(self, new_key: bytes) -> bytes:
        """
        Rotate signing key
        
        Args:
            new_key: New signing key
            
        Returns:
            Old key (for transition period if needed)
        """
        old_key = self.signing_key
        self.signing_key = new_key
        return old_key


class SignedRequestBuilder:
    """
    Helper class for building properly signed requests
    
    Simplifies client-side request creation
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
    print("REQUEST SIGNER - HMAC MESSAGE AUTHENTICATION")
    print("=" * 70)
    print()
    
    # Create signer
    signer = RequestSigner()
    print(f"✅ Signer initialized with key: {signer.signing_key.hex()[:32]}...")
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
    
    signed_request = signer.create_signed_request(request_data)
    
    print(f"  Original data: {request_data}")
    print(f"  Nonce: {signed_request['nonce'][:16]}...")
    print(f"  Timestamp: {signed_request['timestamp']:.2f}")
    print(f"  Signature: {signed_request['signature'][:16]}...")
    print()
    
    # Test 2: Verify valid signature
    print("Test 2: Verifying valid signature")
    is_valid, message = signer.verify_signature(
        request_data,
        signed_request['nonce'],
        signed_request['timestamp'],
        signed_request['signature']
    )
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
    print(f"  Message: {message}")
    print()
    
    # Test 3: Detect tampering
    print("Test 3: Detecting tampered data")
    tampered_data = request_data.copy()
    tampered_data["status"] = "failed"  # Changed after signing!
    
    is_valid, message = signer.verify_signature(
        tampered_data,  # Tampered!
        signed_request['nonce'],
        signed_request['timestamp'],
        signed_request['signature']  # Original signature
    )
    print(f"  Tampered field: status = 'failed' (was 'completed')")
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (correctly detected)'}")
    print(f"  Message: {message}")
    print()
    
    # Test 4: Detect modified signature
    print("Test 4: Detecting modified signature")
    modified_sig = signed_request['signature'][:-4] + "FAKE"
    
    is_valid, message = signer.verify_signature(
        request_data,
        signed_request['nonce'],
        signed_request['timestamp'],
        modified_sig  # Modified signature
    )
    print(f"  Modified signature: ...{modified_sig[-8:]}")
    print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (correctly detected)'}")
    print(f"  Message: {message}")
    print()
    
    # Test 5: Using builder helper
    print("Test 5: Using SignedRequestBuilder helper")
    builder = SignedRequestBuilder(signer)
    
    status_update = builder.build_status_update(
        agent_id="worker-002",
        task_id="task-456",
        status="in_progress",
        progress=50,
        details={"message": "Halfway done"}
    )
    
    print(f"  Created: status_update request")
    print(f"  Agent: {status_update['agent_id']}")
    print(f"  Task: {status_update['task_id']}")
    print(f"  Signed: ✅ (nonce: {status_update['nonce'][:16]}...)")
    print()
    
    # Verify it
    verify_data = {k: v for k, v in status_update.items() 
                   if k not in ('nonce', 'timestamp', 'signature')}
    is_valid, message = signer.verify_signature(
        verify_data,
        status_update['nonce'],
        status_update['timestamp'],
        status_update['signature']
    )
    print(f"  Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
    print()
    
    # Test 6: Key rotation
    print("Test 6: Key rotation")
    old_key = signer.signing_key
    new_key = secrets.token_bytes(32)
    
    print(f"  Old key: {old_key.hex()[:32]}...")
    returned_old = signer.rotate_key(new_key)
    print(f"  New key: {signer.signing_key.hex()[:32]}...")
    print(f"  Returned old key matches: {returned_old == old_key}")
    print()
    
    # Old signature won't verify with new key
    is_valid, message = signer.verify_signature(
        request_data,
        signed_request['nonce'],
        signed_request['timestamp'],
        signed_request['signature']
    )
    print(f"  Old signature with new key: {'✅ VALID' if is_valid else '❌ INVALID (expected)'}")
    print()
    
    print("=" * 70)
    print("🎓 LESSON: HMAC request signing")
    print()
    print("   Benefits:")
    print("     1. Message authenticity - proves sender has key")
    print("     2. Message integrity - detects any tampering")
    print("     3. Non-repudiation - sender can't deny sending")
    print("     4. Replay protection - when combined with nonces")
    print()
    print("   Stage 2: No request signing → tampering possible")
    print("   Stage 3: HMAC-SHA256 signing → tamper-proof messages")
    print("=" * 70)