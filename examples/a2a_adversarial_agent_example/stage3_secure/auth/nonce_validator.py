"""
Nonce Validator - Stage 3: Production Security

Prevents replay attacks by ensuring each request is unique.

✅ Stage 3: Nonce-based replay protection
❌ Stage 2: No replay protection (messages could be replayed)

Security Features:
- Time-windowed nonce validation
- Automatic nonce expiration
- Memory-efficient storage (OrderedDict)
- Protection against replay attacks
- Protection against clock manipulation

Usage:
    validator = NonceValidator(ttl=300)  # 5 minute window
    
    # Validate nonce
    if validator.validate_nonce(nonce, timestamp):
        process_request()
    else:
        reject_request("Replay attack detected")
"""

import time
from typing import Optional
from collections import OrderedDict
import hashlib
import secrets


class NonceValidator:
    """
    Nonce-based replay attack prevention
    
    A nonce (Number used ONCE) ensures that each request is unique
    and cannot be replayed, even if an attacker captures a valid
    signed message.
    
    Design:
    - Time-ordered cache with TTL
    - Automatic expiration of old nonces
    - Memory-efficient (max size limit)
    - Constant-time lookups
    
    Security Properties:
    ✅ Each nonce can only be used once
    ✅ Nonces expire after TTL
    ✅ Prevents replay attacks
    ✅ Detects clock manipulation attempts
    ✅ Memory bounded
    """
    
    def __init__(
        self,
        ttl: int = 300,
        max_cache_size: int = 100000
    ):
        """
        Initialize nonce validator
        
        Args:
            ttl: Time-to-live for nonces in seconds (default 5 minutes)
            max_cache_size: Maximum number of nonces to cache
        """
        # ✅ Time-ordered nonce cache
        # OrderedDict maintains insertion order for efficient cleanup
        self.nonces: OrderedDict[str, float] = OrderedDict()
        
        # ✅ Nonce validity window
        self.ttl = ttl
        
        # ✅ Max cache size (prevent memory exhaustion)
        self.max_cache_size = max_cache_size
        
        # ✅ Clock skew tolerance (1 minute)
        # Allows for minor time differences between client and server
        self.clock_skew_tolerance = 60
        
        print(f"✅ NonceValidator initialized")
        print(f"   TTL: {ttl} seconds")
        print(f"   Max cache size: {max_cache_size}")
        print(f"   Clock skew tolerance: {self.clock_skew_tolerance} seconds")
    
    def validate_nonce(
        self,
        nonce: str,
        timestamp: float
    ) -> bool:
        """
        Validate nonce and timestamp
        
        A valid request must:
        1. Have a unique nonce (never seen before)
        2. Have a recent timestamp (within TTL window)
        3. Not have a future timestamp (accounting for clock skew)
        
        Args:
            nonce: Unique nonce string (should be cryptographically random)
            timestamp: Unix timestamp of request
        
        Returns:
            True if valid (first time seeing this nonce with valid timestamp)
            False if invalid (replay detected or timestamp issue)
        
        Example:
            import time
            import secrets
            
            nonce = secrets.token_urlsafe(32)
            timestamp = time.time()
            
            if validator.validate_nonce(nonce, timestamp):
                # Process request
                pass
            else:
                # Reject - replay attack detected
                pass
        """
        now = time.time()
        
        # 1. ✅ Check timestamp is not too old
        age = now - timestamp
        if age > self.ttl:
            print(f"❌ Nonce validation failed: timestamp too old")
            print(f"   Age: {age:.1f} seconds (max: {self.ttl})")
            return False
        
        # 2. ✅ Check timestamp is not in the future
        # Allow small clock skew between client and server
        if timestamp > (now + self.clock_skew_tolerance):
            print(f"❌ Nonce validation failed: timestamp in future")
            print(f"   Difference: {timestamp - now:.1f} seconds")
            print(f"   Possible clock attack or clock drift")
            return False
        
        # 3. ✅ Check nonce has not been seen before
        if nonce in self.nonces:
            # ❌ REPLAY ATTACK DETECTED!
            previous_timestamp = self.nonces[nonce]
            print(f"❌ REPLAY ATTACK DETECTED!")
            print(f"   Nonce: {nonce[:16]}...")
            print(f"   Original request: {previous_timestamp}")
            print(f"   Replay attempt: {timestamp}")
            print(f"   Time difference: {abs(timestamp - previous_timestamp):.1f}s")
            return False
        
        # 4. ✅ Store nonce with timestamp
        self.nonces[nonce] = timestamp
        
        # 5. ✅ Cleanup expired nonces
        self._cleanup_expired_nonces()
        
        # 6. ✅ Enforce max cache size
        if len(self.nonces) > self.max_cache_size:
            # Remove oldest 10% when cache is full
            remove_count = self.max_cache_size // 10
            for _ in range(remove_count):
                self.nonces.popitem(last=False)  # Remove oldest
        
        # ✅ Nonce validated successfully
        return True
    
    def _cleanup_expired_nonces(self):
        """
        Remove expired nonces from cache
        
        Nonces older than TTL can be safely removed as they
        would be rejected anyway.
        """
        now = time.time()
        cutoff = now - self.ttl
        
        # Find expired nonces
        expired = [
            nonce for nonce, ts in self.nonces.items()
            if ts < cutoff
        ]
        
        # Remove expired nonces
        for nonce in expired:
            del self.nonces[nonce]
        
        if expired:
            print(f"🗑️  Cleaned up {len(expired)} expired nonce(s)")
    
    def get_cache_stats(self) -> dict:
        """
        Get cache statistics
        
        Returns:
            Dictionary with cache statistics
        """
        now = time.time()
        cutoff = now - self.ttl
        
        active_count = sum(1 for ts in self.nonces.values() if ts >= cutoff)
        expired_count = len(self.nonces) - active_count
        
        return {
            "total_nonces": len(self.nonces),
            "active_nonces": active_count,
            "expired_nonces": expired_count,
            "cache_utilization": len(self.nonces) / self.max_cache_size,
            "ttl_seconds": self.ttl,
            "max_cache_size": self.max_cache_size
        }
    
    def generate_nonce(self) -> str:
        """
        Generate a cryptographically secure nonce
        
        This is a helper method for clients. The nonce should be
        generated client-side and included in each request.
        
        Returns:
            URL-safe base64 encoded random string (32 bytes = 256 bits)
        
        Example:
            nonce = validator.generate_nonce()
            # Returns: "xK9vR2mP3nL8wQ7fD6sT1hY4bN5cV0zA..."
        """
        return secrets.token_urlsafe(32)  # 256 bits of entropy


def create_signed_message_with_nonce(
    message: dict,
    secret_key: str
) -> dict:
    """
    Helper function to create a signed message with nonce
    
    This demonstrates how to properly use nonces with HMAC signatures
    for replay protection.
    
    Args:
        message: Message dictionary to sign
        secret_key: Secret key for HMAC
    
    Returns:
        Message with nonce, timestamp, and signature
    
    Example:
        message = {
            "type": "create_project",
            "project_name": "My Project"
        }
        
        signed = create_signed_message_with_nonce(message, secret_key)
        # signed now has: nonce, timestamp, signature
    """
    import json
    import hmac
    
    # ✅ Generate unique nonce
    nonce = secrets.token_urlsafe(32)
    
    # ✅ Add timestamp
    timestamp = time.time()
    
    # ✅ Add nonce and timestamp to message
    message_with_nonce = {
        **message,
        "nonce": nonce,
        "timestamp": timestamp
    }
    
    # ✅ Create HMAC signature over entire message
    message_json = json.dumps(message_with_nonce, sort_keys=True)
    signature = hmac.new(
        secret_key.encode(),
        message_json.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # ✅ Return signed message
    return {
        **message_with_nonce,
        "signature": signature
    }


if __name__ == "__main__":
    """
    Test the NonceValidator
    
    Usage:
        python -m security.nonce_validator
    """
    print("=" * 70)
    print("NonceValidator Test")
    print("=" * 70)
    
    # Create validator with short TTL for testing
    validator = NonceValidator(ttl=10)  # 10 seconds
    
    print("\n--- Test 1: Valid Nonce ---")
    nonce1 = validator.generate_nonce()
    timestamp1 = time.time()
    
    result = validator.validate_nonce(nonce1, timestamp1)
    print(f"Result: {result} (should be True)")
    
    print("\n--- Test 2: Replay Attack (Same Nonce) ---")
    result = validator.validate_nonce(nonce1, timestamp1)
    print(f"Result: {result} (should be False - replay detected)")
    
    print("\n--- Test 3: Different Nonce (Valid) ---")
    nonce2 = validator.generate_nonce()
    timestamp2 = time.time()
    
    result = validator.validate_nonce(nonce2, timestamp2)
    print(f"Result: {result} (should be True)")
    
    print("\n--- Test 4: Old Timestamp ---")
    nonce3 = validator.generate_nonce()
    old_timestamp = time.time() - 15  # 15 seconds ago (> 10 sec TTL)
    
    result = validator.validate_nonce(nonce3, old_timestamp)
    print(f"Result: {result} (should be False - too old)")
    
    print("\n--- Test 5: Future Timestamp ---")
    nonce4 = validator.generate_nonce()
    future_timestamp = time.time() + 120  # 2 minutes in future
    
    result = validator.validate_nonce(nonce4, future_timestamp)
    print(f"Result: {result} (should be False - clock attack)")
    
    print("\n--- Test 6: Expiration Test ---")
    print("Creating nonces and waiting for expiration...")
    
    for i in range(3):
        nonce = validator.generate_nonce()
        validator.validate_nonce(nonce, time.time())
    
    print(f"Nonces in cache: {len(validator.nonces)}")
    print("Waiting 11 seconds for nonces to expire...")
    time.sleep(11)
    
    # Trigger cleanup by validating new nonce
    validator.validate_nonce(validator.generate_nonce(), time.time())
    
    print(f"Nonces in cache after cleanup: {len(validator.nonces)}")
    
    print("\n--- Test 7: Cache Statistics ---")
    stats = validator.get_cache_stats()
    print(f"Cache stats: {stats}")
    
    print("\n--- Test 8: HMAC + Nonce (Proper Usage) ---")
    message = {
        "type": "create_project",
        "project_name": "Test Project"
    }
    
    secret_key = "test-secret-key-12345"
    signed_message = create_signed_message_with_nonce(message, secret_key)
    
    print("Signed message with nonce:")
    print(f"  Nonce: {signed_message['nonce'][:16]}...")
    print(f"  Timestamp: {signed_message['timestamp']}")
    print(f"  Signature: {signed_message['signature'][:16]}...")
    
    # Validate nonce
    nonce_valid = validator.validate_nonce(
        signed_message['nonce'],
        signed_message['timestamp']
    )
    print(f"  Nonce valid: {nonce_valid}")
    
    # Try to replay
    print("\nAttempting to replay same message...")
    replay_valid = validator.validate_nonce(
        signed_message['nonce'],
        signed_message['timestamp']
    )
    print(f"  Replay valid: {replay_valid} (should be False)")
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ NonceValidator prevents replay attacks")
    print("   - Each nonce can only be used once")
    print("   - Old nonces are rejected")
    print("   - Future timestamps rejected")
    print("   - Automatic cleanup")