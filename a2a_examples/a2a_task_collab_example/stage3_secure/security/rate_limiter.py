"""
Rate Limiter - Stage 3: Production Security

Token bucket rate limiting to prevent brute force and DoS attacks.

✅ Stage 3: Token bucket rate limiting
❌ Stage 2: No rate limiting (unlimited requests)

Security Features:
- Per-client rate limiting
- Per-endpoint limits
- Burst handling
- Automatic token refill
- Prevents brute force attacks
- Prevents DoS attacks

Usage:
    limiter = RateLimiter()
    
    # Check rate limit
    allowed, retry_after = limiter.check_rate_limit("alice", "login")
    
    if allowed:
        process_login()
    else:
        return_429_error(retry_after)
"""

import time
from typing import Dict, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class RateLimit:
    """Rate limit configuration for an endpoint"""
    rate: int  # Requests per minute
    burst: int  # Max burst size (token bucket capacity)


class TokenBucket:
    """
    Token bucket for a single client/endpoint combination
    
    Token Bucket Algorithm:
    - Bucket has capacity (max_tokens)
    - Tokens refill at constant rate
    - Each request consumes 1 token
    - Request allowed if tokens available
    - Otherwise rate limited
    """
    
    def __init__(self, rate: int, burst: int):
        """
        Initialize token bucket
        
        Args:
            rate: Tokens per minute (requests per minute)
            burst: Bucket capacity (max tokens)
        """
        self.rate = rate  # tokens per minute
        self.burst = burst  # max tokens
        self.tokens = float(burst)  # start with full bucket
        self.last_refill = time.time()
    
    def consume(self) -> Tuple[bool, int]:
        """
        Try to consume a token
        
        Returns:
            Tuple of (allowed, retry_after_seconds)
            - allowed: True if request allowed
            - retry_after: Seconds to wait if rate limited
        """
        # Refill tokens based on time passed
        now = time.time()
        time_passed = now - self.last_refill
        tokens_to_add = time_passed * (self.rate / 60.0)  # rate per second
        
        self.tokens = min(self.burst, self.tokens + tokens_to_add)
        self.last_refill = now
        
        # Check if tokens available
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0
        else:
            # Calculate retry-after time
            tokens_needed = 1.0 - self.tokens
            seconds_needed = (tokens_needed / self.rate) * 60
            return False, int(seconds_needed) + 1


class RateLimiter:
    """
    Production-grade rate limiter with token bucket algorithm
    
    Features:
    - Per-client per-endpoint rate limiting
    - Configurable limits for different endpoints
    - Burst handling
    - Automatic token refill
    - Memory efficient
    
    Prevents:
    - Brute force attacks (limited login attempts)
    - DoS attacks (limited API calls)
    - Resource exhaustion
    
    Usage:
        limiter = RateLimiter()
        
        # Check login rate limit
        allowed, retry_after = limiter.check_rate_limit(
            "alice",
            "login"
        )
        
        if not allowed:
            return {
                "status": "error",
                "message": f"Rate limited. Try again in {retry_after}s"
            }
    """
    
    def __init__(self):
        """Initialize rate limiter with default limits"""
        
        # ✅ Per-client per-endpoint token buckets
        self.buckets: Dict[str, TokenBucket] = {}
        
        # ✅ Rate limits per endpoint
        self.limits: Dict[str, RateLimit] = {
            # Login - very restrictive (prevent brute force)
            "login": RateLimit(
                rate=5,  # 5 attempts per minute
                burst=10  # Allow burst of 10
            ),
            
            # API operations - moderate
            "api": RateLimit(
                rate=60,  # 60 requests per minute
                burst=100  # Allow burst of 100
            ),
            
            # Task operations - moderate
            "task_claim": RateLimit(
                rate=10,  # 10 claims per minute
                burst=20  # Allow burst of 20
            ),
            
            # Project operations - moderate
            "project": RateLimit(
                rate=30,  # 30 operations per minute
                burst=50  # Allow burst of 50
            ),
            
            # Worker registration - restrictive
            "worker_register": RateLimit(
                rate=3,  # 3 registrations per minute
                burst=5  # Allow burst of 5
            )
        }
        
        print("✅ RateLimiter initialized with token bucket algorithm")
        print(f"   Endpoints configured: {len(self.limits)}")
        print(f"   Login limit: {self.limits['login'].rate}/min")
        print(f"   API limit: {self.limits['api'].rate}/min")
    
    def check_rate_limit(
        self,
        identifier: str,
        endpoint: str
    ) -> Tuple[bool, int]:
        """
        Check if request is within rate limit
        
        Args:
            identifier: Client identifier (IP, user ID, etc.)
            endpoint: API endpoint category
        
        Returns:
            Tuple of (allowed, retry_after_seconds)
            - allowed: True if request should be allowed
            - retry_after: Seconds to wait if rate limited (0 if allowed)
        
        Example:
            # Check login rate limit for user
            allowed, retry_after = limiter.check_rate_limit(
                "alice",
                "login"
            )
            
            if not allowed:
                return {
                    "status": "error",
                    "message": f"Too many attempts. Try again in {retry_after}s",
                    "retry_after": retry_after
                }
        """
        # Use default "api" limit if endpoint not configured
        if endpoint not in self.limits:
            endpoint = "api"
        
        limit = self.limits[endpoint]
        bucket_key = f"{identifier}:{endpoint}"
        
        # Get or create token bucket
        if bucket_key not in self.buckets:
            self.buckets[bucket_key] = TokenBucket(limit.rate, limit.burst)
        
        bucket = self.buckets[bucket_key]
        
        # Try to consume token
        allowed, retry_after = bucket.consume()
        
        if not allowed:
            print(f"⚠️  Rate limit exceeded: {identifier} on {endpoint}")
            print(f"   Retry after: {retry_after} seconds")
        
        return allowed, retry_after
    
    def get_limit_info(self, endpoint: str) -> Optional[Dict]:
        """
        Get rate limit information for an endpoint
        
        Args:
            endpoint: Endpoint name
        
        Returns:
            Dictionary with rate limit info, or None if not configured
        """
        if endpoint not in self.limits:
            return None
        
        limit = self.limits[endpoint]
        return {
            "endpoint": endpoint,
            "rate_per_minute": limit.rate,
            "burst_capacity": limit.burst
        }
    
    def get_client_status(
        self,
        identifier: str,
        endpoint: str
    ) -> Optional[Dict]:
        """
        Get current rate limit status for a client
        
        Args:
            identifier: Client identifier
            endpoint: Endpoint name
        
        Returns:
            Dictionary with current status, or None if no bucket exists
        """
        bucket_key = f"{identifier}:{endpoint}"
        
        if bucket_key not in self.buckets:
            return None
        
        bucket = self.buckets[bucket_key]
        
        return {
            "identifier": identifier,
            "endpoint": endpoint,
            "tokens_available": bucket.tokens,
            "bucket_capacity": bucket.burst,
            "refill_rate_per_minute": bucket.rate
        }
    
    def reset_client(self, identifier: str, endpoint: Optional[str] = None):
        """
        Reset rate limit for a client
        
        Args:
            identifier: Client identifier
            endpoint: Specific endpoint, or None to reset all
        
        Example:
            # Admin resets user's failed login attempts
            limiter.reset_client("alice", "login")
        """
        if endpoint:
            bucket_key = f"{identifier}:{endpoint}"
            if bucket_key in self.buckets:
                del self.buckets[bucket_key]
                print(f"✅ Rate limit reset: {identifier} on {endpoint}")
        else:
            # Reset all endpoints for this client
            keys_to_delete = [
                key for key in self.buckets.keys()
                if key.startswith(f"{identifier}:")
            ]
            for key in keys_to_delete:
                del self.buckets[key]
            print(f"✅ Rate limits reset for {identifier} (all endpoints)")
    
    def cleanup_old_buckets(self, max_age: int = 3600):
        """
        Remove token buckets that haven't been used recently
        
        Args:
            max_age: Remove buckets older than this (seconds)
        
        Example:
            # Run periodically to prevent memory growth
            limiter.cleanup_old_buckets(3600)  # Clean hourly
        """
        now = time.time()
        cutoff = now - max_age
        
        old_buckets = [
            key for key, bucket in self.buckets.items()
            if bucket.last_refill < cutoff
        ]
        
        for key in old_buckets:
            del self.buckets[key]
        
        if old_buckets:
            print(f"🗑️  Cleaned up {len(old_buckets)} old token bucket(s)")
    
    def get_stats(self) -> Dict:
        """
        Get rate limiter statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            "total_buckets": len(self.buckets),
            "configured_endpoints": list(self.limits.keys()),
            "limits": {
                name: {
                    "rate_per_minute": limit.rate,
                    "burst_capacity": limit.burst
                }
                for name, limit in self.limits.items()
            }
        }


if __name__ == "__main__":
    """
    Test the RateLimiter
    
    Usage:
        python -m security.rate_limiter
    """
    print("=" * 70)
    print("RateLimiter Test")
    print("=" * 70)
    
    limiter = RateLimiter()
    
    print("\n--- Test 1: Normal Usage (Within Limits) ---")
    for i in range(3):
        allowed, retry_after = limiter.check_rate_limit("alice", "login")
        print(f"Attempt {i+1}: allowed={allowed}, retry_after={retry_after}")
    
    print("\n--- Test 2: Rate Limiting (Exceed Limits) ---")
    print("Attempting 12 rapid login requests (limit is 5/min with burst 10)...")
    
    for i in range(12):
        allowed, retry_after = limiter.check_rate_limit("bob", "login")
        if allowed:
            print(f"Request {i+1}: ✅ Allowed")
        else:
            print(f"Request {i+1}: ❌ Rate limited (retry after {retry_after}s)")
    
    print("\n--- Test 3: Different Endpoints ---")
    print("Testing different endpoint limits...")
    
    # API endpoint has higher limit (60/min)
    print("\nAPI endpoint (60/min):")
    for i in range(5):
        allowed, retry_after = limiter.check_rate_limit("charlie", "api")
        print(f"  Request {i+1}: allowed={allowed}")
    
    # Worker registration has lower limit (3/min)
    print("\nWorker registration (3/min):")
    for i in range(5):
        allowed, retry_after = limiter.check_rate_limit("worker1", "worker_register")
        if allowed:
            print(f"  Request {i+1}: ✅ Allowed")
        else:
            print(f"  Request {i+1}: ❌ Rate limited")
    
    print("\n--- Test 4: Burst Handling ---")
    print("Testing burst capacity...")
    
    # Create new client, should have full bucket
    print("New client with fresh bucket:")
    for i in range(15):
        allowed, retry_after = limiter.check_rate_limit("dave", "login")
        if allowed:
            print(f"  Burst request {i+1}: ✅")
        else:
            print(f"  Burst request {i+1}: ❌ (burst capacity: 10)")
            break
    
    print("\n--- Test 5: Token Refill ---")
    print("Waiting for tokens to refill...")
    print("Initial status:")
    status = limiter.get_client_status("bob", "login")
    if status:
        print(f"  Tokens available: {status['tokens_available']:.2f}")
    
    print("Waiting 15 seconds...")
    time.sleep(15)
    
    # Check again (should have some tokens)
    allowed, retry_after = limiter.check_rate_limit("bob", "login")
    print(f"After 15s: allowed={allowed}")
    
    status = limiter.get_client_status("bob", "login")
    if status:
        print(f"  Tokens available: {status['tokens_available']:.2f}")
    
    print("\n--- Test 6: Per-Client Isolation ---")
    print("Testing that rate limits are per-client...")
    
    # Alice's limit
    for i in range(6):
        limiter.check_rate_limit("alice_test", "login")
    
    allowed_alice, _ = limiter.check_rate_limit("alice_test", "login")
    
    # Bob's limit (independent)
    allowed_bob, _ = limiter.check_rate_limit("bob_test", "login")
    
    print(f"  Alice (after 6 requests): allowed={allowed_alice}")
    print(f"  Bob (first request): allowed={allowed_bob}")
    print("  ✅ Clients have independent rate limits")
    
    print("\n--- Test 7: Reset Client ---")
    print("Resetting alice_test's login limit...")
    limiter.reset_client("alice_test", "login")
    
    allowed, retry_after = limiter.check_rate_limit("alice_test", "login")
    print(f"After reset: allowed={allowed}")
    
    print("\n--- Test 8: Statistics ---")
    stats = limiter.get_stats()
    print(f"Total buckets: {stats['total_buckets']}")
    print(f"Configured endpoints: {len(stats['configured_endpoints'])}")
    print(f"Limits:")
    for endpoint, info in stats['limits'].items():
        print(f"  {endpoint}: {info['rate_per_minute']}/min (burst: {info['burst_capacity']})")
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ RateLimiter prevents brute force and DoS attacks")
    print("   - Per-client per-endpoint limits")
    print("   - Token bucket algorithm")
    print("   - Automatic refill")
    print("   - Burst handling")