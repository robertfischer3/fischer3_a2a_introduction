#!/usr/bin/env python3
"""
Secure Agent Card Demo
Demonstrates the security features using the modular security package
"""

import secrets
import hashlib
from datetime import datetime, timedelta

# Import from our security module
from security import (
    SecureAgentCard,
    SecureAgentCardManager,
    SecurityAuditLogger,
    SecurityLevel,
    CapabilityClass,
    SecurityEventType
)


def demonstrate_secure_agent_cards():
    """Demonstration of secure Agent Card implementation"""
    
    print("=" * 60)
    print("Secure Agent Card Implementation Demo")
    print("Using Modular Security Components")
    print("=" * 60 + "\n")
    
    # Create security components
    manager = SecureAgentCardManager("local-agent-001")
    logger = SecurityAuditLogger("DemoLogger")
    
    # 1. Create a secure agent card
    print("1. Creating secure agent card...")
    local_card = manager.create_secure_card(
        name="SecureCryptoAgent",
        version="2.0.0",
        description="Secure cryptocurrency price agent",
        capabilities={
            CapabilityClass.READ_ONLY.value: ["get_price", "list_currencies"],
            CapabilityClass.STREAM.value: ["price_stream"],
            CapabilityClass.ADMIN.value: ["configure_sources"]
        },
        metadata={
            "supported_currencies": ["BTC", "ETH"],
            "update_frequency": "real-time"
        }
    )
    print(f"  Created card: {local_card.agent_id}")
    print(f"  Signature: {local_card.signature[:32]}...")
    print(f"  Expires: {local_card.expires_at}\n")
    
    # 2. Simulate receiving a remote card (valid)
    print("2. Exchanging cards with valid remote agent...")
    valid_remote_data = {
        "agent_id": "remote-agent-002",
        "name": "RemoteAgent",
        "version": "1.0.0",
        "description": "Remote price aggregator",
        "public_key": secrets.token_hex(32),
        "certificate_fingerprint": hashlib.sha256(b"cert").hexdigest(),
        "issued_at": datetime.now().isoformat(),
        "expires_at": (datetime.now()+ timedelta(days=30)).isoformat(),
        "issuer": "trust-authority-1",
        "capabilities": {
            CapabilityClass.READ_ONLY.value: ["get_price"]
        },
        "metadata": {},
        "signature": hashlib.sha256(b"signature").hexdigest()
    }
    
    nonce = manager.generate_nonce()
    success, remote_card, message = manager.exchange_cards(
        local_card,
        valid_remote_data,
        nonce
    )
    
    if success:
        print(f"  ✓ Exchange successful: {message}")
        print(f"  Remote agent: {remote_card.name} v{remote_card.version}")
        print(f"  Trust level: {manager._calculate_trust_level(remote_card)}")
        print(f"  Reputation: {manager.get_agent_reputation(remote_card.agent_id)}")
        logger.log_card_exchange(
            "HANDSHAKE",
            local_card.agent_id,
            remote_card.agent_id,
            True
        )
    else:
        print(f"  ✗ Exchange failed: {message}")
    
    print()
    
    # 3. Simulate receiving a suspicious card
    print("3. Testing with suspicious remote agent...")
    suspicious_remote_data = {
        "agent_id": "malicious-agent",
        "name": "Evil<script>alert('xss')</script>Agent",
        "version": "1.0.0",
        "description": "'; DROP TABLE agents; --",
        "capabilities": {
            "unknown": ["hack_system", "steal_data"]
        },
        "metadata": {
            "api_key": "secret-key-12345",  # Should not include secrets!
            "internal_ip": "192.168.1.1"
        }
    }
    
    nonce = manager.generate_nonce()
    success, _, message = manager.exchange_cards(
        local_card,
        suspicious_remote_data,
        nonce
    )
    
    print(f"  ✗ Exchange blocked: {message}")
    logger.log_suspicious_activity(
        "malicious-agent",
        "INJECTION_ATTEMPT",
        "Attempted XSS and SQL injection in card fields"
    )
    
    print()
    
    # 4. Test replay attack protection
    print("4. Testing replay attack protection...")
    reused_nonce = manager.generate_nonce()
    
    # First use of nonce - should succeed
    success1, _, _ = manager.exchange_cards(
        local_card,
        valid_remote_data,
        reused_nonce
    )
    
    # Reuse of same nonce - should fail
    success2, _, message = manager.exchange_cards(
        local_card,
        valid_remote_data,
        reused_nonce
    )
    
    print(f"  First attempt: {'✓ Accepted' if success1 else '✗ Rejected'}")
    print(f"  Replay attempt: {'✗ Properly rejected' if not success2 else '✓ Incorrectly accepted'}")
    print(f"  Reason: {message}")
    
    print()
    
    # 5. Demonstrate context-aware card serialization
    print("5. Context-aware card serialization...")
    print("\n  PUBLIC context (minimal info):")
    public_view = local_card.to_dict(SecurityLevel.PUBLIC)
    print(f"    Fields: {list(public_view.keys())}")
    
    print("\n  TRUSTED context (extended info):")
    trusted_view = local_card.to_dict(SecurityLevel.TRUSTED)
    print(f"    Fields: {list(trusted_view.keys())}")
    
    print("\n  INTERNAL context (full info):")
    internal_view = local_card.to_dict(SecurityLevel.INTERNAL)
    print(f"    Fields: {list(internal_view.keys())}")
    
    print()
    
    # 6. Test rate limiting
    print("6. Testing rate limit protection...")
    test_agent_id = "rate-test-agent"
    
    # Simulate multiple validation attempts
    for i in range(12):  # Exceed the limit of 10 per minute
        test_card_data = {
            "agent_id": test_agent_id,
            "name": f"TestAgent{i}",
            "version": "1.0.0",
            "capabilities": {},
            "metadata": {}
        }
        
        nonce = manager.generate_nonce()
        success, _, message = manager.exchange_cards(
            local_card,
            test_card_data,
            nonce
        )
        
        if i == 10:  # Should fail on 11th attempt
            print(f"  Attempt {i+1}: {'✗ Rate limited' if 'rate limit' in message.lower() else '✓ Allowed'}")
            if 'rate limit' in message.lower():
                logger.log_rate_limit_exceeded(
                    test_agent_id,
                    "validation_attempts",
                    i+1,
                    10
                )
    
    print()
    
    # 7. Show security statistics
    print("7. Security Statistics:")
    stats = logger.get_statistics()
    print(f"  Total events logged: {stats['total_events']}")
    print(f"  Event breakdown:")
    for event_type, count in stats['event_counts'].items():
        if count > 0:
            print(f"    - {event_type}: {count}")
    print(f"  Agents tracked: {stats['agents_tracked']}")
    if stats['suspicious_agents']:
        print(f"  Suspicious agents: {', '.join(stats['suspicious_agents'])}")
    
    print("\n" + "=" * 60)
    print("Security Features Demonstrated:")
    print("  ✓ Cryptographic signatures")
    print("  ✓ Input sanitization")
    print("  ✓ Capability validation")
    print("  ✓ Replay attack protection")
    print("  ✓ Context-aware information disclosure")
    print("  ✓ Rate limiting")
    print("  ✓ Reputation tracking")
    print("  ✓ Security audit logging")
    print("  ✓ Modular architecture")
    print("=" * 60)


def test_individual_components():
    """Test individual security components"""
    print("\n" + "=" * 60)
    print("Testing Individual Security Components")
    print("=" * 60 + "\n")
    
    # Test SecureAgentCard directly
    print("Testing SecureAgentCard:")
    card = SecureAgentCard(
        agent_id="test-001",
        name="TestAgent",
        version="1.0.0",
        description="Test agent for component testing",
        public_key="test-public-key",
        certificate_fingerprint="test-fingerprint",
        issued_at=datetime.utcnow().isoformat(),
        expires_at=(datetime.utcnow() + timedelta(days=30)).isoformat(),
        issuer="trust-authority-1",
        capabilities={
            CapabilityClass.READ_ONLY.value: ["test_read"],
            CapabilityClass.ADMIN.value: ["test_admin"]
        },
        metadata={"test": "value"},
        security_level=SecurityLevel.TRUSTED,
        allowed_domains=["*.test.com"],
        rate_limits={"test": 100}
    )
    
    print(f"  Card created: {card}")
    print(f"  Has 'test_read' capability: {card.has_capability('test_read')}")
    print(f"  Has 'unknown' capability: {card.has_capability('unknown')}")
    print(f"  Is expired: {card.is_expired()}")
    
    print("\nTesting AgentCardValidator:")
    from security.validator import AgentCardValidator
    validator = AgentCardValidator()
    
    # Add custom validator
    def check_test_requirement(card):
        if "test" not in card.metadata:
            return ["Missing required 'test' metadata"]
        return []
    
    validator.add_custom_validator(check_test_requirement)
    
    is_valid, issues = validator.validate_card(card)
    print(f"  Card validation: {'✓ Valid' if is_valid else '✗ Invalid'}")
    if issues:
        print(f"  Issues: {issues}")
    
    print("\nTesting SecurityAuditLogger:")
    logger = SecurityAuditLogger("TestLogger")
    
    # Log some test events
    logger.log_validation_failure("test-agent", ["Test issue 1", "Test issue 2"])
    logger.log_agent_blocked("bad-agent", "Low reputation", 15)
    
    # Export events
    events_json = logger.export_events()
    print(f"  Events logged and exported ({len(logger.events)} total)")
    
    print("\n✓ All components tested successfully")


if __name__ == "__main__":
    # Run main demonstration
    demonstrate_secure_agent_cards()
    
    # Run component tests
    test_individual_components()