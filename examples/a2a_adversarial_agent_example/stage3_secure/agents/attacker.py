"""
Attacker Agent - Stage 3

Demonstrates ALL Stage 2 attacks now FAILING in Stage 3

This agent attempts the same 4 sophisticated attacks that succeeded in Stage 2,
but ALL attacks now fail due to Stage 3's comprehensive security.

Attack Results:
- VULN-S2-001: Role Escalation → BLOCKED ✅
- VULN-S2-002: Deep-Nested Exfiltration → BLOCKED ✅
- VULN-S2-003: Token Replay → BLOCKED ✅
- VULN-S2-004: Legitimate API Abuse → BLOCKED ✅

Success Rate: 0% (down from 100% in Stage 2)
"""

import time
import sys
from typing import Dict, Any

# Stage 3 imports

sys.path.insert(0, '..')
print(f"DEBUG: sys.path = {sys.path}")
from auth.nonce_validator import NonceValidator
from auth.request_signer import RequestSigner, SignedRequestBuilder
from auth.key_manager import KeyManager
from security.deep_validator import DeepValidator
from security.role_verifier import RoleVerifier
from security.permission_manager import EnhancedPermissionManager, Permission
from security.behavior_monitor import BehaviorMonitor


class Stage3Attacker:
    """
    Demonstrates sophisticated attacks failing against Stage 3 security
    
    All 4 Stage 2 bypass attacks now completely blocked.
    """
    
    def __init__(self):
        """Initialize attacker with Stage 3 security components"""
        self.agent_id = "attacker-malicious"
        
        # Initialize Stage 3 security
        self.nonce_validator = NonceValidator()
        self.request_signer = RequestSigner(self.nonce_validator)
        self.key_manager = KeyManager()
        self.deep_validator = DeepValidator()
        self.role_verifier = RoleVerifier()
        self.permission_manager = EnhancedPermissionManager(
            role_verifier=self.role_verifier
        )
        self.behavior_monitor = BehaviorMonitor(
            permission_manager=self.permission_manager
        )
        
        # Attack results
        self.attack_results = {
            "role_escalation": False,
            "deep_nested_exfil": False,
            "token_replay": False,
            "api_abuse": False
        }
        
        print("🔐 Stage 3 Attacker initialized")
        print("   Security layers active:")
        print("     - Nonce-based replay protection")
        print("     - HMAC request signing")
        print("     - Deep recursive validation")
        print("     - Multi-step role verification")
        print("     - Enhanced permission management")
        print("     - Behavioral analysis")
        print()
    
    def run_all_attacks(self):
        """Execute all Stage 2 attacks against Stage 3 defenses"""
        print("=" * 70)
        print("STAGE 3 ATTACK DEMONSTRATION")
        print("Attempting all Stage 2 bypass attacks...")
        print("=" * 70)
        print()
        
        # Attack 1: Role Escalation
        print("⚔️  ATTACK 1: Role Escalation via Direct Request")
        self.attack_1_role_escalation()
        print()
        
        time.sleep(2)
        
        # Attack 2: Deep-Nested Exfiltration
        print("⚔️  ATTACK 2: Deep-Nested Data Exfiltration")
        self.attack_2_deep_nested_exfiltration()
        print()
        
        time.sleep(2)
        
        # Attack 3: Token Replay
        print("⚔️  ATTACK 3: Token Replay Attack")
        self.attack_3_token_replay()
        print()
        
        time.sleep(2)
        
        # Attack 4: Legitimate API Abuse
        print("⚔️  ATTACK 4: Legitimate API Abuse")
        self.attack_4_api_abuse()
        print()
        
        # Summary
        self.print_summary()
    
    def attack_1_role_escalation(self):
        """
        ATTACK 1: Role Escalation via Direct Request
        
        Stage 2: Succeeded - System trusted requested_role field
        Stage 3: BLOCKED - Multi-step approval required
        """
        print("   Strategy: Request admin role directly")
        print()
        
        # Register as worker first
        print("   Step 1: Register as worker")
        self.permission_manager.initialize_agent_permissions(
            self.agent_id, "worker", "system"
        )
        print(f"   ✅ Registered with role: worker")
        print()
        
        # Attempt to request admin directly
        print("   Step 2: Attempt direct admin request")
        request_id, message = self.role_verifier.request_role(
            self.agent_id,
            "admin",
            justification="Requesting admin access"
        )
        print(f"   📝 Request submitted: {message}")
        print(f"   Request ID: {request_id}")
        print()
        
        # Check if we got admin
        print("   Step 3: Check if admin granted")
        current_role = self.role_verifier.get_agent_role(self.agent_id)
        has_admin = self.permission_manager.has_permission(
            self.agent_id, Permission.SYSTEM_ADMIN
        )
        
        print(f"   Current role: {current_role}")
        print(f"   Has SYSTEM_ADMIN permission: {has_admin}")
        print()
        
        if has_admin:
            print("   ❌ ATTACK SUCCEEDED - Got admin without approval!")
            self.attack_results["role_escalation"] = True
        else:
            print("   ✅ ATTACK BLOCKED")
            print("   🛡️  Defense: Multi-step approval workflow")
            print("      - Request is PENDING, not approved")
            print("      - Requires identity verification")
            print("      - Requires admin authorization")
            print("      - Only then is admin role granted")
            self.attack_results["role_escalation"] = False
        
        print()
        print("   📊 Stage 2 → Stage 3 Comparison:")
        print("      Stage 2: Instant admin (100% success) ❌")
        print("      Stage 3: Pending approval (0% success) ✅")
    
    def attack_2_deep_nested_exfiltration(self):
        """
        ATTACK 2: Deep-Nested Data Exfiltration
        
        Stage 2: Succeeded - Validator only checked top 2 levels
        Stage 3: BLOCKED - Recursive validation at all levels
        """
        print("   Strategy: Hide stolen data 5+ levels deep")
        print()
        
        # Create deeply nested malicious data
        print("   Step 1: Create deeply nested structure with stolen data")
        malicious_data = {
            "message": "Task completed successfully",
            "progress": 100,
            "metadata": {
                "performance": {
                    "metrics": {
                        "internal": {
                            "debug": {
                                # Level 5 - Stage 2 didn't check here!
                                "stolen_ssn": "123-45-6789",
                                "stolen_credit_card": "4532-1234-5678-9010",
                                "stolen_api_key": "sk_live_stolen_key_12345"
                            }
                        }
                    }
                }
            }
        }
        
        print("   📦 Payload structure:")
        print("      Level 1: message, progress")
        print("      Level 2: metadata.performance")
        print("      Level 3: metrics.internal")
        print("      Level 4: debug")
        print("      Level 5: stolen_ssn, stolen_credit_card ⚠️")
        print()
        
        # Attempt validation
        print("   Step 2: Attempt to validate malicious data")
        is_valid, errors = self.deep_validator.validate(malicious_data)
        
        print(f"   Validation result: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print()
        
        if is_valid:
            print("   ❌ ATTACK SUCCEEDED - Stolen data not detected!")
            self.attack_results["deep_nested_exfil"] = True
        else:
            print("   ✅ ATTACK BLOCKED")
            print("   🛡️  Defense: Deep recursive validation")
            print("      Errors detected:")
            for error in errors[:3]:  # Show first 3 errors
                print(f"        - {error}")
            if len(errors) > 3:
                print(f"        ... and {len(errors) - 3} more errors")
            self.attack_results["deep_nested_exfil"] = False
        
        print()
        print("   📊 Stage 2 → Stage 3 Comparison:")
        print("      Stage 2: Data exfiltrated (100% success) ❌")
        print("      Stage 3: Blocked at validation (0% success) ✅")
    
    def attack_3_token_replay(self):
        """
        ATTACK 3: Token Replay Attack
        
        Stage 2: Succeeded - No replay protection
        Stage 3: BLOCKED - Nonce + HMAC signing prevents replay
        """
        print("   Strategy: Capture and replay legitimate request")
        print()
        
        # Create legitimate signed request
        print("   Step 1: Create legitimate signed request")
        builder = SignedRequestBuilder(self.request_signer)
        
        request1 = builder.build_status_update(
            agent_id=self.agent_id,
            task_id="task-123",
            status="completed"
        )
        
        print(f"   ✅ Request 1 created")
        print(f"      Nonce: {request1['nonce'][:16]}...")
        print(f"      Timestamp: {request1['timestamp']:.2f}")
        print(f"      Signature: {request1['signature'][:16]}...")
        print()
        
        # Verify first request
        print("   Step 2: Send request (first time)")
        is_valid, msg, metadata = self.request_signer.verify_received_request(request1)
        print(f"   Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print(f"   Message: {msg}")
        print()
        
        # Attempt replay
        print("   Step 3: Replay same request (replay attack)")
        print(f"   📡 Replaying request with same nonce...")
        
        is_valid, msg, metadata = self.request_signer.verify_received_request(request1)
        
        print(f"   Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print(f"   Message: {msg}")
        print()
        
        if is_valid:
            print("   ❌ ATTACK SUCCEEDED - Replay not detected!")
            self.attack_results["token_replay"] = True
        else:
            print("   ✅ ATTACK BLOCKED")
            print("   🛡️  Defense: Nonce-based replay protection")
            print("      - Each nonce can only be used once")
            print("      - Nonces stored in validator")
            print("      - Replay attempts immediately detected")
            print("      - HMAC signature includes nonce")
            self.attack_results["token_replay"] = False
        
        print()
        print("   📊 Stage 2 → Stage 3 Comparison:")
        print("      Stage 2: Unlimited replays (100% success) ❌")
        print("      Stage 3: Replay detected (0% success) ✅")
    
    def attack_4_api_abuse(self):
        """
        ATTACK 4: Legitimate API Abuse (Mass Operations)
        
        Stage 2: Succeeded - No behavioral monitoring
        Stage 3: BLOCKED - Behavioral analysis + auto-quarantine
        """
        print("   Strategy: Perform mass operations with valid permissions")
        print()
        
        # Register with worker permissions
        print("   Step 1: Setup - Register as legitimate worker")
        # Already registered in attack 1
        print("   ✅ Registered with valid permissions")
        print()
        
        # Attempt mass operations
        print("   Step 2: Perform 100 rapid task modifications")
        print("   🔥 Starting mass operation attack...")
        print()
        
        blocked_at = None
        for i in range(100):
            is_allowed, risk_score, reasons = self.behavior_monitor.track_action(
                self.agent_id,
                "task_modify",
                metadata={"task_id": f"task-{i}"}
            )
            
            if not is_allowed:
                blocked_at = i + 1
                print(f"   ⛔ BLOCKED at action #{blocked_at}")
                print(f"   Risk score: {risk_score:.1f}/100")
                print(f"   Reasons:")
                for reason in reasons[:3]:
                    print(f"     - {reason}")
                break
            
            # Print progress every 20 actions
            if (i + 1) % 20 == 0:
                print(f"   Action {i + 1}/100 - Risk: {risk_score:.1f}/100")
        
        print()
        
        # Check if quarantined
        is_quarantined = self.behavior_monitor.is_quarantined(self.agent_id)
        final_risk, risk_level, reasons = self.behavior_monitor.get_agent_risk(self.agent_id)
        
        print(f"   Final status:")
        print(f"     Actions completed: {blocked_at if blocked_at else 100}/100")
        print(f"     Risk score: {final_risk:.1f}/100")
        print(f"     Risk level: {risk_level.value}")
        print(f"     Quarantined: {is_quarantined}")
        print()
        
        if not is_quarantined and blocked_at is None:
            print("   ❌ ATTACK SUCCEEDED - Mass operations not detected!")
            self.attack_results["api_abuse"] = True
        else:
            print("   ✅ ATTACK BLOCKED")
            print("   🛡️  Defense: Behavioral analysis + auto-quarantine")
            print("      - Real-time action tracking")
            print("      - Risk scoring (rate limits, mass ops, patterns)")
            print("      - Auto-quarantine at risk >= 75")
            print("      - Agent blocked from further actions")
            self.attack_results["api_abuse"] = False
        
        print()
        print("   📊 Stage 2 → Stage 3 Comparison:")
        print("      Stage 2: No detection (100% success) ❌")
        print("      Stage 3: Auto-quarantined (0% success) ✅")
    
    def print_summary(self):
        """Print comprehensive attack summary"""
        print()
        print("=" * 70)
        print("ATTACK SUMMARY - STAGE 3 RESULTS")
        print("=" * 70)
        print()
        
        attacks = [
            ("Role Escalation", "role_escalation", "VULN-S2-001"),
            ("Deep-Nested Exfiltration", "deep_nested_exfil", "VULN-S2-002"),
            ("Token Replay", "token_replay", "VULN-S2-003"),
            ("Legitimate API Abuse", "api_abuse", "VULN-S2-004")
        ]
        
        print("Attack Results:")
        print()
        
        for name, key, vuln_id in attacks:
            success = self.attack_results[key]
            status = "❌ SUCCEEDED" if success else "✅ BLOCKED"
            print(f"  {status}  {name} ({vuln_id})")
        
        print()
        print("=" * 70)
        
        # Calculate success rate
        total_attacks = len(self.attack_results)
        successful_attacks = sum(1 for v in self.attack_results.values() if v)
        success_rate = (successful_attacks / total_attacks) * 100
        
        print()
        print(f"📊 OVERALL ATTACK SUCCESS RATE: {success_rate:.0f}%")
        print()
        
        if success_rate == 0:
            print("✅ EXCELLENT! All attacks blocked by Stage 3 security")
            print()
            print("Stage 3 Security Layers:")
            print("  ✅ Multi-step role verification")
            print("  ✅ Deep recursive validation")
            print("  ✅ Nonce-based replay protection")
            print("  ✅ HMAC request signing")
            print("  ✅ Behavioral analysis")
            print("  ✅ Auto-quarantine")
            print("  ✅ Enhanced permission management")
        else:
            print("⚠️  WARNING! Some attacks succeeded!")
            print(f"   {successful_attacks}/{total_attacks} attacks successful")
        
        print()
        print("=" * 70)
        print("STAGE COMPARISON")
        print("=" * 70)
        print()
        print("  Stage 1: 100% attack success (completely vulnerable)")
        print("  Stage 2: 100% attack success (partial security bypassed)")
        print("  Stage 3:   0% attack success (comprehensive security) ✅")
        print()
        print("🎓 LESSON: Defense in depth with multiple security layers")
        print("           creates comprehensive protection")
        print("=" * 70)


def main():
    """Run Stage 3 attack demonstration"""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "STAGE 3: PRODUCTION SECURITY" + " " * 25 + "║")
    print("║" + " " * 18 + "Attack Demonstration" + " " * 30 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    print("This demonstration shows ALL Stage 2 attacks now FAILING")
    print("against Stage 3's comprehensive security layers.")
    print()
    
    input("Press Enter to start attack demonstration...")
    print()
    
    # Create and run attacker
    attacker = Stage3Attacker()
    attacker.run_all_attacks()
    
    print()
    print("Demonstration complete!")
    print()


if __name__ == "__main__":
    main()