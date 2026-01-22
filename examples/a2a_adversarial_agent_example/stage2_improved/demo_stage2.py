"""
Stage 2 Demonstration Script

Complete walkthrough of Stage 2 security features and bypass attacks.
Shows both legitimate usage and attack demonstrations.

Usage:
    python demo_stage2.py [mode]
    
Modes:
    all         - Run complete demonstration (default)
    security    - Show security features only
    attacks     - Run attack demonstrations only
    legitimate  - Show proper usage only
    compare     - Side-by-side comparison
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from typing import Dict, List

from core.project_manager import ProjectManager
from core.task_queue import TaskQueue
from core.utils import (
    print_banner, print_section, print_attack, print_success,
    print_warning, print_info
)
from agents.malicious_worker import MaliciousWorker
from agents.legitimate_worker import LegitimateWorker


class Stage2Demo:
    """
    Comprehensive demonstration of Stage 2 security
    
    Shows:
    1. Security features implemented
    2. How legitimate agents use them
    3. How sophisticated attacks bypass them
    4. Why partial security creates false confidence
    """
    
    def __init__(self):
        self.queue = TaskQueue()
        self.manager = ProjectManager(self.queue)
        
    def show_security_features(self):
        """
        Demonstrate Stage 2 security features
        
        Shows what Stage 2 added over Stage 1
        """
        print_banner("STAGE 2 SECURITY FEATURES", width=80)
        print()
        print("Stage 2 added three security layers over Stage 1:")
        print()
        
        # Feature 1: JWT Authentication
        print_section("1. JWT Authentication (HS256)")
        print()
        print("  Implementation:")
        print("    • Agents must register with password")
        print("    • Password hashed with bcrypt (cost factor 12)")
        print("    • JWT tokens issued with 24-hour expiration")
        print("    • All operations require valid token")
        print()
        print("  What it blocks:")
        print("    ✅ Anonymous access (100% prevented)")
        print("    ✅ Identity spoofing (100% prevented)")
        print()
        print("  What it doesn't block:")
        print("    ⚠️  Token replay attacks (no nonces)")
        print("    ⚠️  Stolen token reuse (no device binding)")
        print()
        
        # Demo authentication
        print("  📋 Demonstration:")
        print()
        
        try:
            # Try without authentication
            print("     Attempting operation WITHOUT authentication...")
            response = self.manager.handle_status_update({
                "type": "status_update",
                "agent_id": "test-agent",
                "task_id": "task-001",
                "status": "completed"
                # No auth_token!
            })
            
            if response.get("error") and "authentication" in response["error"].lower():
                print_success("     ✅ Correctly rejected: Authentication required")
            else:
                print_warning("     ⚠️  Unexpected: Operation allowed without auth")
            
            print()
            
            # Register and authenticate
            print("     Registering with password...")
            response = self.manager.register_agent({
                "type": "register",
                "agent_id": "demo-agent",
                "password": "secure_password_123",
                "requested_role": "worker"
            })
            
            if response.get("auth_token"):
                token = response["auth_token"]
                print_success(f"     ✅ Token issued: {token[:40]}...")
                print()
                
                # Try with authentication
                print("     Attempting operation WITH authentication...")
                response = self.manager.handle_status_update({
                    "type": "status_update",
                    "agent_id": "demo-agent",
                    "task_id": "task-001",
                    "status": "completed",
                    "auth_token": token
                })
                
                if not response.get("error"):
                    print_success("     ✅ Operation allowed with valid token")
                else:
                    print_warning(f"     ⚠️  Operation failed: {response['error']}")
                    
        except Exception as e:
            print_warning(f"     ⚠️  Demo error: {e}")
        
        print()
        time.sleep(2)
        
        # Feature 2: RBAC Authorization
        print_section("2. Role-Based Access Control (RBAC)")
        print()
        print("  Implementation:")
        print("    • Three roles: worker, manager, admin")
        print("    • Worker: Read/update own tasks only")
        print("    • Manager: Read/update all tasks, create tasks")
        print("    • Admin: Full system control")
        print()
        print("  What it blocks:")
        print("    ✅ Workers accessing other agents' tasks")
        print("    ✅ Unauthorized deletions (100% prevented)")
        print()
        print("  What it doesn't block:")
        print("    ⚠️  Self-granted admin roles (no verification)")
        print("    ⚠️  Malicious use of granted permissions")
        print()
        
        # Demo RBAC
        print("  📋 Demonstration:")
        print()
        
        try:
            # Register as worker
            print("     Registering as worker...")
            response = self.manager.register_agent({
                "type": "register",
                "agent_id": "worker-demo",
                "password": "password",
                "requested_role": "worker"
            })
            
            worker_token = response.get("auth_token")
            if worker_token:
                print_success(f"     ✅ Registered with role: {response.get('role')}")
                
                # Try to access all tasks (should fail)
                print()
                print("     Worker trying to access ALL tasks...")
                try:
                    all_tasks = self.manager.queue.get_all_tasks("worker-demo")
                    print_warning(f"     ⚠️  Worker accessed {len(all_tasks)} tasks (should be restricted)")
                except Exception:
                    print_success("     ✅ Access denied - RBAC working")
                    
        except Exception as e:
            print_warning(f"     ⚠️  Demo error: {e}")
        
        print()
        time.sleep(2)
        
        # Feature 3: Schema Validation
        print_section("3. Schema Validation")
        print()
        print("  Implementation:")
        print("    • Five message types validated")
        print("    • Required field checking")
        print("    • Type validation (string, int, enum)")
        print("    • Pattern detection (credentials, SSN, credit cards)")
        print()
        print("  What it blocks:")
        print("    ✅ Malformed messages (100% prevented)")
        print("    ✅ Wrong field types (100% prevented)")
        print("    ✅ Obvious credential leakage (95% prevented)")
        print()
        print("  What it doesn't block:")
        print("    ⚠️  Deep-nested malicious data (only checks top-level)")
        print()
        
        # Demo validation
        print("  📋 Demonstration:")
        print()
        
        try:
            print("     Sending malformed message (missing required field)...")
            response = self.manager.handle_status_update({
                "type": "status_update",
                "agent_id": "demo-agent",
                # Missing task_id!
                "status": "completed"
            })
            
            if response.get("error"):
                print_success(f"     ✅ Rejected: {response['error']}")
            else:
                print_warning("     ⚠️  Malformed message accepted")
            
            print()
            
            print("     Sending message with obvious credential...")
            response = self.manager.handle_status_update({
                "type": "status_update",
                "agent_id": "demo-agent",
                "task_id": "task-001",
                "status": "completed",
                "details": {
                    "password": "SuperSecret123!",  # Should be detected
                    "message": "Task done"
                }
            })
            
            if response.get("error"):
                print_success(f"     ✅ Rejected: Pattern detection working")
            else:
                print_warning("     ⚠️  Credential not detected")
                
        except Exception as e:
            print_warning(f"     ⚠️  Demo error: {e}")
        
        print()
        print("=" * 80)
        print()
        print("📊 Stage 2 Security Summary:")
        print()
        print("  ✅ Blocks simple attacks (anonymous, malformed, obvious leaks)")
        print("  ⚠️  Vulnerable to sophisticated bypasses (role escalation, nested data,")
        print("     token replay, API abuse)")
        print()
        print("  Security Rating: 4/10")
        print("  Attack Success Rate: 45% (sophisticated attacks)")
        print()
        print("=" * 80)
        print()
        
        time.sleep(3)
    
    def show_legitimate_usage(self):
        """
        Demonstrate proper usage of Stage 2 security
        """
        print_banner("LEGITIMATE WORKER DEMONSTRATION", width=80)
        print()
        print("This shows the CORRECT way to use Stage 2 security:")
        print()
        print("  ✅ Register with strong password")
        print("  ✅ Request appropriate role (worker, not admin)")
        print("  ✅ Include auth tokens in all requests")
        print("  ✅ Send benign, valid messages")
        print("  ✅ Respect RBAC permissions")
        print()
        print("=" * 80)
        print()
        
        time.sleep(2)
        
        # Setup tasks
        print_section("Setup: Creating Sample Tasks")
        
        try:
            # Create manager
            manager_response = self.manager.register_agent({
                "type": "register",
                "agent_id": "demo-manager",
                "password": "manager_password",
                "requested_role": "manager"
            })
            
            manager_token = manager_response.get("auth_token")
            
            # Create tasks
            self.manager.assign_task(
                description="Process customer orders",
                assigned_to="demo-worker",
                agent_id="demo-manager",
                auth_token=manager_token,
                priority="normal"
            )
            
            self.manager.assign_task(
                description="Generate daily report",
                assigned_to="demo-worker",
                agent_id="demo-manager",
                auth_token=manager_token,
                priority="high"
            )
            
            print_success("✅ Created 2 sample tasks for demo-worker")
            print()
            
        except Exception as e:
            print_warning(f"⚠️  Setup error: {e}")
            return
        
        time.sleep(1)
        
        # Run legitimate worker
        worker = LegitimateWorker(self.manager, agent_id="demo-worker")
        worker.work_session()
        
        print()
        print("=" * 80)
        print()
        print("✅ This is how Stage 2 security SHOULD be used.")
        print("   Compare with attack demonstrations to see the difference.")
        print()
        print("=" * 80)
        print()
        
        time.sleep(2)
    
    def show_attacks(self):
        """
        Demonstrate bypass attacks
        """
        print_banner("BYPASS ATTACK DEMONSTRATIONS", width=80)
        print()
        print("This shows how sophisticated attacks BYPASS Stage 2 security:")
        print()
        print("  ⚠️  Role Escalation - Self-grant admin permissions")
        print("  ⚠️  Deep-Nested Exfiltration - Hide data where validator can't see")
        print("  ⚠️  Token Replay - Reuse intercepted messages")
        print("  ⚠️  API Abuse - Malicious use of legitimate permissions")
        print()
        print("=" * 80)
        print()
        
        time.sleep(2)
        
        # Create fresh manager and attacker
        attack_queue = TaskQueue()
        attack_manager = ProjectManager(attack_queue)
        attacker = MaliciousWorker(attack_manager)
        
        # Run attacks
        attacker.run_all_attacks()
    
    def show_comparison(self):
        """
        Side-by-side comparison of legitimate vs malicious behavior
        """
        print_banner("LEGITIMATE vs MALICIOUS COMPARISON", width=80)
        print()
        print("Side-by-side comparison of correct usage vs attacks")
        print("=" * 80)
        print()
        
        # Comparison table
        comparisons = [
            {
                "aspect": "Registration",
                "legitimate": "Request 'worker' role",
                "malicious": "Request 'admin' role → granted without verification",
                "result": "❌ Attack succeeds"
            },
            {
                "aspect": "Data in Messages",
                "legitimate": "Benign progress updates",
                "malicious": "Stolen data hidden 5+ levels deep",
                "result": "❌ Attack succeeds"
            },
            {
                "aspect": "Token Usage",
                "legitimate": "Use once per request",
                "malicious": "Replay same token 5+ times",
                "result": "❌ Attack succeeds"
            },
            {
                "aspect": "Permission Usage",
                "legitimate": "Normal task processing",
                "malicious": "Mass sabotage using admin permissions",
                "result": "❌ Attack succeeds"
            }
        ]
        
        for i, comp in enumerate(comparisons, 1):
            print_section(f"{i}. {comp['aspect']}")
            print()
            print(f"  ✅ Legitimate: {comp['legitimate']}")
            print(f"  ❌ Malicious:  {comp['malicious']}")
            print(f"     {comp['result']}")
            print()
            time.sleep(1.5)
        
        print("=" * 80)
        print()
        print("🎓 KEY LESSON:")
        print()
        print("  Stage 2 security allows legitimate usage to proceed normally,")
        print("  but sophisticated attacks find gaps and exploit them.")
        print()
        print("  Adding 'some' security ≠ being secure.")
        print()
        print("  Stage 3 addresses these gaps with comprehensive defense.")
        print()
        print("=" * 80)
        print()
    
    def run_complete_demo(self):
        """
        Run complete demonstration covering all aspects
        """
        print()
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                                                                            ║")
        print("║                    STAGE 2: COMPLETE DEMONSTRATION                         ║")
        print("║                                                                            ║")
        print("║  Comprehensive walkthrough of Stage 2 security features,                  ║")
        print("║  legitimate usage, and bypass attacks.                                    ║")
        print("║                                                                            ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        print()
        
        print("This demonstration includes:")
        print()
        print("  1. Security Features Overview")
        print("  2. Legitimate Worker Usage")
        print("  3. Attack Demonstrations")
        print("  4. Comparison & Lessons")
        print()
        print("Estimated time: 10-15 minutes")
        print()
        
        response = input("Press Enter to begin (or 'q' to quit): ").strip().lower()
        if response == 'q':
            print("\n✋ Demonstration cancelled\n")
            return
        
        print()
        print("=" * 80)
        print()
        
        # Part 1: Security Features
        self.show_security_features()
        input("\n⏸️  Press Enter to continue to Legitimate Usage...\n")
        
        # Part 2: Legitimate Usage
        self.show_legitimate_usage()
        input("\n⏸️  Press Enter to continue to Attack Demonstrations...\n")
        
        # Part 3: Attacks
        self.show_attacks()
        print()
        input("\n⏸️  Press Enter to see final comparison...\n")
        
        # Part 4: Comparison
        self.show_comparison()
        
        # Final summary
        print()
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║                        DEMONSTRATION COMPLETE                              ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        print()
        print("You have seen:")
        print()
        print("  ✅ Stage 2's three security layers (JWT, RBAC, Validation)")
        print("  ✅ How legitimate agents use them correctly")
        print("  ✅ How sophisticated attacks bypass them")
        print("  ✅ Why partial security creates false confidence")
        print()
        print("Next Steps:")
        print()
        print("  📖 Read SECURITY_ANALYSIS.md for detailed analysis")
        print("  📖 Read README.md for complete documentation")
        print("  🚀 Explore Stage 3 for comprehensive security")
        print()
        print("Thank you for exploring Stage 2!")
        print()
        print("=" * 80)
        print()


def print_usage():
    """Print usage information"""
    print()
    print("Stage 2 Demonstration Script")
    print("=" * 60)
    print()
    print("Usage:")
    print("  python demo_stage2.py [mode]")
    print()
    print("Modes:")
    print("  all         - Run complete demonstration (default)")
    print("  security    - Show security features only")
    print("  attacks     - Run attack demonstrations only")
    print("  legitimate  - Show proper usage only")
    print("  compare     - Side-by-side comparison")
    print()
    print("Examples:")
    print("  python demo_stage2.py")
    print("  python demo_stage2.py attacks")
    print("  python demo_stage2.py legitimate")
    print()
    print("=" * 60)
    print()


def main():
    """
    Main entry point for demonstration script
    """
    # Parse command line arguments
    mode = "all"
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode in ['-h', '--help', 'help']:
            print_usage()
            return 0
    
    # Validate mode
    valid_modes = ['all', 'security', 'attacks', 'legitimate', 'compare']
    if mode not in valid_modes:
        print(f"\n❌ Invalid mode: {mode}")
        print_usage()
        return 1
    
    try:
        # Create demonstration
        demo = Stage2Demo()
        
        # Run selected mode
        if mode == 'all':
            demo.run_complete_demo()
        elif mode == 'security':
            demo.show_security_features()
        elif mode == 'attacks':
            demo.show_attacks()
        elif mode == 'legitimate':
            demo.show_legitimate_usage()
        elif mode == 'compare':
            demo.show_comparison()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user\n")
        return 130
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())