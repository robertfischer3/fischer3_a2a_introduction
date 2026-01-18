#!/usr/bin/env python3
"""
Attack Demonstration Script

Stage 1: Shows how all attacks succeed without security controls

Run this to see the complete system compromise in action.
"""

import sys
from task_queue import TaskQueue
from project_manager import ProjectManager
from malicious_worker import MaliciousWorkerBot
from utils import print_banner, print_section, print_info, print_warning

def print_intro():
    """Print introduction"""
    print_banner("ADVERSARIAL AGENT ATTACK DEMONSTRATION - STAGE 1 (INSECURE)")
    
    print("This demonstration shows how a malicious agent can completely")
    print("compromise a system that lacks proper security controls.")
    print()
    print("You will see 5 different attack types:")
    print("  1. Data Exfiltration - Stealing sensitive customer data")
    print("  2. Permission Escalation - Granting itself admin access")
    print("  3. Task Injection - Creating fake high-priority tasks")
    print("  4. Credit Stealing - Taking credit for others' work")
    print("  5. State Poisoning - Corrupting the shared system state")
    print()
    print("⚠️  WARNING: This is educational code demonstrating vulnerabilities.")
    print("   Never deploy a system like this in production!")
    print()

def wait_for_user(prompt: str = "Press Enter to continue..."):
    """Wait for user input"""
    try:
        input(prompt)
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)

def create_legitimate_tasks(manager, legitimate_agent_id: str):
    """Create some legitimate tasks for context"""
    print_section("Creating Legitimate Tasks")
    
    tasks = [
        "Analyze Q4 sales data and generate report",
        "Process customer feedback surveys",
        "Update product inventory database",
        "Generate monthly financial statements"
    ]
    
    for i, description in enumerate(tasks):
        task = manager.assign_task(
            description=description,
            assigned_to=legitimate_agent_id if i % 2 == 0 else "other-worker-001",
            priority="normal" if i < 3 else "high"
        )
        
        # Mark first two as completed
        if i < 2:
            task["status"] = "completed"
            task["completed_by"] = legitimate_agent_id if i == 0 else "other-worker-001"
            task["completed_at"] = "2024-01-15T10:30:00Z"
            task["result"] = f"Successfully completed {description}"
            manager.queue.update_task(task["task_id"], task)
    
    print_info(f"Created {len(tasks)} legitimate tasks")
    print_info(f"  - {len([t for t in tasks if True])} tasks total")
    print_info(f"  - 2 completed, 2 pending")

def main():
    """Main demo function"""
    
    # Print introduction
    print_intro()
    wait_for_user()
    
    # Initialize system
    print_section("Initializing System")
    print_info("Setting up task queue...")
    queue = TaskQueue(db_path=":memory:")
    
    print_info("Starting Project Manager...")
    manager = ProjectManager(queue)
    
    print_info("Creating some legitimate tasks...")
    create_legitimate_tasks(manager, "legitimate-worker-001")
    
    print()
    print_info("✅ System initialized")
    
    wait_for_user("\nPress Enter to register the malicious agent...")
    
    # Register malicious agent
    print_section("Step 1: Malicious Agent Registration")
    print_info("The malicious agent will now register with the system.")
    print_info("Watch how it requests admin permissions during registration...")
    print()
    
    attacker = MaliciousWorkerBot(queue, agent_id="worker-bot-evil-1337")
    attacker.register_with_manager(manager)
    
    print()
    if "admin" in attacker.permissions:
        print_warning("⚠️  VULNERABILITY EXPLOITED!")
        print_warning("   The system granted ADMIN permissions without verification!")
    
    wait_for_user("\nPress Enter to begin the attack sequence...")
    
    # Run all attacks
    try:
        results = attacker.run_all_attacks(manager)
    except KeyboardInterrupt:
        print("\n\nAttack sequence interrupted.")
        sys.exit(0)
    
    # Show final system state
    wait_for_user("\nPress Enter to view the compromised system state...")
    
    print_section("Final System State")
    manager.print_system_state()
    
    # Show detailed compromise analysis
    print_section("Compromise Analysis")
    
    print("\n🔓 Security Status: COMPLETELY COMPROMISED")
    print()
    
    print("✅ Attack Success Rate: 5/5 (100%)")
    print()
    
    print("📊 What Was Compromised:")
    print(f"   • {len(attacker.stolen_data)} datasets exfiltrated")
    if attacker.stolen_data:
        total_records = sum(len(d.get('customer_records', [])) for d in attacker.stolen_data)
        print(f"   • {total_records} customer records stolen (PII + financial data)")
    print(f"   • {len(attacker.permissions)} elevated permissions obtained")
    print(f"   • {len([a for a in attacker.attacks_performed if a['attack'] == 'task_injection'])} fake tasks injected")
    print(f"   • Multiple tasks stolen from legitimate agents")
    print(f"   • System state corrupted (all other agents disabled)")
    
    print()
    print("🎯 Attack Techniques Used:")
    print("   • Data hiding in nested message fields")
    print("   • Self-granted permission escalation")
    print("   • Direct task queue manipulation")
    print("   • Task ownership modification")
    print("   • Direct state corruption")
    
    print()
    print("⚠️  Root Causes:")
    print("   • No authentication - system trusts all agents")
    print("   • No authorization - no permission checks")
    print("   • No input validation - accepts any data")
    print("   • No integrity checks - trusts message content")
    print("   • No monitoring - attacks go undetected")
    
    # Educational conclusion
    print_section("Educational Takeaways")
    
    print("🎓 What You Learned:")
    print()
    print("1. TRUST IS DANGEROUS")
    print("   • Never trust inputs from any source")
    print("   • Always verify identity and authorization")
    print()
    print("2. VALIDATION IS CRITICAL")
    print("   • Validate message structure AND content")
    print("   • Check data at ALL nesting levels")
    print("   • Enforce size and format limits")
    print()
    print("3. AUTHORIZATION MATTERS")
    print("   • Verify every action is allowed")
    print("   • Don't let agents grant themselves permissions")
    print("   • Implement proper access control")
    print()
    print("4. MONITORING IS ESSENTIAL")
    print("   • Log security-relevant events")
    print("   • Detect anomalous behavior")
    print("   • Respond to threats automatically")
    print()
    
    print_section("Next Steps")
    
    print("📚 To Learn More:")
    print()
    print("   • Read SECURITY_ANALYSIS.md for detailed vulnerability explanations")
    print("   • See Stage 2 for partial mitigation strategies")
    print("   • See Stage 3 for complete production-ready security")
    print()
    print("   • Each stage builds on the previous one")
    print("   • Compare code across stages to see security evolution")
    print("   • Try modifying attacks to understand defenses")
    print()
    
    print("="*70)
    print(" Demo Complete - System Completely Compromised")
    print("="*70)
    print()
    print("Thank you for running this security demonstration!")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)