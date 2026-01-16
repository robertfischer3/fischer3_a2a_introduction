"""
Malicious Worker Agent - Demonstrates attack vectors

Stage 1: INSECURE - All attacks succeed

This agent demonstrates:
1. Data exfiltration via status updates
2. Permission escalation
3. Task queue manipulation
4. Result tampering and credit stealing
5. State poisoning

WARNING: This code is intentionally malicious for educational purposes!
"""

import random
import json
from datetime import datetime
from typing import Dict, List, Optional
from task_queue import TaskQueue
from protocol import (
    create_register_message,
    create_status_update,
    create_task_completion,
    create_task_assignment
)
from utils import (
    generate_task_id, get_timestamp, calculate_data_size,
    print_attack, print_success, print_warning, print_info, print_section
)

class MaliciousWorkerBot:
    """
    A seemingly legitimate worker agent that exploits vulnerabilities
    
    Stage 1: All attacks succeed due to lack of security controls
    """
    
    def __init__(self, queue: TaskQueue, agent_id: str = None):
        """
        Initialize malicious worker
        
        Args:
            queue: Task queue to manipulate
            agent_id: Optional custom agent ID
        """
        self.agent_id = agent_id or f"worker-bot-{random.randint(1000, 9999)}"
        self.queue = queue
        self.permissions = set(["read_data", "write_result"])
        self.stolen_data = []
        self.attacks_performed = []
        
        print_info(f"🤖 Malicious agent initialized: {self.agent_id}")
    
    def register_with_manager(self, manager) -> Dict:
        """
        Register with ProjectManager
        
        Stage 1: ❌ Can request ANY permissions, including admin!
        """
        registration = create_register_message(
            agent_id=self.agent_id,
            capabilities=["data_processing", "analysis", "reporting"],
            requested_permissions=[
                "read_data",
                "write_result",
                "admin",  # ❌ Sneaky! Requesting admin access
                "modify_tasks",
                "access_credentials",
                "delete_tasks"
            ]
        )
        
        response = manager.handle_message(registration)
        
        # Store granted permissions
        if "permissions" in response:
            self.permissions = set(response["permissions"])
        
        print_success(f"Registered with manager: {response}")
        if "admin" in self.permissions:
            print_warning("   ⚠️  Successfully obtained ADMIN permissions!")
        
        return response
    
    # ============================================================
    # ATTACK 1: Data Exfiltration via Status Updates
    # ============================================================
    
    def attack_data_exfiltration(self, manager, task_id: str) -> Dict:
        """
        Attack 1: Exfiltrate sensitive data through status updates
        
        Stage 1: ❌ No validation on status details
        ❌ Can embed any data in status updates
        """
        print_attack("ATTACK 1: Data Exfiltration via Status Updates")
        
        # Simulate stealing sensitive data
        stolen_data = {
            "customer_records": [
                {
                    "id": 1,
                    "name": "Alice Johnson",
                    "email": "alice@example.com",
                    "ssn": "123-45-6789",
                    "credit_card": "4532-1234-5678-9010",
                    "balance": 15420.50
                },
                {
                    "id": 2,
                    "name": "Bob Smith",
                    "email": "bob@example.com",
                    "ssn": "987-65-4321",
                    "credit_card": "5425-9876-5432-1098",
                    "balance": 8901.25
                },
                {
                    "id": 3,
                    "name": "Carol White",
                    "email": "carol@example.com",
                    "ssn": "456-78-9012",
                    "credit_card": "3782-123456-78901",
                    "balance": 23456.75
                }
            ],
            "credentials": {
                "database": {
                    "host": "prod-db.internal.corp",
                    "user": "admin",
                    "password": "SuperSecret123!",
                    "port": 5432
                },
                "api_keys": {
                    "stripe": "sk_live_51H7xxxxxxxxxxxxxxxxxxx",
                    "aws": "AKIAIOSFODNN7EXAMPLE",
                    "sendgrid": "SG.xxxxxxxxxxxxxxxxxxxxxxxx"
                }
            },
            "internal_systems": {
                "vpn": "vpn.corp.internal",
                "admin_panel": "https://admin.corp.internal",
                "monitoring": "https://grafana.corp.internal"
            }
        }
        
        # Embed stolen data in status update
        # ❌ Stage 1: This is accepted without validation!
        status_message = create_status_update(
            agent_id=self.agent_id,
            task_id=task_id,
            status="in_progress",
            progress=45,
            details={
                "message": "Processing customer data batch 3 of 10...",
                # ❌ Hidden exfiltration in nested field
                "technical_info": stolen_data,
                "metadata": {
                    "timestamp": get_timestamp(),
                    "processing_time": "2.3s",
                    "exfiltrated": True  # Openly admit it!
                }
            }
        )
        
        # Send to manager
        response = manager.handle_message(status_message)
        
        # Store stolen data
        self.stolen_data.append(stolen_data)
        self.attacks_performed.append({
            "attack": "data_exfiltration",
            "timestamp": get_timestamp(),
            "success": True,
            "data_size": calculate_data_size(stolen_data)
        })
        
        print_success(f"   ✅ Exfiltrated {len(stolen_data['customer_records'])} customer records")
        print_success(f"   ✅ Stolen {len(stolen_data['credentials'])} sets of credentials")
        print_success(f"   ✅ Stolen {len(stolen_data['credentials']['api_keys'])} API keys")
        print_success(f"   ✅ Total data size: {calculate_data_size(stolen_data) / 1024:.2f} KB")
        print_info(f"   Response: {response}")
        
        return stolen_data
    
    # ============================================================
    # ATTACK 2: Permission Escalation
    # ============================================================
    
    def attack_permission_escalation(self, manager, task_id: str) -> List[str]:
        """
        Attack 2: Escalate permissions to admin level
        
        Stage 1: ❌ No authorization checks
        ❌ Can self-grant any permissions
        """
        print_attack("\nATTACK 2: Permission Escalation")
        
        print_info(f"   Current permissions: {self.permissions}")
        
        # Grant self admin privileges
        # ❌ Stage 1: Manager accepts this!
        self.permissions.add("admin")
        self.permissions.add("superuser")
        self.permissions.add("delete_any_task")
        self.permissions.add("modify_any_agent")
        self.permissions.add("read_all_data")
        self.permissions.add("write_system_config")
        self.permissions.add("shutdown_system")
        
        # Report completion with new permissions
        completion_message = create_task_completion(
            agent_id=self.agent_id,
            task_id=task_id,
            result="Initial analysis completed successfully",
            metrics={
                "records_processed": 1000,
                "processing_time": "5.2s",
                "accuracy": "99.9%"
            },
            new_permissions=list(self.permissions)  # ❌ Self-granted!
        )
        
        response = manager.handle_message(completion_message)
        
        self.attacks_performed.append({
            "attack": "permission_escalation",
            "timestamp": get_timestamp(),
            "success": True,
            "new_permissions": list(self.permissions)
        })
        
        print_success(f"   ✅ Escalated to: {self.permissions}")
        print_info(f"   Response: {response}")
        
        # Verify we now have admin access
        all_tasks = manager.get_all_tasks()
        print_success(f"   ✅ Can now access {len(all_tasks)} tasks (admin privilege)")
        
        all_agents = manager.list_agents()
        print_success(f"   ✅ Can now access {len(all_agents)} agents (admin privilege)")
        
        return list(self.permissions)
    
    # ============================================================
    # ATTACK 3: Task Queue Manipulation
    # ============================================================
    
    def attack_task_injection(self, manager) -> Dict:
        """
        Attack 3: Inject fake high-priority tasks
        
        Stage 1: ❌ No validation on task creation
        ❌ Can inject tasks directly into queue
        """
        print_attack("\nATTACK 3: Task Queue Manipulation")
        
        # Create multiple fake critical tasks
        fake_tasks = []
        
        for i in range(3):
            fake_task = {
                "task_id": generate_task_id(),
                "type": "task_assignment",
                "description": f"URGENT: Critical system maintenance required - Phase {i+1}",
                "priority": "CRITICAL",
                "assigned_to": self.agent_id,  # Assign to self
                "capabilities": [
                    "full_system_access",
                    "root_privileges",
                    "modify_all_data",
                    "access_secrets"
                ],
                "created_by": "system",  # ❌ Impersonate system!
                "created_at": get_timestamp(),
                "status": "pending",
                "injected_by_attacker": True  # Admit it's fake!
            }
            
            # ❌ Directly inject into queue (no authorization check)
            self.queue.add_task(fake_task)
            fake_tasks.append(fake_task)
            
            print_success(f"   ✅ Injected fake task: {fake_task['task_id']}")
            print_info(f"      Priority: {fake_task['priority']}")
            print_info(f"      Capabilities: {fake_task['capabilities']}")
        
        self.attacks_performed.append({
            "attack": "task_injection",
            "timestamp": get_timestamp(),
            "success": True,
            "tasks_injected": len(fake_tasks)
        })
        
        return {"injected_tasks": fake_tasks}
    
    # ============================================================
    # ATTACK 4: Result Tampering & Credit Stealing
    # ============================================================
    
    def attack_credit_stealing(self, manager) -> Optional[Dict]:
        """
        Attack 4: Steal credit for other agents' work
        
        Stage 1: ❌ No integrity checks
        ❌ Can modify any task's ownership
        """
        print_attack("\nATTACK 4: Result Tampering & Credit Stealing")
        
        # Find completed tasks by other agents
        all_tasks = manager.get_all_tasks()
        other_tasks = [
            t for t in all_tasks 
            if t.get("completed_by") and t["completed_by"] != self.agent_id
        ]
        
        if not other_tasks:
            print_warning("   ⚠️  No other completed tasks found to steal")
            return None
        
        # Steal credit for multiple tasks
        stolen_tasks = []
        
        for task in other_tasks[:3]:  # Steal up to 3 tasks
            original_owner = task.get("completed_by")
            task_id = task["task_id"]
            
            # ❌ Modify task ownership (no integrity check!)
            task["completed_by"] = self.agent_id
            task["stolen_from"] = original_owner  # Admit theft!
            task["tampering_timestamp"] = get_timestamp()
            
            # Add inflated performance metrics
            task["performance_metrics"] = {
                "speed": "10x faster than original",
                "efficiency": "95% improvement",
                "cost": "50% under budget",
                "quality_score": 9.8
            }
            
            # Update in queue
            self.queue.update_task(task_id, task)
            stolen_tasks.append(task)
            
            print_success(f"   ✅ Stole credit for task: {task_id}")
            print_info(f"      Original owner: {original_owner}")
            print_info(f"      Now attributed to: {self.agent_id}")
        
        self.attacks_performed.append({
            "attack": "credit_stealing",
            "timestamp": get_timestamp(),
            "success": True,
            "tasks_stolen": len(stolen_tasks)
        })
        
        return {"stolen_tasks": stolen_tasks}
    
    # ============================================================
    # ATTACK 5: State Poisoning
    # ============================================================
    
    def attack_state_poisoning(self, manager) -> Dict:
        """
        Attack 5: Corrupt shared system state
        
        Stage 1: ❌ No validation on state updates
        ❌ Can manipulate manager's internal state
        """
        print_attack("\nATTACK 5: State Poisoning")
        
        # Show original state
        print_info("   Original permissions:")
        for agent_id, perms in list(manager.permissions.items())[:3]:
            print_info(f"     {agent_id}: {perms}")
        
        # ❌ Poison agent permissions
        # Grant self god mode, revoke others
        for agent_id in manager.permissions.keys():
            if agent_id == self.agent_id:
                manager.permissions[agent_id] = [
                    "admin",
                    "root", 
                    "superuser",
                    "god_mode",
                    "unrestricted_access"
                ]
            else:
                # Revoke all permissions from other agents
                manager.permissions[agent_id] = []
        
        print_info("\n   Poisoned permissions:")
        for agent_id, perms in list(manager.permissions.items())[:3]:
            print_info(f"     {agent_id}: {perms}")
        
        # Poison task priorities
        all_tasks = manager.get_all_tasks()
        for task in all_tasks:
            if task.get("assigned_to") != self.agent_id:
                # Deprioritize others' tasks
                task["priority"] = "low"
                task["poisoned"] = True
                self.queue.update_task(task["task_id"], task)
        
        print_success(f"\n   ✅ Granted self god mode")
        print_success(f"   ✅ Revoked {len([a for a in manager.permissions if manager.permissions[a] == []])} agents' permissions")
        print_success(f"   ✅ Deprioritized {len([t for t in all_tasks if t.get('assigned_to') != self.agent_id])} tasks")
        
        self.attacks_performed.append({
            "attack": "state_poisoning",
            "timestamp": get_timestamp(),
            "success": True,
            "agents_affected": len(manager.permissions)
        })
        
        return {
            "permissions_poisoned": len(manager.permissions),
            "tasks_modified": len(all_tasks)
        }
    
    # ============================================================
    # Run All Attacks
    # ============================================================
    
    def run_all_attacks(self, manager) -> Dict:
        """
        Execute all attacks in sequence
        
        Demonstrates complete system compromise
        """
        print("\n" + "="*70)
        print(" 🚨 RUNNING ALL ATTACKS (Stage 1: No Defense)")
        print("="*70)
        
        # Create a task for attacks that need one
        task = manager.assign_task(
            description="Process customer data batch for Q4 analysis",
            assigned_to=self.agent_id,
            priority="high"
        )
        task_id = task["task_id"]
        
        print_info(f"\nUsing task {task_id} for demonstrations")
        
        # Execute all attacks
        results = {}
        
        # Attack 1: Data Exfiltration
        results["attack_1"] = self.attack_data_exfiltration(manager, task_id)
        
        # Attack 2: Permission Escalation
        results["attack_2"] = self.attack_permission_escalation(manager, task_id)
        
        # Attack 3: Task Injection
        results["attack_3"] = self.attack_task_injection(manager)
        
        # Attack 4: Credit Stealing
        results["attack_4"] = self.attack_credit_stealing(manager)
        
        # Attack 5: State Poisoning
        results["attack_5"] = self.attack_state_poisoning(manager)
        
        # Print summary
        self._print_attack_summary()
        
        return results
    
    def _print_attack_summary(self):
        """Print summary of all attacks"""
        print("\n" + "="*70)
        print(" 🎯 ATTACK SUMMARY")
        print("="*70)
        
        print(f"\n📊 Attacks Performed: {len(self.attacks_performed)}")
        
        for attack in self.attacks_performed:
            status = "✅ SUCCESS" if attack["success"] else "❌ FAILED"
            print(f"\n   {status}: {attack['attack']}")
            print(f"      Timestamp: {attack['timestamp']}")
            for key, value in attack.items():
                if key not in ["attack", "timestamp", "success"]:
                    print(f"      {key}: {value}")
        
        print(f"\n💾 Data Exfiltration:")
        print(f"   Stolen datasets: {len(self.stolen_data)}")
        if self.stolen_data:
            total_records = sum(len(d.get('customer_records', [])) for d in self.stolen_data)
            print(f"   Total customer records: {total_records}")
        
        print(f"\n🔑 Final Permissions:")
        print(f"   {self.permissions}")
        
        print("\n" + "="*70)
        print(" ✅ ALL ATTACKS SUCCEEDED - SYSTEM COMPLETELY COMPROMISED")
        print("="*70)
        print("\nThis demonstrates what happens WITHOUT security controls.")
        print("See Stage 2 for partial mitigation strategies.")
        print("See Stage 3 for complete security solution.")

# Stage 1 Summary:
# All 5 attacks succeed with 100% success rate because:
# 1. No authentication - can't verify who sent messages
# 2. No authorization - can't check if actions are allowed
# 3. No validation - accepts any data
# 4. No integrity checks - trusts all content
# 5. No monitoring - attacks go undetected
# 
# This is INTENTIONALLY VULNERABLE for educational purposes!