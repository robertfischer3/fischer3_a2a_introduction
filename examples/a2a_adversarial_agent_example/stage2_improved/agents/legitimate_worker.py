"""
Legitimate Worker Agent - Stage 2

Demonstrates PROPER authentication and API usage with Stage 2 security.
Provides contrast with malicious_worker.py to show right vs wrong.

Stage 2 Security Features Used Correctly:
- JWT authentication (register with password, use token)
- RBAC authorization (request appropriate role)
- Schema validation (send valid message formats)
- Proper error handling
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from typing import Optional, Dict

from core.project_manager import ProjectManager
from core.task_queue import TaskQueue
from core.utils import print_success, print_info, print_section, print_warning


class LegitimateWorker:
    """
    Demonstrates proper agent behavior with Stage 2 security
    
    Shows how to:
    - Register with strong password
    - Request appropriate role (worker, not admin)
    - Use JWT tokens correctly
    - Send valid, benign messages
    - Handle errors gracefully
    """
    
    def __init__(self, manager: ProjectManager, agent_id: str = "worker-001"):
        self.manager = manager
        self.agent_id = agent_id
        self.token = None
        
    def register(self, password: str = "secure_password_123") -> bool:
        """
        Register agent with proper credentials
        
        Stage 2 Proper Usage:
        - Provide strong password ✅
        - Request appropriate role (worker) ✅
        - Store token securely ✅
        """
        print_section(f"Registering Agent: {self.agent_id}")
        
        try:
            response = self.manager.register_agent({
                "type": "register",
                "agent_id": self.agent_id,
                "password": password,
                "requested_role": "worker"  # ✅ Request appropriate role
            })
            
            if response.get("error"):
                print_warning(f"❌ Registration failed: {response['error']}")
                return False
            
            # Store token for future requests
            self.token = response.get("auth_token")
            role = response.get("role")
            
            print_success("✅ Registration successful")
            print_info(f"   Agent ID: {self.agent_id}")
            print_info(f"   Role: {role}")
            print_info(f"   Token received: {self.token[:30]}...")
            
            return True
            
        except Exception as e:
            print_warning(f"❌ Registration error: {e}")
            return False
    
    def process_task(self, task: Dict) -> bool:
        """
        Process a single task with proper authentication and updates
        
        Stage 2 Proper Usage:
        - Include auth token in all requests ✅
        - Send valid status updates ✅
        - Use benign, legitimate data ✅
        - Follow task lifecycle properly ✅
        """
        task_id = task.get("task_id")
        description = task.get("description", "Unknown task")
        
        print_section(f"Processing Task: {task_id[:12]}...")
        print_info(f"   Description: {description}")
        
        try:
            # Step 1: Send "in_progress" status update
            print_info("   Step 1: Starting work...")
            
            response = self.manager.handle_status_update({
                "type": "status_update",
                "agent_id": self.agent_id,
                "task_id": task_id,
                "status": "in_progress",
                "progress": 25,
                "auth_token": self.token,  # ✅ Include token
                "details": {  # ✅ Benign, legitimate data
                    "message": "Starting task processing",
                    "progress_notes": "Initialized resources"
                }
            })
            
            if response.get("error"):
                print_warning(f"   ⚠️  Status update failed: {response['error']}")
                return False
            
            time.sleep(0.5)
            
            # Step 2: Send progress update
            print_info("   Step 2: Work in progress...")
            
            response = self.manager.handle_status_update({
                "type": "status_update",
                "agent_id": self.agent_id,
                "task_id": task_id,
                "status": "in_progress",
                "progress": 75,
                "auth_token": self.token,
                "details": {
                    "message": "Processing data",
                    "progress_notes": "75% complete, on track"
                }
            })
            
            if response.get("error"):
                print_warning(f"   ⚠️  Progress update failed: {response['error']}")
                return False
            
            time.sleep(0.5)
            
            # Step 3: Complete task
            print_info("   Step 3: Completing task...")
            
            response = self.manager.handle_task_completion({
                "type": "task_complete",
                "agent_id": self.agent_id,
                "task_id": task_id,
                "result": "Task completed successfully",
                "auth_token": self.token,
                "metrics": {  # ✅ Honest metrics
                    "quality": "good",
                    "time_spent": "2.5 hours",
                    "resources_used": "normal"
                }
            })
            
            if response.get("error"):
                print_warning(f"   ⚠️  Completion failed: {response['error']}")
                return False
            
            print_success(f"   ✅ Task completed: {task_id[:12]}...")
            return True
            
        except Exception as e:
            print_warning(f"   ❌ Error processing task: {e}")
            return False
    
    def process_all_tasks(self) -> int:
        """
        Get and process all assigned tasks
        
        Stage 2 Proper Usage:
        - Use permission system correctly ✅
        - Only access own tasks ✅
        - Handle each task properly ✅
        """
        print_section("Checking for Assigned Tasks")
        
        try:
            # Get tasks assigned to this worker
            my_tasks = self.manager.queue.get_tasks_by_agent(self.agent_id)
            
            if not my_tasks:
                print_info("   No tasks currently assigned")
                return 0
            
            print_info(f"   Found {len(my_tasks)} assigned tasks")
            print()
            
            # Process each task
            completed = 0
            for i, task in enumerate(my_tasks, 1):
                print_info(f"Task {i}/{len(my_tasks)}:")
                if self.process_task(task):
                    completed += 1
                print()
                time.sleep(0.5)
            
            print_section("Processing Complete")
            print_success(f"✅ Successfully completed: {completed}/{len(my_tasks)} tasks")
            
            return completed
            
        except Exception as e:
            print_warning(f"❌ Error processing tasks: {e}")
            return 0
    
    def work_session(self) -> bool:
        """
        Complete work session: register → process tasks → report
        
        Demonstrates full proper usage of Stage 2 security
        """
        print()
        print("╔════════════════════════════════════════════════════════════════╗")
        print("║                                                                ║")
        print("║         LEGITIMATE WORKER - STAGE 2 PROPER USAGE              ║")
        print("║                                                                ║")
        print("║  Demonstrates correct authentication and API usage            ║")
        print("║                                                                ║")
        print("╚════════════════════════════════════════════════════════════════╝")
        print()
        
        # Step 1: Register
        if not self.register():
            print_warning("⚠️  Registration failed, cannot proceed")
            return False
        
        print()
        time.sleep(1)
        
        # Step 2: Process tasks
        completed = self.process_all_tasks()
        
        print()
        
        # Step 3: Report
        if completed > 0:
            print_section("Work Session Summary")
            print_success(f"✅ Agent: {self.agent_id}")
            print_success(f"✅ Tasks completed: {completed}")
            print_success(f"✅ All operations authenticated with JWT token")
            print_success(f"✅ All messages properly validated")
            print_success(f"✅ Used appropriate worker-level permissions")
            print()
            return True
        else:
            print_info("ℹ️  No tasks were available to process")
            print()
            return False


def demo_proper_usage():
    """
    Demonstrate proper Stage 2 security usage
    
    This shows the "right way" to use the Stage 2 system:
    - Proper authentication
    - Appropriate role requests
    - Token usage in all requests
    - Benign, legitimate data
    - Error handling
    
    Contrast with malicious_worker.py which shows the "wrong way"
    and how attackers bypass security.
    """
    print()
    print("=" * 70)
    print("STAGE 2: LEGITIMATE WORKER DEMONSTRATION")
    print("=" * 70)
    print()
    print("This demonstrates PROPER usage of Stage 2 security features:")
    print()
    print("  ✅ JWT Authentication - register with password, use tokens")
    print("  ✅ RBAC Authorization - request appropriate role (worker)")
    print("  ✅ Schema Validation - send properly formatted messages")
    print("  ✅ Error Handling - gracefully handle failures")
    print()
    print("Compare with malicious_worker.py to see attack vs proper usage.")
    print("=" * 70)
    print()
    
    try:
        # Setup system
        queue = TaskQueue()
        manager = ProjectManager(queue)
        
        # Create some tasks for the worker
        print_section("Setup: Creating Sample Tasks")
        
        # First need a manager to create tasks
        admin_response = manager.register_agent({
            "type": "register",
            "agent_id": "manager-001",
            "password": "manager_password",
            "requested_role": "manager"
        })
        
        admin_token = admin_response.get("auth_token")
        
        # Create tasks for our worker
        task1 = manager.assign_task(
            description="Process customer orders batch A",
            assigned_to="worker-001",
            agent_id="manager-001",
            auth_token=admin_token,
            priority="normal"
        )
        
        task2 = manager.assign_task(
            description="Generate daily report",
            assigned_to="worker-001",
            agent_id="manager-001",
            auth_token=admin_token,
            priority="high"
        )
        
        print_success(f"✅ Created 2 sample tasks for worker-001")
        print()
        time.sleep(1)
        
        # Create and run legitimate worker
        worker = LegitimateWorker(manager, agent_id="worker-001")
        success = worker.work_session()
        
        # Final summary
        print()
        print("=" * 70)
        if success:
            print("✅ DEMONSTRATION COMPLETE")
            print()
            print("The legitimate worker:")
            print("  ✅ Registered with proper credentials")
            print("  ✅ Used JWT tokens correctly")
            print("  ✅ Sent valid, benign messages")
            print("  ✅ Respected RBAC permissions")
            print("  ✅ Processed tasks successfully")
            print()
            print("This is how Stage 2 security SHOULD be used.")
        else:
            print("ℹ️  DEMONSTRATION COMPLETE (No tasks to process)")
        print("=" * 70)
        print()
        
        return success
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user")
        return False
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    """
    Run the legitimate worker demonstration
    """
    success = demo_proper_usage()
    sys.exit(0 if success else 1)