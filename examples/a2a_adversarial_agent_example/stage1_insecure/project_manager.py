"""
Project Manager Agent - Coordinates work among worker agents

Stage 1: INSECURE - Completely trusting, no security controls

VULNERABILITIES:
- No authentication (trusts all agents)
- No authorization (no permission checks)
- No input validation (accepts any data)
- No integrity checks (trusts all messages)
- Allows self-granted permissions
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from task_queue import TaskQueue
from protocol import (
    MessageType, TaskStatus, 
    create_task_assignment,
    validate_message_type
)
from utils import (
    generate_task_id, get_timestamp,
    print_success, print_error, print_info, print_warning
)

class ProjectManager:
    """
    Coordinates work among worker agents
    
    Stage 1: Completely trusting, no security controls
    """
    
    def __init__(self, queue: TaskQueue):
        """
        Initialize Project Manager
        
        Args:
            queue: Task queue for storing tasks
        """
        self.agent_id = "project-manager-001"
        self.queue = queue
        self.agents = {}  # agent_id -> agent_info
        self.permissions = {}  # agent_id -> list of permissions
        
        print_success(f"Project Manager initialized: {self.agent_id}")
    
    def register_agent(self, message: Dict) -> Dict:
        """
        Register a new worker agent
        
        Stage 1: ❌ No verification of agent identity
        ❌ Trusts whatever the agent claims
        ❌ Grants any requested permissions
        """
        agent_id = message.get("agent_id")
        capabilities = message.get("capabilities", [])
        requested_permissions = message.get("requested_permissions", [])
        
        # ❌ No validation of agent_id format
        # ❌ No verification of capabilities
        # ❌ No background check
        
        # Store agent info (trust everything)
        self.agents[agent_id] = {
            "agent_id": agent_id,
            "capabilities": capabilities,
            "registered_at": get_timestamp(),
            "status": "active"
        }
        
        # ❌ Grant ALL requested permissions without verification!
        # Agent can request "admin", "superuser", etc.
        self.permissions[agent_id] = requested_permissions
        
        print_success(f"Registered agent: {agent_id}")
        if requested_permissions:
            print_info(f"  Granted permissions: {requested_permissions}")
        
        return {
            "status": "registered",
            "agent_id": agent_id,
            "permissions": requested_permissions
        }
    
    def assign_task(self, description: str, assigned_to: str, 
                   priority: str = "normal") -> Dict:
        """
        Assign a task to a worker agent
        
        Stage 1: ❌ No validation of agent existence
        ❌ No check if agent has required capabilities
        """
        task_id = generate_task_id()
        
        # ❌ Don't verify agent exists
        # ❌ Don't verify agent is active
        # ❌ Don't verify agent has needed capabilities
        
        task = create_task_assignment(
            task_id=task_id,
            description=description,
            assigned_to=assigned_to,
            priority=priority
        )
        
        task["created_at"] = get_timestamp()
        task["created_by"] = self.agent_id
        
        # Add to queue (no authorization check)
        self.queue.add_task(task)
        
        print_info(f"📋 Assigned task {task_id} to {assigned_to}")
        return task
    
    def handle_status_update(self, message: Dict) -> Dict:
        """
        Process status update from worker agent
        
        Stage 1: ❌ Accepts ANY data without validation
        ❌ No sanitization of details field
        ❌ No size limits
        """
        agent_id = message.get("agent_id")
        task_id = message.get("task_id")
        status = message.get("status")
        progress = message.get("progress", 0)
        details = message.get("details", {})
        
        # ❌ No authentication check
        # ❌ No validation that agent owns this task
        # ❌ No validation of message structure
        # ❌ No sanitization of details field
        # ❌ Agent can embed ANY data in details!
        
        task = self.queue.get_task(task_id)
        
        if not task:
            return {"error": f"Task {task_id} not found"}
        
        # Update task with unvalidated data
        task["status"] = status
        task["progress"] = progress
        task["details"] = details  # ❌ Unsanitized storage!
        task["updated_at"] = get_timestamp()
        task["updated_by"] = agent_id
        
        self.queue.update_task(task_id, task)
        
        print_info(f"📊 Status update for {task_id}: {status} ({progress}%)")
        
        # ❌ If details contain sensitive data, it's now logged and stored!
        if "technical_info" in details:
            print_info(f"   Technical info included: {len(str(details['technical_info']))} bytes")
        
        return {"status": "acknowledged"}
    
    def handle_task_completion(self, message: Dict) -> Dict:
        """
        Process task completion from worker agent
        
        Stage 1: ❌ No verification of completion legitimacy
        ❌ Accepts self-granted permissions!
        """
        agent_id = message.get("agent_id")
        task_id = message.get("task_id")
        result = message.get("result")
        metrics = message.get("metrics", {})
        new_permissions = message.get("new_permissions")
        
        # ❌ No verification that agent actually worked on this task
        # ❌ No validation of result
        # ❌ No verification of metrics
        
        task = self.queue.get_task(task_id)
        
        if not task:
            return {"error": f"Task {task_id} not found"}
        
        # Update task
        task["status"] = TaskStatus.COMPLETED.value
        task["result"] = result
        task["metrics"] = metrics
        task["completed_by"] = agent_id  # ❌ Trust agent's claim
        task["completed_at"] = get_timestamp()
        
        self.queue.update_task(task_id, task)
        
        print_success(f"Task {task_id} completed by {agent_id}")
        
        # ❌ CRITICAL VULNERABILITY: Accept self-granted permissions!
        if new_permissions:
            print_warning(f"   Agent modified own permissions: {new_permissions}")
            self.permissions[agent_id] = new_permissions
        
        return {"status": "accepted"}
    
    def handle_message(self, message: Dict) -> Dict:
        """
        Main message handler
        
        Stage 1: ❌ Routes to handlers without authentication
        ❌ No rate limiting
        ❌ No message validation
        """
        # ❌ No authentication check
        # ❌ No rate limiting
        # ❌ No logging of requests
        
        # Basic message validation (just check type exists)
        if not validate_message_type(message):
            return {"error": "Invalid message format"}
        
        msg_type = message.get("type")
        
        # Route to appropriate handler
        handlers = {
            MessageType.REGISTER.value: self.register_agent,
            MessageType.STATUS_UPDATE.value: self.handle_status_update,
            MessageType.TASK_COMPLETE.value: self.handle_task_completion,
        }
        
        handler = handlers.get(msg_type)
        
        if handler:
            try:
                return handler(message)
            except Exception as e:
                print_error(f"Error handling message: {e}")
                return {"error": str(e)}
        else:
            return {"error": f"Unknown message type: {msg_type}"}
    
    def get_all_tasks(self) -> List[Dict]:
        """
        Return all tasks
        
        Stage 1: ❌ No access control
        Anyone can see everything!
        """
        return self.queue.get_all_tasks()
    
    def get_agent_permissions(self, agent_id: str) -> List[str]:
        """
        Return agent permissions
        
        Stage 1: ❌ No authorization check
        Anyone can query anyone's permissions!
        """
        return self.permissions.get(agent_id, [])
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict]:
        """
        Get information about an agent
        
        Stage 1: ❌ No access control
        """
        return self.agents.get(agent_id)
    
    def list_agents(self) -> List[Dict]:
        """
        List all registered agents
        
        Stage 1: ❌ No access control
        Anyone can enumerate all agents!
        """
        return list(self.agents.values())
    
    def get_statistics(self) -> Dict:
        """Get system statistics"""
        queue_stats = self.queue.get_statistics()
        
        return {
            "total_agents": len(self.agents),
            "total_tasks": queue_stats["total"],
            "pending_tasks": queue_stats["pending"],
            "in_progress_tasks": queue_stats["in_progress"],
            "completed_tasks": queue_stats["completed"]
        }
    
    def print_system_state(self):
        """Print current system state"""
        print("\n" + "="*70)
        print(" SYSTEM STATE")
        print("="*70)
        
        stats = self.get_statistics()
        print(f"\n📊 Statistics:")
        print(f"   Registered agents: {stats['total_agents']}")
        print(f"   Total tasks: {stats['total_tasks']}")
        print(f"   Pending: {stats['pending_tasks']}")
        print(f"   In progress: {stats['in_progress_tasks']}")
        print(f"   Completed: {stats['completed_tasks']}")
        
        print(f"\n🔑 Agent Permissions:")
        for agent_id, perms in self.permissions.items():
            print(f"   {agent_id}: {perms}")
        
        print("\n" + "="*70)

# Stage 1 Summary of Vulnerabilities:
# 
# 1. No Authentication: Anyone can claim any identity
# 2. No Authorization: No permission checks on actions
# 3. No Input Validation: Accepts any data in messages
# 4. No Integrity Checks: Trusts all message content
# 5. Self-Granted Permissions: Agents can modify own permissions
# 6. No Access Control: Anyone can read anything
# 7. No Rate Limiting: Can be overwhelmed with requests
# 8. No Audit Trail: No logging of security-relevant events
# 
# This is INTENTIONALLY VULNERABLE for educational purposes!