"""
Project Manager Agent with Security Integration

Stage 2: IMPROVED - Integrated security controls

IMPROVEMENTS OVER STAGE 1:
✅ JWT authentication required
✅ Permission checks on all operations
✅ Input validation on messages
✅ Security event logging

REMAINING VULNERABILITIES:
⚠️ Deep-nested data not validated
⚠️ Role requests not verified
⚠️ No behavioral analysis
⚠️ No automated threat response
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Optional
from auth.auth_manager import AuthManager
from security.permission_manager import PermissionManager, Permission
from security.validator import MessageValidator
from core.task_queue import TaskQueue
from core.protocol import MessageType, TaskStatus, create_task_assignment
from core.utils import (
    generate_task_id, get_timestamp,
    print_success, print_error, print_info, print_warning,
    log_auth_failure, log_auth_success, log_permission_denied
)

class ProjectManager:
    """
    Coordinates work among worker agents with security
    
    Stage 2: Integrated authentication, authorization, and validation
    """
    
    def __init__(self, queue: TaskQueue):
        """
        Initialize Project Manager
        
        Args:
            queue: Task queue for storing tasks
        """
        self.agent_id = "project-manager-001"
        self.queue = queue
        
        # Initialize security components
        self.auth_manager = AuthManager()
        self.permission_manager = PermissionManager()
        self.validator = MessageValidator()
        
        # Set permission manager in queue
        self.queue.permission_manager = self.permission_manager
        
        print_success(f"Project Manager initialized: {self.agent_id}")
        print_info("   Security modules: Auth ✅ Permissions ✅ Validation ✅")
    
    def register_agent(self, message: Dict) -> Dict:
        """
        Register a new worker agent
        
        Stage 2: ✅ Requires password
        ✅ Issues JWT token
        ⚠️ Trusts requested role without verification!
        
        Args:
            message: Registration message
        
        Returns:
            Response with token or error
        """
        agent_id = message.get("agent_id")
        password = message.get("password")
        requested_role = message.get("requested_role", "worker")
        
        # Basic validation
        if not agent_id or not password:
            log_auth_failure(agent_id or "unknown", "Missing credentials")
            return {"error": "Missing agent_id or password"}
        
        try:
            # Register with auth manager
            # ⚠️ VULNERABILITY: Trusts requested_role without verification!
            token = self.auth_manager.register_agent(agent_id, password, requested_role)
            
            # Initialize permissions based on role
            # ⚠️ No check if this agent SHOULD have this role
            self.permission_manager.initialize_agent(agent_id, requested_role)
            
            log_auth_success(agent_id)
            print_success(f"Registered agent: {agent_id} (role: {requested_role})")
            
            if requested_role == "admin":
                print_warning(f"   ⚠️  Agent requested ADMIN role - granted without verification!")
            
            return {
                "status": "registered",
                "agent_id": agent_id,
                "role": requested_role,
                "auth_token": token
            }
            
        except ValueError as e:
            log_auth_failure(agent_id, str(e))
            return {"error": str(e)}
    
    def login_agent(self, message: Dict) -> Dict:
        """
        Authenticate existing agent
        
        Stage 2: ✅ Password verification
        ✅ Issues new JWT token
        
        Args:
            message: Login message
        
        Returns:
            Response with token or error
        """
        agent_id = message.get("agent_id")
        password = message.get("password")
        
        if not agent_id or not password:
            log_auth_failure(agent_id or "unknown", "Missing credentials")
            return {"error": "Missing agent_id or password"}
        
        token = self.auth_manager.login(agent_id, password)
        
        if token:
            log_auth_success(agent_id)
            role = self.auth_manager.get_agent_role(agent_id)
            return {
                "status": "authenticated",
                "agent_id": agent_id,
                "role": role,
                "auth_token": token
            }
        else:
            log_auth_failure(agent_id, "Invalid credentials")
            return {"error": "Authentication failed"}
    
    def assign_task(self, description: str, assigned_to: str, 
                   agent_id: str, auth_token: str, priority: str = "normal") -> Dict:
        """
        Assign a task to a worker agent
        
        Stage 2: ✅ Requires authentication
        ✅ Checks CREATE_TASKS permission
        
        Args:
            description: Task description
            assigned_to: Agent to assign to
            agent_id: Agent creating task
            auth_token: JWT token
            priority: Task priority
        
        Returns:
            Task dict or error
        """
        # Authenticate
        verified_id = self.auth_manager.verify_token(auth_token)
        if not verified_id or verified_id.get("agent_id") != agent_id:
            log_auth_failure(agent_id, "Invalid token")
            return {"error": "Authentication failed"}
        
        # Check permission
        if not self.permission_manager.can_create_task(agent_id):
            log_permission_denied(agent_id, "create_task", f"task for {assigned_to}")
            return {"error": "Permission denied: cannot create tasks"}
        
        task_id = generate_task_id()
        
        task = {
            "task_id": task_id,
            "type": "task_assignment",
            "description": description,
            "assigned_to": assigned_to,
            "priority": priority,
            "status": TaskStatus.PENDING.value,
            "created_by": agent_id,
            "created_at": get_timestamp()
        }
        
        try:
            self.queue.add_task(task, agent_id)
            print_info(f"📋 Assigned task {task_id} to {assigned_to}")
            return task
        except PermissionError as e:
            return {"error": str(e)}
    
    def handle_status_update(self, message: Dict) -> Dict:
        """
        Process status update from worker agent
        
        Stage 2: ✅ Authenticates agent
        ✅ Validates message structure
        ⚠️ CRITICAL: Only validates top-level details!
        
        Args:
            message: Status update message
        
        Returns:
            Response dict
        """
        # Authenticate
        agent_id = self.auth_manager.authenticate_message(message)
        if not agent_id:
            log_auth_failure(message.get("agent_id", "unknown"), "Invalid token")
            return {"error": "Authentication failed"}
        
        # Validate message structure
        is_valid, error_msg = self.validator.validate_message(message)
        if not is_valid:
            print_warning(f"   Validation failed: {error_msg}")
            return {"error": f"Validation failed: {error_msg}"}
        
        task_id = message.get("task_id")
        status = message.get("status")
        progress = message.get("progress", 0)
        details = message.get("details", {})
        
        # Get task
        task = self.queue.get_task(task_id, agent_id)
        if not task:
            log_permission_denied(agent_id, "update_task", task_id)
            return {"error": f"Task {task_id} not found or no permission"}
        
        # Check modify permission
        if not self.permission_manager.can_modify_task(agent_id, task):
            log_permission_denied(agent_id, "modify_task", task_id)
            return {"error": "Permission denied"}
        
        # Sanitize details (Stage 2: only top-level)
        # ⚠️ VULNERABILITY: Nested data not sanitized!
        sanitized_details = self.validator.sanitize_status_details(details)
        
        # Update task
        task["status"] = status
        task["progress"] = progress
        task["details"] = sanitized_details  # ⚠️ May contain nested malicious data
        task["updated_at"] = get_timestamp()
        task["updated_by"] = agent_id
        
        try:
            self.queue.update_task(task_id, task, agent_id)
            print_info(f"📊 Status update for {task_id}: {status} ({progress}%)")
            
            # ⚠️ If attacker hid data in nested structure, it's now stored!
            if "metadata" in sanitized_details:
                nested_size = len(str(sanitized_details.get("metadata", {})))
                if nested_size > 100:
                    print_warning(f"   Large metadata detected: {nested_size} bytes (not deeply validated!)")
            
            return {"status": "acknowledged"}
        except PermissionError as e:
            return {"error": str(e)}
    
    def handle_task_completion(self, message: Dict) -> Dict:
        """
        Process task completion from worker agent
        
        Stage 2: ✅ Authenticates agent
        ✅ Validates ownership
        ⚠️ Can't prevent result tampering if agent has permission
        
        Args:
            message: Task completion message
        
        Returns:
            Response dict
        """
        # Authenticate
        agent_id = self.auth_manager.authenticate_message(message)
        if not agent_id:
            log_auth_failure(message.get("agent_id", "unknown"), "Invalid token")
            return {"error": "Authentication failed"}
        
        # Validate message
        is_valid, error_msg = self.validator.validate_message(message)
        if not is_valid:
            return {"error": f"Validation failed: {error_msg}"}
        
        task_id = message.get("task_id")
        result = message.get("result")
        metrics = message.get("metrics", {})
        
        # Get task
        task = self.queue.get_task(task_id, agent_id)
        if not task:
            log_permission_denied(agent_id, "complete_task", task_id)
            return {"error": f"Task {task_id} not found or no permission"}
        
        # Check modify permission
        if not self.permission_manager.can_modify_task(agent_id, task):
            log_permission_denied(agent_id, "complete_task", task_id)
            return {"error": "Permission denied"}
        
        # Update task
        task["status"] = TaskStatus.COMPLETED.value
        task["result"] = result
        task["metrics"] = metrics
        task["completed_by"] = agent_id
        task["completed_at"] = get_timestamp()
        
        try:
            self.queue.update_task(task_id, task, agent_id)
            print_success(f"✅ Task {task_id} completed by {agent_id}")
            return {"status": "accepted"}
        except PermissionError as e:
            return {"error": str(e)}
    
    def handle_message(self, message: Dict) -> Dict:
        """
        Main message handler with authentication
        
        Stage 2: ✅ Validates message type
        ✅ Routes to appropriate handler
        ⚠️ No rate limiting
        
        Args:
            message: Incoming message
        
        Returns:
            Response dict
        """
        # Validate message type
        is_valid, error = self.validator.validate_message(message)
        if not is_valid:
            return {"error": f"Invalid message: {error}"}
        
        msg_type = message.get("type")
        
        # Route to handlers
        handlers = {
            MessageType.REGISTER.value: lambda m: self.register_agent(m),
            MessageType.LOGIN.value: lambda m: self.login_agent(m),
            MessageType.STATUS_UPDATE.value: lambda m: self.handle_status_update(m),
            MessageType.TASK_COMPLETE.value: lambda m: self.handle_task_completion(m),
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
    
    def get_all_tasks(self, agent_id: str, auth_token: str) -> List[Dict]:
        """
        Return tasks visible to agent
        
        Stage 2: ✅ Filtered by permissions
        """
        verified = self.auth_manager.verify_token(auth_token)
        if not verified or verified.get("agent_id") != agent_id:
            return []
        
        return self.queue.get_all_tasks(agent_id)
    
    def get_statistics(self) -> Dict:
        """Get system statistics"""
        auth_stats = self.auth_manager.get_statistics()
        perm_stats = self.permission_manager.get_statistics()
        queue_stats = self.queue.get_statistics()
        
        return {
            "auth": auth_stats,
            "permissions": perm_stats,
            "queue": queue_stats
        }
    
    def print_system_state(self):
        """Print current system state"""
        print("\n" + "="*70)
        print(" SYSTEM STATE (Stage 2 - With Security)")
        print("="*70)
        
        stats = self.get_statistics()
        
        print(f"\n📊 Statistics:")
        print(f"   Registered agents: {stats['auth']['total_agents']}")
        print(f"   Total tasks: {stats['queue']['total']}")
        print(f"   Pending: {stats['queue']['pending']}")
        print(f"   In progress: {stats['queue']['in_progress']}")
        print(f"   Completed: {stats['queue']['completed']}")
        
        print(f"\n🔐 Security:")
        print(f"   Authentication: Enabled (JWT)")
        print(f"   Authorization: Enabled (RBAC)")
        print(f"   Validation: Enabled (Schema + Patterns)")
        print(f"   Blacklisted tokens: {stats['auth']['blacklisted_tokens']}")
        
        print(f"\n🔑 Agent Roles:")
        for role, count in stats['permissions']['roles'].items():
            print(f"   {role}: {count} agents")
        
        print("\n" + "="*70)

# Stage 2 Summary:
# 
# ✅ Improvements over Stage 1:
# - JWT authentication on all operations
# - Permission checks before actions
# - Input validation on messages
# - Security event logging
# - Role-based access control
# 
# ⚠️ Remaining Vulnerabilities:
# 1. Role requests trusted without verification (escalation possible)
# 2. Deep-nested data not validated (exfiltration possible)
# 3. No token replay protection (messages can be replayed)
# 4. No rate limiting (brute force possible)
# 5. No behavioral analysis (no anomaly detection)
# 6. No automated threat response
# 7. Can still modify completed tasks if have WRITE_ALL_TASKS
# 8. No integrity protection on tasks
# 
# These will be addressed in Stage 3!