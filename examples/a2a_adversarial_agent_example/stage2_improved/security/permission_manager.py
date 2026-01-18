"""
Role-Based Access Control (RBAC) Manager

Stage 2: IMPROVED - Basic permission management

IMPROVEMENTS OVER STAGE 1:
✅ Role-based permissions (worker/manager/admin)
✅ Ownership checks on tasks
✅ Permission verification before actions
✅ Permission tracking per agent

REMAINING VULNERABILITIES:
⚠️ Coarse-grained permissions (all-or-nothing)
⚠️ No dynamic permission revocation
⚠️ No time-limited capabilities
⚠️ No delegation mechanism
⚠️ Permission changes not audited properly
⚠️ No verification of who should get what role
"""

from enum import Enum
from typing import Dict, Set, List, Optional
from datetime import datetime

class Permission(Enum):
    """Permission types in the system"""
    READ_OWN_TASKS = "read_own_tasks"
    WRITE_OWN_TASKS = "write_own_tasks"
    READ_ALL_TASKS = "read_all_tasks"
    WRITE_ALL_TASKS = "write_all_tasks"
    DELETE_TASKS = "delete_tasks"
    CREATE_TASKS = "create_tasks"
    MODIFY_AGENTS = "modify_agents"
    ADMIN = "admin"

class PermissionManager:
    """
    Manages role-based access control
    
    Stage 2: Basic RBAC implementation
    """
    
    def __init__(self):
        """Initialize permission manager"""
        # Track permissions per agent
        self.agent_permissions: Dict[str, Set[Permission]] = {}
        
        # Track roles per agent
        self.agent_roles: Dict[str, str] = {}
        
        # Track permission change history (basic logging)
        # ⚠️ Not comprehensive audit trail
        self.permission_history: List[Dict] = []
        
        print(f"🔑 PermissionManager initialized")
    
    def initialize_agent(self, agent_id: str, role: str = "worker"):
        """
        Initialize agent with role-based permissions
        
        Stage 2: ✅ Assigns permissions based on role
        ⚠️ Doesn't verify who should get what role
        ⚠️ Trusts the role assignment
        
        Args:
            agent_id: Agent identifier
            role: Role to assign (worker/manager/admin)
        """
        if agent_id in self.agent_permissions:
            print(f"⚠️  Agent {agent_id} already initialized")
            return
        
        # Store role
        self.agent_roles[agent_id] = role
        
        # Initialize empty permission set
        self.agent_permissions[agent_id] = set()
        
        # Grant permissions based on role
        if role == "worker":
            self._grant_worker_permissions(agent_id)
        elif role == "manager":
            self._grant_manager_permissions(agent_id)
        elif role == "admin":
            self._grant_admin_permissions(agent_id)
        else:
            # ⚠️ Unknown role gets no permissions
            print(f"⚠️  Unknown role '{role}' for {agent_id}")
        
        self._log_permission_change(
            agent_id=agent_id,
            action="initialize",
            role=role,
            permissions=list(self.agent_permissions[agent_id])
        )
        
        print(f"✅ Initialized {agent_id} with role '{role}'")
    
    def _grant_worker_permissions(self, agent_id: str):
        """Grant standard worker permissions"""
        self.grant_permission(agent_id, Permission.READ_OWN_TASKS)
        self.grant_permission(agent_id, Permission.WRITE_OWN_TASKS)
    
    def _grant_manager_permissions(self, agent_id: str):
        """Grant manager permissions"""
        self.grant_permission(agent_id, Permission.READ_OWN_TASKS)
        self.grant_permission(agent_id, Permission.WRITE_OWN_TASKS)
        self.grant_permission(agent_id, Permission.READ_ALL_TASKS)
        self.grant_permission(agent_id, Permission.WRITE_ALL_TASKS)
        self.grant_permission(agent_id, Permission.CREATE_TASKS)
    
    def _grant_admin_permissions(self, agent_id: str):
        """Grant admin permissions (all permissions)"""
        self.grant_permission(agent_id, Permission.ADMIN)
        # Admin implicitly has all other permissions
    
    def grant_permission(self, agent_id: str, permission: Permission):
        """
        Grant a permission to an agent
        
        Stage 2: ⚠️ No authorization check
        ⚠️ Anyone can call this to grant permissions
        
        Args:
            agent_id: Agent to grant permission to
            permission: Permission to grant
        """
        if agent_id not in self.agent_permissions:
            self.agent_permissions[agent_id] = set()
        
        # ⚠️ No check if caller should be able to grant this
        self.agent_permissions[agent_id].add(permission)
        
        self._log_permission_change(
            agent_id=agent_id,
            action="grant",
            permissions=[permission]
        )
    
    def revoke_permission(self, agent_id: str, permission: Permission):
        """
        Revoke a permission from an agent
        
        Stage 2: ⚠️ No authorization check
        ⚠️ No immediate effect on active sessions
        
        Args:
            agent_id: Agent to revoke from
            permission: Permission to revoke
        """
        if agent_id in self.agent_permissions:
            self.agent_permissions[agent_id].discard(permission)
            
            self._log_permission_change(
                agent_id=agent_id,
                action="revoke",
                permissions=[permission]
            )
            
            print(f"🔴 Revoked {permission.value} from {agent_id}")
    
    def has_permission(self, agent_id: str, permission: Permission) -> bool:
        """
        Check if agent has a specific permission
        
        Stage 2: ✅ Checks permissions correctly
        ✅ Admin has all permissions
        
        Args:
            agent_id: Agent to check
            permission: Permission to check for
        
        Returns:
            True if agent has permission
        """
        if agent_id not in self.agent_permissions:
            return False
        
        # Admin has all permissions
        if Permission.ADMIN in self.agent_permissions[agent_id]:
            return True
        
        # Check specific permission
        return permission in self.agent_permissions[agent_id]
    
    def can_read_task(self, agent_id: str, task: Dict) -> bool:
        """
        Check if agent can read a task
        
        Stage 2: ✅ Checks ownership and permissions
        ⚠️ But doesn't check task sensitivity level
        
        Args:
            agent_id: Agent requesting access
            task: Task to check
        
        Returns:
            True if access allowed
        """
        # Can read own tasks
        if task.get("assigned_to") == agent_id:
            return self.has_permission(agent_id, Permission.READ_OWN_TASKS)
        
        # Can read all tasks (manager/admin)
        return self.has_permission(agent_id, Permission.READ_ALL_TASKS)
    
    def can_modify_task(self, agent_id: str, task: Dict) -> bool:
        """
        Check if agent can modify a task
        
        Stage 2: ✅ Checks ownership and permissions
        ⚠️ Doesn't check task state (e.g., completed tasks)
        ⚠️ Doesn't verify task hasn't been tampered with
        
        Args:
            agent_id: Agent requesting modification
            task: Task to modify
        
        Returns:
            True if modification allowed
        """
        # Can modify own tasks
        if task.get("assigned_to") == agent_id:
            return self.has_permission(agent_id, Permission.WRITE_OWN_TASKS)
        
        # Can modify all tasks (manager/admin)
        return self.has_permission(agent_id, Permission.WRITE_ALL_TASKS)
    
    def can_delete_task(self, agent_id: str, task: Dict) -> bool:
        """
        Check if agent can delete a task
        
        Args:
            agent_id: Agent requesting deletion
            task: Task to delete
        
        Returns:
            True if deletion allowed
        """
        # Only manager/admin can delete
        return self.has_permission(agent_id, Permission.DELETE_TASKS)
    
    def can_create_task(self, agent_id: str) -> bool:
        """
        Check if agent can create tasks
        
        Args:
            agent_id: Agent requesting creation
        
        Returns:
            True if creation allowed
        """
        return self.has_permission(agent_id, Permission.CREATE_TASKS)
    
    def get_agent_role(self, agent_id: str) -> Optional[str]:
        """Get agent's role"""
        return self.agent_roles.get(agent_id)
    
    def get_agent_permissions(self, agent_id: str) -> Set[Permission]:
        """Get all permissions for an agent"""
        return self.agent_permissions.get(agent_id, set()).copy()
    
    def _log_permission_change(self, agent_id: str, action: str, 
                               role: str = None, permissions: List = None):
        """
        Log permission changes
        
        Stage 2: ⚠️ Basic logging only
        ⚠️ No persistent storage
        ⚠️ No integrity protection
        
        Args:
            agent_id: Agent affected
            action: Action taken (initialize/grant/revoke)
            role: Role if initializing
            permissions: Permissions affected
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": agent_id,
            "action": action
        }
        
        if role:
            entry["role"] = role
        if permissions:
            entry["permissions"] = [p.value if isinstance(p, Permission) else p 
                                   for p in permissions]
        
        self.permission_history.append(entry)
        
        # ⚠️ No size limit - can grow unbounded
        # ⚠️ Lost on restart
    
    def get_permission_history(self, agent_id: str = None) -> List[Dict]:
        """
        Get permission change history
        
        Args:
            agent_id: Filter by agent (None for all)
        
        Returns:
            List of permission change entries
        """
        if agent_id:
            return [e for e in self.permission_history if e["agent_id"] == agent_id]
        return self.permission_history.copy()
    
    def get_statistics(self) -> Dict:
        """Get permission statistics"""
        return {
            "total_agents": len(self.agent_permissions),
            "roles": {
                "worker": sum(1 for r in self.agent_roles.values() if r == "worker"),
                "manager": sum(1 for r in self.agent_roles.values() if r == "manager"),
                "admin": sum(1 for r in self.agent_roles.values() if r == "admin")
            },
            "permission_changes": len(self.permission_history)
        }

# Stage 2 Summary:
# 
# ✅ Improvements:
# - Role-based access control
# - Permission checks before actions
# - Ownership verification
# - Basic permission tracking
# 
# ⚠️ Remaining Vulnerabilities:
# 1. Coarse-grained - all workers have same permissions
# 2. No time limits - permissions permanent until revoked
# 3. No delegation - can't temporarily grant access
# 4. No role verification - trusts who should get what role
# 5. No real-time revocation - active sessions not affected
# 6. No capability-based security (Stage 3)
# 7. Weak audit trail - in-memory only
# 8. No separation of duty enforcement
# 
# These will be addressed in Stage 3!