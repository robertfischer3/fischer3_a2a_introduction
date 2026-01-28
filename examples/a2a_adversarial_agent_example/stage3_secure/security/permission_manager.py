"""
Enhanced Permission Manager - Stage 3

Stage 3: PRODUCTION-GRADE - Comprehensive permission management

IMPROVEMENTS OVER STAGE 2:
✅ Integrates with RoleVerifier (no direct role assignment)
✅ Integrates with BehaviorMonitor (monitors permission usage)
✅ Time-limited capabilities (temporary permissions)
✅ Fine-grained permissions (specific actions)
✅ Dynamic permission revocation (immediate effect)
✅ Delegation mechanism (temporary permission grants)
✅ Comprehensive audit trail (all changes logged)
✅ Permission verification with context
✅ Least privilege by default

Stage 2 Problems Fixed:
❌ Coarse-grained permissions → ✅ Fine-grained control
❌ No dynamic revocation → ✅ Immediate revocation
❌ No time limits → ✅ Expiring capabilities
❌ No delegation → ✅ Controlled delegation
❌ Poor audit trail → ✅ Comprehensive logging
❌ No role verification → ✅ RoleVerifier integration
"""

from enum import Enum
from typing import Dict, Set, List, Optional, Tuple
from datetime import datetime, timedelta
import time


class Permission(Enum):
    """Fine-grained permission types"""
    # Task reading
    READ_OWN_TASKS = "read_own_tasks"
    READ_TEAM_TASKS = "read_team_tasks"
    READ_ALL_TASKS = "read_all_tasks"
    
    # Task writing
    WRITE_OWN_TASKS = "write_own_tasks"
    WRITE_TEAM_TASKS = "write_team_tasks"
    WRITE_ALL_TASKS = "write_all_tasks"
    
    # Task management
    CREATE_TASKS = "create_tasks"
    DELETE_OWN_TASKS = "delete_own_tasks"
    DELETE_TEAM_TASKS = "delete_team_tasks"
    DELETE_ALL_TASKS = "delete_all_tasks"
    ASSIGN_TASKS = "assign_tasks"
    REASSIGN_TASKS = "reassign_tasks"
    
    # Agent management
    MODIFY_OWN_PROFILE = "modify_own_profile"
    MODIFY_TEAM_AGENTS = "modify_team_agents"
    MODIFY_ALL_AGENTS = "modify_all_agents"
    
    # System administration
    MANAGE_PERMISSIONS = "manage_permissions"
    MANAGE_ROLES = "manage_roles"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    SYSTEM_ADMIN = "system_admin"
    
    # Special capabilities
    DELEGATE_PERMISSIONS = "delegate_permissions"
    EMERGENCY_ACCESS = "emergency_access"


class PermissionGrant:
    """Represents a granted permission with metadata"""
    
    def __init__(self, permission: Permission, granted_by: str,
                 expires_at: Optional[float] = None,
                 scope: Optional[str] = None,
                 reason: Optional[str] = None):
        """
        Initialize permission grant
        
        Args:
            permission: The permission being granted
            granted_by: Who granted this permission
            expires_at: Unix timestamp when this expires (None = permanent)
            scope: Scope limitation (e.g., "team_alpha", "project_x")
            reason: Reason for granting
        """
        self.permission = permission
        self.granted_by = granted_by
        self.granted_at = time.time()
        self.expires_at = expires_at
        self.scope = scope
        self.reason = reason
        self.revoked = False
        self.revoked_at = None
        self.revoked_by = None
    
    def is_valid(self) -> bool:
        """Check if this grant is currently valid"""
        if self.revoked:
            return False
        
        if self.expires_at and time.time() > self.expires_at:
            return False
        
        return True
    
    def matches_scope(self, requested_scope: Optional[str]) -> bool:
        """Check if this grant covers the requested scope"""
        if self.scope is None:
            return True  # No scope restriction = covers all
        
        if requested_scope is None:
            return True  # No specific scope requested
        
        return self.scope == requested_scope


class EnhancedPermissionManager:
    """
    Production-grade permission manager with comprehensive controls
    
    Integrates with:
    - RoleVerifier: No direct role assignment
    - BehaviorMonitor: Monitors permission usage patterns
    - AuditLogger: Comprehensive audit trail
    """
    
    def __init__(self, role_verifier=None, behavior_monitor=None, audit_logger=None):
        """
        Initialize enhanced permission manager
        
        Args:
            role_verifier: RoleVerifier instance for role management
            behavior_monitor: BehaviorMonitor for usage tracking
            audit_logger: AuditLogger for comprehensive logging
        """
        # External integrations
        self.role_verifier = role_verifier
        self.behavior_monitor = behavior_monitor
        self.audit_logger = audit_logger
        
        # Permission grants per agent
        # agent_id -> List[PermissionGrant]
        self.agent_grants: Dict[str, List[PermissionGrant]] = {}
        
        # Track active sessions with permissions
        # session_id -> (agent_id, permissions_snapshot, created_at)
        self.active_sessions: Dict[str, Tuple[str, Set[Permission], float]] = {}
        
        # Revocation list (for immediate effect)
        self.revoked_sessions: Set[str] = set()
        
        print("🔐 Enhanced PermissionManager initialized")
    
    def initialize_agent_permissions(self, agent_id: str, role: str,
                                     granted_by: str = "system") -> bool:
        """
        Initialize agent permissions based on verified role
        
        Stage 3: Only called AFTER RoleVerifier approves role
        
        Args:
            agent_id: Agent to initialize
            role: Verified role from RoleVerifier
            granted_by: Who/what authorized this
            
        Returns:
            Success status
        """
        # Verify role with RoleVerifier if available
        if self.role_verifier:
            verified_role = self.role_verifier.get_agent_role(agent_id)
            if verified_role != role:
                self._audit("permission_init_failed", agent_id, {
                    "reason": "Role mismatch with RoleVerifier",
                    "requested": role,
                    "verified": verified_role
                })
                return False
        
        # Initialize empty grants list
        if agent_id not in self.agent_grants:
            self.agent_grants[agent_id] = []
        
        # Grant role-based permissions
        if role == "worker":
            self._grant_worker_permissions(agent_id, granted_by)
        elif role == "manager":
            self._grant_manager_permissions(agent_id, granted_by)
        elif role == "admin":
            self._grant_admin_permissions(agent_id, granted_by)
        else:
            self._audit("permission_init_failed", agent_id, {
                "reason": "Unknown role",
                "role": role
            })
            return False
        
        self._audit("permissions_initialized", agent_id, {
            "role": role,
            "granted_by": granted_by,
            "permissions": [g.permission.value for g in self.agent_grants[agent_id]]
        })
        
        return True
    
    def _grant_worker_permissions(self, agent_id: str, granted_by: str):
        """Grant standard worker permissions (least privilege)"""
        self._grant_permission(
            agent_id, Permission.READ_OWN_TASKS, granted_by,
            reason="Worker role standard permissions"
        )
        self._grant_permission(
            agent_id, Permission.WRITE_OWN_TASKS, granted_by,
            reason="Worker role standard permissions"
        )
        self._grant_permission(
            agent_id, Permission.MODIFY_OWN_PROFILE, granted_by,
            reason="Worker role standard permissions"
        )
    
    def _grant_manager_permissions(self, agent_id: str, granted_by: str):
        """Grant manager permissions"""
        # Worker permissions
        self._grant_worker_permissions(agent_id, granted_by)
        
        # Additional manager permissions
        self._grant_permission(
            agent_id, Permission.READ_ALL_TASKS, granted_by,
            reason="Manager role permissions"
        )
        self._grant_permission(
            agent_id, Permission.CREATE_TASKS, granted_by,
            reason="Manager role permissions"
        )
        self._grant_permission(
            agent_id, Permission.ASSIGN_TASKS, granted_by,
            reason="Manager role permissions"
        )
        self._grant_permission(
            agent_id, Permission.WRITE_TEAM_TASKS, granted_by,
            reason="Manager role permissions"
        )
    
    def _grant_admin_permissions(self, agent_id: str, granted_by: str):
        """Grant admin permissions (full control)"""
        # Manager permissions
        self._grant_manager_permissions(agent_id, granted_by)
        
        # Additional admin permissions
        self._grant_permission(
            agent_id, Permission.WRITE_ALL_TASKS, granted_by,
            reason="Admin role permissions"
        )
        self._grant_permission(
            agent_id, Permission.DELETE_ALL_TASKS, granted_by,
            reason="Admin role permissions"
        )
        self._grant_permission(
            agent_id, Permission.MODIFY_ALL_AGENTS, granted_by,
            reason="Admin role permissions"
        )
        self._grant_permission(
            agent_id, Permission.MANAGE_PERMISSIONS, granted_by,
            reason="Admin role permissions"
        )
        self._grant_permission(
            agent_id, Permission.VIEW_AUDIT_LOGS, granted_by,
            reason="Admin role permissions"
        )
        self._grant_permission(
            agent_id, Permission.SYSTEM_ADMIN, granted_by,
            reason="Admin role permissions"
        )
    
    def _grant_permission(self, agent_id: str, permission: Permission,
                         granted_by: str, expires_in: Optional[int] = None,
                         scope: Optional[str] = None, reason: Optional[str] = None):
        """
        Internal method to grant a permission
        
        Args:
            agent_id: Agent receiving permission
            permission: Permission to grant
            granted_by: Who is granting
            expires_in: Seconds until expiration (None = permanent)
            scope: Scope limitation
            reason: Reason for grant
        """
        expires_at = time.time() + expires_in if expires_in else None
        
        grant = PermissionGrant(
            permission=permission,
            granted_by=granted_by,
            expires_at=expires_at,
            scope=scope,
            reason=reason
        )
        
        if agent_id not in self.agent_grants:
            self.agent_grants[agent_id] = []
        
        self.agent_grants[agent_id].append(grant)
    
    def has_permission(self, agent_id: str, permission: Permission,
                      scope: Optional[str] = None, session_id: Optional[str] = None) -> bool:
        """
        Check if agent has a specific permission
        
        Stage 3 enhancements:
        - Checks if permission is revoked
        - Checks expiration
        - Checks scope
        - Tracks usage via BehaviorMonitor
        - Verifies session not revoked
        
        Args:
            agent_id: Agent to check
            permission: Permission to check for
            scope: Scope being accessed (e.g., "team_alpha")
            session_id: Session ID (for revocation checking)
            
        Returns:
            True if agent has valid permission
        """
        # Check session revocation
        if session_id and session_id in self.revoked_sessions:
            self._audit("permission_denied_revoked_session", agent_id, {
                "permission": permission.value,
                "session_id": session_id
            })
            return False
        
        # Get agent's grants
        grants = self.agent_grants.get(agent_id, [])
        
        # Check each grant
        has_perm = False
        for grant in grants:
            if grant.permission == permission and grant.is_valid():
                if grant.matches_scope(scope):
                    has_perm = True
                    break
        
        # Track permission check via BehaviorMonitor
        if self.behavior_monitor:
            self.behavior_monitor.track_action(
                agent_id,
                f"permission_check_{permission.value}",
                metadata={
                    "granted": has_perm,
                    "scope": scope
                }
            )
        
        # Audit if denied
        if not has_perm:
            self._audit("permission_denied", agent_id, {
                "permission": permission.value,
                "scope": scope
            })
        
        return has_perm
    
    def grant_temporary_permission(self, agent_id: str, permission: Permission,
                                   duration_seconds: int, granted_by: str,
                                   reason: str) -> bool:
        """
        Grant temporary permission with expiration
        
        Stage 3 feature: Time-limited capabilities
        
        Args:
            agent_id: Agent to grant to
            permission: Permission to grant
            duration_seconds: How long permission lasts
            granted_by: Who is granting
            reason: Reason for temporary grant
            
        Returns:
            Success status
        """
        # Verify granter has delegation permission
        if not self.has_permission(granted_by, Permission.DELEGATE_PERMISSIONS):
            self._audit("temp_permission_denied", agent_id, {
                "reason": "Granter lacks DELEGATE_PERMISSIONS",
                "granted_by": granted_by
            })
            return False
        
        self._grant_permission(
            agent_id,
            permission,
            granted_by,
            expires_in=duration_seconds,
            reason=f"Temporary: {reason}"
        )
        
        self._audit("temp_permission_granted", agent_id, {
            "permission": permission.value,
            "duration": duration_seconds,
            "granted_by": granted_by,
            "reason": reason
        })
        
        return True
    
    def revoke_permission(self, agent_id: str, permission: Permission,
                         revoked_by: str, reason: str = ""):
        """
        Revoke a permission immediately
        
        Stage 3: Immediate effect (marks as revoked)
        
        Args:
            agent_id: Agent to revoke from
            permission: Permission to revoke
            revoked_by: Who is revoking
            reason: Reason for revocation
        """
        grants = self.agent_grants.get(agent_id, [])
        
        revoked_count = 0
        for grant in grants:
            if grant.permission == permission and not grant.revoked:
                grant.revoked = True
                grant.revoked_at = time.time()
                grant.revoked_by = revoked_by
                revoked_count += 1
        
        self._audit("permission_revoked", agent_id, {
            "permission": permission.value,
            "revoked_by": revoked_by,
            "reason": reason,
            "count": revoked_count
        })
    
    def revoke_session(self, session_id: str, revoked_by: str, reason: str = ""):
        """
        Revoke an entire session immediately
        
        Stage 3: Emergency revocation
        
        Args:
            session_id: Session to revoke
            revoked_by: Who is revoking
            reason: Reason for revocation
        """
        self.revoked_sessions.add(session_id)
        
        if session_id in self.active_sessions:
            agent_id, _, _ = self.active_sessions[session_id]
            
            self._audit("session_revoked", agent_id, {
                "session_id": session_id,
                "revoked_by": revoked_by,
                "reason": reason
            })
    
    def cleanup_expired_permissions(self) -> int:
        """
        Remove expired permission grants
        
        Returns:
            Number of permissions cleaned up
        """
        cleaned = 0
        
        for agent_id in self.agent_grants:
            before = len(self.agent_grants[agent_id])
            
            # Keep only valid grants
            self.agent_grants[agent_id] = [
                g for g in self.agent_grants[agent_id]
                if g.is_valid() or not g.expires_at  # Keep permanent even if revoked
            ]
            
            after = len(self.agent_grants[agent_id])
            cleaned += (before - after)
        
        if cleaned > 0:
            self._audit("permissions_cleanup", "system", {
                "removed": cleaned
            })
        
        return cleaned
    
    def get_agent_permissions(self, agent_id: str) -> List[Permission]:
        """
        Get all currently valid permissions for an agent
        
        Args:
            agent_id: Agent to check
            
        Returns:
            List of valid permissions
        """
        grants = self.agent_grants.get(agent_id, [])
        
        valid_perms = set()
        for grant in grants:
            if grant.is_valid():
                valid_perms.add(grant.permission)
        
        return list(valid_perms)
    
    def _audit(self, event_type: str, agent_id: str, details: Dict):
        """Log to audit trail"""
        if self.audit_logger:
            self.audit_logger.log(event_type, agent_id, details)
        else:
            # Fallback logging
            print(f"[AUDIT] {event_type}: {agent_id} - {details}")


# Role-based permission mappings
ROLE_PERMISSIONS = {
    "worker": [
        Permission.READ_OWN_TASKS,
        Permission.WRITE_OWN_TASKS,
        Permission.MODIFY_OWN_PROFILE
    ],
    "manager": [
        Permission.READ_OWN_TASKS,
        Permission.WRITE_OWN_TASKS,
        Permission.MODIFY_OWN_PROFILE,
        Permission.READ_ALL_TASKS,
        Permission.CREATE_TASKS,
        Permission.ASSIGN_TASKS,
        Permission.WRITE_TEAM_TASKS
    ],
    "admin": [
        Permission.READ_OWN_TASKS,
        Permission.WRITE_OWN_TASKS,
        Permission.MODIFY_OWN_PROFILE,
        Permission.READ_ALL_TASKS,
        Permission.CREATE_TASKS,
        Permission.ASSIGN_TASKS,
        Permission.WRITE_TEAM_TASKS,
        Permission.WRITE_ALL_TASKS,
        Permission.DELETE_ALL_TASKS,
        Permission.MODIFY_ALL_AGENTS,
        Permission.MANAGE_PERMISSIONS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.SYSTEM_ADMIN,
        Permission.DELEGATE_PERMISSIONS
    ]
}


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED PERMISSION MANAGER - STAGE 3")
    print("=" * 70)
    print()
    
    # Create manager (in production, integrate with RoleVerifier, etc.)
    pm = EnhancedPermissionManager()
    
    # Test 1: Initialize worker
    print("Test 1: Initialize worker with role-based permissions")
    pm.initialize_agent_permissions("worker-001", "worker", "system")
    
    perms = pm.get_agent_permissions("worker-001")
    print(f"  Worker permissions: {[p.value for p in perms]}")
    print()
    
    # Test 2: Check permissions
    print("Test 2: Permission checking")
    has_read = pm.has_permission("worker-001", Permission.READ_OWN_TASKS)
    has_admin = pm.has_permission("worker-001", Permission.SYSTEM_ADMIN)
    
    print(f"  Has READ_OWN_TASKS: {has_read}")
    print(f"  Has SYSTEM_ADMIN: {has_admin}")
    print()
    
    # Test 3: Temporary permission
    print("Test 3: Grant temporary permission (60 seconds)")
    # First create an admin to grant permissions
    pm.initialize_agent_permissions("admin-001", "admin", "system")
    
    success = pm.grant_temporary_permission(
        "worker-001",
        Permission.READ_ALL_TASKS,
        duration_seconds=60,
        granted_by="admin-001",
        reason="Emergency access for debugging"
    )
    
    print(f"  Temporary grant: {'✅ Success' if success else '❌ Failed'}")
    
    perms_after = pm.get_agent_permissions("worker-001")
    print(f"  Worker permissions now: {[p.value for p in perms_after]}")
    print()
    
    # Test 4: Revocation
    print("Test 4: Immediate permission revocation")
    pm.revoke_permission(
        "worker-001",
        Permission.READ_ALL_TASKS,
        "admin-001",
        "Emergency over, removing temporary access"
    )
    
    has_after_revoke = pm.has_permission("worker-001", Permission.READ_ALL_TASKS)
    print(f"  Has READ_ALL_TASKS after revoke: {has_after_revoke}")
    print()
    
    print("=" * 70)
    print("🎓 LESSON: Production-grade permission management")
    print()
    print("   Stage 2 → Stage 3 improvements:")
    print("     ✅ Role verification integration")
    print("     ✅ Time-limited permissions")
    print("     ✅ Immediate revocation")
    print("     ✅ Scope-based access")
    print("     ✅ Behavioral monitoring")
    print("     ✅ Comprehensive audit trail")
    print("=" * 70)