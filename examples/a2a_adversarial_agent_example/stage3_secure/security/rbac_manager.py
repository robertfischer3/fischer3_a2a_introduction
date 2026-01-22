"""
RBAC Manager - Stage 3: Production Security

Real-time role-based access control with fine-grained permissions.

✅ Stage 3: Real-time RBAC with permission checking
❌ Stage 2: Stale permissions (cached in session)

Security Features:
- Real-time permission evaluation
- Role hierarchy
- Resource-level permissions
- Permission inheritance
- Audit logging
- Dynamic permission updates

Usage:
    rbac = RBACManager()
    
    # Check permission
    if rbac.check_permission(user_id, "project:create"):
        create_project()
    else:
        deny_access()
"""

from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from enum import Enum
import json


class Permission(Enum):
    """
    System permissions
    
    Format: resource:action
    """
    # Project permissions
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    PROJECT_LIST = "project:list"
    
    # Task permissions
    TASK_CREATE = "task:create"
    TASK_READ = "task:read"
    TASK_UPDATE = "task:update"
    TASK_DELETE = "task:delete"
    TASK_ASSIGN = "task:assign"
    TASK_CLAIM = "task:claim"
    
    # Worker permissions
    WORKER_REGISTER = "worker:register"
    WORKER_MANAGE = "worker:manage"
    
    # System permissions
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_AUDIT = "system:audit"
    USER_MANAGE = "user:manage"
    
    # Session permissions
    SESSION_MANAGE = "session:manage"


class Role(Enum):
    """Predefined system roles"""
    USER = "user"
    COORDINATOR = "coordinator"
    ADMIN = "admin"
    AUDITOR = "auditor"


class RBACManager:
    """
    Production-grade RBAC implementation
    
    Features:
    - Real-time permission checking (no cached permissions)
    - Role hierarchy
    - Resource-level access control
    - Permission inheritance
    - Ownership-based access
    - Dynamic permission updates
    - Comprehensive audit logging
    
    Design Philosophy:
    - Least privilege by default
    - Explicit grant required
    - Real-time evaluation
    - Centralized policy enforcement
    
    Usage:
        rbac = RBACManager()
        
        # Assign role to user
        rbac.assign_role("alice", Role.USER)
        
        # Check permission
        allowed = rbac.check_permission(
            "alice",
            Permission.PROJECT_CREATE
        )
        
        # Check resource permission (ownership)
        allowed = rbac.check_resource_permission(
            "alice",
            Permission.PROJECT_UPDATE,
            resource_type="project",
            resource_id="proj-123",
            resource_owner="alice"
        )
    """
    
    def __init__(self):
        """Initialize RBAC manager with default policies"""
        
        # ✅ User role assignments (user_id -> set of roles)
        self.user_roles: Dict[str, Set[Role]] = {}
        
        # ✅ Role permissions (role -> set of permissions)
        self.role_permissions: Dict[Role, Set[Permission]] = self._init_role_permissions()
        
        # ✅ Role hierarchy (parent -> children)
        self.role_hierarchy: Dict[Role, Set[Role]] = self._init_role_hierarchy()
        
        # ✅ User-specific permissions (overrides)
        self.user_permissions: Dict[str, Set[Permission]] = {}
        
        # ✅ Resource ownership tracking
        self.resource_owners: Dict[str, Dict[str, str]] = {}  # resource_type -> {resource_id: owner}
        
        # ✅ Audit log
        self.audit_log: List[Dict] = []
        
        print("✅ RBACManager initialized (Stage 3: Real-time permissions)")
        print(f"   Roles configured: {len(self.role_permissions)}")
        print(f"   Permissions defined: {len(Permission)}")
        print(f"   Role hierarchy enabled: Yes")
    
    def _init_role_permissions(self) -> Dict[Role, Set[Permission]]:
        """
        Initialize default role permissions
        
        Design: Least privilege principle
        - USER: Basic project and task operations
        - COORDINATOR: Can manage tasks and workers
        - ADMIN: Full system access
        - AUDITOR: Read-only audit access
        """
        return {
            # USER: Basic operations on own resources
            Role.USER: {
                Permission.PROJECT_CREATE,
                Permission.PROJECT_READ,
                Permission.PROJECT_UPDATE,
                Permission.PROJECT_DELETE,
                Permission.PROJECT_LIST,
                Permission.TASK_CREATE,
                Permission.TASK_READ,
                Permission.TASK_UPDATE,
                Permission.TASK_CLAIM,
            },
            
            # COORDINATOR: Task and worker management
            Role.COORDINATOR: {
                Permission.PROJECT_CREATE,
                Permission.PROJECT_READ,
                Permission.PROJECT_LIST,
                Permission.TASK_CREATE,
                Permission.TASK_READ,
                Permission.TASK_UPDATE,
                Permission.TASK_ASSIGN,
                Permission.TASK_CLAIM,
                Permission.WORKER_REGISTER,
                Permission.WORKER_MANAGE,
            },
            
            # ADMIN: Full system access
            Role.ADMIN: {
                # All permissions
                perm for perm in Permission
            },
            
            # AUDITOR: Read-only audit access
            Role.AUDITOR: {
                Permission.SYSTEM_AUDIT,
                Permission.PROJECT_LIST,
                Permission.PROJECT_READ,
                Permission.TASK_READ,
            }
        }
    
    def _init_role_hierarchy(self) -> Dict[Role, Set[Role]]:
        """
        Initialize role hierarchy
        
        Hierarchy allows role inheritance:
        - ADMIN inherits from COORDINATOR and USER
        - COORDINATOR inherits from USER
        
        Returns:
            Dict mapping parent roles to their inherited roles
        """
        return {
            Role.ADMIN: {Role.COORDINATOR, Role.USER},
            Role.COORDINATOR: {Role.USER},
            Role.USER: set(),
            Role.AUDITOR: set()
        }
    
    def assign_role(self, user_id: str, role: Role) -> bool:
        """
        Assign a role to a user
        
        Args:
            user_id: User identifier
            role: Role to assign
        
        Returns:
            True if role assigned successfully
        
        Example:
            rbac.assign_role("alice", Role.USER)
            rbac.assign_role("bob", Role.COORDINATOR)
        """
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        
        self.user_roles[user_id].add(role)
        
        self._audit("role_assigned", {
            "user_id": user_id,
            "role": role.value
        })
        
        print(f"✅ Role assigned: {user_id} -> {role.value}")
        return True
    
    def revoke_role(self, user_id: str, role: Role) -> bool:
        """
        Revoke a role from a user
        
        Args:
            user_id: User identifier
            role: Role to revoke
        
        Returns:
            True if role revoked successfully
        """
        if user_id not in self.user_roles:
            return False
        
        if role in self.user_roles[user_id]:
            self.user_roles[user_id].remove(role)
            
            self._audit("role_revoked", {
                "user_id": user_id,
                "role": role.value
            })
            
            print(f"✅ Role revoked: {user_id} -> {role.value}")
            return True
        
        return False
    
    def get_user_roles(self, user_id: str) -> Set[Role]:
        """
        Get all roles assigned to a user
        
        Args:
            user_id: User identifier
        
        Returns:
            Set of roles
        """
        return self.user_roles.get(user_id, set())
    
    def get_effective_roles(self, user_id: str) -> Set[Role]:
        """
        Get effective roles including inherited roles
        
        Args:
            user_id: User identifier
        
        Returns:
            Set of roles including inherited ones
        
        Example:
            # User has ADMIN role
            roles = rbac.get_effective_roles("alice")
            # Returns: {ADMIN, COORDINATOR, USER} (due to hierarchy)
        """
        assigned_roles = self.user_roles.get(user_id, set())
        effective_roles = set(assigned_roles)
        
        # Add inherited roles
        for role in assigned_roles:
            if role in self.role_hierarchy:
                effective_roles.update(self.role_hierarchy[role])
        
        return effective_roles
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """
        Get all permissions for a user (real-time calculation)
        
        ✅ Stage 3: Real-time calculation
        ❌ Stage 2: Cached in session (stale)
        
        Args:
            user_id: User identifier
        
        Returns:
            Set of all permissions user has
        """
        permissions = set()
        
        # 1. Get permissions from roles (including inherited)
        effective_roles = self.get_effective_roles(user_id)
        
        for role in effective_roles:
            if role in self.role_permissions:
                permissions.update(self.role_permissions[role])
        
        # 2. Add user-specific permission overrides
        if user_id in self.user_permissions:
            permissions.update(self.user_permissions[user_id])
        
        return permissions
    
    def check_permission(
        self,
        user_id: str,
        permission: Permission
    ) -> bool:
        """
        Check if user has a specific permission
        
        ✅ Stage 3: Real-time check (fresh permissions)
        ❌ Stage 2: Check cached session permissions (stale)
        
        Args:
            user_id: User identifier
            permission: Permission to check
        
        Returns:
            True if user has permission
        
        Example:
            if rbac.check_permission("alice", Permission.PROJECT_CREATE):
                create_project()
            else:
                return {"error": "Access denied"}
        """
        # ✅ Real-time permission calculation
        user_permissions = self.get_user_permissions(user_id)
        
        has_permission = permission in user_permissions
        
        # Audit denied access
        if not has_permission:
            self._audit("permission_denied", {
                "user_id": user_id,
                "permission": permission.value
            })
        
        return has_permission
    
    def check_resource_permission(
        self,
        user_id: str,
        permission: Permission,
        resource_type: str,
        resource_id: str,
        resource_owner: Optional[str] = None
    ) -> bool:
        """
        Check permission with resource-level access control
        
        Checks:
        1. User has the required permission
        2. User has access to this specific resource
        
        Resource access rules:
        - Owner always has access
        - ADMIN has access to all resources
        - Others need explicit permission
        
        Args:
            user_id: User identifier
            permission: Permission to check
            resource_type: Type of resource (project, task, etc.)
            resource_id: Resource identifier
            resource_owner: Resource owner (if known)
        
        Returns:
            True if user has permission for this resource
        
        Example:
            # Check if alice can update bob's project
            allowed = rbac.check_resource_permission(
                "alice",
                Permission.PROJECT_UPDATE,
                resource_type="project",
                resource_id="proj-123",
                resource_owner="bob"
            )
            # False - alice can only update her own projects
        """
        # 1. Check if user has the permission at all
        if not self.check_permission(user_id, permission):
            return False
        
        # 2. Check if user is admin (admins have access to everything)
        if Role.ADMIN in self.get_effective_roles(user_id):
            return True
        
        # 3. Check ownership
        if resource_owner:
            # Owner has access to their own resources
            if user_id == resource_owner:
                return True
        
        # 4. Look up ownership if not provided
        if not resource_owner and resource_type in self.resource_owners:
            stored_owner = self.resource_owners[resource_type].get(resource_id)
            if stored_owner and user_id == stored_owner:
                return True
        
        # 5. If not owner and not admin, deny access
        self._audit("resource_access_denied", {
            "user_id": user_id,
            "permission": permission.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_owner": resource_owner
        })
        
        return False
    
    def register_resource(
        self,
        resource_type: str,
        resource_id: str,
        owner: str
    ):
        """
        Register a resource with its owner
        
        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            owner: Owner user ID
        
        Example:
            # Alice creates a project
            rbac.register_resource("project", "proj-123", "alice")
        """
        if resource_type not in self.resource_owners:
            self.resource_owners[resource_type] = {}
        
        self.resource_owners[resource_type][resource_id] = owner
        
        self._audit("resource_registered", {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "owner": owner
        })
    
    def transfer_ownership(
        self,
        resource_type: str,
        resource_id: str,
        new_owner: str,
        requesting_user: str
    ) -> bool:
        """
        Transfer resource ownership
        
        Only current owner or admin can transfer ownership
        
        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            new_owner: New owner user ID
            requesting_user: User requesting transfer
        
        Returns:
            True if transfer successful
        """
        if resource_type not in self.resource_owners:
            return False
        
        if resource_id not in self.resource_owners[resource_type]:
            return False
        
        current_owner = self.resource_owners[resource_type][resource_id]
        
        # Check authorization
        is_owner = requesting_user == current_owner
        is_admin = Role.ADMIN in self.get_effective_roles(requesting_user)
        
        if not (is_owner or is_admin):
            self._audit("transfer_denied", {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "requesting_user": requesting_user
            })
            return False
        
        # Transfer ownership
        self.resource_owners[resource_type][resource_id] = new_owner
        
        self._audit("ownership_transferred", {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "old_owner": current_owner,
            "new_owner": new_owner,
            "transferred_by": requesting_user
        })
        
        print(f"✅ Ownership transferred: {resource_type}:{resource_id}")
        print(f"   {current_owner} -> {new_owner}")
        
        return True
    
    def grant_permission(
        self,
        user_id: str,
        permission: Permission,
        granter: str
    ) -> bool:
        """
        Grant a specific permission to a user (override)
        
        Only admins can grant permissions
        
        Args:
            user_id: User to grant permission to
            permission: Permission to grant
            granter: User granting the permission
        
        Returns:
            True if granted successfully
        """
        # Check if granter is admin
        if Role.ADMIN not in self.get_effective_roles(granter):
            self._audit("grant_denied", {
                "user_id": user_id,
                "permission": permission.value,
                "granter": granter,
                "reason": "granter_not_admin"
            })
            return False
        
        if user_id not in self.user_permissions:
            self.user_permissions[user_id] = set()
        
        self.user_permissions[user_id].add(permission)
        
        self._audit("permission_granted", {
            "user_id": user_id,
            "permission": permission.value,
            "granted_by": granter
        })
        
        print(f"✅ Permission granted: {user_id} -> {permission.value}")
        return True
    
    def revoke_permission(
        self,
        user_id: str,
        permission: Permission,
        revoker: str
    ) -> bool:
        """
        Revoke a specific permission from a user
        
        Only admins can revoke permissions
        
        Args:
            user_id: User to revoke permission from
            permission: Permission to revoke
            revoker: User revoking the permission
        
        Returns:
            True if revoked successfully
        """
        # Check if revoker is admin
        if Role.ADMIN not in self.get_effective_roles(revoker):
            return False
        
        if user_id not in self.user_permissions:
            return False
        
        if permission in self.user_permissions[user_id]:
            self.user_permissions[user_id].remove(permission)
            
            self._audit("permission_revoked", {
                "user_id": user_id,
                "permission": permission.value,
                "revoked_by": revoker
            })
            
            print(f"✅ Permission revoked: {user_id} -> {permission.value}")
            return True
        
        return False
    
    def _audit(self, event_type: str, details: Dict):
        """Log RBAC event for audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        self.audit_log.append(log_entry)
        
        # Keep last 10000 events
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
    
    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Get audit log entries
        
        Args:
            user_id: Filter by user (optional)
            event_type: Filter by event type (optional)
            limit: Maximum entries to return
        
        Returns:
            List of audit log entries
        """
        filtered = self.audit_log
        
        if user_id:
            filtered = [
                entry for entry in filtered
                if entry["details"].get("user_id") == user_id
            ]
        
        if event_type:
            filtered = [
                entry for entry in filtered
                if entry["event_type"] == event_type
            ]
        
        return filtered[-limit:]
    
    def get_stats(self) -> Dict:
        """Get RBAC statistics"""
        return {
            "total_users": len(self.user_roles),
            "total_roles": len(self.role_permissions),
            "total_permissions": len(Permission),
            "users_with_overrides": len(self.user_permissions),
            "tracked_resources": sum(
                len(resources) for resources in self.resource_owners.values()
            ),
            "audit_entries": len(self.audit_log)
        }


if __name__ == "__main__":
    """Test the RBAC Manager"""
    print("=" * 70)
    print("RBAC Manager Test (Stage 3: Real-time permissions)")
    print("=" * 70)
    
    rbac = RBACManager()
    
    print("\n--- Test 1: Assign Roles ---")
    rbac.assign_role("alice", Role.USER)
    rbac.assign_role("bob", Role.COORDINATOR)
    rbac.assign_role("admin", Role.ADMIN)
    
    print("\n--- Test 2: Check Basic Permissions ---")
    print("Alice (USER) permissions:")
    alice_perms = rbac.get_user_permissions("alice")
    print(f"  Has {len(alice_perms)} permissions")
    print(f"  Can create projects: {rbac.check_permission('alice', Permission.PROJECT_CREATE)}")
    print(f"  Can manage workers: {rbac.check_permission('alice', Permission.WORKER_MANAGE)}")
    
    print("\nBob (COORDINATOR) permissions:")
    bob_perms = rbac.get_user_permissions("bob")
    print(f"  Has {len(bob_perms)} permissions")
    print(f"  Can create projects: {rbac.check_permission('bob', Permission.PROJECT_CREATE)}")
    print(f"  Can manage workers: {rbac.check_permission('bob', Permission.WORKER_MANAGE)}")
    
    print("\nAdmin (ADMIN) permissions:")
    admin_perms = rbac.get_user_permissions("admin")
    print(f"  Has {len(admin_perms)} permissions (all)")
    print(f"  Can admin system: {rbac.check_permission('admin', Permission.SYSTEM_ADMIN)}")
    
    print("\n--- Test 3: Role Hierarchy ---")
    print("Admin effective roles (with inheritance):")
    admin_roles = rbac.get_effective_roles("admin")
    print(f"  {[role.value for role in admin_roles]}")
    print("  ✅ ADMIN inherits from COORDINATOR and USER")
    
    print("\n--- Test 4: Resource-Level Access Control ---")
    
    # Alice creates a project
    rbac.register_resource("project", "proj-alice-1", "alice")
    
    # Bob creates a project
    rbac.register_resource("project", "proj-bob-1", "bob")
    
    print("Alice's project (proj-alice-1):")
    print(f"  Alice can update: {rbac.check_resource_permission('alice', Permission.PROJECT_UPDATE, 'project', 'proj-alice-1', 'alice')}")
    print(f"  Bob can update: {rbac.check_resource_permission('bob', Permission.PROJECT_UPDATE, 'project', 'proj-alice-1', 'alice')}")
    print(f"  Admin can update: {rbac.check_resource_permission('admin', Permission.PROJECT_UPDATE, 'project', 'proj-alice-1', 'alice')}")
    
    print("\n--- Test 5: Permission Grants (Overrides) ---")
    print("Granting special permission to Alice...")
    rbac.grant_permission("alice", Permission.WORKER_MANAGE, "admin")
    
    print(f"Alice can now manage workers: {rbac.check_permission('alice', Permission.WORKER_MANAGE)}")
    
    print("\n--- Test 6: Real-time Permission Updates ---")
    print("Stage 2 problem: Permissions cached in session")
    print("Stage 3 solution: Real-time evaluation")
    
    print("\nAlice currently has USER role")
    print(f"  Can admin system: {rbac.check_permission('alice', Permission.SYSTEM_ADMIN)}")
    
    print("\nPromoting Alice to ADMIN...")
    rbac.assign_role("alice", Role.ADMIN)
    
    print("Checking again (real-time):")
    print(f"  Can admin system: {rbac.check_permission('alice', Permission.SYSTEM_ADMIN)}")
    print("  ✅ Permission change takes effect immediately!")
    
    print("\n--- Test 7: Ownership Transfer ---")
    print("Alice transfers project to Bob...")
    success = rbac.transfer_ownership("project", "proj-alice-1", "bob", "alice")
    print(f"Transfer successful: {success}")
    
    print("After transfer:")
    print(f"  Alice can update: {rbac.check_resource_permission('alice', Permission.PROJECT_UPDATE, 'project', 'proj-alice-1', 'bob')}")
    print(f"  Bob can update: {rbac.check_resource_permission('bob', Permission.PROJECT_UPDATE, 'project', 'proj-alice-1', 'bob')}")
    
    print("\n--- Test 8: Statistics ---")
    stats = rbac.get_stats()
    print(f"Total users: {stats['total_users']}")
    print(f"Total roles: {stats['total_roles']}")
    print(f"Total permissions: {stats['total_permissions']}")
    print(f"Tracked resources: {stats['tracked_resources']}")
    print(f"Audit entries: {stats['audit_entries']}")
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ RBAC Manager provides production-grade access control")
    print("   - Real-time permission evaluation")
    print("   - Role hierarchy with inheritance")
    print("   - Resource-level permissions")
    print("   - Ownership-based access")
    print("   - Dynamic permission updates")
    print("   - Comprehensive audit trail")