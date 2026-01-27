"""
Role Verifier - Stage 3

Blocks VULN-S2-001: Role Escalation via Unverified Requests

This module implements a multi-step role verification workflow that prevents
agents from self-granting administrative privileges.

Stage 2 Problem:
    System trusted the requested_role field without verification.
    Attackers could request "admin" and be instantly granted those permissions.

Stage 3 Solution:
    - Multi-step approval workflow
    - Admin authorization required for role elevation
    - External identity verification
    - Comprehensive audit trail
    - Pending request queue
"""

import time
import secrets
from typing import Dict, List, Optional, Tuple
from enum import Enum


class RoleRequestStatus(Enum):
    """Status of role elevation request"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class RoleLevel(Enum):
    """Role hierarchy levels"""
    WORKER = 1
    MANAGER = 2
    ADMIN = 3


ROLE_HIERARCHY = {
    "worker": RoleLevel.WORKER,
    "manager": RoleLevel.MANAGER,
    "admin": RoleLevel.ADMIN
}


class RoleVerifier:
    """
    Manages role elevation requests with approval workflow
    
    Workflow:
    1. Agent requests role elevation
    2. Request enters pending queue
    3. System performs identity verification (external check)
    4. Admin reviews and approves/denies
    5. Role granted only after approval
    6. All steps logged to audit trail
    """
    
    REQUEST_EXPIRATION = 3600  # 1 hour - requests expire if not processed
    
    def __init__(self, audit_logger=None):
        """
        Initialize role verifier
        
        Args:
            audit_logger: Logger for audit trail
        """
        self.pending_requests = {}  # request_id -> request_data
        self.approved_roles = {}    # agent_id -> role
        self.audit_logger = audit_logger
        self.stats = {
            "total_requests": 0,
            "pending": 0,
            "approved": 0,
            "denied": 0,
            "expired": 0
        }
    
    def request_role(self, agent_id: str, requested_role: str, 
                     justification: str = "") -> Tuple[str, str]:
        """
        Submit role elevation request
        
        Args:
            agent_id: Agent requesting elevation
            requested_role: Desired role (manager or admin)
            justification: Reason for request
            
        Returns:
            (request_id, status_message)
        """
        # Validate role
        if requested_role not in ROLE_HIERARCHY:
            return None, f"Invalid role: {requested_role}"
        
        # Worker role doesn't require approval
        if requested_role == "worker":
            self.approved_roles[agent_id] = "worker"
            self._audit("role_granted_automatic", agent_id, {"role": "worker"})
            return None, "Worker role granted automatically"
        
        # Check if already has role
        current_role = self.approved_roles.get(agent_id, "none")
        if current_role == requested_role:
            return None, f"Agent already has role: {requested_role}"
        
        # Check if trying to elevate to lower role
        if self._is_downgrade(current_role, requested_role):
            return None, "Cannot request lower role than current"
        
        # Create pending request
        request_id = self._generate_request_id()
        request = {
            "request_id": request_id,
            "agent_id": agent_id,
            "requested_role": requested_role,
            "current_role": current_role,
            "justification": justification,
            "created_at": time.time(),
            "expires_at": time.time() + self.REQUEST_EXPIRATION,
            "status": RoleRequestStatus.PENDING.value,
            "identity_verified": False,
            "admin_reviewed": False
        }
        
        self.pending_requests[request_id] = request
        self.stats["total_requests"] += 1
        self.stats["pending"] += 1
        
        self._audit("role_request_submitted", agent_id, {
            "request_id": request_id,
            "requested_role": requested_role,
            "justification": justification
        })
        
        return request_id, "Request submitted for approval"
    
    def verify_identity(self, request_id: str, verification_result: bool,
                       verification_method: str = "external_idp") -> Tuple[bool, str]:
        """
        Verify agent identity against external identity provider
        
        In production, this would check against:
        - LDAP/Active Directory
        - OAuth provider
        - HR database
        - Security clearance system
        
        Args:
            request_id: Request to verify
            verification_result: Result from identity provider
            verification_method: Method used for verification
            
        Returns:
            (success, message)
        """
        request = self.pending_requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        if request["status"] != RoleRequestStatus.PENDING.value:
            return False, f"Request status is {request['status']}, cannot verify"
        
        request["identity_verified"] = verification_result
        request["verification_method"] = verification_method
        request["verified_at"] = time.time()
        
        if not verification_result:
            # Identity verification failed
            request["status"] = RoleRequestStatus.DENIED.value
            self.stats["pending"] -= 1
            self.stats["denied"] += 1
            
            self._audit("role_request_denied_identity", request["agent_id"], {
                "request_id": request_id,
                "reason": "Identity verification failed"
            })
            
            return False, "Identity verification failed - request denied"
        
        self._audit("role_request_identity_verified", request["agent_id"], {
            "request_id": request_id,
            "method": verification_method
        })
        
        return True, "Identity verified - awaiting admin approval"
    
    def approve_request(self, request_id: str, admin_id: str,
                       admin_notes: str = "") -> Tuple[bool, str]:
        """
        Approve role elevation request (admin only)
        
        Args:
            request_id: Request to approve
            admin_id: ID of approving admin
            admin_notes: Admin's notes/comments
            
        Returns:
            (success, message)
        """
        # Verify admin has authority
        if not self._is_admin(admin_id):
            return False, "Only admins can approve role requests"
        
        request = self.pending_requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        if request["status"] != RoleRequestStatus.PENDING.value:
            return False, f"Request status is {request['status']}, cannot approve"
        
        # Check if expired
        if time.time() > request["expires_at"]:
            request["status"] = RoleRequestStatus.EXPIRED.value
            self.stats["pending"] -= 1
            self.stats["expired"] += 1
            return False, "Request has expired"
        
        # Check identity was verified
        if not request.get("identity_verified", False):
            return False, "Cannot approve - identity not verified"
        
        # Grant role
        agent_id = request["agent_id"]
        new_role = request["requested_role"]
        
        self.approved_roles[agent_id] = new_role
        request["status"] = RoleRequestStatus.APPROVED.value
        request["approved_by"] = admin_id
        request["approved_at"] = time.time()
        request["admin_notes"] = admin_notes
        request["admin_reviewed"] = True
        
        self.stats["pending"] -= 1
        self.stats["approved"] += 1
        
        self._audit("role_request_approved", agent_id, {
            "request_id": request_id,
            "new_role": new_role,
            "approved_by": admin_id,
            "notes": admin_notes
        })
        
        return True, f"Role '{new_role}' granted to {agent_id}"
    
    def deny_request(self, request_id: str, admin_id: str,
                    reason: str = "") -> Tuple[bool, str]:
        """
        Deny role elevation request (admin only)
        
        Args:
            request_id: Request to deny
            admin_id: ID of denying admin
            reason: Reason for denial
            
        Returns:
            (success, message)
        """
        # Verify admin has authority
        if not self._is_admin(admin_id):
            return False, "Only admins can deny role requests"
        
        request = self.pending_requests.get(request_id)
        if not request:
            return False, "Request not found"
        
        if request["status"] != RoleRequestStatus.PENDING.value:
            return False, f"Request status is {request['status']}, cannot deny"
        
        # Deny request
        agent_id = request["agent_id"]
        
        request["status"] = RoleRequestStatus.DENIED.value
        request["denied_by"] = admin_id
        request["denied_at"] = time.time()
        request["denial_reason"] = reason
        request["admin_reviewed"] = True
        
        self.stats["pending"] -= 1
        self.stats["denied"] += 1
        
        self._audit("role_request_denied", agent_id, {
            "request_id": request_id,
            "denied_by": admin_id,
            "reason": reason
        })
        
        return True, f"Request denied: {reason}"
    
    def get_agent_role(self, agent_id: str) -> str:
        """Get current role for agent"""
        return self.approved_roles.get(agent_id, "none")
    
    def get_pending_requests(self) -> List[Dict]:
        """Get all pending requests (admin view)"""
        self._expire_old_requests()
        
        return [
            request for request in self.pending_requests.values()
            if request["status"] == RoleRequestStatus.PENDING.value
        ]
    
    def get_request_status(self, request_id: str) -> Optional[Dict]:
        """Get status of specific request"""
        return self.pending_requests.get(request_id)
    
    def _is_admin(self, agent_id: str) -> bool:
        """Check if agent has admin role"""
        return self.approved_roles.get(agent_id) == "admin"
    
    def _is_downgrade(self, current_role: str, requested_role: str) -> bool:
        """Check if request is for lower role"""
        if current_role == "none":
            return False
        
        current_level = ROLE_HIERARCHY.get(current_role, RoleLevel.WORKER)
        requested_level = ROLE_HIERARCHY.get(requested_role, RoleLevel.WORKER)
        
        return requested_level.value < current_level.value
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return f"role_req_{secrets.token_hex(8)}"
    
    def _expire_old_requests(self):
        """Mark expired requests"""
        current_time = time.time()
        
        for request_id, request in self.pending_requests.items():
            if (request["status"] == RoleRequestStatus.PENDING.value and
                current_time > request["expires_at"]):
                request["status"] = RoleRequestStatus.EXPIRED.value
                self.stats["pending"] -= 1
                self.stats["expired"] += 1
                
                self._audit("role_request_expired", request["agent_id"], {
                    "request_id": request_id
                })
    
    def _audit(self, event_type: str, agent_id: str, details: Dict):
        """Log to audit trail"""
        if self.audit_logger:
            self.audit_logger.log(event_type, agent_id, details)
        else:
            # Fallback to print for demo
            print(f"[AUDIT] {event_type}: {agent_id} - {details}")
    
    def get_statistics(self) -> Dict:
        """Get role verifier statistics"""
        return self.stats.copy()


# Example usage and testing
if __name__ == "__main__":
    print("=" * 70)
    print("ROLE VERIFIER - ROLE ESCALATION PREVENTION")
    print("=" * 70)
    print()
    
    verifier = RoleVerifier()
    
    # Bootstrap: Create first admin manually (in production, seed from config)
    verifier.approved_roles["bootstrap-admin"] = "admin"
    print("Bootstrap: Created initial admin 'bootstrap-admin'")
    print()
    
    # Test 1: Agent requests admin role
    print("Test 1: Agent requests admin role")
    print("  Agent: worker-001")
    print("  Requested role: admin")
    
    request_id, message = verifier.request_role(
        "worker-001",
        "admin",
        justification="Need admin access for system maintenance"
    )
    
    print(f"  Result: {message}")
    print(f"  Request ID: {request_id}")
    print()
    
    # Test 2: Check request status (should be pending)
    print("Test 2: Check request status")
    status = verifier.get_request_status(request_id)
    print(f"  Status: {status['status']}")
    print(f"  Identity verified: {status['identity_verified']}")
    print(f"  Admin reviewed: {status['admin_reviewed']}")
    print()
    
    # Test 3: Verify identity
    print("Test 3: Verify identity against external IdP")
    success, message = verifier.verify_identity(request_id, True, "LDAP")
    print(f"  Result: {message}")
    print()
    
    # Test 4: Try to use role before approval (should fail)
    print("Test 4: Check if agent has admin role (before approval)")
    current_role = verifier.get_agent_role("worker-001")
    print(f"  Current role: {current_role}")
    print(f"  Has admin: {'✅ YES' if current_role == 'admin' else '❌ NO (correctly blocked)'}")
    print()
    
    # Test 5: Admin approves request
    print("Test 5: Admin approves role request")
    success, message = verifier.approve_request(
        request_id,
        "bootstrap-admin",
        admin_notes="Verified need for system maintenance tasks"
    )
    print(f"  Result: {message}")
    print()
    
    # Test 6: Check role after approval
    print("Test 6: Check agent role after approval")
    current_role = verifier.get_agent_role("worker-001")
    print(f"  Current role: {current_role}")
    print(f"  Has admin: {'✅ YES' if current_role == 'admin' else '❌ NO'}")
    print()
    
    # Test 7: Agent tries to request again (should be rejected)
    print("Test 7: Agent tries to request admin again")
    request_id2, message = verifier.request_role("worker-001", "admin")
    print(f"  Result: {message}")
    print()
    
    # Statistics
    print("=" * 70)
    print("VERIFICATION STATISTICS")
    print("=" * 70)
    stats = verifier.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print()
    
    print("=" * 70)
    print("🎓 LESSON: Multi-step role verification")
    print()
    print("   Role elevation requires:")
    print("     1. Agent submits request with justification")
    print("     2. Identity verified against external IdP")
    print("     3. Admin reviews and approves")
    print("     4. Role granted only after all steps complete")
    print("     5. Complete audit trail maintained")
    print()
    print("   Stage 2: Trusted requested_role → instant admin")
    print("   Stage 3: Multi-step approval → prevents self-escalation")
    print("=" * 70)