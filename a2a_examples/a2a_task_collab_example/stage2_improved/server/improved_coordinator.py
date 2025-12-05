#!/usr/bin/env python3
"""
Task Coordinator Agent - Stage 2: IMPROVED

⚠️  WARNING: This code has BASIC SECURITY but is NOT PRODUCTION-READY.
    Security Rating: 4/10

Purpose: Demonstrate incremental security improvements and their limitations
Improvements: 20 security enhancements over Stage 1
Remaining Issues: 15 critical vulnerabilities

This coordinator shows why "better" doesn't mean "secure".
"""

import socket
import json
import threading
import uuid
import hmac
import hashlib
import bcrypt
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class ImprovedCoordinator:
    """
    Improved coordinator with basic security measures.
    
    ⚠️  PARTIALLY SECURE - NOT PRODUCTION-READY
    
    Improvements over Stage 1:
    + Random session IDs (UUID4)
    + Password authentication
    + HMAC signatures
    + Idle timeout
    + Logout destroys sessions
    + Basic input validation
    + Role-based permissions (partial)
    
    Still vulnerable to:
    - Replay attacks (no nonce)
    - Session hijacking (weak binding)
    - Stale permissions
    - No rate limiting
    - State not encrypted
    - And 10 more issues...
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.agent_id = "coordinator-001"
        self.agent_name = "ImprovedCoordinator"
        
        # ✅ IMPROVEMENT 1: Random session IDs (UUID4)
        # Better than sequential, but still not cryptographically secure
        # ⚠️  Should use secrets.token_urlsafe(32) in production
        self.sessions: Dict[str, dict] = {}
        
        # ✅ IMPROVEMENT 2: Idle timeout
        # Sessions expire after 30 minutes of inactivity
        # ⚠️  But no absolute timeout (sessions can live forever if active)
        self.IDLE_TIMEOUT = timedelta(minutes=30)
        
        # ✅ IMPROVEMENT 3: User credentials storage
        # Simple password authentication with bcrypt
        # ⚠️  In production, use proper user database
        self.users: Dict[str, dict] = {}
        self._initialize_users()
        
        # ✅ IMPROVEMENT 4: Shared secret for HMAC
        # Used for request signing
        # ⚠️  Shared secrets problematic at scale (use RSA in production)
        self.hmac_secret = b"shared_secret_key_12345"
        
        # State storage
        self.projects: Dict[str, dict] = {}
        self.tasks: Dict[str, dict] = {}
        self.workers: Dict[str, dict] = {}
        
        # Counters
        self.project_counter = 0
        self.task_counter = 0
        
        print(f"🚀 Improved Task Coordinator started")
        print(f"   Host: {self.host}:{self.port}")
        print(f"   ⚠️  PARTIAL SECURITY - 4/10 rating")
        print(f"   Improvements: 20")
        print(f"   Remaining Issues: 15")
        print()
    
    def _initialize_users(self):
        """
        Initialize test users with hashed passwords
        
        ✅ IMPROVEMENT: Password hashing with bcrypt
        ⚠️  Weak: No password policy, no lockout, no salt rotation
        """
        # Create test users
        users_data = [
            ("admin", "admin123", "admin"),
            ("coordinator1", "coord123", "coordinator"),
            ("worker1", "work123", "worker"),
            ("viewer1", "view123", "observer")
        ]
        
        for username, password, role in users_data:
            password_hash = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            )
            self.users[username] = {
                "password_hash": password_hash,
                "role": role,
                "created_at": datetime.now().isoformat()
            }
        
        print(f"✅ Initialized {len(self.users)} test users")
        print(f"   (admin/admin123, coordinator1/coord123, worker1/work123, viewer1/view123)")
        print()
    
    def start(self):
        """Start the coordinator server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"📡 Listening on {self.host}:{self.port}")
        print(f"   Authentication: Required")
        print(f"   Signatures: HMAC-SHA256")
        print()
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                print(f"📥 New connection from {address}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\n🛑 Shutting down coordinator...")
                break
            except Exception as e:
                print(f"❌ Error accepting connection: {e}")
        
        server_socket.close()
    
    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle a client connection"""
        try:
            while True:
                data = client_socket.recv(65536)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    response = {
                        "status": "error",
                        "message": "Invalid JSON"
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    continue
                
                # Process message
                response = self.process_message(message, address)
                client_socket.send(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            print(f"❌ Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"📤 Connection closed: {address}")
    
    def process_message(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """
        Process incoming message
        
        ✅ IMPROVEMENT: Basic message validation
        ⚠️  Still incomplete validation
        """
        action = message.get("action", "unknown")
        
        print(f"📨 Received: {action} from {address}")
        
        # Route to handler
        if action == "HANDSHAKE":
            return self.handle_handshake(message)
        elif action == "login":
            return self.handle_login(message, address)
        elif action == "logout":
            return self.handle_logout(message)
        elif action == "create_project":
            return self.handle_create_project(message, address)
        elif action == "list_projects":
            return self.handle_list_projects(message, address)
        elif action == "get_project":
            return self.handle_get_project(message, address)
        elif action == "assign_task":
            return self.handle_assign_task(message, address)
        elif action == "update_task":
            return self.handle_update_task(message, address)
        elif action == "register_worker":
            return self.handle_register_worker(message, address)
        elif action == "get_session_info":
            return self.handle_get_session_info(message)
        else:
            return {
                "status": "error",
                "message": f"Unknown action: {action}"
            }
    
    def handle_handshake(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initial handshake"""
        return {
            "status": "success",
            "message": "Handshake successful",
            "agent_card": {
                "agent_id": self.agent_id,
                "name": self.agent_name,
                "type": "coordinator",
                "capabilities": [
                    "project_management",
                    "task_assignment",
                    "worker_coordination"
                ],
                "version": "2.0.0-improved",
                "security_level": "PARTIAL - 4/10",
                "authentication": "Password + HMAC",
                "improvements": [
                    "Random session IDs",
                    "Password authentication",
                    "HMAC signatures",
                    "Idle timeout (30 min)",
                    "Logout destroys sessions"
                ],
                "remaining_issues": [
                    "No replay protection",
                    "No rate limiting",
                    "Stale permissions",
                    "State not encrypted"
                ]
            }
        }
    
    def handle_login(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """
        Handle agent login
        
        ✅ IMPROVEMENTS:
        - Password authentication required
        - Bcrypt password hashing
        - Random session IDs (UUID4)
        - IP address stored
        - Idle timeout enforced
        
        ⚠️  STILL VULNERABLE:
        - No absolute timeout
        - UUID4 not cryptographically secure
        - No TLS fingerprint binding
        - No concurrent session limits
        - Weak password policy
        """
        agent_id = message.get("agent_id")
        password = message.get("password")
        
        # ✅ IMPROVEMENT: Require authentication
        if not agent_id or not password:
            print(f"❌ Login failed: Missing credentials")
            return {
                "status": "error",
                "message": "agent_id and password required"
            }
        
        # ✅ IMPROVEMENT: Verify credentials
        if agent_id not in self.users:
            print(f"❌ Login failed: Unknown user {agent_id}")
            return {
                "status": "error",
                "message": "Invalid credentials"
            }
        
        user = self.users[agent_id]
        
        # ✅ IMPROVEMENT: Bcrypt password verification
        if not bcrypt.checkpw(password.encode('utf-8'), user["password_hash"]):
            print(f"❌ Login failed: Wrong password for {agent_id}")
            # ⚠️  Should implement lockout after N failed attempts
            return {
                "status": "error",
                "message": "Invalid credentials"
            }
        
        # ✅ IMPROVEMENT 1: Random session ID (UUID4)
        # Better than sequential but not cryptographically secure
        session_id = str(uuid.uuid4())
        
        # ✅ IMPROVEMENT 2: Store session metadata
        now = datetime.now()
        client_ip = address[0]
        
        self.sessions[session_id] = {
            "agent_id": agent_id,
            "role": user["role"],
            "created_at": now.isoformat(),
            "last_activity": now.isoformat(),
            "client_ip": client_ip,
            # ⚠️  Missing: TLS fingerprint
            # ⚠️  Missing: absolute timeout
            # ⚠️  Missing: concurrent session tracking
        }
        
        print(f"✅ Login successful: {agent_id} (role: {user['role']})")
        print(f"   Session: {session_id}")
        print(f"   IP: {client_ip}")
        print(f"   ⚠️  UUID4 - not cryptographically secure")
        
        return {
            "status": "success",
            "session_id": session_id,
            "message": f"Logged in as {user['role']}",
            "agent_id": agent_id,
            "role": user["role"]
        }
    
    def handle_logout(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle agent logout
        
        ✅ IMPROVEMENT: Actually destroys session now!
        """
        session_id = message.get("session_id")
        
        if session_id in self.sessions:
            agent_id = self.sessions[session_id]["agent_id"]
            
            # ✅ IMPROVEMENT: Actually delete the session!
            del self.sessions[session_id]
            
            print(f"✅ Logout: {agent_id}")
            print(f"   Session destroyed: {session_id}")
            
            return {
                "status": "success",
                "message": "Logged out successfully - session destroyed"
            }
        else:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
    
    def validate_session(self, session_id: str, client_ip: str) -> Optional[dict]:
        """
        Validate session
        
        ✅ IMPROVEMENTS:
        - Checks if session exists
        - Enforces idle timeout
        - Checks client IP
        
        ⚠️  STILL MISSING:
        - No absolute timeout
        - No TLS fingerprint check
        - IP mismatch only warns, doesn't block
        - No nonce checking (replay possible)
        """
        # ✅ Check existence
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        now = datetime.now()
        
        # ✅ IMPROVEMENT: Idle timeout enforcement
        last_activity = datetime.fromisoformat(session["last_activity"])
        if now - last_activity > self.IDLE_TIMEOUT:
            print(f"⏰ Session expired (idle timeout): {session_id}")
            del self.sessions[session_id]
            return None
        
        # ⚠️  Missing: Absolute timeout check
        # Session can live forever if kept active!
        
        # ✅ IMPROVEMENT: IP checking
        # ⚠️  But only warns, doesn't block!
        if client_ip != session["client_ip"]:
            print(f"⚠️  IP mismatch for session {session_id}")
            print(f"   Original: {session['client_ip']}")
            print(f"   Current: {client_ip}")
            # ⚠️  Should reject here, but we just warn
            # This is security theater!
        
        # ✅ Update activity timestamp
        session["last_activity"] = now.isoformat()
        
        return session
    
    def verify_signature(self, message: Dict[str, Any]) -> bool:
        """
        Verify HMAC signature
        
        ✅ IMPROVEMENT: Request signatures required
        ⚠️  LIMITATION: No nonce = replay attacks possible
        """
        auth = message.get("auth", {})
        
        provided_signature = auth.get("signature")
        if not provided_signature:
            return False
        
        # ✅ Extract message components
        agent_id = auth.get("agent_id")
        timestamp = auth.get("timestamp")
        
        # ✅ IMPROVEMENT: Timestamp validation
        # ⚠️  But 30-minute window is too large
        current_time = time.time()
        if abs(current_time - timestamp) > 1800:  # 30 minutes
            print(f"⚠️  Request too old: {current_time - timestamp} seconds")
            return False
        
        # ⚠️  MISSING: Nonce checking
        # Same signed request can be replayed infinite times!
        
        # ✅ Compute expected signature
        payload_str = json.dumps(message.get("payload", {}), sort_keys=True)
        message_to_sign = f"{agent_id}:{timestamp}:{payload_str}"
        
        expected_signature = hmac.new(
            self.hmac_secret,
            message_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # ✅ Constant-time comparison
        return hmac.compare_digest(provided_signature, expected_signature)
    
    def check_permission(self, session: dict, required_role: str) -> bool:
        """
        Check if session has required permission
        
        ✅ IMPROVEMENT: Basic RBAC
        ⚠️  LIMITATIONS:
        - Inconsistent enforcement
        - Stale permissions (role changes don't propagate)
        - Simple role hierarchy
        """
        role_hierarchy = {
            "admin": 4,
            "coordinator": 3,
            "worker": 2,
            "observer": 1
        }
        
        user_role = session.get("role", "observer")
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    def handle_create_project(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """
        Create a new project
        
        ✅ IMPROVEMENTS:
        - Session validation required
        - Signature verification
        - Role-based authorization
        - Input validation
        
        ⚠️  STILL VULNERABLE:
        - Replay attacks (no nonce)
        - Input sanitization incomplete
        """
        session_id = message.get("session_id")
        client_ip = address[0]
        
        # ✅ IMPROVEMENT: Validate session
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        # ✅ IMPROVEMENT: Verify signature
        if not self.verify_signature(message):
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # ✅ IMPROVEMENT: Check authorization
        # Only coordinators and admins can create projects
        if not self.check_permission(session, "coordinator"):
            return {
                "status": "error",
                "message": "Insufficient permissions - coordinator role required"
            }
        
        payload = message.get("payload", {})
        
        # ✅ IMPROVEMENT: Input validation
        project_name = payload.get("name", "")
        if not project_name or len(project_name) > 200:
            return {
                "status": "error",
                "message": "Invalid project name (1-200 characters required)"
            }
        
        description = payload.get("description", "")
        if len(description) > 2000:
            return {
                "status": "error",
                "message": "Description too long (max 2000 characters)"
            }
        
        # ⚠️  Missing: Sanitization (XSS, injection still possible)
        
        # Create project
        self.project_counter += 1
        project_id = f"proj_{self.project_counter:03d}"
        
        self.projects[project_id] = {
            "project_id": project_id,
            "name": project_name,
            "description": description,
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "created_by": session["agent_id"],
            "tasks": [],
            "metadata": payload.get("metadata", {})
        }
        
        print(f"📁 Project created: {project_id} - {project_name}")
        print(f"   By: {session['agent_id']} ({session['role']})")
        
        return {
            "status": "success",
            "project_id": project_id,
            "message": f"Project '{project_name}' created",
            "data": self.projects[project_id]
        }
    
    def handle_list_projects(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """
        List all projects
        
        ✅ IMPROVEMENT: Authentication required
        ⚠️  Still returns all projects (no ownership filtering)
        """
        session_id = message.get("session_id")
        client_ip = address[0]
        
        # ✅ Validate session
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        # ⚠️  No authorization check
        # ⚠️  Returns ALL projects regardless of ownership
        
        project_list = []
        for proj_id, proj in self.projects.items():
            project_list.append({
                "project_id": proj_id,
                "name": proj["name"],
                "status": proj["status"],
                "task_count": len(proj["tasks"])
            })
        
        return {
            "status": "success",
            "projects": project_list,
            "count": len(project_list)
        }
    
    def handle_get_project(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """Get project details"""
        session_id = message.get("session_id")
        client_ip = address[0]
        
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        payload = message.get("payload", {})
        project_id = payload.get("project_id")
        
        if project_id not in self.projects:
            return {
                "status": "error",
                "message": f"Project {project_id} not found"
            }
        
        # ⚠️  No ownership check
        return {
            "status": "success",
            "project": self.projects[project_id]
        }
    
    def handle_assign_task(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """Assign a task"""
        session_id = message.get("session_id")
        client_ip = address[0]
        
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        # ✅ Authorization check
        if not self.check_permission(session, "coordinator"):
            return {
                "status": "error",
                "message": "Only coordinators can assign tasks"
            }
        
        payload = message.get("payload", {})
        project_id = payload.get("project_id")
        task_description = payload.get("task")
        worker_id = payload.get("worker_id", "unassigned")
        
        if project_id not in self.projects:
            return {
                "status": "error",
                "message": f"Project {project_id} not found"
            }
        
        # Create task
        self.task_counter += 1
        task_id = f"task_{self.task_counter:03d}"
        
        self.tasks[task_id] = {
            "task_id": task_id,
            "project_id": project_id,
            "description": task_description,
            "worker_id": worker_id,
            "status": "assigned",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        self.projects[project_id]["tasks"].append(task_id)
        
        print(f"📋 Task assigned: {task_id}")
        
        return {
            "status": "success",
            "task_id": task_id,
            "message": "Task assigned",
            "task": self.tasks[task_id]
        }
    
    def handle_update_task(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """Update task status"""
        session_id = message.get("session_id")
        client_ip = address[0]
        
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        payload = message.get("payload", {})
        task_id = payload.get("task_id")
        new_status = payload.get("status")
        
        if task_id not in self.tasks:
            return {
                "status": "error",
                "message": f"Task {task_id} not found"
            }
        
        # ⚠️  Weak: Should check if user is assigned worker
        
        old_status = self.tasks[task_id]["status"]
        self.tasks[task_id]["status"] = new_status
        self.tasks[task_id]["updated_at"] = datetime.now().isoformat()
        
        print(f"✏️  Task updated: {task_id}: {old_status} → {new_status}")
        
        return {
            "status": "success",
            "message": f"Task status updated to {new_status}",
            "task": self.tasks[task_id]
        }
    
    def handle_register_worker(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """Register a worker agent"""
        session_id = message.get("session_id")
        client_ip = address[0]
        
        session = self.validate_session(session_id, client_ip)
        if not session:
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        payload = message.get("payload", {})
        worker_id = payload.get("worker_id")
        capabilities = payload.get("capabilities", [])
        
        self.workers[worker_id] = {
            "worker_id": worker_id,
            "capabilities": capabilities,
            "registered_at": datetime.now().isoformat(),
            "status": "available"
        }
        
        print(f"👷 Worker registered: {worker_id}")
        
        return {
            "status": "success",
            "message": f"Worker {worker_id} registered",
            "worker": self.workers[worker_id]
        }
    
    def handle_get_session_info(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Get session information (for demonstration)"""
        session_id = message.get("session_id")
        
        if session_id not in self.sessions:
            return {
                "status": "error",
                "message": "Session not found or expired"
            }
        
        session = self.sessions[session_id].copy()
        
        # Mask sensitive data slightly
        return {
            "status": "success",
            "session": session,
            "warning": "Session info available for demo purposes"
        }


def main():
    """Main entry point"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   Task Coordinator - Stage 2: IMPROVED            ║")
    print("║   ⚠️  PARTIAL SECURITY - 4/10 Rating              ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    print("✅ Improvements over Stage 1:")
    print("   • Random session IDs (UUID4)")
    print("   • Password authentication")
    print("   • HMAC signatures")
    print("   • Idle timeout (30 min)")
    print("   • Logout destroys sessions")
    print("   • Basic input validation")
    print()
    print("⚠️  Still vulnerable to:")
    print("   • Replay attacks (no nonce)")
    print("   • Session hijacking (weak binding)")
    print("   • Stale permissions")
    print("   • No rate limiting")
    print("   • State not encrypted")
    print()
    print("Requirements:")
    print("   pip install bcrypt")
    print()
    
    coordinator = ImprovedCoordinator()
    coordinator.start()


if __name__ == "__main__":
    main()