#!/usr/bin/env python3
"""
Task Coordinator Agent - Stage 2: Improved

⚠️  This is Stage 2: IMPROVED but still has vulnerabilities for learning.
    Security Rating: 4/10

Stage 2 Improvements:
✅ Requires authentication (password with bcrypt)
✅ UUID4 session IDs (unpredictable)
✅ Session validation with client binding
✅ Idle timeout (30 minutes)
✅ Basic authorization (owner checks)
✅ Input size limits
✅ Basic audit logging

Still Vulnerable (Fixed in Stage 3):
❌ No TLS encryption
❌ No replay protection
❌ No rate limiting
❌ IP mismatch only logged
❌ No absolute session timeout
❌ Stale permissions (cached in session)

For production security, see Stage 3.
"""

import socket
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security import (
    AuthManager,
    SessionManager,
    SimpleAuthProvider,
    create_default_users
)


class TaskCoordinator:
    """
    Task Coordinator with Stage 2 security improvements
    
    Improvements over Stage 1:
    - Requires authentication before any operations
    - UUID4 session IDs
    - Session validation on every request
    - Basic authorization checks
    - Input size limits
    - Audit logging
    
    Usage:
        coordinator = TaskCoordinator()
        coordinator.start()
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        
        # ✅ NEW: Authentication system
        print("Initializing authentication system...")
        auth_provider = create_default_users("config/users.json")
        self.auth_manager = AuthManager(auth_provider)
        
        # ✅ NEW: Session management
        print("Initializing session manager...")
        self.session_manager = SessionManager(idle_timeout=1800)  # 30 minutes
        
        # Business data storage
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.workers: Dict[str, Dict[str, Any]] = {}
        
        # ✅ NEW: Size limits (prevent DoS)
        self.max_message_size = 1048576  # 1 MB
        self.max_projects_per_user = 100
        self.max_tasks_per_project = 1000
        
        # ✅ NEW: Audit log
        self.audit_log: List[Dict] = []
        
        print("✅ Task Coordinator initialized (Stage 2: Improved)")
        print(f"   Security Rating: 4/10 ⚠️")
        print(f"   Auth: Password (bcrypt) ✅")
        print(f"   Sessions: UUID4 with idle timeout ✅")
        print(f"   Authorization: Basic owner checks ✅")
        print(f"   ⚠️  Still missing: TLS, rate limiting, replay protection")
    
    def start(self):
        """Start the coordinator server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        print(f"\n🚀 Task Coordinator started on {self.host}:{self.port}")
        print(f"   ⚠️  Stage 2: No TLS encryption (plain TCP)")
        print(f"   Waiting for connections...")
        print()
        
        # Start session cleanup thread
        cleanup_thread = threading.Thread(
            target=self._session_cleanup_worker,
            daemon=True
        )
        cleanup_thread.start()
        
        try:
            while True:
                client_socket, address = self.socket.accept()
                print(f"📞 Connection from {address[0]}:{address[1]}")
                
                # Handle client in new thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
        
        except KeyboardInterrupt:
            print("\n\n🛑 Shutting down coordinator...")
        finally:
            if self.socket:
                self.socket.close()
    
    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle client connection"""
        client_ip = address[0]
        
        try:
            while True:
                # Receive message
                message = self._receive_message(client_socket)
                
                if not message:
                    break
                
                # ✅ NEW: Check message size
                message_json = json.dumps(message)
                if len(message_json) > self.max_message_size:
                    response = {
                        "status": "error",
                        "message": "Message too large"
                    }
                    self._send_message(client_socket, response)
                    continue
                
                # Route message to handler
                response = self._route_message(message, client_ip)
                
                # Send response
                self._send_message(client_socket, response)
        
        except Exception as e:
            print(f"❌ Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"📴 Connection closed: {address[0]}:{address[1]}")
    
    def _route_message(self, message: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
        """Route message to appropriate handler"""
        message_type = message.get("type")
        
        # ✅ NEW: Login doesn't require existing session
        if message_type == "login":
            return self.handle_login(message, client_ip)
        
        # ✅ NEW: All other operations require valid session
        session_id = message.get("session_id")
        client_id = message.get("client_id")
        
        if not session_id or not client_id:
            return {
                "status": "error",
                "message": "session_id and client_id required"
            }
        
        # ✅ NEW: Validate session
        valid, session = self.session_manager.validate_session(
            session_id,
            client_id,
            client_ip
        )
        
        if not valid:
            self._audit_log("invalid_session", {
                "session_id": session_id[:8] + "...",
                "client_id": client_id,
                "client_ip": client_ip
            })
            return {
                "status": "error",
                "message": "Invalid or expired session"
            }
        
        # Route to handlers
        handlers = {
            "logout": self.handle_logout,
            "create_project": self.handle_create_project,
            "list_projects": self.handle_list_projects,
            "get_project": self.handle_get_project,
            "create_task": self.handle_create_task,
            "list_tasks": self.handle_list_tasks,
            "claim_task": self.handle_claim_task,
            "update_task_status": self.handle_update_task_status,
            "register_worker": self.handle_register_worker,
            "get_session_info": self.handle_get_session_info
        }
        
        handler = handlers.get(message_type)
        
        if handler:
            return handler(message, session)
        else:
            return {
                "status": "error",
                "message": f"Unknown message type: {message_type}"
            }
    
    # ========================================================================
    # AUTHENTICATION HANDLERS
    # ========================================================================
    
    def handle_login(self, message: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
        """
        Handle login request
        
        ✅ NEW: Requires username/password
        ✅ Uses bcrypt for password verification
        ✅ Creates secure session on success
        
        ❌ Stage 2: No rate limiting (fixed in Stage 3)
        ❌ Stage 2: No MFA (added in Stage 3)
        """
        username = message.get("username")
        password = message.get("password")
        user_agent = message.get("user_agent")
        
        if not username or not password:
            return {
                "status": "error",
                "message": "username and password required"
            }
        
        print(f"🔐 Login attempt: {username} from {client_ip}")
        
        # ✅ Authenticate with AuthManager
        success, session_data, error = self.auth_manager.login(
            username,
            password,
            client_info={"ip": client_ip, "user_agent": user_agent}
        )
        
        if not success:
            self._audit_log("login_failure", {
                "username": username,
                "client_ip": client_ip,
                "error": error
            })
            return {
                "status": "error",
                "message": error
            }
        
        # ✅ Create session
        session_id = self.session_manager.create_session(
            client_id=username,
            client_ip=client_ip,
            user_agent=user_agent,
            session_data=session_data
        )
        
        self._audit_log("login_success", {
            "username": username,
            "session_id": session_id[:8] + "...",
            "client_ip": client_ip
        })
        
        return {
            "status": "success",
            "session_id": session_id,
            "user_info": {
                "username": session_data["username"],
                "email": session_data["email"],
                "roles": session_data["roles"]
            },
            "message": "Login successful"
        }
    
    def handle_logout(self, message: Dict[str, Any], session: Dict) -> Dict[str, Any]:
        """
        Handle logout request
        
        ✅ NEW: Properly destroys session
        """
        session_id = message.get("session_id")
        
        self.session_manager.invalidate_session(session_id)
        
        self._audit_log("logout", {
            "username": session["client_id"],
            "session_id": session_id[:8] + "..."
        })
        
        return {
            "status": "success",
            "message": "Logged out successfully"
        }
    
    # ========================================================================
    # PROJECT HANDLERS
    # ========================================================================
    
    def handle_create_project(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Create a new project
        
        ✅ NEW: Validates session
        ✅ NEW: Enforces project quota
        ✅ NEW: Owner automatically set from session
        """
        client_id = session["client_id"]
        payload = message.get("payload", {})
        
        project_name = payload.get("project_name")
        description = payload.get("description", "")
        
        if not project_name:
            return {
                "status": "error",
                "message": "project_name required"
            }
        
        # ✅ NEW: Check project quota
        user_projects = [
            p for p in self.projects.values()
            if p["owner"] == client_id
        ]
        
        if len(user_projects) >= self.max_projects_per_user:
            return {
                "status": "error",
                "message": f"Project quota exceeded ({self.max_projects_per_user} max)"
            }
        
        # Create project
        import uuid
        project_id = str(uuid.uuid4())
        
        self.projects[project_id] = {
            "project_id": project_id,
            "project_name": project_name,
            "description": description,
            "owner": client_id,  # ✅ From session, not from request
            "created_at": datetime.now().isoformat(),
            "status": "active",
            "tasks": []
        }
        
        self._audit_log("project_created", {
            "project_id": project_id,
            "owner": client_id,
            "project_name": project_name
        })
        
        print(f"✅ Project created: {project_id} by {client_id}")
        
        return {
            "status": "success",
            "project": self.projects[project_id]
        }
    
    def handle_list_projects(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        List projects
        
        ✅ NEW: Only returns user's own projects
        """
        client_id = session["client_id"]
        
        # ✅ NEW: Filter to user's own projects
        user_projects = [
            p for p in self.projects.values()
            if p["owner"] == client_id
        ]
        
        return {
            "status": "success",
            "projects": user_projects
        }
    
    def handle_get_project(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Get project details
        
        ✅ NEW: Checks ownership before returning
        """
        client_id = session["client_id"]
        payload = message.get("payload", {})
        project_id = payload.get("project_id")
        
        if not project_id:
            return {
                "status": "error",
                "message": "project_id required"
            }
        
        if project_id not in self.projects:
            return {
                "status": "error",
                "message": "Project not found"
            }
        
        project = self.projects[project_id]
        
        # ✅ NEW: Check authorization
        if project["owner"] != client_id:
            self._audit_log("unauthorized_access", {
                "client_id": client_id,
                "project_id": project_id,
                "owner": project["owner"]
            })
            return {
                "status": "error",
                "message": "Access denied"
            }
        
        return {
            "status": "success",
            "project": project
        }
    
    # ========================================================================
    # TASK HANDLERS
    # ========================================================================
    
    def handle_create_task(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Create a task
        
        ✅ NEW: Validates project ownership
        ✅ NEW: Enforces task quota per project
        
        ❌ Stage 2: No input sanitization (fixed in Stage 3)
        """
        client_id = session["client_id"]
        payload = message.get("payload", {})
        
        project_id = payload.get("project_id")
        task_type = payload.get("task_type")
        description = payload.get("description")
        priority = payload.get("priority", "medium")
        data = payload.get("data", {})
        
        if not all([project_id, task_type, description]):
            return {
                "status": "error",
                "message": "project_id, task_type, and description required"
            }
        
        # ✅ Check project exists and user owns it
        if project_id not in self.projects:
            return {
                "status": "error",
                "message": "Project not found"
            }
        
        project = self.projects[project_id]
        
        if project["owner"] != client_id:
            return {
                "status": "error",
                "message": "Access denied"
            }
        
        # ✅ Check task quota
        project_tasks = [
            t for t in self.tasks.values()
            if t["project_id"] == project_id
        ]
        
        if len(project_tasks) >= self.max_tasks_per_project:
            return {
                "status": "error",
                "message": f"Task quota exceeded ({self.max_tasks_per_project} max)"
            }
        
        # Create task
        import uuid
        task_id = str(uuid.uuid4())
        
        self.tasks[task_id] = {
            "task_id": task_id,
            "project_id": project_id,
            "task_type": task_type,
            "description": description,
            "priority": priority,
            "status": "pending",
            "data": data,  # ❌ Stage 2: Not validated (fixed in Stage 3)
            "created_at": datetime.now().isoformat(),
            "assigned_to": None,
            "result": None
        }
        
        # Add to project
        project["tasks"].append(task_id)
        
        self._audit_log("task_created", {
            "task_id": task_id,
            "project_id": project_id,
            "client_id": client_id,
            "task_type": task_type
        })
        
        print(f"✅ Task created: {task_id} in project {project_id}")
        
        return {
            "status": "success",
            "task": self.tasks[task_id]
        }
    
    def handle_list_tasks(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        List tasks
        
        ✅ NEW: Only returns tasks from user's projects
        """
        client_id = session["client_id"]
        payload = message.get("payload", {})
        project_id = payload.get("project_id")
        
        if project_id:
            # List tasks for specific project
            if project_id not in self.projects:
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            project = self.projects[project_id]
            
            # ✅ Check ownership
            if project["owner"] != client_id:
                return {
                    "status": "error",
                    "message": "Access denied"
                }
            
            project_tasks = [
                self.tasks[tid] for tid in project["tasks"]
                if tid in self.tasks
            ]
            
            return {
                "status": "success",
                "tasks": project_tasks
            }
        else:
            # List all tasks from user's projects
            user_project_ids = [
                pid for pid, p in self.projects.items()
                if p["owner"] == client_id
            ]
            
            user_tasks = [
                t for t in self.tasks.values()
                if t["project_id"] in user_project_ids
            ]
            
            return {
                "status": "success",
                "tasks": user_tasks
            }
    
    def handle_claim_task(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Worker claims a task
        
        ⚠️  Stage 2: Basic check (worker registered)
        ❌ Still missing: Capability verification
        """
        payload = message.get("payload", {})
        task_id = payload.get("task_id")
        worker_id = payload.get("worker_id")
        
        if not all([task_id, worker_id]):
            return {
                "status": "error",
                "message": "task_id and worker_id required"
            }
        
        if task_id not in self.tasks:
            return {
                "status": "error",
                "message": "Task not found"
            }
        
        # ⚠️  Stage 2: Basic check - is worker registered?
        if worker_id not in self.workers:
            return {
                "status": "error",
                "message": "Worker not registered"
            }
        
        task = self.tasks[task_id]
        
        if task["status"] != "pending":
            return {
                "status": "error",
                "message": f"Task not available (status: {task['status']})"
            }
        
        # Assign task
        task["status"] = "assigned"
        task["assigned_to"] = worker_id
        
        self._audit_log("task_claimed", {
            "task_id": task_id,
            "worker_id": worker_id,
            "task_type": task["task_type"]
        })
        
        print(f"✅ Task {task_id} claimed by {worker_id}")
        
        return {
            "status": "success",
            "task": task
        }
    
    def handle_update_task_status(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Update task status
        
        ⚠️  Stage 2: Basic check (worker owns task)
        """
        payload = message.get("payload", {})
        task_id = payload.get("task_id")
        new_status = payload.get("new_status")
        result = payload.get("result")
        worker_id = payload.get("worker_id")
        
        if not all([task_id, new_status, worker_id]):
            return {
                "status": "error",
                "message": "task_id, new_status, and worker_id required"
            }
        
        if task_id not in self.tasks:
            return {
                "status": "error",
                "message": "Task not found"
            }
        
        task = self.tasks[task_id]
        
        # ⚠️  Stage 2: Check task is assigned to this worker
        if task["assigned_to"] != worker_id:
            return {
                "status": "error",
                "message": "Task not assigned to this worker"
            }
        
        # Update task
        task["status"] = new_status
        if result:
            task["result"] = result
        
        self._audit_log("task_updated", {
            "task_id": task_id,
            "worker_id": worker_id,
            "new_status": new_status
        })
        
        print(f"✅ Task {task_id} updated to {new_status}")
        
        return {
            "status": "success",
            "task": task
        }
    
    # ========================================================================
    # WORKER HANDLERS
    # ========================================================================
    
    def handle_register_worker(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Register a worker
        
        ⚠️  Stage 2: Still accepts self-reported capabilities
        ❌ Fixed in Stage 3: Certificate-based verification
        """
        payload = message.get("payload", {})
        worker_id = payload.get("worker_id")
        capabilities = payload.get("capabilities", [])
        
        if not worker_id:
            return {
                "status": "error",
                "message": "worker_id required"
            }
        
        # ⚠️  Stage 2: No verification of capabilities
        self.workers[worker_id] = {
            "worker_id": worker_id,
            "capabilities": capabilities,
            "registered_at": datetime.now().isoformat(),
            "status": "available"
        }
        
        self._audit_log("worker_registered", {
            "worker_id": worker_id,
            "capabilities": capabilities
        })
        
        print(f"👷 Worker registered: {worker_id}")
        print(f"   ⚠️  Capabilities not verified: {capabilities}")
        
        return {
            "status": "success",
            "worker": self.workers[worker_id]
        }
    
    # ========================================================================
    # INFO HANDLERS
    # ========================================================================
    
    def handle_get_session_info(
        self,
        message: Dict[str, Any],
        session: Dict
    ) -> Dict[str, Any]:
        """
        Get session information
        
        ⚠️  Stage 2: Returns own session info only
        ❌ Stage 1: Could query any session!
        """
        session_id = message.get("session_id")
        
        # ✅ Only allow viewing own session
        session_info = self.session_manager.get_session_info(session_id)
        
        if not session_info:
            return {
                "status": "error",
                "message": "Session not found"
            }
        
        return {
            "status": "success",
            "session": session_info
        }
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def _send_message(self, sock: socket.socket, message: Dict[str, Any]):
        """Send JSON message"""
        message_json = json.dumps(message)
        message_bytes = message_json.encode() + b'\n'
        sock.sendall(message_bytes)
    
    def _receive_message(self, sock: socket.socket) -> Optional[Dict[str, Any]]:
        """Receive JSON message"""
        try:
            buffer = b""
            while b'\n' not in buffer:
                chunk = sock.recv(4096)
                if not chunk:
                    return None
                buffer += chunk
            
            message_json = buffer.split(b'\n')[0].decode()
            return json.loads(message_json)
        except Exception as e:
            print(f"❌ Error receiving message: {e}")
            return None
    
    def _audit_log(self, event_type: str, details: Dict):
        """
        Log security event
        
        ✅ Stage 2: Basic logging
        ❌ Not written to file (Stage 3)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        
        self.audit_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    def _session_cleanup_worker(self):
        """Background thread to cleanup expired sessions"""
        import time
        
        while True:
            time.sleep(300)  # Every 5 minutes
            count = self.session_manager.cleanup_expired_sessions()
            if count > 0:
                print(f"🗑️  Cleaned up {count} expired session(s)")


def main():
    """Main entry point"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   Task Coordinator - Stage 2: IMPROVED           ║")
    print("║   ⚠️  Still has vulnerabilities (for learning)    ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    print("Stage 2 Improvements:")
    print("  ✅ Authentication required (bcrypt)")
    print("  ✅ UUID4 session IDs")
    print("  ✅ Session validation")
    print("  ✅ Basic authorization")
    print("  ✅ Input size limits")
    print()
    print("Still Vulnerable:")
    print("  ❌ No TLS encryption")
    print("  ❌ No rate limiting")
    print("  ❌ No replay protection")
    print("  ❌ IP mismatch only logged")
    print()
    print("For production security, use Stage 3.")
    print()
    print("Default test users:")
    print("  - alice / AlicePass123")
    print("  - bob / BobPass456")
    print("  - admin / AdminPass789")
    print()
    
    coordinator = TaskCoordinator()
    coordinator.start()


if __name__ == "__main__":
    main()