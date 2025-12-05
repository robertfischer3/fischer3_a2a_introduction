#!/usr/bin/env python3
"""
Task Coordinator Agent - Stage 1: INSECURE

⚠️  WARNING: This code is INTENTIONALLY VULNERABLE for educational purposes.
    DO NOT USE IN PRODUCTION!

Purpose: Demonstrate session management and state security vulnerabilities
Security Rating: 0/10

This coordinator manages projects and assigns tasks to worker agents.
It contains 25+ intentional security vulnerabilities to teach session security.
"""

import socket
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class TaskCoordinator:
    """
    Coordinator agent for multi-agent task collaboration.
    
    ⚠️  INTENTIONALLY VULNERABLE - FOR EDUCATION ONLY
    
    Vulnerabilities demonstrated:
    - Predictable session IDs
    - No session validation
    - No timeouts
    - No authentication
    - No authorization
    - Stale permissions
    - Replay attacks possible
    - And many more...
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.agent_id = "coordinator-001"
        self.agent_name = "TaskCoordinator"
        
        # ❌ VULNERABILITY 1: Predictable session IDs
        # Using sequential counter makes sessions trivially guessable
        self.session_counter = 0
        
        # ❌ VULNERABILITY 2: No session validation
        # Sessions stored but never validated
        self.sessions: Dict[str, dict] = {}
        
        # ❌ VULNERABILITY 3: No session timeouts
        # Sessions never expire - can use old sessions forever
        # No idle timeout, no absolute timeout
        
        # ❌ VULNERABILITY 4: No session binding
        # Sessions not tied to IP, user agent, or any client characteristic
        # Same session can be used from any location
        
        # ❌ VULNERABILITY 5: Sessions shared
        # Multiple agents can share the same session
        # No concurrent session detection
        
        # State storage
        self.projects: Dict[str, dict] = {}  # project_id -> project data
        self.tasks: Dict[str, dict] = {}     # task_id -> task data
        self.workers: Dict[str, dict] = {}   # worker_id -> worker info
        
        # ❌ VULNERABILITY 9: No state validation
        # State can be corrupted, no schema checking
        
        # ❌ VULNERABILITY 10: State not encrypted
        # All state stored in plaintext in memory
        
        # Counters for ID generation
        self.project_counter = 0
        self.task_counter = 0
        
        print(f"🚀 Task Coordinator started")
        print(f"   Host: {self.host}:{self.port}")
        print(f"   ⚠️  INSECURE MODE - For learning only!")
        print(f"   Vulnerabilities: 25+")
        print()
    
    def start(self):
        """Start the coordinator server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"📡 Listening on {self.host}:{self.port}")
        print(f"   Waiting for connections...")
        print()
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                print(f"📥 New connection from {address}")
                
                # Handle each client in a separate thread
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
                # Receive message
                data = client_socket.recv(65536)  # 64KB buffer
                if not data:
                    break
                
                # Parse message
                try:
                    message = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    response = {
                        "status": "error",
                        "message": "Invalid JSON"
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    continue
                
                # ❌ VULNERABILITY 15: No authentication required
                # Never checks if client is who they claim to be
                # No signature verification, no credentials
                
                # Process message
                response = self.process_message(message, address)
                
                # Send response
                client_socket.send(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            print(f"❌ Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"📤 Connection closed: {address}")
    
    def process_message(self, message: Dict[str, Any], address: tuple) -> Dict[str, Any]:
        """
        Process incoming message
        
        ❌ VULNERABILITY: No message validation, accepts any structure
        """
        action = message.get("action", "unknown")
        
        print(f"📨 Received: {action} from {address}")
        
        # Route to appropriate handler
        if action == "HANDSHAKE":
            return self.handle_handshake(message)
        elif action == "login":
            return self.handle_login(message)
        elif action == "logout":
            return self.handle_logout(message)
        elif action == "create_project":
            return self.handle_create_project(message)
        elif action == "list_projects":
            return self.handle_list_projects(message)
        elif action == "get_project":
            return self.handle_get_project(message)
        elif action == "assign_task":
            return self.handle_assign_task(message)
        elif action == "update_task":
            return self.handle_update_task(message)
        elif action == "register_worker":
            return self.handle_register_worker(message)
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
                "version": "1.0.0-insecure",
                "security_level": "NONE - Educational Only"
            }
        }
    
    def handle_login(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle agent login
        
        ❌ VULNERABILITIES:
        - No password/credential verification
        - Predictable session IDs
        - No session binding
        - Sessions never expire
        """
        agent_id = message.get("agent_id", "unknown")
        role = message.get("role", "worker")  # ❌ Client sets own role!
        
        # ❌ VULNERABILITY 1: Predictable session IDs
        self.session_counter += 1
        session_id = f"sess_{self.session_counter}"
        
        # ❌ VULNERABILITY 2 & 3: No validation, no timeout
        self.sessions[session_id] = {
            "agent_id": agent_id,
            "role": role,
            "created_at": datetime.now().isoformat(),
            # ❌ No expiration time!
            # ❌ No last_activity tracking
            # ❌ No IP binding
            # ❌ No fingerprinting
        }
        
        print(f"✅ Login: {agent_id} → session: {session_id}")
        print(f"   ⚠️  Predictable session ID!")
        print(f"   ⚠️  No authentication performed!")
        
        return {
            "status": "success",
            "session_id": session_id,
            "message": f"Logged in as {role}",
            "agent_id": agent_id
        }
    
    def handle_logout(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle agent logout
        
        ❌ VULNERABILITY 6: Sessions persist after logout
        """
        session_id = message.get("session_id")
        
        # ❌ VULNERABILITY 6: Logout doesn't actually destroy session!
        # Just pretends to log out but session remains valid
        if session_id in self.sessions:
            print(f"🚪 Logout: session {session_id}")
            print(f"   ⚠️  Session NOT destroyed - still valid!")
            # Note: We DON'T delete the session!
            # del self.sessions[session_id]  # This is what SHOULD happen
        
        return {
            "status": "success",
            "message": "Logged out (but session still valid!)"
        }
    
    def handle_create_project(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new project
        
        ❌ VULNERABILITIES:
        - No authentication check
        - No authorization check
        - No session validation
        - No input validation
        """
        # ❌ VULNERABILITY 15: No authentication required!
        # Anyone can create projects
        
        # ❌ VULNERABILITY 2: No session validation
        # Doesn't check if session_id is valid
        session_id = message.get("session_id", "none")
        
        # ❌ VULNERABILITY 19: No authorization check
        # Doesn't check if user has permission to create projects
        
        payload = message.get("payload", {})
        project_name = payload.get("name", "Unnamed Project")
        description = payload.get("description", "")
        
        # ❌ VULNERABILITY 9: No input validation
        # Accepts any name, any description, no limits
        
        # Create project
        self.project_counter += 1
        project_id = f"proj_{self.project_counter:03d}"
        
        self.projects[project_id] = {
            "project_id": project_id,
            "name": project_name,
            "description": description,
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "created_by": session_id,  # ❌ Session, not actual user!
            "tasks": [],
            "metadata": payload.get("metadata", {})
        }
        
        print(f"📁 Project created: {project_id} - {project_name}")
        print(f"   ⚠️  No authentication performed!")
        print(f"   ⚠️  No authorization check!")
        
        return {
            "status": "success",
            "project_id": project_id,
            "message": f"Project '{project_name}' created",
            "data": self.projects[project_id]
        }
    
    def handle_list_projects(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        List all projects
        
        ❌ VULNERABILITY: No authorization - anyone can see all projects
        """
        # ❌ No session validation
        # ❌ No permission check
        # ❌ Returns ALL projects regardless of ownership
        
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
    
    def handle_get_project(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get project details
        
        ❌ VULNERABILITY: No authorization check
        """
        payload = message.get("payload", {})
        project_id = payload.get("project_id")
        
        if project_id not in self.projects:
            return {
                "status": "error",
                "message": f"Project {project_id} not found"
            }
        
        # ❌ No permission check - returns sensitive data to anyone
        return {
            "status": "success",
            "project": self.projects[project_id]
        }
    
    def handle_assign_task(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assign a task to a worker
        
        ❌ VULNERABILITIES: No auth, no validation
        """
        # ❌ No session validation
        # ❌ No authorization check (can user assign tasks?)
        
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
        
        # Add to project
        self.projects[project_id]["tasks"].append(task_id)
        
        print(f"📋 Task assigned: {task_id}")
        print(f"   Project: {project_id}")
        print(f"   Worker: {worker_id}")
        print(f"   ⚠️  No authorization check!")
        
        return {
            "status": "success",
            "task_id": task_id,
            "message": "Task assigned",
            "task": self.tasks[task_id]
        }
    
    def handle_update_task(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update task status
        
        ❌ VULNERABILITY: Anyone can update any task
        """
        payload = message.get("payload", {})
        task_id = payload.get("task_id")
        new_status = payload.get("status")
        
        if task_id not in self.tasks:
            return {
                "status": "error",
                "message": f"Task {task_id} not found"
            }
        
        # ❌ No check if user is authorized to update this task
        # ❌ No check if user is the assigned worker
        
        old_status = self.tasks[task_id]["status"]
        self.tasks[task_id]["status"] = new_status
        self.tasks[task_id]["updated_at"] = datetime.now().isoformat()
        
        print(f"✏️  Task updated: {task_id}")
        print(f"   {old_status} → {new_status}")
        print(f"   ⚠️  No authorization check!")
        
        return {
            "status": "success",
            "message": f"Task status updated to {new_status}",
            "task": self.tasks[task_id]
        }
    
    def handle_register_worker(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a worker agent
        
        ❌ VULNERABILITY: Anyone can register as any worker
        """
        payload = message.get("payload", {})
        worker_id = payload.get("worker_id")
        capabilities = payload.get("capabilities", [])
        
        # ❌ No authentication - anyone can register
        # ❌ No verification of worker identity
        # ❌ Worker can claim any capabilities
        
        self.workers[worker_id] = {
            "worker_id": worker_id,
            "capabilities": capabilities,
            "registered_at": datetime.now().isoformat(),
            "status": "available"
        }
        
        print(f"👷 Worker registered: {worker_id}")
        print(f"   Capabilities: {capabilities}")
        print(f"   ⚠️  No identity verification!")
        
        return {
            "status": "success",
            "message": f"Worker {worker_id} registered",
            "worker": self.workers[worker_id]
        }
    
    def handle_get_session_info(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get session information (for demonstration purposes)
        
        ❌ VULNERABILITY: Information disclosure
        """
        session_id = message.get("session_id")
        
        if session_id not in self.sessions:
            return {
                "status": "error",
                "message": "Session not found"
            }
        
        # ❌ Returns sensitive session data to anyone who asks
        return {
            "status": "success",
            "session": self.sessions[session_id],
            "warning": "⚠️  This exposes sensitive session data!"
        }


def main():
    """Main entry point"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   Task Coordinator - Stage 1: INSECURE            ║")
    print("║   ⚠️  For Educational Purposes Only               ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    print("⚠️  WARNING: This code is INTENTIONALLY VULNERABLE")
    print("   - Predictable session IDs")
    print("   - No authentication")
    print("   - No session validation")
    print("   - No timeouts")
    print("   - Session hijacking trivial")
    print("   - And 20+ more vulnerabilities...")
    print()
    print("   DO NOT use in production!")
    print()
    
    coordinator = TaskCoordinator()
    coordinator.start()


if __name__ == "__main__":
    main()