#!/usr/bin/env python3
"""
Task Collaboration Client - Stage 2: Improved

Interactive client with authentication support.

Stage 2 Improvements:
✅ Login required before operations
✅ Session management
✅ Password authentication
✅ Logout support

Usage:
    python client/client.py
"""

import socket
import json
import sys
from typing import Dict, Any, Optional
from getpass import getpass


class TaskCollaborationClient:
    """
    Client for Task Collaboration Agent - Stage 2
    
    Improvements:
    - Must authenticate before operations
    - Maintains session
    - Automatic session handling
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        
        # ✅ NEW: Session management
        self.session_id: Optional[str] = None
        self.username: Optional[str] = None
        self.user_info: Optional[Dict] = None
        
        print("╔═══════════════════════════════════════════════════╗")
        print("║   Task Collaboration Client - Stage 2            ║")
        print("║   ✅ Authentication Required                      ║")
        print("╚═══════════════════════════════════════════════════╝")
        print()
    
    def connect(self):
        """Connect to coordinator"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"✅ Connected to coordinator at {self.host}:{self.port}")
            print()
            return True
        except Exception as e:
            print(f"❌ Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from coordinator"""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("📴 Disconnected from coordinator")
    
    def login(self, username: Optional[str] = None, password: Optional[str] = None):
        """
        Login to coordinator
        
        ✅ NEW: Authentication required
        """
        if not username:
            username = input("Username: ")
        
        if not password:
            password = getpass("Password: ")
        
        print(f"\n🔐 Logging in as {username}...")
        
        # Send login request
        message = {
            "type": "login",
            "username": username,
            "password": password,
            "user_agent": "TaskCollaborationClient/2.0"
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
            self.username = username
            self.user_info = response.get("user_info")
            
            print(f"✅ Login successful!")
            print(f"   Username: {self.user_info['username']}")
            print(f"   Email: {self.user_info['email']}")
            print(f"   Roles: {', '.join(self.user_info['roles'])}")
            print(f"   Session: {self.session_id[:16]}...")
            print()
            return True
        else:
            print(f"❌ Login failed: {response.get('message')}")
            print()
            return False
    
    def logout(self):
        """
        Logout from coordinator
        
        ✅ NEW: Properly destroys session
        """
        if not self.session_id:
            print("⚠️  Not logged in")
            return
        
        print("\n👋 Logging out...")
        
        message = {
            "type": "logout",
            "session_id": self.session_id,
            "client_id": self.username
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            print("✅ Logged out successfully")
            self.session_id = None
            self.username = None
            self.user_info = None
        else:
            print(f"⚠️  Logout error: {response.get('message')}")
        
        print()
    
    def create_project(self, project_name: str, description: str = ""):
        """Create a new project"""
        if not self._check_logged_in():
            return None
        
        print(f"\n📁 Creating project: {project_name}")
        
        message = {
            "type": "create_project",
            "session_id": self.session_id,
            "client_id": self.username,
            "payload": {
                "project_name": project_name,
                "description": description
            }
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            project = response.get("project")
            print(f"✅ Project created: {project['project_id']}")
            print(f"   Name: {project['project_name']}")
            print(f"   Owner: {project['owner']}")
            return project
        else:
            print(f"❌ Failed: {response.get('message')}")
            return None
    
    def list_projects(self):
        """List user's projects"""
        if not self._check_logged_in():
            return []
        
        print(f"\n📋 Listing projects for {self.username}...")
        
        message = {
            "type": "list_projects",
            "session_id": self.session_id,
            "client_id": self.username,
            "payload": {}
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            projects = response.get("projects", [])
            
            if projects:
                print(f"✅ Found {len(projects)} project(s):\n")
                for i, project in enumerate(projects, 1):
                    print(f"  {i}. {project['project_name']}")
                    print(f"     ID: {project['project_id']}")
                    print(f"     Owner: {project['owner']}")
                    print(f"     Tasks: {len(project.get('tasks', []))}")
                    print(f"     Status: {project['status']}")
                    print()
            else:
                print("ℹ️  No projects found")
            
            return projects
        else:
            print(f"❌ Failed: {response.get('message')}")
            return []
    
    def create_task(
        self,
        project_id: str,
        task_type: str,
        description: str,
        priority: str = "medium",
        data: Optional[Dict] = None
    ):
        """Create a task in a project"""
        if not self._check_logged_in():
            return None
        
        print(f"\n📝 Creating task in project {project_id[:8]}...")
        
        message = {
            "type": "create_task",
            "session_id": self.session_id,
            "client_id": self.username,
            "payload": {
                "project_id": project_id,
                "task_type": task_type,
                "description": description,
                "priority": priority,
                "data": data or {}
            }
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            task = response.get("task")
            print(f"✅ Task created: {task['task_id']}")
            print(f"   Type: {task['task_type']}")
            print(f"   Priority: {task['priority']}")
            print(f"   Status: {task['status']}")
            return task
        else:
            print(f"❌ Failed: {response.get('message')}")
            return None
    
    def list_tasks(self, project_id: Optional[str] = None):
        """List tasks"""
        if not self._check_logged_in():
            return []
        
        if project_id:
            print(f"\n📋 Listing tasks for project {project_id[:8]}...")
        else:
            print(f"\n📋 Listing all tasks for {self.username}...")
        
        message = {
            "type": "list_tasks",
            "session_id": self.session_id,
            "client_id": self.username,
            "payload": {
                "project_id": project_id
            } if project_id else {}
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            tasks = response.get("tasks", [])
            
            if tasks:
                print(f"✅ Found {len(tasks)} task(s):\n")
                for i, task in enumerate(tasks, 1):
                    print(f"  {i}. {task['description']}")
                    print(f"     ID: {task['task_id']}")
                    print(f"     Type: {task['task_type']}")
                    print(f"     Status: {task['status']}")
                    print(f"     Priority: {task['priority']}")
                    if task.get('assigned_to'):
                        print(f"     Assigned to: {task['assigned_to']}")
                    print()
            else:
                print("ℹ️  No tasks found")
            
            return tasks
        else:
            print(f"❌ Failed: {response.get('message')}")
            return []
    
    def get_session_info(self):
        """Get current session information"""
        if not self._check_logged_in():
            return None
        
        print(f"\n🔍 Getting session information...")
        
        message = {
            "type": "get_session_info",
            "session_id": self.session_id,
            "client_id": self.username,
            "payload": {}
        }
        
        response = self._send_and_receive(message)
        
        if response.get("status") == "success":
            session = response.get("session")
            print(f"✅ Session Information:")
            print(f"   Session ID: {session['session_id'][:16]}...")
            print(f"   Client ID: {session['client_id']}")
            print(f"   Client IP: {session['client_ip']}")
            print(f"   Created: {session['created_at']}")
            print(f"   Last Activity: {session['last_activity']}")
            print(f"   Expires: {session['expires_at']}")
            print(f"   Idle Timeout: {session['idle_timeout']} seconds")
            return session
        else:
            print(f"❌ Failed: {response.get('message')}")
            return None
    
    def _check_logged_in(self) -> bool:
        """Check if user is logged in"""
        if not self.session_id:
            print("❌ Not logged in. Please login first.")
            return False
        return True
    
    def _send_and_receive(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send message and receive response"""
        try:
            # Send message
            message_json = json.dumps(message)
            message_bytes = message_json.encode() + b'\n'
            self.socket.sendall(message_bytes)
            
            # Receive response
            buffer = b""
            while b'\n' not in buffer:
                chunk = self.socket.recv(4096)
                if not chunk:
                    return {"status": "error", "message": "Connection closed"}
                buffer += chunk
            
            response_json = buffer.split(b'\n')[0].decode()
            return json.loads(response_json)
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def interactive_menu(self):
        """Interactive menu for client operations"""
        if not self.connect():
            return
        
        # Login first
        print("Please login to continue:")
        while not self.login():
            retry = input("Try again? (y/n): ").lower()
            if retry != 'y':
                self.disconnect()
                return
        
        # Main menu
        while True:
            print("\n" + "=" * 50)
            print("MAIN MENU")
            print("=" * 50)
            print("1. Create Project")
            print("2. List Projects")
            print("3. Create Task")
            print("4. List Tasks")
            print("5. Get Session Info")
            print("6. Logout")
            print("7. Exit")
            print()
            
            choice = input("Choose option (1-7): ").strip()
            
            if choice == "1":
                name = input("Project name: ").strip()
                desc = input("Description (optional): ").strip()
                self.create_project(name, desc)
            
            elif choice == "2":
                self.list_projects()
            
            elif choice == "3":
                projects = self.list_projects()
                if projects:
                    project_id = input("Project ID: ").strip()
                    task_type = input("Task type (data_analysis/code_review/testing/documentation): ").strip()
                    description = input("Description: ").strip()
                    priority = input("Priority (low/medium/high) [medium]: ").strip() or "medium"
                    self.create_task(project_id, task_type, description, priority)
            
            elif choice == "4":
                print("\nFilter by project? (leave empty for all tasks)")
                project_id = input("Project ID (optional): ").strip() or None
                self.list_tasks(project_id)
            
            elif choice == "5":
                self.get_session_info()
            
            elif choice == "6":
                self.logout()
                print("Please login again:")
                if not self.login():
                    break
            
            elif choice == "7":
                if self.session_id:
                    self.logout()
                break
            
            else:
                print("❌ Invalid option")
        
        self.disconnect()


def main():
    """Main entry point"""
    client = TaskCollaborationClient()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("Usage: python client.py [username] [password]")
            print()
            print("If no credentials provided, will prompt interactively.")
            print()
            print("Test users:")
            print("  alice / AlicePass123")
            print("  bob / BobPass456")
            print("  admin / AdminPass789")
            return
    
    # Interactive mode
    try:
        client.interactive_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        client.disconnect()


if __name__ == "__main__":
    main()