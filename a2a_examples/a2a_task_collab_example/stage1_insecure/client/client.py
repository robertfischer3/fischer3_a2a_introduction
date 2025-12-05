#!/usr/bin/env python3
"""
Task Collaboration Client - Stage 1

Interactive client for testing the INSECURE coordinator.
Includes demonstrations of session security vulnerabilities.

⚠️  For Educational Purposes Only
"""

import socket
import json
import time
from typing import Dict, Any, Optional


class TaskCollaborationClient:
    """
    Client for interacting with Task Coordinator
    
    Includes attack demonstrations to show session vulnerabilities
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.client_id = "client-001"
        self.session_id: Optional[str] = None
        self.socket: Optional[socket.socket] = None
    
    def connect(self):
        """Connect to coordinator"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"✅ Connected to {self.host}:{self.port}\n")
            
            # Perform handshake
            self.handshake()
            
        except ConnectionRefusedError:
            print(f"❌ Connection refused. Is the coordinator running?")
            print(f"   Start it with: python server/task_coordinator.py")
            exit(1)
        except Exception as e:
            print(f"❌ Connection error: {e}")
            exit(1)
    
    def disconnect(self):
        """Disconnect from coordinator"""
        if self.socket:
            self.socket.close()
            print("\n👋 Disconnected")
    
    def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send message and receive response"""
        try:
            # Send message
            message_str = json.dumps(message)
            self.socket.send(message_str.encode('utf-8'))
            
            # Receive response
            data = self.socket.recv(65536)  # 64KB buffer
            response = json.loads(data.decode('utf-8'))
            
            return response
            
        except Exception as e:
            print(f"❌ Communication error: {e}")
            return {"status": "error", "message": str(e)}
    
    def handshake(self):
        """Perform initial handshake"""
        message = {
            "action": "HANDSHAKE",
            "sender_id": self.client_id
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            agent_card = response.get("agent_card", {})
            print(f"🤝 Connected to: {agent_card.get('name')}")
            print(f"   Type: {agent_card.get('type')}")
            print(f"   Security: {agent_card.get('security_level')}")
            print()
    
    def login(self, agent_id: str, role: str = "user") -> bool:
        """Login to get a session"""
        message = {
            "action": "login",
            "agent_id": agent_id,
            "role": role  # ⚠️  Client sets own role!
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            self.session_id = response.get("session_id")
            print(f"✅ Logged in as: {agent_id}")
            print(f"   Role: {role}")
            print(f"   Session: {self.session_id}")
            print(f"   ⚠️  Notice the predictable session ID!")
            print()
            return True
        else:
            print(f"❌ Login failed: {response.get('message')}")
            return False
    
    def logout(self):
        """Logout (but session remains valid!)"""
        if not self.session_id:
            print("⚠️  Not logged in")
            return
        
        message = {
            "action": "logout",
            "session_id": self.session_id
        }
        
        response = self.send_message(message)
        print(f"✅ {response.get('message')}")
        
        # Keep session_id to show it still works!
        # self.session_id = None  # This is what SHOULD happen
    
    def create_project(self, name: str, description: str):
        """Create a new project"""
        message = {
            "action": "create_project",
            "session_id": self.session_id,
            "payload": {
                "name": name,
                "description": description
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            project_id = response.get("project_id")
            print(f"✅ Project created: {project_id}")
            print(f"   Name: {name}")
            return project_id
        else:
            print(f"❌ Error: {response.get('message')}")
            return None
    
    def list_projects(self):
        """List all projects"""
        message = {
            "action": "list_projects",
            "session_id": self.session_id
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            projects = response.get("projects", [])
            print(f"\n📊 Projects ({len(projects)}):")
            for proj in projects:
                print(f"   • {proj['project_id']}: {proj['name']} ({proj['status']})")
                print(f"     Tasks: {proj['task_count']}")
        else:
            print(f"❌ Error: {response.get('message')}")
    
    def get_project(self, project_id: str):
        """Get project details"""
        message = {
            "action": "get_project",
            "session_id": self.session_id,
            "payload": {
                "project_id": project_id
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            project = response.get("project")
            print(f"\n📋 Project: {project['name']}")
            print(f"   ID: {project['project_id']}")
            print(f"   Status: {project['status']}")
            print(f"   Description: {project['description']}")
            print(f"   Created: {project['created_at']}")
            print(f"   Tasks: {len(project['tasks'])}")
        else:
            print(f"❌ Error: {response.get('message')}")
    
    def assign_task(self, project_id: str, task_description: str, worker_id: str):
        """Assign a task"""
        message = {
            "action": "assign_task",
            "session_id": self.session_id,
            "payload": {
                "project_id": project_id,
                "task": task_description,
                "worker_id": worker_id
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            task_id = response.get("task_id")
            print(f"✅ Task assigned: {task_id}")
            print(f"   Worker: {worker_id}")
            return task_id
        else:
            print(f"❌ Error: {response.get('message')}")
            return None
    
    def update_task(self, task_id: str, status: str):
        """Update task status"""
        message = {
            "action": "update_task",
            "session_id": self.session_id,
            "payload": {
                "task_id": task_id,
                "status": status
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            print(f"✅ Task updated: {task_id} → {status}")
        else:
            print(f"❌ Error: {response.get('message')}")
    
    # ============================================================================
    # ATTACK DEMONSTRATIONS
    # ============================================================================
    
    def demo_session_hijacking(self):
        """
        Demonstrate session hijacking attack
        
        Shows how predictable session IDs + no validation = easy hijacking
        """
        print("\n" + "="*60)
        print("🎭 ATTACK DEMO: Session Hijacking")
        print("="*60)
        print()
        print("This demonstrates how an attacker can hijack a session:")
        print("1. User logs in and gets a predictable session ID")
        print("2. Attacker guesses or sniffs the session ID")
        print("3. Attacker uses stolen session ID")
        print("4. System accepts it (no validation)")
        print()
        input("Press Enter to continue...")
        print()
        
        # Step 1: Legitimate login
        print("Step 1: Legitimate user logs in")
        print("-" * 40)
        victim_id = "legitimate_user"
        self.login(victim_id, "user")
        victim_session = self.session_id
        print(f"   Victim's session: {victim_session}")
        print()
        
        time.sleep(1)
        
        # Step 2: Attacker "steals" the session
        print("Step 2: Attacker captures session ID")
        print("-" * 40)
        print(f"   🎣 Attacker intercepts: {victim_session}")
        print(f"   ⚠️  Session ID is predictable and not encrypted!")
        print()
        
        time.sleep(1)
        
        # Step 3: Attacker uses stolen session
        print("Step 3: Attacker uses stolen session")
        print("-" * 40)
        stolen_session = victim_session
        
        # Create project as victim
        message = {
            "action": "create_project",
            "session_id": stolen_session,  # Using stolen session!
            "payload": {
                "name": "🚨 HIJACKED PROJECT",
                "description": "Created by attacker using stolen session"
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            print(f"   ✅ Attack successful!")
            print(f"   Created project: {response.get('project_id')}")
            print(f"   Project appears to be owned by: {victim_id}")
            print()
        
        time.sleep(1)
        
        # Summary
        print("="*60)
        print("⚠️  VULNERABILITY: Session Hijacking")
        print("="*60)
        print("Why this works:")
        print("  • Session IDs are predictable (sess_1, sess_2, etc.)")
        print("  • No session validation (IP, fingerprint, etc.)")
        print("  • No encryption in transit")
        print("  • Attacker can impersonate any user")
        print()
        print("Impact:")
        print("  • Complete account takeover")
        print("  • Unauthorized actions")
        print("  • Data theft")
        print("="*60)
        print()
    
    def demo_session_fixation(self):
        """
        Demonstrate session fixation attack
        
        Shows how attacker can set victim's session ID
        """
        print("\n" + "="*60)
        print("🎭 ATTACK DEMO: Session Fixation")
        print("="*60)
        print()
        print("This demonstrates session fixation:")
        print("1. Attacker knows session ID will be sess_X")
        print("2. Attacker tricks victim to use that session")
        print("3. Victim logs in with attacker's session ID")
        print("4. Attacker has access to authenticated session")
        print()
        input("Press Enter to continue...")
        print()
        
        # Step 1: Attacker predicts next session ID
        print("Step 1: Attacker predicts next session ID")
        print("-" * 40)
        # In real scenario, attacker might know current counter
        # or create a session to see the pattern
        print("   🔮 Attacker predicts next session will be: sess_X")
        print("   ⚠️  IDs are predictable sequential!")
        print()
        
        time.sleep(1)
        
        # Step 2: Victim logs in (we simulate the fixation)
        print("Step 2: Victim logs in")
        print("-" * 40)
        victim_id = "unsuspecting_victim"
        self.login(victim_id, "user")
        fixed_session = self.session_id
        print(f"   Victim got session: {fixed_session}")
        print()
        
        time.sleep(1)
        
        # Step 3: Attacker uses the session
        print("Step 3: Attacker uses victim's authenticated session")
        print("-" * 40)
        
        message = {
            "action": "create_project",
            "session_id": fixed_session,  # Attacker knows this!
            "payload": {
                "name": "🚨 FIXED SESSION PROJECT",
                "description": "Created by attacker using fixed session"
            }
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            print(f"   ✅ Attack successful!")
            print(f"   Attacker created project as victim!")
            print(f"   Project ID: {response.get('project_id')}")
            print()
        
        time.sleep(1)
        
        # Summary
        print("="*60)
        print("⚠️  VULNERABILITY: Session Fixation")
        print("="*60)
        print("Why this works:")
        print("  • Predictable session IDs")
        print("  • System doesn't generate new ID on login")
        print("  • No validation of session origin")
        print()
        print("Impact:")
        print("  • Attacker gains authenticated access")
        print("  • Can perform actions as victim")
        print("="*60)
        print()
    
    def demo_stale_permissions(self):
        """
        Demonstrate stale permissions attack
        
        Shows how permission changes don't affect active sessions
        """
        print("\n" + "="*60)
        print("🎭 ATTACK DEMO: Stale Permissions")
        print("="*60)
        print()
        print("This demonstrates stale permissions:")
        print("1. User logs in with 'worker' role")
        print("2. Admin promotes user to 'coordinator'")
        print("3. Session still shows old 'worker' role")
        print("4. OR: Admin demotes but session keeps privileges")
        print()
        input("Press Enter to continue...")
        print()
        
        # Step 1: Login as worker
        print("Step 1: User logs in as worker")
        print("-" * 40)
        self.login("worker_user", "worker")
        original_session = self.session_id
        print()
        
        time.sleep(1)
        
        # Step 2: Simulate permission change
        print("Step 2: Admin promotes user to coordinator")
        print("-" * 40)
        print("   👔 Admin: \"Promote worker_user to coordinator\"")
        print("   ✅ Permission changed in database")
        print("   ⚠️  But active session NOT updated!")
        print()
        
        time.sleep(1)
        
        # Step 3: Try to use elevated permissions
        print("Step 3: User tries coordinator action with old session")
        print("-" * 40)
        print(f"   Using session: {original_session}")
        
        # In a secure system, this should fail or trigger re-auth
        # But here, the session role is stale
        
        message = {
            "action": "get_session_info",
            "session_id": original_session
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            session_data = response.get("session")
            print(f"   Session role: {session_data.get('role')}")
            print(f"   ⚠️  Role is still: 'worker' (STALE!)")
            print(f"   ⚠️  User can't use new coordinator privileges")
            print(f"   ⚠️  OR worse: demoted user keeps old privileges!")
            print()
        
        time.sleep(1)
        
        # Summary
        print("="*60)
        print("⚠️  VULNERABILITY: Stale Permissions")
        print("="*60)
        print("Why this works:")
        print("  • Permissions cached in session")
        print("  • No synchronization with auth system")
        print("  • Permission changes don't affect active sessions")
        print("  • Sessions never expire or re-validate")
        print()
        print("Impact:")
        print("  • Users can't use new permissions")
        print("  • Demoted users keep elevated access")
        print("  • Compliance violations")
        print("="*60)
        print()
    
    def demo_replay_attack(self):
        """
        Demonstrate replay attack
        
        Shows how requests can be captured and replayed
        """
        print("\n" + "="*60)
        print("🎭 ATTACK DEMO: Replay Attack")
        print("="*60)
        print()
        print("This demonstrates replay attacks:")
        print("1. Attacker captures legitimate request")
        print("2. System processes request successfully")
        print("3. Attacker replays same request multiple times")
        print("4. System accepts all replays (no nonce)")
        print()
        input("Press Enter to continue...")
        print()
        
        # Step 1: Send legitimate request
        print("Step 1: Send legitimate create project request")
        print("-" * 40)
        
        message = {
            "action": "create_project",
            "session_id": self.session_id,
            "payload": {
                "name": "Original Project",
                "description": "This is the original request"
            }
        }
        
        response = self.send_message(message)
        print(f"   ✅ Project created: {response.get('project_id')}")
        print()
        
        time.sleep(1)
        
        # Step 2: Attacker captures and replays
        print("Step 2: Attacker captures request and replays it")
        print("-" * 40)
        print("   🎣 Attacker captured the request")
        print("   🔄 Replaying 3 times...")
        print()
        
        for i in range(3):
            # Send exact same message again!
            response = self.send_message(message)
            if response.get("status") == "success":
                print(f"   Replay {i+1}: ✅ Created {response.get('project_id')}")
            time.sleep(0.5)
        
        print()
        time.sleep(1)
        
        # Summary
        print("="*60)
        print("⚠️  VULNERABILITY: Replay Attack")
        print("="*60)
        print("Why this works:")
        print("  • No nonce (unique token per request)")
        print("  • No request ID validation")
        print("  • Same request can be processed infinite times")
        print()
        print("Impact:")
        print("  • Duplicate transactions")
        print("  • Resource exhaustion")
        print("  • Financial loss (if payments involved)")
        print("="*60)
        print()
    
    # ============================================================================
    # INTERACTIVE MENU
    # ============================================================================
    
    def interactive_menu(self):
        """Run interactive menu"""
        while True:
            print("\n" + "="*60)
            print("╔════════════════════════════════════════════════╗")
            print("║   Task Collaboration Client - Stage 1          ║")
            print("║   ⚠️  INSECURE - For Learning Only             ║")
            print("╚════════════════════════════════════════════════╝")
            print()
            print("Normal Operations:")
            print("  1. Create new project")
            print("  2. List projects")
            print("  3. Assign task to worker")
            print("  4. Update task status")
            print("  5. Get project details")
            print()
            print("Attack Demonstrations:")
            print("  6. [ATTACK] Session hijacking demo")
            print("  7. [ATTACK] Session fixation demo")
            print("  8. [ATTACK] Stale permissions demo")
            print("  9. [ATTACK] Replay attack demo")
            print()
            print("Session Management:")
            print("  10. Logout")
            print("  11. Get session info")
            print()
            print("  0. Quit")
            print("="*60)
            
            choice = input("\nEnter choice: ").strip()
            
            if choice == "0":
                print("\n👋 Goodbye!")
                break
            elif choice == "1":
                self.menu_create_project()
            elif choice == "2":
                self.list_projects()
            elif choice == "3":
                self.menu_assign_task()
            elif choice == "4":
                self.menu_update_task()
            elif choice == "5":
                self.menu_get_project()
            elif choice == "6":
                self.demo_session_hijacking()
            elif choice == "7":
                self.demo_session_fixation()
            elif choice == "8":
                self.demo_stale_permissions()
            elif choice == "9":
                self.demo_replay_attack()
            elif choice == "10":
                self.logout()
            elif choice == "11":
                self.menu_get_session_info()
            else:
                print("❌ Invalid choice")
            
            input("\nPress Enter to continue...")
    
    def menu_create_project(self):
        """Menu option: Create project"""
        print("\n--- Create New Project ---")
        name = input("Project name: ")
        description = input("Description: ")
        self.create_project(name, description)
    
    def menu_assign_task(self):
        """Menu option: Assign task"""
        print("\n--- Assign Task ---")
        project_id = input("Project ID: ")
        task = input("Task description: ")
        worker_id = input("Worker ID: ")
        self.assign_task(project_id, task, worker_id)
    
    def menu_update_task(self):
        """Menu option: Update task"""
        print("\n--- Update Task ---")
        task_id = input("Task ID: ")
        status = input("New status (assigned/in_progress/completed): ")
        self.update_task(task_id, status)
    
    def menu_get_project(self):
        """Menu option: Get project"""
        print("\n--- Get Project Details ---")
        project_id = input("Project ID: ")
        self.get_project(project_id)
    
    def menu_get_session_info(self):
        """Menu option: Get session info"""
        if not self.session_id:
            print("⚠️  Not logged in")
            return
        
        message = {
            "action": "get_session_info",
            "session_id": self.session_id
        }
        
        response = self.send_message(message)
        
        if response.get("status") == "success":
            session = response.get("session")
            print(f"\n📊 Session Info:")
            print(f"   Session ID: {self.session_id}")
            print(f"   Agent ID: {session.get('agent_id')}")
            print(f"   Role: {session.get('role')}")
            print(f"   Created: {session.get('created_at')}")
            print(f"   ⚠️  {response.get('warning')}")


def main():
    """Main entry point"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   Task Collaboration Client - Stage 1             ║")
    print("║   ⚠️  Testing INSECURE Coordinator                ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    
    client = TaskCollaborationClient()
    
    try:
        client.connect()
        
        # Initial login
        print("Initial Login")
        print("-" * 40)
        agent_id = input("Enter your agent ID (or press Enter for 'demo_user'): ").strip()
        if not agent_id:
            agent_id = "demo_user"
        
        role = input("Enter role [user/coordinator/admin]: ").strip()
        if not role:
            role = "user"
        
        if client.login(agent_id, role):
            # Run interactive menu
            client.interactive_menu()
        
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()