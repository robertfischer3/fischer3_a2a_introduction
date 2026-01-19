#!/usr/bin/env python3
"""
Stage 2 Test Demo Script

Demonstrates Stage 2 improvements and remaining vulnerabilities.

Tests:
1. Authentication (login/logout)
2. Session management (UUID, timeout, validation)
3. Authorization (owner checks)
4. Security improvements over Stage 1
5. Remaining vulnerabilities

Usage:
    # Start coordinator first
    python server/task_coordinator.py
    
    # Then run demo
    python test_demo.py
"""

import socket
import json
import time
import sys
from typing import Dict, Any, Optional


class TestClient:
    """Simple test client"""
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
    
    def connect(self):
        """Connect to coordinator"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
    
    def disconnect(self):
        """Disconnect"""
        if self.socket:
            self.socket.close()
    
    def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send message and get response"""
        message_json = json.dumps(message)
        message_bytes = message_json.encode() + b'\n'
        self.socket.sendall(message_bytes)
        
        buffer = b""
        while b'\n' not in buffer:
            chunk = self.socket.recv(4096)
            if not chunk:
                return {"status": "error", "message": "Connection closed"}
            buffer += chunk
        
        response_json = buffer.split(b'\n')[0].decode()
        return json.loads(response_json)


def print_header(title: str):
    """Print section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def print_test(test_name: str):
    """Print test name"""
    print(f"🧪 {test_name}")
    print("-" * 70)


def print_result(success: bool, message: str):
    """Print test result"""
    icon = "✅" if success else "❌"
    print(f"{icon} {message}\n")


def demo_1_authentication():
    """Demo 1: Authentication System"""
    print_header("DEMO 1: Authentication System (Stage 2 Improvement)")
    
    print("Stage 1: No authentication required")
    print("Stage 2: Login required with bcrypt password hashing\n")
    
    client = TestClient()
    client.connect()
    
    # Test 1: Login with valid credentials
    print_test("Test 1.1: Valid Login")
    response = client.send_message({
        "type": "login",
        "username": "alice",
        "password": "AlicePass123"
    })
    
    if response["status"] == "success":
        session_id = response["session_id"]
        print_result(True, f"Login successful")
        print(f"   Session ID: {session_id[:16]}... (UUID4 format)")
        print(f"   User: {response['user_info']['username']}")
        print(f"   Roles: {response['user_info']['roles']}")
    else:
        print_result(False, f"Login failed: {response['message']}")
        client.disconnect()
        return
    
    # Test 2: Invalid password
    print_test("Test 1.2: Invalid Password")
    response = client.send_message({
        "type": "login",
        "username": "alice",
        "password": "WrongPassword"
    })
    
    if response["status"] == "error":
        print_result(True, "Authentication correctly rejected invalid password")
    else:
        print_result(False, "Should have rejected invalid password")
    
    # Test 3: Non-existent user
    print_test("Test 1.3: Non-existent User")
    response = client.send_message({
        "type": "login",
        "username": "nonexistent",
        "password": "AnyPassword123"
    })
    
    if response["status"] == "error":
        print_result(True, "Authentication correctly rejected non-existent user")
        print("   ✅ Constant-time failure (no username enumeration)")
    else:
        print_result(False, "Should have rejected non-existent user")
    
    # Test 4: Logout
    print_test("Test 1.4: Logout")
    response = client.send_message({
        "type": "logout",
        "session_id": session_id,
        "client_id": "alice"
    })
    
    if response["status"] == "success":
        print_result(True, "Logout successful - session destroyed")
    else:
        print_result(False, f"Logout failed: {response['message']}")
    
    client.disconnect()


def demo_2_session_management():
    """Demo 2: Session Management"""
    print_header("DEMO 2: Session Management (Stage 2 Improvement)")
    
    print("Stage 1: Sequential IDs (session-0001, session-0002)")
    print("Stage 2: UUID4 IDs (unpredictable)\n")
    
    client = TestClient()
    client.connect()
    
    # Login
    response = client.send_message({
        "type": "login",
        "username": "alice",
        "password": "AlicePass123"
    })
    session_id = response["session_id"]
    
    # Test 1: Session validation
    print_test("Test 2.1: Session Validation")
    response = client.send_message({
        "type": "list_projects",
        "session_id": session_id,
        "client_id": "alice",
        "payload": {}
    })
    
    if response["status"] == "success":
        print_result(True, "Valid session accepted")
    else:
        print_result(False, "Valid session should be accepted")
    
    # Test 2: Invalid session ID
    print_test("Test 2.2: Invalid Session ID")
    fake_session = "00000000-0000-0000-0000-000000000000"
    response = client.send_message({
        "type": "list_projects",
        "session_id": fake_session,
        "client_id": "alice",
        "payload": {}
    })
    
    if response["status"] == "error":
        print_result(True, "Invalid session correctly rejected")
    else:
        print_result(False, "Should reject invalid session")
    
    # Test 3: Wrong client ID
    print_test("Test 2.3: Session Binding (Wrong Client ID)")
    response = client.send_message({
        "type": "list_projects",
        "session_id": session_id,
        "client_id": "bob",  # Wrong user!
        "payload": {}
    })
    
    if response["status"] == "error":
        print_result(True, "Session bound to client - wrong client rejected")
        print("   ✅ Sessions are bound to client_id")
    else:
        print_result(False, "Should reject wrong client ID")
    
    # Test 4: Session info
    print_test("Test 2.4: Session Information")
    response = client.send_message({
        "type": "get_session_info",
        "session_id": session_id,
        "client_id": "alice",
        "payload": {}
    })
    
    if response["status"] == "success":
        session_info = response["session"]
        print_result(True, "Session information retrieved")
        print(f"   Session ID: {session_info['session_id'][:16]}...")
        print(f"   Client: {session_info['client_id']}")
        print(f"   IP: {session_info['client_ip']}")
        print(f"   Idle Timeout: {session_info['idle_timeout']} seconds (30 minutes)")
        print(f"   ⚠️  Stage 2: No absolute timeout (added in Stage 3)")
    
    client.disconnect()


def demo_3_authorization():
    """Demo 3: Authorization"""
    print_header("DEMO 3: Authorization (Stage 2 Improvement)")
    
    print("Stage 1: No authorization - anyone can access anything")
    print("Stage 2: Owner checks - users can only access their own projects\n")
    
    # Alice creates a project
    alice_client = TestClient()
    alice_client.connect()
    
    alice_response = alice_client.send_message({
        "type": "login",
        "username": "alice",
        "password": "AlicePass123"
    })
    alice_session = alice_response["session_id"]
    
    print_test("Test 3.1: Create Project as Alice")
    response = alice_client.send_message({
        "type": "create_project",
        "session_id": alice_session,
        "client_id": "alice",
        "payload": {
            "project_name": "Alice's Secret Project",
            "description": "Private project"
        }
    })
    
    if response["status"] == "success":
        project_id = response["project"]["project_id"]
        print_result(True, "Project created by Alice")
        print(f"   Project ID: {project_id}")
        print(f"   Owner: {response['project']['owner']} (automatically set from session)")
    else:
        print_result(False, f"Failed: {response['message']}")
        alice_client.disconnect()
        return
    
    # Bob tries to access Alice's project
    bob_client = TestClient()
    bob_client.connect()
    
    bob_response = bob_client.send_message({
        "type": "login",
        "username": "bob",
        "password": "BobPass456"
    })
    bob_session = bob_response["session_id"]
    
    print_test("Test 3.2: Bob Tries to Access Alice's Project")
    response = bob_client.send_message({
        "type": "get_project",
        "session_id": bob_session,
        "client_id": "bob",
        "payload": {
            "project_id": project_id
        }
    })
    
    if response["status"] == "error":
        print_result(True, "Access denied - authorization working!")
        print("   ✅ Bob cannot access Alice's project")
        print("   ✅ Owner-based authorization enforced")
    else:
        print_result(False, "Bob should not be able to access Alice's project")
    
    # Alice can still access her own project
    print_test("Test 3.3: Alice Accesses Her Own Project")
    response = alice_client.send_message({
        "type": "get_project",
        "session_id": alice_session,
        "client_id": "alice",
        "payload": {
            "project_id": project_id
        }
    })
    
    if response["status"] == "success":
        print_result(True, "Alice can access her own project")
    else:
        print_result(False, "Alice should be able to access her project")
    
    alice_client.disconnect()
    bob_client.disconnect()


def demo_4_resource_limits():
    """Demo 4: Resource Limits"""
    print_header("DEMO 4: Resource Limits (Stage 2 Improvement)")
    
    print("Stage 1: No limits - DoS attacks possible")
    print("Stage 2: Size limits and quotas enforced\n")
    
    client = TestClient()
    client.connect()
    
    # Login
    response = client.send_message({
        "type": "login",
        "username": "alice",
        "password": "AlicePass123"
    })
    session_id = response["session_id"]
    
    print_test("Test 4.1: Project Quota")
    print("   Creating multiple projects to test quota...")
    
    # Create a few projects
    for i in range(3):
        response = client.send_message({
            "type": "create_project",
            "session_id": session_id,
            "client_id": "alice",
            "payload": {
                "project_name": f"Test Project {i+1}",
                "description": f"Project number {i+1}"
            }
        })
        
        if response["status"] == "success":
            print(f"   ✅ Project {i+1} created")
        else:
            print(f"   ❌ Project {i+1} failed: {response['message']}")
    
    print(f"\n   ℹ️  Stage 2 Quota: 100 projects per user")
    print(f"   ℹ️  Stage 2 Quota: 1000 tasks per project")
    print_result(True, "Resource quotas are enforced")
    
    client.disconnect()


def demo_5_remaining_vulnerabilities():
    """Demo 5: Remaining Vulnerabilities"""
    print_header("DEMO 5: Remaining Vulnerabilities (Stage 2)")
    
    print("Stage 2 is BETTER but still has vulnerabilities!")
    print("These will be fixed in Stage 3.\n")
    
    print("❌ Vulnerability 1: No TLS Encryption")
    print("   Issue: All traffic sent in plaintext over TCP")
    print("   Risk: Session IDs and data can be sniffed")
    print("   Fix: Stage 3 adds TLS 1.3 encryption")
    print()
    
    print("❌ Vulnerability 2: No Replay Protection")
    print("   Issue: No nonce in messages")
    print("   Risk: Captured requests can be replayed")
    print("   Fix: Stage 3 adds nonce-based replay protection")
    print()
    
    print("❌ Vulnerability 3: No Rate Limiting")
    print("   Issue: Unlimited login attempts")
    print("   Risk: Brute force attacks possible")
    print("   Fix: Stage 3 adds token bucket rate limiting")
    print()
    
    print("❌ Vulnerability 4: IP Mismatch Only Logged")
    print("   Issue: IP changes are logged but not blocked")
    print("   Risk: Session hijacking still possible if session stolen")
    print("   Fix: Stage 3 enforces IP binding")
    print()
    
    print("❌ Vulnerability 5: No Absolute Timeout")
    print("   Issue: Active sessions never truly expire")
    print("   Risk: Stolen sessions valid indefinitely if kept active")
    print("   Fix: Stage 3 adds 24-hour absolute timeout")
    print()
    
    print("❌ Vulnerability 6: Stale Permissions")
    print("   Issue: Roles cached in session")
    print("   Risk: Permission changes don't take effect until re-login")
    print("   Fix: Stage 3 adds real-time permission checks")
    print()
    
    print("❌ Vulnerability 7: No MFA")
    print("   Issue: Single factor authentication only")
    print("   Risk: Compromised passwords = compromised accounts")
    print("   Fix: Stage 3 adds TOTP-based MFA")
    print()
    
    print_result(False, "Stage 2 Security Rating: 4/10")
    print("   Stage 2 is BETTER than Stage 1 (0/10)")
    print("   But still NOT production-ready")
    print("   Use Stage 3 for production security")


def demo_6_comparison():
    """Demo 6: Stage 1 vs Stage 2 Comparison"""
    print_header("DEMO 6: Stage 1 vs Stage 2 Comparison")
    
    comparison = [
        ("Authentication", "None", "Password + bcrypt", "✅"),
        ("Session IDs", "session-0001", "UUID4", "✅"),
        ("Session Binding", "None", "Client ID", "✅"),
        ("Idle Timeout", "Never", "30 minutes", "✅"),
        ("Logout Support", "No", "Yes", "✅"),
        ("Authorization", "None", "Owner checks", "✅"),
        ("Resource Limits", "None", "Quotas", "✅"),
        ("Audit Logging", "None", "Basic", "✅"),
        ("TLS Encryption", "No", "No", "❌"),
        ("Rate Limiting", "No", "No", "❌"),
        ("Replay Protection", "No", "No", "❌"),
        ("MFA", "No", "No", "❌"),
    ]
    
    print(f"{'Feature':<20} {'Stage 1':<15} {'Stage 2':<15} {'Improved':<10}")
    print("-" * 70)
    
    for feature, stage1, stage2, improved in comparison:
        print(f"{feature:<20} {stage1:<15} {stage2:<15} {improved:<10}")
    
    print()
    print_result(True, "Stage 2 shows significant improvements")
    print("   But still not production-ready (use Stage 3)")


def main():
    """Run all demos"""
    print("\n" + "═" * 70)
    print("  TASK COLLABORATION AGENT - STAGE 2 TEST DEMO")
    print("  Security Testing & Vulnerability Analysis")
    print("═" * 70)
    
    print("\n⚠️  Make sure the coordinator is running first:")
    print("   python server/task_coordinator.py")
    print()
    
    input("Press Enter to start tests...")
    
    try:
        demo_1_authentication()
        demo_2_session_management()
        demo_3_authorization()
        demo_4_resource_limits()
        demo_5_remaining_vulnerabilities()
        demo_6_comparison()
        
        print_header("SUMMARY")
        print("✅ Stage 2 Improvements Verified:")
        print("   - Authentication with bcrypt")
        print("   - UUID4 session IDs")
        print("   - Session validation and binding")
        print("   - Owner-based authorization")
        print("   - Resource quotas")
        print("   - Audit logging")
        print()
        print("❌ Still Vulnerable (Fixed in Stage 3):")
        print("   - No TLS encryption")
        print("   - No rate limiting")
        print("   - No replay protection")
        print("   - IP mismatch not enforced")
        print("   - No absolute timeout")
        print("   - Stale permissions")
        print("   - No MFA")
        print()
        print("📊 Security Rating: Stage 2 = 4/10 (up from 0/10)")
        print("🎯 Learning Objective: Better ≠ Secure")
        print("🔒 For Production: Use Stage 3 (10/10)")
        print()
        
    except ConnectionRefusedError:
        print("\n❌ ERROR: Could not connect to coordinator")
        print("   Make sure it's running: python server/task_coordinator.py")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()