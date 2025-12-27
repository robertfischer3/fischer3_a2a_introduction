#!/usr/bin/env python3
"""
Task Worker Agent - Stage 1: INSECURE

⚠️  WARNING: This code is INTENTIONALLY VULNERABLE for educational purposes.
    DO NOT USE IN PRODUCTION!

Purpose: Demonstrate session management and state security vulnerabilities
Security Rating: 0/10

This worker agent connects to the coordinator, registers its capabilities,
and executes assigned tasks. It contains intentional security vulnerabilities
to teach session and state management security.

Key Vulnerabilities Demonstrated:
- No authentication when registering
- No verification of task assignments
- No session validation
- Accepts any session ID
- No encryption of sensitive data
- And many more...
"""

import socket
import json
import threading
import time
import random
from datetime import datetime
from typing import Dict, List, Any, Optional


class TaskWorker:
    """
    Worker agent that executes tasks assigned by the coordinator
    
    ❌ INTENTIONALLY VULNERABLE - For learning purposes only
    
    Capabilities:
    - data_analysis: Analyzes data and generates reports
    - code_review: Reviews code for quality and security
    - testing: Runs automated tests
    - documentation: Creates technical documentation
    """
    
    def __init__(
        self,
        worker_id: str,
        capabilities: List[str],
        host: str = "localhost",
        port: int = 9000
    ):
        self.worker_id = worker_id
        self.capabilities = capabilities
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.session_id: Optional[str] = None
        self.running = False
        
        # Track assigned tasks
        self.assigned_tasks: Dict[str, Dict[str, Any]] = {}
        self.completed_tasks: List[str] = []
        
        print(f"🤖 Task Worker Initialized")
        print(f"   Worker ID: {worker_id}")
        print(f"   Capabilities: {', '.join(capabilities)}")
        print(f"   ⚠️  WARNING: No security measures implemented!")
        print()
    
    def connect_to_coordinator(self) -> bool:
        """
        Connect to the coordinator
        
        ❌ VULNERABILITY: No TLS encryption
        ❌ VULNERABILITY: No certificate validation
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            print(f"✅ Connected to coordinator at {self.host}:{self.port}")
            print(f"   ⚠️  Connection is unencrypted!")
            
            # Perform handshake
            return self.handshake()
            
        except ConnectionRefusedError:
            print(f"❌ Could not connect to coordinator at {self.host}:{self.port}")
            print("   Make sure the coordinator is running first!")
            return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def handshake(self) -> bool:
        """
        Perform handshake with coordinator
        
        ❌ VULNERABILITY: No authentication required
        ❌ VULNERABILITY: Session ID accepted without validation
        """
        try:
            # Send handshake
            handshake_msg = {
                "type": "handshake",
                "client_id": self.worker_id,
                "client_type": "worker",
                "protocol_version": "1.0"
            }
            
            self._send_message(handshake_msg)
            response = self._receive_message()
            
            if response.get("status") == "success":
                # ❌ Accept session ID without any validation
                self.session_id = response.get("session_id")
                
                print(f"✅ Handshake successful")
                print(f"   Session ID: {self.session_id}")
                print(f"   ⚠️  Session ID accepted without validation!")
                
                # Register worker capabilities
                return self.register_worker()
            else:
                print(f"❌ Handshake failed: {response.get('message')}")
                return False
                
        except Exception as e:
            print(f"❌ Handshake error: {e}")
            return False
    
    def register_worker(self) -> bool:
        """
        Register this worker with the coordinator
        
        ❌ VULNERABILITY: No authentication - anyone can register as any worker
        ❌ VULNERABILITY: Can claim false capabilities
        ❌ VULNERABILITY: No verification of identity
        """
        try:
            # ❌ No credentials required for registration
            register_msg = {
                "type": "register_worker",
                "session_id": self.session_id,  # ❌ Unvalidated session
                "payload": {
                    "worker_id": self.worker_id,
                    "capabilities": self.capabilities
                }
            }
            
            self._send_message(register_msg)
            response = self._receive_message()
            
            if response.get("status") == "success":
                print(f"✅ Worker registered successfully")
                print(f"   ⚠️  No identity verification performed!")
                print(f"   ⚠️  Could claim false capabilities!")
                return True
            else:
                print(f"❌ Registration failed: {response.get('message')}")
                return False
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False
    
    def start_listening(self):
        """
        Start listening for task assignments
        
        ❌ VULNERABILITY: No authentication of task source
        ❌ VULNERABILITY: Accepts any task without validation
        """
        self.running = True
        print()
        print("👂 Listening for task assignments...")
        print("   Press Ctrl+C to stop")
        print()
        
        try:
            while self.running:
                # Poll for new tasks periodically
                time.sleep(2)
                
                # Request available tasks
                self.check_for_tasks()
                
                # Process any assigned tasks
                self.process_assigned_tasks()
                
        except KeyboardInterrupt:
            print("\n🛑 Shutting down worker...")
            self.running = False
        finally:
            self.disconnect()
    
    def check_for_tasks(self):
        """
        Check for available tasks matching our capabilities
        
        ❌ VULNERABILITY: No verification that tasks are legitimately assigned to us
        """
        try:
            # Request tasks for our capabilities
            request_msg = {
                "type": "get_available_tasks",
                "session_id": self.session_id,  # ❌ Unvalidated session
                "payload": {
                    "worker_id": self.worker_id,
                    "capabilities": self.capabilities
                }
            }
            
            self._send_message(request_msg)
            response = self._receive_message()
            
            if response.get("status") == "success":
                available_tasks = response.get("tasks", [])
                
                # Claim tasks that match our capabilities
                for task in available_tasks:
                    if task["status"] == "pending":
                        task_type = task.get("task_type", "")
                        if task_type in self.capabilities:
                            self.claim_task(task["task_id"])
                            
        except Exception as e:
            # Silently handle errors during polling
            pass
    
    def claim_task(self, task_id: str):
        """
        Claim a task for execution
        
        ❌ VULNERABILITY: No verification that we're authorized to claim this task
        """
        try:
            claim_msg = {
                "type": "claim_task",
                "session_id": self.session_id,
                "payload": {
                    "task_id": task_id,
                    "worker_id": self.worker_id
                }
            }
            
            self._send_message(claim_msg)
            response = self._receive_message()
            
            if response.get("status") == "success":
                task = response.get("task")
                self.assigned_tasks[task_id] = task
                
                print(f"📋 Claimed task: {task_id}")
                print(f"   Type: {task['task_type']}")
                print(f"   Description: {task.get('description', 'N/A')}")
                print(f"   ⚠️  No authorization check performed!")
                
        except Exception as e:
            print(f"❌ Error claiming task {task_id}: {e}")
    
    def process_assigned_tasks(self):
        """
        Process all assigned tasks
        
        ❌ VULNERABILITY: No validation of task data
        ❌ VULNERABILITY: No sandboxing of task execution
        """
        for task_id, task in list(self.assigned_tasks.items()):
            if task["status"] == "assigned":
                print(f"\n⚙️  Processing task: {task_id}")
                
                # Execute the task
                result = self.execute_task(task)
                
                # Update task status
                self.update_task_status(task_id, "completed", result)
                
                # Move to completed
                self.completed_tasks.append(task_id)
                del self.assigned_tasks[task_id]
    
    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a task based on its type
        
        ❌ VULNERABILITY: No input validation
        ❌ VULNERABILITY: No sandboxing
        ❌ VULNERABILITY: Could execute malicious payloads
        """
        task_type = task["task_type"]
        task_data = task.get("data", {})
        
        print(f"   Executing {task_type} task...")
        print(f"   ⚠️  No input validation or sandboxing!")
        
        # Simulate task execution time
        execution_time = random.uniform(1, 3)
        time.sleep(execution_time)
        
        # Execute based on task type
        if task_type == "data_analysis":
            return self.execute_data_analysis(task_data)
        elif task_type == "code_review":
            return self.execute_code_review(task_data)
        elif task_type == "testing":
            return self.execute_testing(task_data)
        elif task_type == "documentation":
            return self.execute_documentation(task_data)
        else:
            return {
                "status": "error",
                "message": f"Unknown task type: {task_type}"
            }
    
    def execute_data_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate data analysis task
        
        ❌ VULNERABILITY: Processes untrusted data without validation
        """
        print("   📊 Analyzing data...")
        
        # ❌ No validation of input data
        dataset = data.get("dataset", [])
        analysis_type = data.get("analysis_type", "summary")
        
        # Simulate analysis
        return {
            "status": "success",
            "analysis_type": analysis_type,
            "records_processed": len(dataset),
            "summary": "Analysis completed successfully",
            "insights": [
                "Key finding 1: Data shows positive trend",
                "Key finding 2: Outliers detected in region X",
                "Key finding 3: Recommend further investigation"
            ],
            "completion_time": datetime.now().isoformat()
        }
    
    def execute_code_review(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate code review task
        
        ❌ VULNERABILITY: No validation of code source
        """
        print("   🔍 Reviewing code...")
        
        # ❌ No validation of code origin or integrity
        file_path = data.get("file_path", "unknown")
        code_snippet = data.get("code_snippet", "")
        
        # Simulate review
        return {
            "status": "success",
            "file_reviewed": file_path,
            "lines_reviewed": len(code_snippet.split("\n")),
            "issues_found": random.randint(0, 5),
            "recommendations": [
                "Consider adding input validation",
                "Add error handling for edge cases",
                "Improve code documentation"
            ],
            "approval_status": "approved_with_recommendations",
            "completion_time": datetime.now().isoformat()
        }
    
    def execute_testing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate testing task
        
        ❌ VULNERABILITY: Could execute malicious test code
        """
        print("   🧪 Running tests...")
        
        # ❌ No validation of test code
        test_suite = data.get("test_suite", "unknown")
        test_type = data.get("test_type", "unit")
        
        # Simulate testing
        total_tests = random.randint(10, 50)
        passed_tests = random.randint(int(total_tests * 0.7), total_tests)
        
        return {
            "status": "success",
            "test_suite": test_suite,
            "test_type": test_type,
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": total_tests - passed_tests,
            "pass_rate": f"{(passed_tests/total_tests*100):.1f}%",
            "completion_time": datetime.now().isoformat()
        }
    
    def execute_documentation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate documentation task
        
        ❌ VULNERABILITY: No content validation
        """
        print("   📝 Creating documentation...")
        
        # ❌ No validation of documentation content
        doc_type = data.get("doc_type", "api")
        sections = data.get("sections", [])
        
        # Simulate documentation creation
        return {
            "status": "success",
            "doc_type": doc_type,
            "sections_created": len(sections),
            "word_count": random.randint(500, 2000),
            "format": "markdown",
            "completion_time": datetime.now().isoformat()
        }
    
    def update_task_status(
        self,
        task_id: str,
        new_status: str,
        result: Dict[str, Any]
    ):
        """
        Update task status with the coordinator
        
        ❌ VULNERABILITY: No verification that update is from legitimate worker
        """
        try:
            update_msg = {
                "type": "update_task_status",
                "session_id": self.session_id,  # ❌ Unvalidated session
                "payload": {
                    "task_id": task_id,
                    "new_status": new_status,
                    "result": result,
                    "worker_id": self.worker_id
                }
            }
            
            self._send_message(update_msg)
            response = self._receive_message()
            
            if response.get("status") == "success":
                print(f"✅ Task {task_id} marked as {new_status}")
                print(f"   ⚠️  No verification that this worker owns the task!")
            else:
                print(f"❌ Failed to update task: {response.get('message')}")
                
        except Exception as e:
            print(f"❌ Error updating task status: {e}")
    
    def _send_message(self, message: Dict[str, Any]):
        """
        Send a message to the coordinator
        
        ❌ VULNERABILITY: No encryption
        ❌ VULNERABILITY: No message integrity checks
        """
        try:
            message_json = json.dumps(message)
            message_bytes = message_json.encode() + b'\n'
            self.socket.sendall(message_bytes)
        except Exception as e:
            print(f"❌ Error sending message: {e}")
            raise
    
    def _receive_message(self) -> Dict[str, Any]:
        """
        Receive a message from the coordinator
        
        ❌ VULNERABILITY: No encryption
        ❌ VULNERABILITY: No message authentication
        """
        try:
            buffer = b""
            while b'\n' not in buffer:
                chunk = self.socket.recv(4096)
                if not chunk:
                    raise ConnectionError("Connection closed by coordinator")
                buffer += chunk
            
            message_json = buffer.split(b'\n')[0].decode()
            return json.loads(message_json)
        except Exception as e:
            print(f"❌ Error receiving message: {e}")
            raise
    
    def disconnect(self):
        """Disconnect from coordinator"""
        if self.socket:
            try:
                self.socket.close()
                print("✅ Disconnected from coordinator")
            except Exception as e:
                print(f"❌ Error disconnecting: {e}")


def main():
    """Main entry point"""
    print("╔═══════════════════════════════════════════════════╗")
    print("║   Task Worker Agent - Stage 1: INSECURE           ║")
    print("║   ⚠️  For Educational Purposes Only               ║")
    print("╚═══════════════════════════════════════════════════╝")
    print()
    print("⚠️  WARNING: This code is INTENTIONALLY VULNERABLE")
    print("   - No authentication")
    print("   - No session validation")
    print("   - No input validation")
    print("   - No sandboxing")
    print("   - No encryption")
    print("   - No authorization checks")
    print("   - And many more vulnerabilities...")
    print()
    print("   DO NOT use in production!")
    print()
    
    # Get worker configuration
    import sys
    if len(sys.argv) > 1:
        worker_id = sys.argv[1]
    else:
        worker_id = f"worker-{random.randint(1000, 9999)}"
    
    # Default capabilities
    capabilities = ["data_analysis", "code_review", "testing", "documentation"]
    
    # Create and start worker
    worker = TaskWorker(
        worker_id=worker_id,
        capabilities=capabilities
    )
    
    # Connect to coordinator
    if worker.connect_to_coordinator():
        # Start listening for tasks
        worker.start_listening()
    else:
        print("❌ Failed to connect to coordinator")
        print("   Make sure the coordinator is running first:")
        print("   python server/task_coordinator.py")


if __name__ == "__main__":
    main()