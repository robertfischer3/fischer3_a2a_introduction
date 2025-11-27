#!/usr/bin/env python3
"""
Credit Report Client - Stage 2 (Improved)

Client for interacting with the IMPROVED Credit Report Analysis Agent.
Includes basic authentication support.
"""

import asyncio
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any


class ImprovedCreditReportClient:
    """Client for interacting with Improved Credit Report Analysis Agent"""
    
    def __init__(self, host: str = "localhost", port: int = 9001):
        self.host = host
        self.port = port
        self.client_id = "credit-client-improved-001"
        self.agent_card = None
        
        # ✅ Shared secret for authentication (matches server)
        # ⚠️ In production, use PKI/certificates, not shared secrets
        self.shared_secret = "demo_secret_key_12345"
    
    async def connect(self):
        """Connect to the agent server"""
        print(f"🔗 Connecting to {self.host}:{self.port}...")
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port
        )
        print("✅ Connected successfully")
        
        # Perform handshake
        await self.handshake()
    
    async def handshake(self):
        """Perform handshake with agent"""
        handshake_msg = {
            "action": "HANDSHAKE",
            "sender_id": self.client_id,
            "timestamp": "2025-01-15T10:00:00Z"
        }
        
        response = await self.send_message(handshake_msg, authenticated=False)
        
        if response.get("status") == "success":
            self.agent_card = response.get("agent_card")
            print(f"🤝 Handshake complete with: {self.agent_card.get('name')}")
            print(f"   Security Level: {self.agent_card.get('security_level', 'unknown')}")
            print(f"   Capabilities: {', '.join(self.agent_card.get('capabilities', []))}")
        else:
            print(f"❌ Handshake failed: {response.get('message')}")
    
    def create_auth_tag(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        ✅ Create authentication tag for request
        
        ⚠️ WEAKNESS: No nonce, vulnerable to replay attacks
        """
        payload_str = json.dumps(payload, sort_keys=True)
        signature = self.compute_signature(self.client_id, payload_str)
        
        return {
            "sender_id": self.client_id,
            "signature": signature
            # ⚠️ Missing: nonce, timestamp
        }
    
    def compute_signature(self, sender_id: str, payload: str) -> str:
        """Compute HMAC signature"""
        message = f"{sender_id}:{payload}"
        signature = hmac.new(
            self.shared_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    async def send_message(self, message: Dict[str, Any], 
                          authenticated: bool = True) -> Dict[str, Any]:
        """Send message to agent and receive response"""
        
        # ✅ Add authentication if required
        if authenticated:
            if "payload" in message:
                message["auth_tag"] = self.create_auth_tag(message["payload"])
        
        message_str = json.dumps(message)
        self.writer.write(message_str.encode('utf-8'))
        await self.writer.drain()
        
        data = await self.reader.read(1024 * 1024 * 10)  # Read up to 10MB
        response = json.loads(data.decode('utf-8'))
        
        return response
    
    async def upload_report(self, file_path: Path) -> Dict[str, Any]:
        """Upload a credit report file"""
        print(f"\n📤 Uploading: {file_path.name}")
        
        # Read file content
        with open(file_path, "r") as f:
            file_data = f.read()
        
        file_size = len(file_data)
        print(f"   Size: {file_size} bytes")
        
        # ✅ Client-side size check
        MAX_SIZE = 5 * 1024 * 1024
        if file_size > MAX_SIZE:
            print(f"❌ File too large ({file_size} bytes > {MAX_SIZE} bytes)")
            return {"status": "error", "message": "File too large"}
        
        # Send upload message with authentication
        message = {
            "action": "upload_report",
            "sender_id": self.client_id,
            "payload": {
                "filename": file_path.name,
                "file_data": file_data
            }
        }
        
        response = await self.send_message(message, authenticated=True)
        
        if response.get("status") == "success":
            print(f"✅ Upload successful!")
            print(f"   Report ID: {response.get('report_id')}")
            
            # Display analysis
            analysis = response.get("analysis", {})
            if analysis and not analysis.get("error"):
                print(f"\n📊 Analysis Results:")
                print(f"   Credit Score: {analysis.get('credit_score')}")
                print(f"   Risk Level: {analysis.get('risk_level')}")
                print(f"   Total Accounts: {analysis.get('total_accounts')}")
                print(f"   Total Balance: ${analysis.get('total_balance', 0):,.2f}")
                print(f"   Credit Utilization: {analysis.get('credit_utilization')}%")
                print(f"   Hard Inquiries: {analysis.get('hard_inquiries')}")
        else:
            print(f"❌ Upload failed: {response.get('message')}")
        
        return response
    
    async def analyze_report(self, report_id: str) -> Dict[str, Any]:
        """Analyze an existing report"""
        message = {
            "action": "analyze_report",
            "sender_id": self.client_id,
            "payload": {
                "report_id": report_id
            }
        }
        
        response = await self.send_message(message, authenticated=True)
        return response
    
    async def list_reports(self) -> Dict[str, Any]:
        """List all stored reports"""
        message = {
            "action": "list_reports",
            "sender_id": self.client_id,
            "payload": {}
        }
        
        response = await self.send_message(message, authenticated=True)
        
        if response.get("status") == "success":
            count = response.get("count")
            truncated = response.get("truncated", False)
            print(f"\n📋 Stored Reports: {count}")
            if truncated:
                print("   ⚠️  Results truncated to 100")
            for report_id in response.get("report_ids", []):
                print(f"   - {report_id}")
        
        return response
    
    async def get_summary(self) -> Dict[str, Any]:
        """Get summary of all reports"""
        message = {
            "action": "get_summary",
            "sender_id": self.client_id,
            "payload": {}
        }
        
        response = await self.send_message(message, authenticated=True)
        
        if response.get("status") == "success":
            print(f"\n📊 Summary of {response.get('total_reports')} Reports:")
            for report in response.get("reports", []):
                print(f"\n   Report: {report.get('report_id')}")
                print(f"   Name: {report.get('subject_name')}")
                print(f"   SSN: {report.get('ssn')}")  # ✅ Now masked
                print(f"   Score: {report.get('credit_score')}")
        
        return response
    
    async def close(self):
        """Close connection"""
        self.writer.close()
        await self.writer.wait_closed()


async def interactive_menu(client: ImprovedCreditReportClient):
    """Interactive menu for testing"""
    
    while True:
        print("\n" + "=" * 50)
        print("📋 Credit Report Client Menu (Improved)")
        print("=" * 50)
        print("1. Upload valid report")
        print("2. Upload malicious report (test injection)")
        print("3. List all reports")
        print("4. Get summary of all reports")
        print("5. Analyze specific report")
        print("6. Test oversized file (DoS)")
        print("7. Test wrong file type")
        print("8. Test replay attack (reuse request)")
        print("9. Quit")
        print("-" * 50)
        
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == "1":
            # Upload valid report
            report_path = Path("../insecure/sample_reports/valid_report.json")
            if report_path.exists():
                await client.upload_report(report_path)
            else:
                print(f"❌ File not found: {report_path}")
        
        elif choice == "2":
            # Upload malicious report
            report_path = Path("../insecure/sample_reports/malicious_report.json")
            if report_path.exists():
                print("\n⚠️  Uploading malicious report...")
                print("   ✅ Stage 2 improvements should catch some issues")
                await client.upload_report(report_path)
            else:
                print(f"❌ File not found: {report_path}")
        
        elif choice == "3":
            # List reports
            await client.list_reports()
        
        elif choice == "4":
            # Get summary
            await client.get_summary()
        
        elif choice == "5":
            # Analyze specific report
            report_id = input("Enter report ID: ").strip()
            response = await client.analyze_report(report_id)
            print(f"\n{json.dumps(response, indent=2)}")
        
        elif choice == "6":
            # Test oversized file
            print("\n⚠️  Testing file size limits...")
            print("   ✅ Stage 2 has size limits (should reject)")
            oversized_path = Path("../insecure/sample_reports/oversized_report.json")
            if oversized_path.exists():
                try:
                    await client.upload_report(oversized_path)
                except Exception as e:
                    print(f"   ❌ Upload rejected (expected): {e}")
            else:
                print("   Generate oversized file first:")
                print("   cd ../insecure/sample_reports && python generate_oversized.py")
        
        elif choice == "7":
            # Test wrong file type
            print("\n⚠️  Testing file type validation...")
            print("   ✅ Stage 2 checks extensions (should reject .sh)")
            wrong_type = Path("../insecure/sample_reports/fake_report.sh")
            if wrong_type.exists():
                try:
                    await client.upload_report(wrong_type)
                except Exception as e:
                    print(f"   Expected rejection: {e}")
            else:
                print(f"   ❌ File not found: {wrong_type}")
        
        elif choice == "8":
            # Test replay attack
            print("\n⚠️  Testing replay attack...")
            print("   ⚠️  Stage 2 is VULNERABLE to this!")
            print("   No nonce means same request can be sent multiple times")
            
            report_path = Path("../insecure/sample_reports/valid_report.json")
            if report_path.exists():
                print("\n   Sending same request 3 times:")
                for i in range(3):
                    print(f"\n   Attempt {i+1}:")
                    await client.upload_report(report_path)
                    await asyncio.sleep(1)
                
                print("\n   ⚠️  All 3 succeeded! Replay attack worked!")
                print("   This is why Stage 3 adds nonce-based protection")
            else:
                print(f"   ❌ File not found: {report_path}")
        
        elif choice == "9":
            print("\n✅ Exiting...")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")


async def main():
    """Main entry point"""
    
    # Change to script directory for relative paths
    script_dir = Path(__file__).parent.parent
    import os
    os.chdir(script_dir)
    
    client = ImprovedCreditReportClient()
    
    try:
        await client.connect()
        await interactive_menu(client)
        await client.close()
    
    except ConnectionRefusedError:
        print("❌ Connection refused. Make sure the improved server is running:")
        print("   python server/improved_credit_agent.py")
    except KeyboardInterrupt:
        print("\n✅ Client interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
