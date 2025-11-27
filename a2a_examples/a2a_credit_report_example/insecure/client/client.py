#!/usr/bin/env python3
"""
Credit Report Client - Stage 1

Simple client for uploading and analyzing credit reports.
Works with the INSECURE agent (for educational purposes).
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any


class CreditReportClient:
    """Client for interacting with Credit Report Analysis Agent"""
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.client_id = "credit-client-001"
        self.agent_card = None
    
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
        
        response = await self.send_message(handshake_msg)
        
        if response.get("status") == "success":
            self.agent_card = response.get("agent_card")
            print(f"🤝 Handshake complete with: {self.agent_card.get('name')}")
            print(f"   Capabilities: {', '.join(self.agent_card.get('capabilities', []))}")
        else:
            print(f"❌ Handshake failed: {response.get('message')}")
    
    async def send_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send message to agent and receive response"""
        message_str = json.dumps(message)
        self.writer.write(message_str.encode('utf-8'))
        await self.writer.drain()
        
        data = await self.reader.read(1024 * 1024 * 20)  # Read up to 20MB
        response = json.loads(data.decode('utf-8'))
        
        return response
    
    async def upload_report(self, file_path: Path) -> Dict[str, Any]:
        """Upload a credit report file"""
        print(f"\n📤 Uploading: {file_path.name}")
        
        # Read file content
        with open(file_path, "r") as f:
            file_data = f.read()
        
        print(f"   Size: {len(file_data)} bytes")
        
        # Send upload message
        message = {
            "action": "upload_report",
            "sender_id": self.client_id,
            "payload": {
                "filename": file_path.name,
                "file_data": file_data
            }
        }
        
        response = await self.send_message(message)
        
        if response.get("status") == "success":
            print(f"✅ Upload successful!")
            print(f"   Report ID: {response.get('report_id')}")
            
            # Display analysis
            analysis = response.get("analysis", {})
            if analysis:
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
        
        response = await self.send_message(message)
        return response
    
    async def list_reports(self) -> Dict[str, Any]:
        """List all stored reports"""
        message = {
            "action": "list_reports",
            "sender_id": self.client_id,
            "payload": {}
        }
        
        response = await self.send_message(message)
        
        if response.get("status") == "success":
            print(f"\n📋 Stored Reports: {response.get('count')}")
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
        
        response = await self.send_message(message)
        
        if response.get("status") == "success":
            print(f"\n📊 Summary of {response.get('total_reports')} Reports:")
            for report in response.get("reports", []):
                print(f"\n   Report: {report.get('report_id')}")
                print(f"   Name: {report.get('subject_name')}")
                print(f"   SSN: {report.get('ssn')}")
                print(f"   Score: {report.get('credit_score')}")
        
        return response
    
    async def close(self):
        """Close connection"""
        self.writer.close()
        await self.writer.wait_closed()


async def interactive_menu(client: CreditReportClient):
    """Interactive menu for testing"""
    
    while True:
        print("\n" + "=" * 50)
        print("📋 Credit Report Client Menu")
        print("=" * 50)
        print("1. Upload valid report")
        print("2. Upload malicious report (test injection)")
        print("3. List all reports")
        print("4. Get summary of all reports")
        print("5. Analyze specific report")
        print("6. Test oversized file (DoS)")
        print("7. Test XML bomb")
        print("8. Quit")
        print("-" * 50)
        
        choice = input("\nEnter choice (1-8): ").strip()
        
        if choice == "1":
            # Upload valid report
            report_path = Path("sample_reports/valid_report.json")
            if report_path.exists():
                await client.upload_report(report_path)
            else:
                print(f"❌ File not found: {report_path}")
        
        elif choice == "2":
            # Upload malicious report
            report_path = Path("sample_reports/malicious_report.json")
            if report_path.exists():
                print("\n⚠️  Uploading malicious report to test injection vulnerabilities...")
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
            print("\n⚠️  Testing DoS with oversized file...")
            print("   This will attempt to upload a large file to exhaust memory.")
            confirm = input("   Continue? (yes/no): ").strip().lower()
            if confirm == "yes":
                # Check if oversized file exists
                oversized_path = Path("sample_reports/oversized_report.json")
                if not oversized_path.exists():
                    print("   Generating oversized report (this may take a moment)...")
                    import subprocess
                    subprocess.run([
                        sys.executable,
                        "sample_reports/generate_oversized.py"
                    ], cwd=Path.cwd())
                
                if oversized_path.exists():
                    try:
                        await client.upload_report(oversized_path)
                    except Exception as e:
                        print(f"   ❌ Upload failed (expected): {e}")
        
        elif choice == "7":
            # Test XML bomb
            print("\n⚠️  Testing XML bomb...")
            print("   Note: Current agent expects JSON, not XML.")
            print("   This would crash a vulnerable XML parser.")
            xml_path = Path("sample_reports/xml_bomb.xml")
            if xml_path.exists():
                with open(xml_path, "r") as f:
                    content = f.read()
                print(f"\n   XML bomb content preview:")
                print(f"   {content[:200]}...")
            else:
                print(f"   ❌ File not found: {xml_path}")
        
        elif choice == "8":
            print("\n✅ Exiting...")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")


async def main():
    """Main entry point"""
    
    # Change to script directory
    script_dir = Path(__file__).parent.parent
    import os
    os.chdir(script_dir)
    
    client = CreditReportClient()
    
    try:
        await client.connect()
        await interactive_menu(client)
        await client.close()
    
    except ConnectionRefusedError:
        print("❌ Connection refused. Make sure the server is running.")
    except KeyboardInterrupt:
        print("\n✅ Client interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
