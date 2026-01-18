#!/usr/bin/env python3
"""
INSECURE Credit Report Analysis Agent - Stage 1

⚠️  WARNING: This code is INTENTIONALLY VULNERABLE for educational purposes.
    DO NOT use in production. This demonstrates common security mistakes.

Vulnerabilities demonstrated:
1. No file size limits (DoS via large files)
2. No file type validation (accepts any file)
3. No input sanitization (injection attacks)
4. No authentication (anyone can upload)
5. Sensitive data in logs (PII exposure)
6. No rate limiting (resource exhaustion)
7. Unsafe JSON parsing (malformed data)
8. Unbounded storage (disk exhaustion)

Educational Purpose: Learn to identify these vulnerabilities before writing secure code.
"""

import asyncio
import json
import os
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class CreditReportAgent:
    """
    VULNERABLE Credit Report Analysis Agent
    
    This agent accepts credit report uploads and performs basic analysis.
    It contains INTENTIONAL security vulnerabilities for educational purposes.
    """
    
    def __init__(self, host: str = "localhost", port: int = 9000):
        self.host = host
        self.port = port
        self.agent_id = "credit-agent-insecure-001"
        self.agent_name = "Credit Report Analyzer"
        
        # ❌ VULNERABILITY 1: No size limits on storage
        self.storage_dir = Path("./stored_reports")
        self.storage_dir.mkdir(exist_ok=True)
        
        # Agent card (capability advertisement)
        self.agent_card = {
            "agent_id": self.agent_id,
            "name": self.agent_name,
            "version": "1.0.0",
            "description": "Analyzes credit reports and provides risk assessments",
            "capabilities": [
                "upload_report",
                "analyze_report",
                "get_summary",
                "list_reports"
            ],
            "supported_protocols": ["A2A/1.0"],
            "metadata": {
                "supported_formats": ["json", "csv", "xml"],
                "analysis_types": ["credit_score", "risk_assessment", "account_summary"]
            }
        }
    
    async def start(self):
        """Start the agent server"""
        server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        addr = server.sockets[0].getsockname()
        print("=" * 60)
        print(f"  💳 Credit Report Analysis Agent")
        print(f"  ⚠️  INSECURE VERSION (Educational Only)")
        print("=" * 60)
        print(f"📡 Listening on {addr[0]}:{addr[1]}")
        print(f"🆔 Agent ID: {self.agent_id}")
        print(f"📁 Storage: {self.storage_dir.absolute()}")
        print()
        print("⚠️  WARNING: This server has intentional security vulnerabilities!")
        print("   Do not use with real data or on production networks.")
        print()
        
        async with server:
            await server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle incoming client connection"""
        addr = writer.get_extra_info('peername')
        print(f"📥 New connection from {addr}")
        
        try:
            while True:
                # Read message
                data = await reader.read(1024 * 1024 * 20)  # ❌ VULNERABILITY 2: Reads up to 20MB!
                if not data:
                    break
                
                # ❌ VULNERABILITY 3: No authentication check!
                # Anyone can connect and upload
                
                message_str = data.decode('utf-8')
                message = json.loads(message_str)
                
                print(f"📨 Received: {message.get('action', 'UNKNOWN')} from {message.get('sender_id', 'UNKNOWN')}")
                
                # Route to handler
                response = await self.route_message(message)
                
                # Send response
                response_str = json.dumps(response)
                writer.write(response_str.encode('utf-8'))
                await writer.drain()
                
        except json.JSONDecodeError as e:
            # ❌ VULNERABILITY 4: Exposes error details
            error_msg = {
                "status": "error",
                "message": f"JSON parse error: {str(e)}",
                "details": message_str[:200] if 'message_str' in locals() else "Unknown"
            }
            writer.write(json.dumps(error_msg).encode('utf-8'))
            await writer.drain()
        
        except Exception as e:
            # ❌ VULNERABILITY 5: Exposes stack traces
            print(f"❌ Error handling client: {e}")
            import traceback
            traceback.print_exc()
            
            error_msg = {
                "status": "error",
                "message": str(e),
                "traceback": traceback.format_exc()  # ❌ Leaks system info!
            }
            writer.write(json.dumps(error_msg).encode('utf-8'))
            await writer.drain()
        
        finally:
            print(f"👋 Connection closed: {addr}")
            writer.close()
            await writer.wait_closed()
    
    async def route_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Route message to appropriate handler"""
        action = message.get("action")
        
        if action == "HANDSHAKE":
            return self.handle_handshake(message)
        elif action == "upload_report":
            return await self.handle_upload_report(message)
        elif action == "analyze_report":
            return await self.handle_analyze_report(message)
        elif action == "get_summary":
            return self.handle_get_summary(message)
        elif action == "list_reports":
            return self.handle_list_reports(message)
        else:
            return {
                "status": "error",
                "message": f"Unknown action: {action}"
            }
    
    def handle_handshake(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle handshake and return agent card"""
        return {
            "status": "success",
            "action": "HANDSHAKE_ACK",
            "agent_card": self.agent_card,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def handle_upload_report(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle credit report upload
        
        ❌ CRITICAL VULNERABILITIES IN THIS METHOD:
        - No file size validation
        - No file type validation
        - No input sanitization
        - No authentication
        - Logs sensitive PII
        """
        payload = message.get("payload", {})
        
        # ❌ VULNERABILITY 6: No file size check!
        file_data = payload.get("file_data", "")
        filename = payload.get("filename", "unknown.json")
        
        # ❌ VULNERABILITY 7: No file type validation!
        # Accepts any filename, could be .exe, .sh, etc.
        
        # ❌ VULNERABILITY 8: No filename sanitization!
        # Could contain path traversal: ../../../../etc/passwd
        print(f"📄 Uploading file: {filename}")
        print(f"📊 Size: {len(file_data)} bytes")
        
        try:
            # ❌ VULNERABILITY 9: Unsafe JSON parsing
            # No validation before parsing, trusts all input
            report = json.loads(file_data)
            
            # ❌ VULNERABILITY 10: Logs PII directly!
            print(f"   Subject: {report.get('subject', {}).get('name', 'Unknown')}")
            print(f"   SSN: {report.get('subject', {}).get('ssn', 'Unknown')}")  # ❌ SSN in logs!
            print(f"   Credit Score: {report.get('credit_score', {}).get('score', 'Unknown')}")
            
            # ❌ VULNERABILITY 11: No input validation
            # Accepts any values, even malicious ones
            report_id = report.get("report_id", "unknown")
            
            # ❌ VULNERABILITY 12: Unbounded storage
            # Saves everything, no cleanup, no limits
            save_path = self.storage_dir / f"{report_id}.json"
            with open(save_path, "w") as f:
                json.dump(report, f, indent=2)
            
            print(f"✅ Saved to: {save_path}")
            
            # Perform basic analysis
            analysis = self.analyze_credit_report(report)
            
            return {
                "status": "success",
                "message": "Report uploaded successfully",
                "report_id": report_id,
                "analysis": analysis
            }
            
        except json.JSONDecodeError as e:
            # ❌ VULNERABILITY 13: Exposes parsing errors
            return {
                "status": "error",
                "message": f"Invalid JSON: {str(e)}",
                "file_preview": file_data[:500]  # ❌ Leaks file content!
            }
        except Exception as e:
            # ❌ VULNERABILITY 14: Exposes all errors
            return {
                "status": "error",
                "message": f"Upload failed: {str(e)}",
                "error_type": type(e).__name__
            }
    
    def analyze_credit_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze credit report and generate risk assessment
        
        ❌ VULNERABILITIES:
        - No validation of report structure
        - Direct access to fields (KeyError possible)
        - No sanitization of input data
        """
        
        # ❌ VULNERABILITY 15: No validation, assumes fields exist
        try:
            credit_score = report["credit_score"]["score"]
            accounts = report.get("accounts", [])
            inquiries = report.get("inquiries", [])
            
            # ❌ VULNERABILITY 16: No range validation
            # credit_score could be negative, over 850, or non-numeric
            
            # Simple risk assessment
            if credit_score >= 740:
                risk_level = "LOW"
            elif credit_score >= 670:
                risk_level = "MEDIUM"
            else:
                risk_level = "HIGH"
            
            # ❌ VULNERABILITY 17: Uses untrusted input in calculations
            total_balance = sum(acc.get("balance", 0) for acc in accounts)
            total_credit_limit = sum(acc.get("credit_limit", 0) for acc in accounts)
            
            # ❌ VULNERABILITY 18: No division by zero check
            utilization = (total_balance / total_credit_limit) * 100 if total_credit_limit > 0 else 0
            
            analysis = {
                "credit_score": credit_score,
                "risk_level": risk_level,
                "total_accounts": len(accounts),
                "total_balance": total_balance,
                "credit_utilization": round(utilization, 2),
                "hard_inquiries": len([i for i in inquiries if i.get("type") == "hard"]),
                "analysis_date": datetime.utcnow().isoformat()
            }
            
            # ❌ VULNERABILITY 19: Logs full analysis (may contain PII)
            print(f"📊 Analysis complete: {json.dumps(analysis, indent=2)}")
            
            return analysis
            
        except KeyError as e:
            # ❌ VULNERABILITY 20: Exposes structure details
            return {
                "error": f"Missing required field: {str(e)}",
                "report_structure": list(report.keys())
            }
        except Exception as e:
            # ❌ VULNERABILITY 21: Generic error exposure
            return {
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    async def handle_analyze_report(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an existing report by ID"""
        payload = message.get("payload", {})
        report_id = payload.get("report_id")
        
        # ❌ VULNERABILITY 22: No input sanitization on report_id
        # Could contain path traversal
        report_path = self.storage_dir / f"{report_id}.json"
        
        try:
            with open(report_path, "r") as f:
                report = json.load(f)
            
            analysis = self.analyze_credit_report(report)
            
            return {
                "status": "success",
                "report_id": report_id,
                "analysis": analysis
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "message": f"Report not found: {report_id}"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def handle_get_summary(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary of all stored reports"""
        
        # ❌ VULNERABILITY 23: Lists all files (information disclosure)
        reports = []
        for report_file in self.storage_dir.glob("*.json"):
            try:
                with open(report_file, "r") as f:
                    report = json.load(f)
                
                # ❌ VULNERABILITY 24: Includes PII in summary
                summary = {
                    "report_id": report.get("report_id"),
                    "subject_name": report.get("subject", {}).get("name"),  # ❌ PII
                    "ssn": report.get("subject", {}).get("ssn"),  # ❌ PII!
                    "credit_score": report.get("credit_score", {}).get("score"),
                    "file": str(report_file.name)
                }
                reports.append(summary)
            except Exception as e:
                print(f"⚠️  Error reading {report_file}: {e}")
        
        return {
            "status": "success",
            "total_reports": len(reports),
            "reports": reports
        }
    
    def handle_list_reports(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """List all report IDs"""
        
        # ❌ VULNERABILITY 25: No pagination, could return thousands
        report_ids = [f.stem for f in self.storage_dir.glob("*.json")]
        
        return {
            "status": "success",
            "count": len(report_ids),
            "report_ids": report_ids
        }


async def main():
    """Main entry point"""
    agent = CreditReportAgent()
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n")
        print("👋 Agent shutting down...")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
