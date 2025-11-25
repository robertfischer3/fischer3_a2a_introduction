#!/usr/bin/env python3
"""
IMPROVED Credit Report Analysis Agent - Stage 2

⚠️  WARNING: This code has PARTIAL security improvements but is still vulnerable.
    This demonstrates incremental security - better than Stage 1 but not production-ready.

Security Improvements from Stage 1:
✅ File size limits (prevents large file DoS)
✅ Basic file type validation (extension check)
✅ Simple authentication (basic signature verification)
✅ Input validation (required fields, types)
✅ Filename sanitization (path traversal prevention)
✅ Storage limits (bounded disk usage)
✅ Basic error handling (reduced info disclosure)
✅ Partial PII masking (SSN last 4 only)

Remaining Vulnerabilities:
⚠️ No replay attack prevention (can reuse signatures)
⚠️ Weak cryptography (simple hash-based auth)
⚠️ No rate limiting (still vulnerable to DoS)
⚠️ Incomplete input validation (ranges not checked)
⚠️ No content-based file validation (magic bytes)
⚠️ No comprehensive audit logging
⚠️ No RBAC (everyone has same permissions)
⚠️ No encryption (data in transit or at rest)
⚠️ Still logs some PII (address, name)
⚠️ No nonce-based authentication

Educational Purpose: Learn about security trade-offs and why partial security isn't enough.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class ImprovedCreditReportAgent:
    """
    IMPROVED Credit Report Analysis Agent
    
    This agent has basic security controls but is NOT production-ready.
    Demonstrates incremental security improvements and their limitations.
    """
    
    # ✅ IMPROVEMENT 1: Define size limits
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit
    MAX_STORED_REPORTS = 1000  # Limit stored reports
    
    # ✅ IMPROVEMENT 2: Define allowed file types
    ALLOWED_EXTENSIONS = {'.json', '.csv'}
    ALLOWED_CONTENT_TYPES = {'application/json', 'text/csv'}
    
    def __init__(self, host: str = "localhost", port: int = 9001):
        self.host = host
        self.port = port
        self.agent_id = "credit-agent-improved-001"
        self.agent_name = "Credit Report Analyzer (Improved)"
        
        # ✅ IMPROVEMENT 3: Storage with limits
        self.storage_dir = Path("./stored_reports_improved")
        self.storage_dir.mkdir(exist_ok=True)
        
        # ✅ IMPROVEMENT 4: Simple authentication (shared secret)
        # ⚠️ STILL VULNERABLE: Not production-grade crypto
        self.shared_secret = "demo_secret_key_12345"  # ⚠️ Hardcoded secret!
        
        # Agent card
        self.agent_card = {
            "agent_id": self.agent_id,
            "name": self.agent_name,
            "version": "2.0.0",
            "description": "Analyzes credit reports with basic security controls",
            "capabilities": [
                "upload_report",
                "analyze_report",
                "get_summary",
                "list_reports",
                "authenticated"  # ✅ New capability
            ],
            "supported_protocols": ["A2A/1.0"],
            "security_level": "basic",
            "metadata": {
                "supported_formats": ["json", "csv"],
                "max_file_size": self.MAX_FILE_SIZE,
                "authentication": "required",
                "analysis_types": ["credit_score", "risk_assessment"]
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
        print(f"  ⚠️  IMPROVED VERSION (Partial Security)")
        print("=" * 60)
        print(f"📡 Listening on {addr[0]}:{addr[1]}")
        print(f"🆔 Agent ID: {self.agent_id}")
        print(f"📁 Storage: {self.storage_dir.absolute()}")
        print(f"🔒 Security Level: BASIC (not production)")
        print()
        print("✅ Improvements from Stage 1:")
        print("   - File size limits")
        print("   - Basic authentication")
        print("   - Input validation")
        print("   - Filename sanitization")
        print()
        print("⚠️  Still Vulnerable:")
        print("   - No replay protection")
        print("   - Weak cryptography")
        print("   - No rate limiting")
        print()
        
        async with server:
            await server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, 
                           writer: asyncio.StreamWriter):
        """Handle incoming client connection"""
        addr = writer.get_extra_info('peername')
        print(f"📥 New connection from {addr}")
        
        try:
            # ✅ IMPROVEMENT 5: Size limit on read
            data = await reader.read(self.MAX_FILE_SIZE + 1024)
            if not data:
                return
            
            # ✅ IMPROVEMENT 6: Check size before processing
            if len(data) > self.MAX_FILE_SIZE:
                error_msg = {
                    "status": "error",
                    "message": f"Request too large: {len(data)} bytes (max: {self.MAX_FILE_SIZE})"
                }
                writer.write(json.dumps(error_msg).encode('utf-8'))
                await writer.drain()
                return
            
            message_str = data.decode('utf-8')
            message = json.loads(message_str)
            
            print(f"📨 Received: {message.get('action', 'UNKNOWN')} from {message.get('sender_id', 'UNKNOWN')}")
            
            # ✅ IMPROVEMENT 7: Authenticate most requests
            action = message.get("action")
            if action not in ["HANDSHAKE"]:  # Handshake doesn't need auth
                if not self.authenticate_request(message):
                    error_msg = {
                        "status": "error",
                        "message": "Authentication failed"
                    }
                    print(f"❌ Authentication failed for {addr}")
                    writer.write(json.dumps(error_msg).encode('utf-8'))
                    await writer.drain()
                    return
            
            # Route to handler
            response = await self.route_message(message)
            
            # Send response
            response_str = json.dumps(response)
            writer.write(response_str.encode('utf-8'))
            await writer.drain()
            
        except json.JSONDecodeError as e:
            # ✅ IMPROVEMENT 8: Less detailed errors
            error_msg = {
                "status": "error",
                "message": "Invalid JSON format"
                # ✅ No longer exposing parse details
            }
            writer.write(json.dumps(error_msg).encode('utf-8'))
            await writer.drain()
        
        except Exception as e:
            # ✅ IMPROVEMENT 9: Generic error messages
            print(f"❌ Error handling client: {e}")
            # ⚠️ STILL VULNERABLE: Stack trace in server logs
            import traceback
            traceback.print_exc()
            
            error_msg = {
                "status": "error",
                "message": "Internal server error"
                # ✅ Not exposing details to client anymore
            }
            writer.write(json.dumps(error_msg).encode('utf-8'))
            await writer.drain()
        
        finally:
            print(f"👋 Connection closed: {addr}")
            writer.close()
            await writer.wait_closed()
    
    def authenticate_request(self, message: Dict[str, Any]) -> bool:
        """
        ✅ IMPROVEMENT 10: Basic authentication
        
        ⚠️ STILL VULNERABLE:
        - Uses simple HMAC (no PKI/certificates)
        - No nonce (vulnerable to replay attacks)
        - No timestamp validation
        - Shared secret (not public/private key)
        """
        auth_tag = message.get("auth_tag")
        if not auth_tag:
            return False
        
        # Check required fields
        sender_id = auth_tag.get("sender_id")
        signature = auth_tag.get("signature")
        
        if not sender_id or not signature:
            return False
        
        # ⚠️ VULNERABILITY: No nonce checking (replay attacks possible)
        # An attacker can capture and reuse valid requests
        
        # Compute expected signature
        payload_str = json.dumps(message.get("payload", {}), sort_keys=True)
        expected_sig = self.compute_signature(sender_id, payload_str)
        
        # ✅ Constant-time comparison
        return hmac.compare_digest(signature, expected_sig)
    
    def compute_signature(self, sender_id: str, payload: str) -> str:
        """
        Compute HMAC signature
        
        ⚠️ STILL VULNERABLE:
        - Simple HMAC-SHA256 (not RSA/ECC)
        - Shared secret (everyone uses same key)
        - No key rotation
        - Not cryptographically strong for production
        """
        import hmac
        message = f"{sender_id}:{payload}"
        signature = hmac.new(
            self.shared_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
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
    
    def sanitize_filename(self, filename: str) -> str:
        """
        ✅ IMPROVEMENT 11: Sanitize filename to prevent path traversal
        
        Removes:
        - Path separators (/, \)
        - Parent directory references (..)
        - Null bytes
        - Control characters
        """
        # Get basename (removes path components)
        safe = os.path.basename(filename)
        
        # Remove dangerous characters
        safe = re.sub(r'[^\w\s.-]', '', safe)
        
        # Remove multiple dots
        safe = re.sub(r'\.\.+', '.', safe)
        
        # Limit length
        if len(safe) > 100:
            safe = safe[:100]
        
        return safe
    
    def validate_file_type(self, filename: str) -> bool:
        """
        ✅ IMPROVEMENT 12: Basic file type validation
        
        ⚠️ STILL VULNERABLE:
        - Only checks extension (not content/magic bytes)
        - Extension can be spoofed
        - No deep content inspection
        """
        ext = Path(filename).suffix.lower()
        return ext in self.ALLOWED_EXTENSIONS
    
    def validate_report_structure(self, report: Dict[str, Any]) -> bool:
        """
        ✅ IMPROVEMENT 13: Basic structure validation
        
        ⚠️ STILL VULNERABLE:
        - Only checks field presence (not ranges)
        - Doesn't validate data types deeply
        - No schema validation library
        """
        required_fields = ["report_id", "subject", "credit_score"]
        
        for field in required_fields:
            if field not in report:
                raise ValueError(f"Missing required field: {field}")
        
        # Check nested required fields
        if "ssn" not in report["subject"]:
            raise ValueError("Missing SSN in subject")
        
        if "score" not in report["credit_score"]:
            raise ValueError("Missing score in credit_score")
        
        # ✅ Basic type validation
        if not isinstance(report["credit_score"]["score"], (int, float)):
            raise ValueError("Credit score must be a number")
        
        # ⚠️ VULNERABILITY: No range validation
        # Score could still be -999999 or 999999
        
        return True
    
    def mask_pii(self, value: str, field_type: str = "default") -> str:
        """
        ✅ IMPROVEMENT 14: Mask PII for logging
        
        ⚠️ STILL VULNERABLE:
        - Only masks SSN, not other PII
        - Name and address still logged
        - Not comprehensive
        """
        if field_type == "ssn":
            # Show only last 4 digits
            if len(value) >= 4:
                return f"***-**-{value[-4:]}"
            return "***"
        
        # ⚠️ Other fields not masked
        return value
    
    async def handle_upload_report(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle credit report upload with improved security
        
        ✅ Improvements:
        - File size validation
        - File type validation
        - Filename sanitization
        - Structure validation
        - Storage limits
        - PII masking in logs
        
        ⚠️ Still Vulnerable:
        - No content-based validation
        - No malware scanning
        - No encryption at rest
        """
        payload = message.get("payload", {})
        
        file_data = payload.get("file_data", "")
        filename = payload.get("filename", "unknown.json")
        
        # ✅ IMPROVEMENT 15: Validate file size
        if len(file_data) > self.MAX_FILE_SIZE:
            return {
                "status": "error",
                "message": f"File too large: {len(file_data)} bytes (max: {self.MAX_FILE_SIZE})"
            }
        
        # ✅ IMPROVEMENT 16: Sanitize filename
        safe_filename = self.sanitize_filename(filename)
        
        # ✅ IMPROVEMENT 17: Validate file type
        if not self.validate_file_type(safe_filename):
            return {
                "status": "error",
                "message": f"Invalid file type. Allowed: {', '.join(self.ALLOWED_EXTENSIONS)}"
            }
        
        print(f"📄 Uploading file: {safe_filename}")
        print(f"📊 Size: {len(file_data)} bytes")
        
        try:
            # Parse JSON
            report = json.loads(file_data)
            
            # ✅ IMPROVEMENT 18: Validate structure
            self.validate_report_structure(report)
            
            # ✅ IMPROVEMENT 19: Mask PII in logs
            ssn_masked = self.mask_pii(
                report.get('subject', {}).get('ssn', 'Unknown'),
                'ssn'
            )
            print(f"   Subject: {report.get('subject', {}).get('name', 'Unknown')}")  # ⚠️ Still logs name
            print(f"   SSN: {ssn_masked}")  # ✅ Masked
            print(f"   Credit Score: {report.get('credit_score', {}).get('score', 'Unknown')}")
            
            report_id = report.get("report_id", "unknown")
            
            # ✅ IMPROVEMENT 20: Check storage limits
            current_count = len(list(self.storage_dir.glob("*.json")))
            if current_count >= self.MAX_STORED_REPORTS:
                return {
                    "status": "error",
                    "message": f"Storage limit reached ({self.MAX_STORED_REPORTS} reports)"
                }
            
            # ✅ IMPROVEMENT 21: Use sanitized filename
            save_path = self.storage_dir / f"{self.sanitize_filename(report_id)}.json"
            
            # ⚠️ VULNERABILITY: No encryption at rest
            with open(save_path, "w") as f:
                json.dump(report, f, indent=2)
            
            print(f"✅ Saved to: {save_path}")
            
            # Perform analysis
            analysis = self.analyze_credit_report(report)
            
            return {
                "status": "success",
                "message": "Report uploaded successfully",
                "report_id": report_id,
                "analysis": analysis
            }
            
        except json.JSONDecodeError:
            # ✅ Generic error message
            return {
                "status": "error",
                "message": "Invalid JSON format"
            }
        except ValueError as e:
            # ✅ Validation errors (but descriptive)
            return {
                "status": "error",
                "message": f"Validation error: {str(e)}"
            }
        except Exception as e:
            # ✅ Generic error message
            print(f"❌ Upload error: {e}")
            return {
                "status": "error",
                "message": "Upload failed"
            }
    
    def analyze_credit_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze credit report with improved validation
        
        ✅ Improvements:
        - Try/except for field access
        - Default values for missing data
        - Division by zero check
        
        ⚠️ Still Vulnerable:
        - No range validation (can have negative scores)
        - No business logic validation
        """
        try:
            credit_score = report.get("credit_score", {}).get("score", 0)
            accounts = report.get("accounts", [])
            inquiries = report.get("inquiries", [])
            
            # ✅ IMPROVEMENT 22: Range check (basic)
            if credit_score < 300 or credit_score > 850:
                # ⚠️ Logs warning but still accepts invalid data
                print(f"⚠️  Warning: Unusual credit score: {credit_score}")
            
            # Risk assessment
            if credit_score >= 740:
                risk_level = "LOW"
            elif credit_score >= 670:
                risk_level = "MEDIUM"
            else:
                risk_level = "HIGH"
            
            # ✅ IMPROVEMENT 23: Safe calculations with defaults
            total_balance = sum(acc.get("balance", 0) for acc in accounts)
            total_credit_limit = sum(acc.get("credit_limit", 0) for acc in accounts)
            
            # ✅ IMPROVEMENT 24: Division by zero check
            if total_credit_limit > 0:
                utilization = (total_balance / total_credit_limit) * 100
            else:
                utilization = 0
            
            analysis = {
                "credit_score": credit_score,
                "risk_level": risk_level,
                "total_accounts": len(accounts),
                "total_balance": total_balance,
                "credit_utilization": round(utilization, 2),
                "hard_inquiries": len([i for i in inquiries if i.get("type") == "hard"]),
                "analysis_date": datetime.utcnow().isoformat()
            }
            
            return analysis
            
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            return {
                "error": "Analysis failed",
                "message": str(e)
            }
    
    async def handle_analyze_report(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an existing report by ID"""
        payload = message.get("payload", {})
        report_id = payload.get("report_id")
        
        # ✅ IMPROVEMENT 25: Sanitize report_id
        safe_report_id = self.sanitize_filename(report_id)
        report_path = self.storage_dir / f"{safe_report_id}.json"
        
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
                "message": "Report not found"
            }
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            return {
                "status": "error",
                "message": "Analysis failed"
            }
    
    def handle_get_summary(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get summary of all stored reports
        
        ✅ Improvements:
        - Masks SSN in output
        
        ⚠️ Still Vulnerable:
        - Still exposes name and other PII
        - No access control (all users see all reports)
        """
        reports = []
        for report_file in self.storage_dir.glob("*.json"):
            try:
                with open(report_file, "r") as f:
                    report = json.load(f)
                
                # ✅ IMPROVEMENT 26: Mask SSN
                ssn = report.get("subject", {}).get("ssn", "")
                ssn_masked = self.mask_pii(ssn, "ssn")
                
                summary = {
                    "report_id": report.get("report_id"),
                    "subject_name": report.get("subject", {}).get("name"),  # ⚠️ Still exposes name
                    "ssn": ssn_masked,  # ✅ Masked
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
        report_ids = [f.stem for f in self.storage_dir.glob("*.json")]
        
        # ✅ IMPROVEMENT 27: Limit returned results
        if len(report_ids) > 100:
            report_ids = report_ids[:100]
            truncated = True
        else:
            truncated = False
        
        return {
            "status": "success",
            "count": len(report_ids),
            "report_ids": report_ids,
            "truncated": truncated
        }


async def main():
    """Main entry point"""
    agent = ImprovedCreditReportAgent()
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n")
        print("👋 Agent shutting down...")
    except Exception as e:
        print(f"❌ Fatal error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
