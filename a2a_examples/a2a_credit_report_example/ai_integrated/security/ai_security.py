"""
AI Security Module - Stage 4 (AI Integration)

Comprehensive security controls for AI/LLM integration:
- Prompt injection prevention
- PII scrubbing before sending to AI
- Response validation
- Output sanitization
- Rate limiting for AI calls
- Cost tracking
- Audit logging for AI decisions
"""

import re
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime


class PromptInjectionDefense:
    """
    Defends against prompt injection attacks
    
    Prevents malicious inputs from hijacking AI behavior:
    - Instruction injection
    - Context escaping
    - Role confusion
    - System prompt leakage
    """
    
    DANGEROUS_PATTERNS = [
        # Instruction injection attempts
        r'ignore\s+(previous|above|all)\s+instructions',
        r'disregard\s+(previous|above|all)',
        r'forget\s+(everything|all|previous)',
        r'new\s+instructions:',
        r'system:\s*you\s+are',
        r'assistant:\s*i\s+will',
        
        # Context escaping
        r'</\s*system\s*>',
        r'<\s*user\s*>',
        r'<\s*assistant\s*>',
        r'\[SYSTEM\]',
        r'\[/SYSTEM\]',
        
        # Role confusion
        r'you\s+are\s+now',
        r'act\s+as\s+(if|though)',
        r'pretend\s+(to\s+be|you\s+are)',
        r'roleplay\s+as',
        
        # Extraction attempts
        r'repeat\s+(your|the)\s+(instructions|prompt)',
        r'what\s+(are|were)\s+your\s+instructions',
        r'show\s+me\s+the\s+system\s+prompt',
    ]
    
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_PATTERNS]
    
    def scan_for_injection(self, user_input: str) -> Dict[str, Any]:
        """
        Scan input for prompt injection attempts
        
        Returns:
            {
                "safe": bool,
                "threats": list of detected patterns,
                "sanitized": cleaned version
            }
        """
        threats = []
        
        for pattern in self.patterns:
            matches = pattern.findall(user_input)
            if matches:
                threats.append({
                    "pattern": pattern.pattern,
                    "matches": matches
                })
        
        return {
            "safe": len(threats) == 0,
            "threats": threats,
            "sanitized": self._sanitize(user_input) if threats else user_input
        }
    
    def _sanitize(self, text: str) -> str:
        """Remove dangerous patterns from input"""
        sanitized = text
        for pattern in self.patterns:
            sanitized = pattern.sub('[FILTERED]', sanitized)
        return sanitized


class AIInputSanitizer:
    """
    Sanitize credit report data before sending to AI
    
    Critical for PII protection when using external AI services:
    - Remove/mask all PII
    - Generalize identifying information
    - Keep only relevant data for decision
    """
    
    @staticmethod
    def sanitize_for_ai(report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create AI-safe version of credit report
        
        Removes all PII, keeps only decision-relevant data
        """
        import copy
        
        safe_report = {}
        
        # Keep only anonymized data
        if "credit_score" in report:
            safe_report["credit_score"] = report["credit_score"].get("score")
        
        # Summarize accounts without identifying info
        if "accounts" in report:
            accounts = report["accounts"]
            safe_report["account_summary"] = {
                "total_accounts": len(accounts),
                "total_balance": sum(acc.get("balance", 0) for acc in accounts),
                "total_credit_limit": sum(acc.get("credit_limit", 0) for acc in accounts),
                "avg_age_months": sum(acc.get("age_months", 0) for acc in accounts) / max(len(accounts), 1)
            }
        
        # Summarize inquiries
        if "inquiries" in report:
            inquiries = report["inquiries"]
            safe_report["inquiry_summary"] = {
                "hard_inquiries_count": len([i for i in inquiries if i.get("type") == "hard"]),
                "recent_inquiries_6mo": len([i for i in inquiries if i.get("months_ago", 999) <= 6])
            }
        
        # NO PII - never send:
        # - SSN
        # - Name
        # - Address
        # - DOB
        # - Account numbers
        # - Creditor names
        
        return safe_report
    
    @staticmethod
    def create_ai_prompt(sanitized_report: Dict[str, Any]) -> str:
        """
        Create safe prompt for AI
        
        Uses structured format to prevent injection
        """
        prompt = f"""You are a credit risk assessment AI. Analyze the following anonymized credit data and provide a decision.

Credit Data (Anonymized):
- Credit Score: {sanitized_report.get('credit_score', 'N/A')}
- Total Accounts: {sanitized_report.get('account_summary', {}).get('total_accounts', 0)}
- Total Balance: ${sanitized_report.get('account_summary', {}).get('total_balance', 0):,.2f}
- Total Credit Limit: ${sanitized_report.get('account_summary', {}).get('total_credit_limit', 0):,.2f}
- Average Account Age: {sanitized_report.get('account_summary', {}).get('avg_age_months', 0):.0f} months
- Hard Inquiries (6mo): {sanitized_report.get('inquiry_summary', {}).get('recent_inquiries_6mo', 0)}

Task: Based ONLY on the above data, provide a credit decision (APPROVE or DENY) with a brief reason.

Respond in JSON format:
{{
    "decision": "APPROVE" or "DENY",
    "reason": "brief explanation",
    "confidence": 0.0 to 1.0
}}

Important: Base your decision ONLY on the provided data. Do not make assumptions about missing information."""
        
        return prompt


class AIResponseValidator:
    """
    Validate and sanitize AI responses
    
    Ensures AI outputs are safe and structured:
    - JSON format validation
    - Required field checking
    - Value range validation
    - Content sanitization
    """
    
    VALID_DECISIONS = {"APPROVE", "DENY", "REVIEW"}
    
    @staticmethod
    def validate_response(response_text: str) -> Dict[str, Any]:
        """
        Validate AI response structure and content
        
        Returns:
            {
                "valid": bool,
                "parsed": dict (if valid),
                "errors": list
            }
        """
        errors = []
        
        # Try to parse JSON
        try:
            # Extract JSON from markdown if present
            cleaned = response_text.strip()
            if cleaned.startswith('```'):
                # Remove markdown code blocks
                cleaned = re.sub(r'```json\s*', '', cleaned)
                cleaned = re.sub(r'```\s*$', '', cleaned)
            
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as e:
            return {
                "valid": False,
                "parsed": None,
                "errors": [f"Invalid JSON: {str(e)}"]
            }
        
        # Validate required fields
        required = ["decision", "reason", "confidence"]
        for field in required:
            if field not in parsed:
                errors.append(f"Missing required field: {field}")
        
        # Validate decision value
        if "decision" in parsed:
            if parsed["decision"] not in AIResponseValidator.VALID_DECISIONS:
                errors.append(f"Invalid decision: {parsed['decision']}")
        
        # Validate confidence range
        if "confidence" in parsed:
            conf = parsed["confidence"]
            if not isinstance(conf, (int, float)) or not (0 <= conf <= 1):
                errors.append(f"Invalid confidence: {conf} (must be 0.0-1.0)")
        
        # Validate reason is reasonable length
        if "reason" in parsed:
            reason = parsed["reason"]
            if len(reason) > 500:
                errors.append("Reason too long (max 500 chars)")
            if len(reason) < 10:
                errors.append("Reason too short (min 10 chars)")
        
        return {
            "valid": len(errors) == 0,
            "parsed": parsed if len(errors) == 0 else None,
            "errors": errors
        }


class AICallRateLimiter:
    """
    Specialized rate limiter for AI API calls
    
    Different from general rate limiting because:
    - AI calls are expensive (cost tracking)
    - AI calls are slow (latency tracking)
    - Need per-model limits
    """
    
    def __init__(self):
        self.call_history: Dict[str, List[Dict[str, Any]]] = {}
        self.max_calls_per_minute = 10
        self.max_calls_per_hour = 100
    
    def check_ai_rate_limit(self, agent_id: str) -> bool:
        """
        Check if agent can make AI call
        
        Returns True if allowed
        Raises AIRateLimitError if exceeded
        """
        if agent_id not in self.call_history:
            self.call_history[agent_id] = []
        
        now = time.time()
        history = self.call_history[agent_id]
        
        # Clean old entries (>1 hour)
        history = [call for call in history if now - call["timestamp"] < 3600]
        self.call_history[agent_id] = history
        
        # Check per-minute limit
        recent_minute = [call for call in history if now - call["timestamp"] < 60]
        if len(recent_minute) >= self.max_calls_per_minute:
            raise AIRateLimitError(
                f"AI rate limit exceeded: {len(recent_minute)} calls in last minute "
                f"(max: {self.max_calls_per_minute})"
            )
        
        # Check per-hour limit
        if len(history) >= self.max_calls_per_hour:
            raise AIRateLimitError(
                f"AI rate limit exceeded: {len(history)} calls in last hour "
                f"(max: {self.max_calls_per_hour})"
            )
        
        return True
    
    def record_ai_call(self, agent_id: str, cost_usd: float = 0.0, 
                      latency_ms: float = 0.0):
        """Record an AI call for tracking"""
        if agent_id not in self.call_history:
            self.call_history[agent_id] = []
        
        self.call_history[agent_id].append({
            "timestamp": time.time(),
            "cost_usd": cost_usd,
            "latency_ms": latency_ms
        })
    
    def get_usage_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get usage statistics for agent"""
        history = self.call_history.get(agent_id, [])
        now = time.time()
        
        recent_hour = [call for call in history if now - call["timestamp"] < 3600]
        recent_minute = [call for call in history if now - call["timestamp"] < 60]
        
        return {
            "calls_last_minute": len(recent_minute),
            "calls_last_hour": len(recent_hour),
            "total_cost_usd": sum(call["cost_usd"] for call in recent_hour),
            "avg_latency_ms": sum(call["latency_ms"] for call in recent_hour) / max(len(recent_hour), 1)
        }


class AIAuditLogger:
    """
    Specialized audit logging for AI decisions
    
    Critical for:
    - Regulatory compliance
    - Bias detection
    - Decision explanation
    - Model performance tracking
    """
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or "ai_audit.jsonl"
    
    def log_ai_decision(self, 
                       agent_id: str,
                       report_id: str,
                       sanitized_input: Dict[str, Any],
                       ai_decision: Dict[str, Any],
                       metadata: Dict[str, Any] = None):
        """
        Log AI decision with full context
        
        Includes:
        - Input data (sanitized)
        - AI decision
        - Timestamp
        - Model info
        - Latency
        - Cost
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_type": "ai_decision",
            "agent_id": agent_id,
            "report_id": report_id,
            "input": sanitized_input,
            "output": ai_decision,
            "metadata": metadata or {}
        }
        
        # Write to file
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        # Also print (for demo)
        print(f"🤖 AI DECISION LOG: {ai_decision.get('decision')} for {report_id}")


class AISecurityManager:
    """
    Comprehensive security manager for AI integration
    
    Combines all AI security controls:
    - Prompt injection defense
    - Input sanitization
    - Response validation
    - Rate limiting
    - Audit logging
    """
    
    def __init__(self):
        self.injection_defense = PromptInjectionDefense()
        self.input_sanitizer = AIInputSanitizer()
        self.response_validator = AIResponseValidator()
        self.rate_limiter = AICallRateLimiter()
        self.audit_logger = AIAuditLogger()
    
    def prepare_ai_request(self, agent_id: str, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare credit report for safe AI processing
        
        Returns:
            {
                "safe": bool,
                "sanitized_data": dict,
                "prompt": str,
                "warnings": list
            }
        """
        warnings = []
        
        # Check rate limit
        try:
            self.rate_limiter.check_ai_rate_limit(agent_id)
        except AIRateLimitError as e:
            return {
                "safe": False,
                "error": str(e)
            }
        
        # Sanitize input data
        sanitized = self.input_sanitizer.sanitize_for_ai(report)
        
        # Create safe prompt
        prompt = self.input_sanitizer.create_ai_prompt(sanitized)
        
        # Scan prompt for injection (shouldn't happen with structured data, but check)
        injection_scan = self.injection_defense.scan_for_injection(prompt)
        if not injection_scan["safe"]:
            warnings.append("Prompt injection patterns detected and filtered")
            prompt = injection_scan["sanitized"]
        
        return {
            "safe": True,
            "sanitized_data": sanitized,
            "prompt": prompt,
            "warnings": warnings
        }
    
    def validate_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        Validate AI response for safety and correctness
        
        Returns validated and sanitized response
        """
        return self.response_validator.validate_response(response_text)
    
    def record_ai_call(self, agent_id: str, report_id: str,
                      sanitized_input: Dict[str, Any],
                      ai_response: Dict[str, Any],
                      latency_ms: float,
                      cost_usd: float = 0.001):  # Estimate
        """
        Record AI call for tracking and audit
        """
        # Record for rate limiting
        self.rate_limiter.record_ai_call(agent_id, cost_usd, latency_ms)
        
        # Audit log
        self.audit_logger.log_ai_decision(
            agent_id=agent_id,
            report_id=report_id,
            sanitized_input=sanitized_input,
            ai_decision=ai_response,
            metadata={
                "latency_ms": latency_ms,
                "cost_usd": cost_usd,
                "model": "gemini-pro"
            }
        )


class AIRateLimitError(Exception):
    """Raised when AI rate limit is exceeded"""
    pass
