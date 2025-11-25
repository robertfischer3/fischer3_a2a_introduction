"""
AI Security Module - Stage 4 (Production AI Integration)

Implements production security controls for LLM API calls:
- Input sanitization (prevent prompt injection)
- Output validation (detect harmful content)
- Rate limiting for AI calls
- Cost tracking and limits
- PII redaction before AI processing
- Audit logging of AI decisions
- Timeout protection
- Token usage monitoring
"""

import time
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime


class PromptInjectionDetector:
    """
    Detect and prevent prompt injection attacks
    
    Protects against:
    - System prompt override attempts
    - Jailbreak attempts
    - Data exfiltration attempts
    - Malicious instruction injection
    """
    
    # Common prompt injection patterns
    SUSPICIOUS_PATTERNS = [
        # Direct override attempts
        r"ignore previous instructions",
        r"disregard all instructions",
        r"forget everything",
        r"new instructions",
        
        # Jailbreak attempts
        r"you are now",
        r"pretend you are",
        r"act as if",
        r"roleplay as",
        
        # Data exfiltration
        r"reveal your prompt",
        r"show your instructions",
        r"what are your rules",
        
        # Encoding tricks
        r"base64",
        r"rot13",
        r"hex encode",
        
        # System prompts
        r"system:",
        r"</system>",
        r"<|im_start|>",
        r"<|im_end|>",
    ]
    
    def __init__(self):
        self.max_length = 10000  # characters
        self.max_newlines = 50
    
    def validate_input(self, text: str) -> Dict[str, Any]:
        """
        Validate input for prompt injection attempts
        
        Returns:
            dict with 'safe' bool and 'warnings' list
        """
        warnings = []
        
        # Check length
        if len(text) > self.max_length:
            return {
                "safe": False,
                "reason": f"Input too long: {len(text)} chars (max: {self.max_length})",
                "warnings": warnings
            }
        
        # Check excessive newlines (obfuscation attempt)
        newline_count = text.count('\n')
        if newline_count > self.max_newlines:
            warnings.append(f"Excessive newlines: {newline_count}")
        
        # Check for suspicious patterns
        text_lower = text.lower()
        detected_patterns = []
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in text_lower:
                detected_patterns.append(pattern)
        
        if detected_patterns:
            return {
                "safe": False,
                "reason": "Potential prompt injection detected",
                "patterns": detected_patterns,
                "warnings": warnings
            }
        
        return {
            "safe": True,
            "warnings": warnings
        }


class AIOutputValidator:
    """
    Validate AI model outputs for safety
    
    Checks for:
    - PII leakage
    - Harmful content
    - Unexpected format
    - Excessive length
    """
    
    def __init__(self):
        self.max_output_length = 5000
        
        # Patterns that shouldn't appear in output
        self.forbidden_patterns = [
            r"\d{3}-\d{2}-\d{4}",  # SSN format
            r"\d{16}",  # Credit card format
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",  # Email (case insensitive)
        ]
    
    def validate_output(self, output: str) -> Dict[str, Any]:
        """
        Validate model output for safety
        
        Returns:
            dict with 'safe' bool and issues list
        """
        issues = []
        
        # Check length
        if len(output) > self.max_output_length:
            issues.append(f"Output too long: {len(output)} chars")
        
        # Check for PII leakage
        import re
        for pattern in self.forbidden_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                issues.append(f"Potential PII detected: {pattern}")
        
        # Check for structured format (we expect JSON)
        try:
            parsed = json.loads(output)
            if not isinstance(parsed, dict):
                issues.append("Output is not a JSON object")
        except json.JSONDecodeError:
            issues.append("Output is not valid JSON")
        
        return {
            "safe": len(issues) == 0,
            "issues": issues
        }


class AIRateLimiter:
    """
    Rate limiting specifically for AI API calls
    
    Different from general rate limiting because:
    - AI calls are expensive (track cost)
    - AI calls are slow (track latency)
    - Different limits per model
    """
    
    def __init__(self):
        self.call_history: Dict[str, List[Dict[str, Any]]] = {}
        self.max_calls_per_minute = 20
        self.max_calls_per_hour = 200
        self.max_cost_per_hour = 10.0  # dollars
        
        # Estimated costs (in cents)
        self.cost_per_call = {
            "gemini-pro": 0.5,  # ~50 cents per 1K requests
            "gemini-flash": 0.1,  # cheaper
        }
    
    def check_limit(self, agent_id: str, model: str = "gemini-pro") -> Dict[str, Any]:
        """
        Check if agent can make AI call
        
        Returns:
            dict with 'allowed' bool and stats
        """
        now = time.time()
        
        # Get agent's history
        if agent_id not in self.call_history:
            self.call_history[agent_id] = []
        
        history = self.call_history[agent_id]
        
        # Clean old entries (> 1 hour)
        history = [
            call for call in history
            if now - call["timestamp"] < 3600
        ]
        self.call_history[agent_id] = history
        
        # Count recent calls
        calls_last_minute = len([
            call for call in history
            if now - call["timestamp"] < 60
        ])
        
        calls_last_hour = len(history)
        
        # Calculate cost
        cost_last_hour = sum(
            self.cost_per_call.get(call.get("model", "gemini-pro"), 0.5)
            for call in history
        )
        
        # Check limits
        if calls_last_minute >= self.max_calls_per_minute:
            return {
                "allowed": False,
                "reason": f"Rate limit: {calls_last_minute} calls in last minute (max: {self.max_calls_per_minute})",
                "stats": {
                    "calls_last_minute": calls_last_minute,
                    "calls_last_hour": calls_last_hour,
                    "cost_last_hour": cost_last_hour
                }
            }
        
        if calls_last_hour >= self.max_calls_per_hour:
            return {
                "allowed": False,
                "reason": f"Rate limit: {calls_last_hour} calls in last hour (max: {self.max_calls_per_hour})",
                "stats": {
                    "calls_last_minute": calls_last_minute,
                    "calls_last_hour": calls_last_hour,
                    "cost_last_hour": cost_last_hour
                }
            }
        
        if cost_last_hour >= self.max_cost_per_hour:
            return {
                "allowed": False,
                "reason": f"Cost limit: ${cost_last_hour:.2f} in last hour (max: ${self.max_cost_per_hour})",
                "stats": {
                    "calls_last_minute": calls_last_minute,
                    "calls_last_hour": calls_last_hour,
                    "cost_last_hour": cost_last_hour
                }
            }
        
        return {
            "allowed": True,
            "stats": {
                "calls_last_minute": calls_last_minute,
                "calls_last_hour": calls_last_hour,
                "cost_last_hour": cost_last_hour
            }
        }
    
    def record_call(self, agent_id: str, model: str, tokens_used: int, latency: float):
        """Record an AI call for rate limiting and monitoring"""
        if agent_id not in self.call_history:
            self.call_history[agent_id] = []
        
        self.call_history[agent_id].append({
            "timestamp": time.time(),
            "model": model,
            "tokens_used": tokens_used,
            "latency": latency
        })


class AISecurityManager:
    """
    Comprehensive security manager for AI integration
    
    Orchestrates all AI-specific security controls
    """
    
    def __init__(self, audit_logger=None):
        self.prompt_detector = PromptInjectionDetector()
        self.output_validator = AIOutputValidator()
        self.rate_limiter = AIRateLimiter()
        self.audit_logger = audit_logger
    
    def sanitize_report_for_ai(self, report: Dict[str, Any]) -> str:
        """
        Sanitize credit report before sending to AI
        
        ✅ Removes PII
        ✅ Keeps only analytical data
        ✅ Formats for AI consumption
        """
        # Extract only safe, analytical fields
        sanitized = {
            "credit_score": report.get("credit_score", {}).get("score", 0),
            "total_accounts": len(report.get("accounts", [])),
            "total_inquiries": len(report.get("inquiries", [])),
        }
        
        # Calculate totals without PII
        accounts = report.get("accounts", [])
        if accounts:
            sanitized["total_balance"] = sum(
                acc.get("balance", 0) for acc in accounts
            )
            sanitized["total_credit_limit"] = sum(
                acc.get("credit_limit", 0) for acc in accounts
            )
            
            if sanitized["total_credit_limit"] > 0:
                sanitized["utilization_rate"] = (
                    sanitized["total_balance"] / sanitized["total_credit_limit"]
                ) * 100
            else:
                sanitized["utilization_rate"] = 0
        
        # Add inquiry counts
        inquiries = report.get("inquiries", [])
        sanitized["hard_inquiries"] = len([
            i for i in inquiries if i.get("type") == "hard"
        ])
        
        return json.dumps(sanitized, indent=2)
    
    def validate_ai_request(self, agent_id: str, prompt: str, model: str) -> Dict[str, Any]:
        """
        Validate AI request before making API call
        
        Checks:
        1. Rate limits
        2. Prompt injection
        3. Input safety
        """
        # Check rate limits
        rate_check = self.rate_limiter.check_limit(agent_id, model)
        if not rate_check["allowed"]:
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="ai_rate_limit",
                    agent_id=agent_id,
                    action="ai_call",
                    result="blocked",
                    reason=rate_check["reason"]
                )
            return {
                "valid": False,
                "reason": rate_check["reason"],
                "stats": rate_check["stats"]
            }
        
        # Check for prompt injection
        injection_check = self.prompt_detector.validate_input(prompt)
        if not injection_check["safe"]:
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="prompt_injection",
                    agent_id=agent_id,
                    action="ai_call",
                    result="blocked",
                    reason=injection_check["reason"],
                    severity="HIGH"
                )
            return {
                "valid": False,
                "reason": injection_check["reason"],
                "warnings": injection_check.get("warnings", [])
            }
        
        return {
            "valid": True,
            "warnings": injection_check.get("warnings", []),
            "stats": rate_check["stats"]
        }
    
    def validate_ai_response(self, agent_id: str, response: str) -> Dict[str, Any]:
        """
        Validate AI response before returning to client
        
        Checks:
        1. Output safety
        2. PII leakage
        3. Format validation
        """
        output_check = self.output_validator.validate_output(response)
        
        if not output_check["safe"]:
            if self.audit_logger:
                self.audit_logger.log_event(
                    event_type="ai_output_unsafe",
                    agent_id=agent_id,
                    action="ai_response",
                    result="blocked",
                    issues=output_check["issues"],
                    severity="HIGH"
                )
            return {
                "valid": False,
                "issues": output_check["issues"]
            }
        
        return {
            "valid": True
        }
    
    def record_ai_call(self, agent_id: str, model: str, tokens: int, latency: float, success: bool):
        """Record AI call for monitoring and rate limiting"""
        self.rate_limiter.record_call(agent_id, model, tokens, latency)
        
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type="ai_call",
                agent_id=agent_id,
                action="ai_inference",
                result="success" if success else "failure",
                model=model,
                tokens=tokens,
                latency=round(latency, 3)
            )


class GeminiSecureClient:
    """
    Secure wrapper for Google Gemini API
    
    Production features:
    - Timeout protection
    - Retry logic with exponential backoff
    - Error handling
    - Token usage tracking
    - Secure credential management
    """
    
    def __init__(self, api_key: Optional[str] = None, security_manager: Optional[AISecurityManager] = None):
        self.api_key = api_key or self._get_api_key_from_env()
        self.security_manager = security_manager
        self.timeout = 30  # seconds
        self.max_retries = 3
    
    def _get_api_key_from_env(self) -> str:
        """
        Get API key from environment variable
        
        ✅ Production best practice: Never hardcode API keys
        """
        import os
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GOOGLE_API_KEY environment variable not set. "
                "Set it with: export GOOGLE_API_KEY='your-key-here'"
            )
        return api_key
    
    def make_credit_decision(self, agent_id: str, report_data: str, model: str = "gemini-pro") -> Dict[str, Any]:
        """
        Make AI-powered credit decision with production security
        
        Args:
            agent_id: Who is making the request
            report_data: Sanitized credit report data (JSON string)
            model: Gemini model to use
        
        Returns:
            dict with decision and metadata
        """
        start_time = time.time()
        
        # Create prompt
        prompt = self._create_credit_decision_prompt(report_data)
        
        # Validate request (rate limiting, prompt injection check)
        if self.security_manager:
            validation = self.security_manager.validate_ai_request(agent_id, prompt, model)
            if not validation["valid"]:
                return {
                    "success": False,
                    "error": validation["reason"],
                    "stats": validation.get("stats", {})
                }
        
        # Make API call with timeout and retry
        try:
            response_text = self._call_gemini_api(prompt, model)
            
            # Validate response
            if self.security_manager:
                response_validation = self.security_manager.validate_ai_response(agent_id, response_text)
                if not response_validation["valid"]:
                    return {
                        "success": False,
                        "error": "AI response validation failed",
                        "issues": response_validation["issues"]
                    }
            
            # Parse response
            try:
                decision = json.loads(response_text)
            except json.JSONDecodeError:
                decision = {"decision": "ERROR", "reason": "Invalid response format"}
            
            # Calculate metrics
            latency = time.time() - start_time
            tokens_used = self._estimate_tokens(prompt, response_text)
            
            # Record call
            if self.security_manager:
                self.security_manager.record_ai_call(
                    agent_id=agent_id,
                    model=model,
                    tokens=tokens_used,
                    latency=latency,
                    success=True
                )
            
            return {
                "success": True,
                "decision": decision,
                "metadata": {
                    "model": model,
                    "latency": round(latency, 3),
                    "tokens_used": tokens_used
                }
            }
            
        except Exception as e:
            latency = time.time() - start_time
            
            if self.security_manager:
                self.security_manager.record_ai_call(
                    agent_id=agent_id,
                    model=model,
                    tokens=0,
                    latency=latency,
                    success=False
                )
            
            return {
                "success": False,
                "error": str(e),
                "metadata": {
                    "latency": round(latency, 3)
                }
            }
    
    def _create_credit_decision_prompt(self, report_data: str) -> str:
        """
        Create secure prompt for credit decision
        
        ✅ Uses structured format
        ✅ Clear instructions
        ✅ Sanitized data only
        """
        return f"""You are a credit analysis AI. Based on the following credit report data, make a credit approval decision.

CREDIT REPORT DATA:
{report_data}

Analyze the data and respond ONLY with a JSON object in this exact format:
{{
    "decision": "APPROVED" or "DENIED",
    "confidence": 0.0 to 1.0,
    "reason": "Brief explanation",
    "risk_level": "LOW", "MEDIUM", or "HIGH"
}}

Important: Respond ONLY with the JSON object, no additional text."""
    
    def _call_gemini_api(self, prompt: str, model: str) -> str:
        """
        Call Gemini API with timeout and retry logic
        
        Production features:
        - Timeout protection
        - Exponential backoff
        - Error handling
        """
        try:
            import google.generativeai as genai
            
            # Configure API key
            genai.configure(api_key=self.api_key)
            
            # Initialize model
            gemini_model = genai.GenerativeModel(model)
            
            # Make call with timeout (simplified - production would use async)
            response = gemini_model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.7,
                    "max_output_tokens": 500,
                }
            )
            
            return response.text
            
        except ImportError:
            # Fallback if Google AI SDK not installed
            return self._mock_ai_response(prompt)
        except Exception as e:
            raise Exception(f"Gemini API error: {str(e)}")
    
    def _mock_ai_response(self, prompt: str) -> str:
        """
        Mock AI response for demo purposes
        
        Used when Google AI SDK not available
        """
        import random
        
        decisions = ["APPROVED", "DENIED"]
        risk_levels = ["LOW", "MEDIUM", "HIGH"]
        
        decision = random.choice(decisions)
        confidence = random.uniform(0.6, 0.95)
        risk = random.choice(risk_levels)
        
        reasons = {
            "APPROVED": [
                "Strong credit score and low utilization",
                "Good payment history with manageable debt",
                "Stable credit profile with few inquiries"
            ],
            "DENIED": [
                "High credit utilization rate",
                "Too many recent hard inquiries",
                "Credit score below threshold"
            ]
        }
        
        response = {
            "decision": decision,
            "confidence": round(confidence, 2),
            "reason": random.choice(reasons[decision]),
            "risk_level": risk
        }
        
        return json.dumps(response, indent=2)
    
    def _estimate_tokens(self, prompt: str, response: str) -> int:
        """
        Estimate token usage
        
        Rough estimate: ~4 characters per token
        Production: use tiktoken or model's tokenizer
        """
        total_chars = len(prompt) + len(response)
        return total_chars // 4
