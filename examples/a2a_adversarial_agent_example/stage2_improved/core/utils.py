"""
Utility Functions

Stage 2: IMPROVED - Added security utilities
"""

import json
import secrets
import hmac
from datetime import datetime
from typing import Dict, Any

def generate_task_id() -> str:
    """Generate cryptographically secure task ID"""
    return f"task-{secrets.token_hex(8)}"

def generate_agent_id(prefix: str = "agent") -> str:
    """Generate cryptographically secure agent ID"""
    return f"{prefix}-{secrets.token_hex(8)}"

def generate_secure_token(nbytes: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(nbytes)

def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks"""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a, b)

def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.utcnow().isoformat()

def serialize_message(message: Dict) -> str:
    """Serialize message to JSON"""
    return json.dumps(message, indent=2)

def deserialize_message(message_str: str) -> Dict:
    """Deserialize message from JSON"""
    try:
        return json.loads(message_str)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

def sanitize_string(s: str, max_length: int = 1000) -> str:
    """Sanitize string for safe display"""
    if not isinstance(s, str):
        return str(s)[:max_length]
    s = s[:max_length]
    s = ''.join(char for char in s if char == '\n' or char == '\t' or not char.iscntrl())
    return s

def format_data_size(size_bytes: int) -> str:
    """Format byte size as human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

def calculate_data_size(data: Any) -> int:
    """Calculate size of data in bytes"""
    return len(json.dumps(data).encode('utf-8'))

def truncate_string(s: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis if too long"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."

# Printing utilities
def print_banner(title: str, width: int = 70):
    """Print a formatted banner"""
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width + "\n")

def print_section(title: str, width: int = 70):
    """Print a section header"""
    print("\n" + "-" * width)
    print(f" {title}")
    print("-" * width)

def print_success(message: str):
    print(f"✅ {message}")

def print_error(message: str):
    print(f"❌ {message}")

def print_warning(message: str):
    print(f"⚠️  {message}")

def print_info(message: str):
    print(f"ℹ️  {message}")

def print_security(message: str):
    print(f"🔐 {message}")

def print_attack(message: str):
    print(f"🔴 {message}")

def print_defense(message: str):
    print(f"🛡️  {message}")

# Security logging utilities
def log_security_event(event_type: str, agent_id: str, details: Dict = None):
    """Log security event"""
    timestamp = get_timestamp()
    print_security(f"[{event_type}] {agent_id}: {json.dumps(details or {})}")

def log_auth_failure(agent_id: str, reason: str):
    log_security_event("AUTH_FAILURE", agent_id, {"reason": reason})

def log_auth_success(agent_id: str):
    log_security_event("AUTH_SUCCESS", agent_id, {})

def log_permission_denied(agent_id: str, action: str, resource: str):
    log_security_event("PERMISSION_DENIED", agent_id, {"action": action, "resource": resource})

def log_suspicious_activity(agent_id: str, activity: str, details: Dict = None):
    log_security_event("SUSPICIOUS_ACTIVITY", agent_id, {"activity": activity, **(details or {})})