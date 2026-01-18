"""
Utility Functions

Stage 1: Basic helpers with no security considerations
"""

import json
import uuid
from datetime import datetime
from typing import Dict, Any

def generate_task_id() -> str:
    """
    Generate unique task ID
    
    Stage 1: Simple counter-based IDs (predictable)
    """
    return f"task-{uuid.uuid4().hex[:8]}"

def generate_agent_id(prefix: str = "agent") -> str:
    """
    Generate agent ID
    
    Stage 1: Simple format (predictable)
    """
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.utcnow().isoformat()

def serialize_message(message: Dict) -> str:
    """
    Serialize message to JSON
    
    Stage 1: No encryption, no signing
    """
    return json.dumps(message, indent=2)

def deserialize_message(message_str: str) -> Dict:
    """
    Deserialize message from JSON
    
    Stage 1: No validation, trusts input
    """
    try:
        return json.loads(message_str)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

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

def print_banner(title: str, width: int = 70):
    """Print a formatted banner"""
    print()
    print("=" * width)
    print(f" {title}")
    print("=" * width)
    print()

def print_section(title: str, width: int = 70):
    """Print a section header"""
    print()
    print("-" * width)
    print(f" {title}")
    print("-" * width)

def print_success(message: str):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message: str):
    """Print error message"""
    print(f"❌ {message}")

def print_warning(message: str):
    """Print warning message"""
    print(f"⚠️  {message}")

def print_info(message: str):
    """Print info message"""
    print(f"ℹ️  {message}")

def print_attack(message: str):
    """Print attack message"""
    print(f"🔴 {message}")

def truncate_string(s: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis if too long"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."

# Stage 1: No security utilities
# No hashing, no encryption, no signing
# Everything is plaintext and trusted