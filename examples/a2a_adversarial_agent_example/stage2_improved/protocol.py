"""
Protocol Definitions for Agent-to-Agent Communication

Stage 2: IMPROVED - Messages include authentication
"""

from typing import Dict, Any, Optional
from enum import Enum
from datetime import datetime

class MessageType(Enum):
    """Types of messages exchanged between agents"""
    REGISTER = "register"
    LOGIN = "login"
    TASK_ASSIGNMENT = "task_assignment"
    STATUS_UPDATE = "status_update"
    TASK_COMPLETE = "task_complete"
    ERROR = "error"

class TaskStatus(Enum):
    """Task status values"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

def create_register_message(agent_id: str, password: str, requested_role: str = "worker") -> Dict:
    """Create agent registration message"""
    return {
        "type": MessageType.REGISTER.value,
        "agent_id": agent_id,
        "password": password,
        "requested_role": requested_role,
        "timestamp": datetime.utcnow().isoformat()
    }

def create_login_message(agent_id: str, password: str) -> Dict:
    """Create login message"""
    return {
        "type": MessageType.LOGIN.value,
        "agent_id": agent_id,
        "password": password,
        "timestamp": datetime.utcnow().isoformat()
    }

def create_status_update(agent_id: str, task_id: str, status: str,
                        auth_token: str, progress: int = 0, details: Dict = None) -> Dict:
    """Create status update message"""
    return {
        "type": MessageType.STATUS_UPDATE.value,
        "agent_id": agent_id,
        "task_id": task_id,
        "status": status,
        "progress": progress,
        "details": details or {},
        "auth_token": auth_token,
        "timestamp": datetime.utcnow().isoformat()
    }

def create_task_completion(agent_id: str, task_id: str, result: Any,
                          auth_token: str, metrics: Dict = None) -> Dict:
    """Create task completion message"""
    return {
        "type": MessageType.TASK_COMPLETE.value,
        "agent_id": agent_id,
        "task_id": task_id,
        "result": result,
        "metrics": metrics or {},
        "auth_token": auth_token,
        "completed_at": datetime.utcnow().isoformat()
    }

def validate_message_type(message: Dict) -> bool:
    """Validate message has required 'type' field"""
    if not isinstance(message, dict):
        return False
    if "type" not in message:
        return False
    valid_types = [t.value for t in MessageType]
    return message["type"] in valid_types