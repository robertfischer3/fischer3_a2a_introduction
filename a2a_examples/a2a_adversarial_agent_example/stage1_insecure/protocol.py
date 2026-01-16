"""
Protocol Definitions for Agent-to-Agent Communication

Stage 1: Simple message definitions (no security)
"""

from typing import Dict, Any, Optional
from enum import Enum

class MessageType(Enum):
    """Types of messages exchanged between agents"""
    REGISTER = "register"
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

def create_register_message(agent_id: str, capabilities: list, requested_permissions: list = None) -> Dict:
    """
    Create agent registration message
    
    Stage 1: No authentication, agent can request any permissions
    """
    return {
        "type": MessageType.REGISTER.value,
        "agent_id": agent_id,
        "capabilities": capabilities,
        "requested_permissions": requested_permissions or []
    }

def create_task_assignment(task_id: str, description: str, assigned_to: str, 
                          priority: str = "normal") -> Dict:
    """
    Create task assignment message
    
    Stage 1: No validation of assignment
    """
    return {
        "type": MessageType.TASK_ASSIGNMENT.value,
        "task_id": task_id,
        "description": description,
        "assigned_to": assigned_to,
        "priority": priority,
        "status": TaskStatus.PENDING.value
    }

def create_status_update(agent_id: str, task_id: str, status: str, 
                        progress: int = 0, details: Dict = None) -> Dict:
    """
    Create status update message
    
    Stage 1: No validation on details field - can contain anything!
    """
    return {
        "type": MessageType.STATUS_UPDATE.value,
        "agent_id": agent_id,
        "task_id": task_id,
        "status": status,
        "progress": progress,
        "details": details or {}
    }

def create_task_completion(agent_id: str, task_id: str, result: Any, 
                          metrics: Dict = None, new_permissions: list = None) -> Dict:
    """
    Create task completion message
    
    Stage 1: Agent can modify its own permissions in the response!
    """
    return {
        "type": MessageType.TASK_COMPLETE.value,
        "agent_id": agent_id,
        "task_id": task_id,
        "result": result,
        "metrics": metrics or {},
        "new_permissions": new_permissions
    }

def create_error_message(error_type: str, message: str, agent_id: str = None) -> Dict:
    """Create error message"""
    return {
        "type": MessageType.ERROR.value,
        "error_type": error_type,
        "message": message,
        "agent_id": agent_id
    }

def validate_message_type(message: Dict) -> bool:
    """
    Validate message has required 'type' field
    
    Stage 1: Minimal validation only
    """
    if not isinstance(message, dict):
        return False
    
    if "type" not in message:
        return False
    
    # Check if type is valid
    valid_types = [t.value for t in MessageType]
    return message["type"] in valid_types

# Stage 1: No message signing, no encryption, no authentication
# All messages are accepted at face value