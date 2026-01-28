"""
Security Module - Stage 3

Provides comprehensive security controls:
- Deep recursive validation (deep_validator.py)
- Role verification workflow (role_verifier.py)
- Behavioral analysis (behavior_monitor.py)
- Enhanced permission management (permission_manager.py)
"""

from .deep_validator import DeepValidator, DeepValidationError
from .role_verifier import RoleVerifier, RoleRequestStatus, RoleLevel, ROLE_HIERARCHY
from .behavior_monitor import BehaviorMonitor, RiskLevel, AgentBehavior, ActionType, BehaviorBaseline
from .permission_manager import (
    EnhancedPermissionManager, 
    Permission, 
    PermissionGrant,
    ROLE_PERMISSIONS
)

__all__ = [
    # Deep Validator
    'DeepValidator',
    'DeepValidationError',
    
    # Role Verifier
    'RoleVerifier',
    'RoleRequestStatus',
    'RoleLevel',
    'ROLE_HIERARCHY',
    
    # Behavior Monitor
    'BehaviorMonitor',
    'RiskLevel',
    'AgentBehavior',
    'ActionType',
    'BehaviorBaseline',
    
    # Permission Manager
    'EnhancedPermissionManager',
    'Permission',
    'PermissionGrant',
    'ROLE_PERMISSIONS',
]

__version__ = '3.0.0'