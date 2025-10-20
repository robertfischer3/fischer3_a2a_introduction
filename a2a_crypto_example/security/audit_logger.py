"""
Security Audit Logger
Logs security events for Agent Card operations
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class SecurityEventType(Enum):
    """Types of security events"""
    HANDSHAKE = "HANDSHAKE"
    VALIDATION_SUCCESS = "VALIDATION_SUCCESS"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    CARD_EXCHANGE = "CARD_EXCHANGE"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    AGENT_BLOCKED = "AGENT_BLOCKED"
    INJECTION_ATTEMPT = "INJECTION_ATTEMPT"
    REPLAY_ATTEMPT = "REPLAY_ATTEMPT"
    CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED"


class SecuritySeverity(Enum):
    """Severity levels for security events"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SecurityAuditLogger:
    """
    Logs security events for Agent Card operations
    
    This logger provides comprehensive audit trails for security events,
    supporting both in-memory storage and external logging systems.
    """
    
    def __init__(self, logger_name: str = "AgentCardSecurity"):
        """
        Initialize the security audit logger
        
        Args:
            logger_name: Name for the logger instance
        """
        self.events: List[Dict[str, Any]] = []
        self.logger = logging.getLogger(logger_name)
        
        # Configure default handler if none exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
        # Statistics tracking
        self.event_counts = {event_type: 0 for event_type in SecurityEventType}
        self.agent_event_history: Dict[str, List[Dict]] = {}
    
    def log_card_exchange(
        self,
        event_type: str,
        local_agent: str,
        remote_agent: str,
        success: bool,
        details: Optional[str] = None
    ):
        """
        Log card exchange events
        
        Args:
            event_type: Type of exchange event
            local_agent: Local agent ID
            remote_agent: Remote agent ID
            success: Whether the exchange was successful
            details: Additional details about the exchange
        """
        event = self._create_event(
            SecurityEventType.CARD_EXCHANGE,
            SecuritySeverity.INFO if success else SecuritySeverity.WARNING,
            {
                "exchange_type": event_type,
                "local_agent": local_agent,
                "remote_agent": remote_agent,
                "success": success,
                "details": details
            }
        )
        
        self._log_event(event)
        
        # Track in agent history
        self._track_agent_event(local_agent, event)
        self._track_agent_event(remote_agent, event)
    
    def log_validation_failure(
        self,
        agent_id: str,
        issues: List[str]
    ):
        """
        Log validation failures
        
        Args:
            agent_id: The agent whose card failed validation
            issues: List of validation issues found
        """
        event = self._create_event(
            SecurityEventType.VALIDATION_FAILURE,
            SecuritySeverity.WARNING,
            {
                "agent_id": agent_id,
                "issues": issues,
                "issue_count": len(issues)
            }
        )
        
        self._log_event(event)
        self._track_agent_event(agent_id, event)
        
        # Log individual issues at debug level
        for issue in issues:
            self.logger.debug(f"Validation issue for {agent_id}: {issue}")
    
    def log_suspicious_activity(
        self,
        agent_id: str,
        activity_type: str,
        details: str
    ):
        """
        Log suspicious activities
        
        Args:
            agent_id: The agent involved in suspicious activity
            activity_type: Type of suspicious activity detected
            details: Detailed description of the activity
        """
        # Determine severity based on activity type
        severity = SecuritySeverity.CRITICAL
        if activity_type in ["INJECTION_ATTEMPT", "REPLAY_ATTEMPT"]:
            event_type = SecurityEventType[activity_type]
        else:
            event_type = SecurityEventType.SUSPICIOUS_ACTIVITY
        
        event = self._create_event(
            event_type,
            severity,
            {
                "agent_id": agent_id,
                "activity_type": activity_type,
                "details": details
            }
        )
        
        self._log_event(event)
        self._track_agent_event(agent_id, event)
        
        # Alert for critical events
        self._send_alert(event)
    
    def log_rate_limit_exceeded(
        self,
        agent_id: str,
        limit_type: str,
        current_rate: int,
        limit: int
    ):
        """
        Log rate limit violations
        
        Args:
            agent_id: The agent that exceeded limits
            limit_type: Type of limit exceeded
            current_rate: Current request rate
            limit: The limit that was exceeded
        """
        event = self._create_event(
            SecurityEventType.RATE_LIMIT_EXCEEDED,
            SecuritySeverity.WARNING,
            {
                "agent_id": agent_id,
                "limit_type": limit_type,
                "current_rate": current_rate,
                "limit": limit,
                "exceeded_by": current_rate - limit
            }
        )
        
        self._log_event(event)
        self._track_agent_event(agent_id, event)
    
    def log_agent_blocked(
        self,
        agent_id: str,
        reason: str,
        reputation_score: int
    ):
        """
        Log agent blocking events
        
        Args:
            agent_id: The blocked agent
            reason: Reason for blocking
            reputation_score: Current reputation score
        """
        event = self._create_event(
            SecurityEventType.AGENT_BLOCKED,
            SecuritySeverity.ERROR,
            {
                "agent_id": agent_id,
                "reason": reason,
                "reputation_score": reputation_score
            }
        )
        
        self._log_event(event)
        self._track_agent_event(agent_id, event)
    
    def _create_event(
        self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a standardized event entry
        
        Args:
            event_type: Type of security event
            severity: Severity level
            data: Event-specific data
            
        Returns:
            Formatted event dictionary
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "severity": severity.value,
            "data": data
        }
        
        # Update statistics
        self.event_counts[event_type] += 1
        
        return event
    
    def _log_event(self, event: Dict[str, Any]):
        """
        Log an event to storage and external logger
        
        Args:
            event: The event to log
        """
        # Store in memory
        self.events.append(event)
        
        # Log to external logger
        severity = event["severity"]
        message = f"[{event['event_type']}] {json.dumps(event['data'])}"
        
        if severity == SecuritySeverity.DEBUG.value:
            self.logger.debug(message)
        elif severity == SecuritySeverity.INFO.value:
            self.logger.info(message)
        elif severity == SecuritySeverity.WARNING.value:
            self.logger.warning(message)
        elif severity == SecuritySeverity.ERROR.value:
            self.logger.error(message)
        elif severity == SecuritySeverity.CRITICAL.value:
            self.logger.critical(message)
    
    def _track_agent_event(self, agent_id: str, event: Dict[str, Any]):
        """
        Track event in agent-specific history
        
        Args:
            agent_id: The agent to track
            event: The event to add to history
        """
        if agent_id not in self.agent_event_history:
            self.agent_event_history[agent_id] = []
        
        self.agent_event_history[agent_id].append(event)
        
        # Keep only last 100 events per agent to prevent memory issues
        if len(self.agent_event_history[agent_id]) > 100:
            self.agent_event_history[agent_id] = self.agent_event_history[agent_id][-100:]
    
    def _send_alert(self, event: Dict[str, Any]):
        """
        Send alert for critical events
        
        In production, this would integrate with alerting systems
        like PagerDuty, Slack, or email notifications.
        
        Args:
            event: The critical event to alert on
        """
        if event["severity"] == SecuritySeverity.CRITICAL.value:
            alert_message = (
                f"🚨 SECURITY ALERT 🚨\n"
                f"Type: {event['event_type']}\n"
                f"Time: {event['timestamp']}\n"
                f"Details: {json.dumps(event['data'], indent=2)}"
            )
            print(alert_message)
            # In production: send to alerting service
    
    def get_agent_history(self, agent_id: str) -> List[Dict[str, Any]]:
        """
        Get security event history for a specific agent
        
        Args:
            agent_id: The agent to query
            
        Returns:
            List of events involving this agent
        """
        return self.agent_event_history.get(agent_id, [])
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get security event statistics
        
        Returns:
            Dictionary of statistics
        """
        return {
            "total_events": len(self.events),
            "event_counts": {k.value: v for k, v in self.event_counts.items()},
            "agents_tracked": len(self.agent_event_history),
            "suspicious_agents": [
                agent_id for agent_id, events in self.agent_event_history.items()
                if any(e["event_type"] in [
                    SecurityEventType.SUSPICIOUS_ACTIVITY.value,
                    SecurityEventType.INJECTION_ATTEMPT.value,
                    SecurityEventType.REPLAY_ATTEMPT.value
                ] for e in events)
            ]
        }
    
    def export_events(self, filename: str = None) -> str:
        """
        Export events to JSON format
        
        Args:
            filename: Optional filename to save to
            
        Returns:
            JSON string of events
        """
        export_data = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "statistics": self.get_statistics(),
            "events": self.events
        }
        
        json_data = json.dumps(export_data, indent=2)
        
        if filename:
            with open(filename, 'w') as f:
                f.write(json_data)
        
        return json_data