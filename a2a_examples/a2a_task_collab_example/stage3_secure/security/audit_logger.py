"""
Audit Logger - Stage 3: Production Security

Pluggable audit logging interface with multiple implementations.

✅ Stage 3: Comprehensive audit logging
❌ Stage 2: Basic in-memory logging only

Architecture:
- Abstract AuditLogger interface
- Multiple logger implementations
- Easy to add new backends (file, database, cloud, SIEM)
- Composable loggers (multi-destination)

Usage:
    # Use file logger
    logger = FileAuditLogger("logs/audit.log")
    
    # Or use database logger
    logger = DatabaseAuditLogger(connection_string)
    
    # Or log to multiple destinations
    logger = CompositeAuditLogger([
        FileAuditLogger("logs/audit.log"),
        SyslogAuditLogger("syslog.example.com"),
        SIEMAuditLogger(api_key="...")
    ])
    
    # Log security event
    logger.log_event(
        event_type="login_success",
        user_id="alice",
        details={"ip": "192.168.1.100"}
    )
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import json


class EventSeverity(Enum):
    """Event severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(Enum):
    """Event categories for filtering"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SESSION = "session"
    DATA_ACCESS = "data_access"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    SYSTEM = "system"


class AuditEvent:
    """
    Structured audit event
    
    Attributes:
        timestamp: ISO 8601 timestamp
        event_type: Type of event (login_success, permission_denied, etc.)
        category: Event category
        severity: Event severity level
        user_id: User identifier (if applicable)
        session_id: Session identifier (if applicable)
        ip_address: Client IP address
        details: Additional event details
        metadata: System metadata (hostname, service, etc.)
    """
    
    def __init__(
        self,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity = EventSeverity.INFO,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ):
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.event_type = event_type
        self.category = category.value
        self.severity = severity.value
        self.user_id = user_id
        self.session_id = session_id
        self.ip_address = ip_address
        self.details = details or {}
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "details": self.details,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())


class AuditLogger(ABC):
    """
    Abstract base class for audit loggers
    
    This interface allows plugging in different logging backends:
    - FileAuditLogger: Write to local files
    - DatabaseAuditLogger: Write to database
    - SyslogAuditLogger: Send to syslog server
    - SIEMAuditLogger: Send to SIEM (Splunk, ELK, etc.)
    - CloudAuditLogger: Send to cloud service (AWS CloudTrail, GCP, Azure)
    - CompositeAuditLogger: Log to multiple destinations
    
    Implementations must provide:
    - log_event(): Log an audit event
    - query_events(): Query logged events
    - get_logger_name(): Return logger identifier
    - flush(): Ensure all events are persisted
    """
    
    @abstractmethod
    def log_event(
        self,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity = EventSeverity.INFO,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Log an audit event
        
        Args:
            event_type: Type of event (e.g., "login_success")
            category: Event category
            severity: Event severity level
            user_id: User identifier
            session_id: Session identifier
            ip_address: Client IP address
            details: Additional event details
            metadata: System metadata
        
        Returns:
            True if event was logged successfully
        
        Example:
            logger.log_event(
                event_type="login_success",
                category=EventCategory.AUTHENTICATION,
                severity=EventSeverity.INFO,
                user_id="alice",
                ip_address="192.168.1.100",
                details={"method": "password"}
            )
        """
        pass
    
    @abstractmethod
    def query_events(
        self,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """
        Query audit events
        
        Args:
            event_type: Filter by event type
            category: Filter by category
            user_id: Filter by user
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of events to return
        
        Returns:
            List of audit events
        
        Example:
            events = logger.query_events(
                event_type="login_failure",
                user_id="alice",
                limit=50
            )
        """
        pass
    
    @abstractmethod
    def get_logger_name(self) -> str:
        """
        Get logger name/identifier
        
        Returns:
            String identifier for this logger
        """
        pass
    
    @abstractmethod
    def flush(self) -> bool:
        """
        Flush any buffered events
        
        Ensures all events are persisted to storage.
        
        Returns:
            True if flush successful
        """
        pass
    
    def log_authentication(
        self,
        event_type: str,
        user_id: str,
        success: bool,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> bool:
        """
        Convenience method for authentication events
        
        Example:
            logger.log_authentication(
                event_type="login",
                user_id="alice",
                success=True,
                ip_address="192.168.1.100"
            )
        """
        severity = EventSeverity.INFO if success else EventSeverity.WARNING
        
        return self.log_event(
            event_type=event_type,
            category=EventCategory.AUTHENTICATION,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            details=details or {}
        )
    
    def log_authorization(
        self,
        event_type: str,
        user_id: str,
        resource: str,
        action: str,
        allowed: bool,
        details: Optional[Dict] = None
    ) -> bool:
        """
        Convenience method for authorization events
        
        Example:
            logger.log_authorization(
                event_type="access_check",
                user_id="alice",
                resource="project:123",
                action="update",
                allowed=False
            )
        """
        severity = EventSeverity.INFO if allowed else EventSeverity.WARNING
        
        event_details = {
            "resource": resource,
            "action": action,
            "allowed": allowed,
            **(details or {})
        }
        
        return self.log_event(
            event_type=event_type,
            category=EventCategory.AUTHORIZATION,
            severity=severity,
            user_id=user_id,
            details=event_details
        )
    
    def log_security_event(
        self,
        event_type: str,
        severity: EventSeverity,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> bool:
        """
        Convenience method for security events
        
        Example:
            logger.log_security_event(
                event_type="replay_attack_detected",
                severity=EventSeverity.CRITICAL,
                ip_address="10.0.0.1",
                details={"nonce": "abc123"}
            )
        """
        return self.log_event(
            event_type=event_type,
            category=EventCategory.SECURITY,
            severity=severity,
            user_id=user_id,
            ip_address=ip_address,
            details=details or {}
        )


class CompositeAuditLogger(AuditLogger):
    """
    Composite logger that logs to multiple destinations
    
    Logs events to all configured loggers. Useful for:
    - Logging to both file and SIEM
    - Redundant logging
    - Multi-destination compliance requirements
    
    Usage:
        logger = CompositeAuditLogger([
            FileAuditLogger("logs/audit.log"),
            SyslogAuditLogger("syslog.example.com"),
            DatabaseAuditLogger(connection_string)
        ])
        
        # Event logged to all three destinations
        logger.log_event(...)
    """
    
    def __init__(self, loggers: List[AuditLogger]):
        """
        Initialize composite logger
        
        Args:
            loggers: List of loggers to use
        """
        self.loggers = loggers
        print(f"✅ CompositeAuditLogger initialized with {len(loggers)} loggers")
        for logger in loggers:
            print(f"   - {logger.get_logger_name()}")
    
    def log_event(
        self,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity = EventSeverity.INFO,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Log to all loggers
        
        Returns True if at least one logger succeeded
        """
        results = []
        
        for logger in self.loggers:
            try:
                result = logger.log_event(
                    event_type=event_type,
                    category=category,
                    severity=severity,
                    user_id=user_id,
                    session_id=session_id,
                    ip_address=ip_address,
                    details=details,
                    metadata=metadata
                )
                results.append(result)
            except Exception as e:
                print(f"⚠️  Logger {logger.get_logger_name()} failed: {e}")
                results.append(False)
        
        # Succeed if at least one logger succeeded
        return any(results)
    
    def query_events(
        self,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """
        Query from first logger that supports querying
        """
        for logger in self.loggers:
            try:
                events = logger.query_events(
                    event_type=event_type,
                    category=category,
                    user_id=user_id,
                    start_time=start_time,
                    end_time=end_time,
                    limit=limit
                )
                return events
            except NotImplementedError:
                continue
            except Exception as e:
                print(f"⚠️  Query failed on {logger.get_logger_name()}: {e}")
                continue
        
        return []
    
    def get_logger_name(self) -> str:
        """Get composite logger name"""
        names = [logger.get_logger_name() for logger in self.loggers]
        return f"Composite[{', '.join(names)}]"
    
    def flush(self) -> bool:
        """Flush all loggers"""
        results = []
        
        for logger in self.loggers:
            try:
                result = logger.flush()
                results.append(result)
            except Exception as e:
                print(f"⚠️  Flush failed on {logger.get_logger_name()}: {e}")
                results.append(False)
        
        return all(results)
    
    def add_logger(self, logger: AuditLogger):
        """Add a logger to the composite"""
        self.loggers.append(logger)
        print(f"✅ Added logger: {logger.get_logger_name()}")
    
    def remove_logger(self, logger_name: str) -> bool:
        """Remove a logger by name"""
        for i, logger in enumerate(self.loggers):
            if logger.get_logger_name() == logger_name:
                del self.loggers[i]
                print(f"✅ Removed logger: {logger_name}")
                return True
        return False


class InMemoryAuditLogger(AuditLogger):
    """
    In-memory audit logger
    
    Stores events in memory. Useful for:
    - Testing
    - Development
    - Small deployments
    
    Warning: Events lost on restart!
    
    Usage:
        logger = InMemoryAuditLogger(max_events=10000)
        logger.log_event(...)
    """
    
    def __init__(self, max_events: int = 10000):
        """
        Initialize in-memory logger
        
        Args:
            max_events: Maximum events to keep in memory
        """
        self.events: List[AuditEvent] = []
        self.max_events = max_events
        print(f"✅ InMemoryAuditLogger initialized")
        print(f"   Max events: {max_events}")
        print(f"   ⚠️  Events will be lost on restart!")
    
    def log_event(
        self,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity = EventSeverity.INFO,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """Log event to memory"""
        event = AuditEvent(
            event_type=event_type,
            category=category,
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            details=details,
            metadata=metadata
        )
        
        self.events.append(event)
        
        # Trim if exceeds max
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
        
        return True
    
    def query_events(
        self,
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        """Query events from memory"""
        filtered = self.events
        
        # Filter by event type
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        
        # Filter by category
        if category:
            filtered = [e for e in filtered if e.category == category.value]
        
        # Filter by user
        if user_id:
            filtered = [e for e in filtered if e.user_id == user_id]
        
        # Filter by time range
        if start_time:
            filtered = [
                e for e in filtered
                if datetime.fromisoformat(e.timestamp.rstrip('Z')) >= start_time
            ]
        
        if end_time:
            filtered = [
                e for e in filtered
                if datetime.fromisoformat(e.timestamp.rstrip('Z')) <= end_time
            ]
        
        # Return last N events
        return filtered[-limit:]
    
    def get_logger_name(self) -> str:
        """Get logger name"""
        return "InMemoryAuditLogger"
    
    def flush(self) -> bool:
        """No-op for in-memory"""
        return True
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        return {
            "total_events": len(self.events),
            "max_events": self.max_events,
            "categories": self._count_by_category(),
            "severities": self._count_by_severity()
        }
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count events by category"""
        counts = {}
        for event in self.events:
            counts[event.category] = counts.get(event.category, 0) + 1
        return counts
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count events by severity"""
        counts = {}
        for event in self.events:
            counts[event.severity] = counts.get(event.severity, 0) + 1
        return counts


if __name__ == "__main__":
    """Test the audit logger interface"""
    print("=" * 70)
    print("Audit Logger Interface Test")
    print("=" * 70)
    
    # Create in-memory logger for testing
    logger = InMemoryAuditLogger(max_events=1000)
    
    print("\n--- Test 1: Log Authentication Event ---")
    logger.log_authentication(
        event_type="login_success",
        user_id="alice",
        success=True,
        ip_address="192.168.1.100",
        details={"method": "password"}
    )
    print("✅ Authentication event logged")
    
    print("\n--- Test 2: Log Failed Authentication ---")
    logger.log_authentication(
        event_type="login_failure",
        user_id="bob",
        success=False,
        ip_address="10.0.0.1",
        details={"reason": "invalid_password"}
    )
    print("✅ Failed authentication logged")
    
    print("\n--- Test 3: Log Authorization Event ---")
    logger.log_authorization(
        event_type="access_check",
        user_id="alice",
        resource="project:123",
        action="delete",
        allowed=False,
        details={"reason": "not_owner"}
    )
    print("✅ Authorization event logged")
    
    print("\n--- Test 4: Log Security Event ---")
    logger.log_security_event(
        event_type="replay_attack_detected",
        severity=EventSeverity.CRITICAL,
        ip_address="192.168.1.200",
        details={"nonce": "abc123", "timestamp": "2025-12-29T10:00:00Z"}
    )
    print("✅ Security event logged")
    
    print("\n--- Test 5: Query Events ---")
    all_events = logger.query_events(limit=10)
    print(f"Total events: {len(all_events)}")
    
    auth_events = logger.query_events(
        category=EventCategory.AUTHENTICATION,
        limit=10
    )
    print(f"Authentication events: {len(auth_events)}")
    
    alice_events = logger.query_events(
        user_id="alice",
        limit=10
    )
    print(f"Alice's events: {len(alice_events)}")
    
    print("\n--- Test 6: Event Structure ---")
    if all_events:
        event = all_events[0]
        print(f"Event type: {event.event_type}")
        print(f"Category: {event.category}")
        print(f"Severity: {event.severity}")
        print(f"User ID: {event.user_id}")
        print(f"Timestamp: {event.timestamp}")
        print(f"Details: {event.details}")
    
    print("\n--- Test 7: Statistics ---")
    stats = logger.get_stats()
    print(f"Total events: {stats['total_events']}")
    print(f"By category: {stats['categories']}")
    print(f"By severity: {stats['severities']}")
    
    print("\n--- Test 8: Composite Logger ---")
    logger2 = InMemoryAuditLogger(max_events=500)
    
    composite = CompositeAuditLogger([
        logger,
        logger2
    ])
    
    composite.log_authentication(
        event_type="login",
        user_id="charlie",
        success=True,
        ip_address="192.168.1.150"
    )
    
    print(f"Logger 1 events: {len(logger.events)}")
    print(f"Logger 2 events: {len(logger2.events)}")
    print("✅ Event logged to both destinations")
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ Audit logger interface is ready for plugins")
    print("   - Abstract interface defined")
    print("   - InMemoryAuditLogger implemented")
    print("   - CompositeAuditLogger for multiple destinations")
    print("   - Ready to plug in file, database, SIEM, cloud loggers")