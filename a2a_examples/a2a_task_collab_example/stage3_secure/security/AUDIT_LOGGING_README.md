# Audit Logging Framework

**Stage 3: Production Security**

Comprehensive audit logging with pluggable backends for compliance and security monitoring.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Built-in Loggers](#built-in-loggers)
- [Plugin System](#plugin-system)
- [Event Structure](#event-structure)
- [Categories & Severity](#categories--severity)
- [Usage Examples](#usage-examples)
- [Cloud Integration](#cloud-integration)
- [Querying Logs](#querying-logs)
- [Production Deployment](#production-deployment)
- [Compliance](#compliance)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)

---

## 🎯 Overview

The Audit Logging Framework provides:

✅ **Pluggable Architecture** - Easy to swap backends (file, database, cloud, SIEM)  
✅ **Structured Events** - Consistent event format with categories and severity  
✅ **Multi-Destination** - Log to multiple backends simultaneously  
✅ **Cloud-Ready** - Production integration with Google Cloud Logging  
✅ **Queryable** - Search and filter logs programmatically  
✅ **Compliance** - Meet audit requirements (SOC 2, HIPAA, PCI-DSS)  

### Why Pluggable?

Different environments need different logging solutions:
- **Development**: In-memory or file logging
- **Production**: Cloud logging (GCP, AWS, Azure)
- **Enterprise**: SIEM integration (Splunk, ELK)
- **Compliance**: Multiple destinations for redundancy

---

## 🏗️ Architecture

### Core Components

```
audit_logger.py
├── AuditLogger (ABC)          # Abstract base class
├── AuditEvent                 # Structured event class
├── EventCategory (Enum)       # Event categories
├── EventSeverity (Enum)       # Severity levels
├── CompositeAuditLogger       # Multi-destination logging
└── InMemoryAuditLogger        # Built-in for testing

audit_logger_plugins.py
├── FileAuditLogger            # JSON Lines format
├── CSVAuditLogger             # CSV format
├── GoogleCloudAuditLogger     # Google Cloud Logging
└── SyslogAuditLogger          # Syslog (RFC 5424)
```

### Data Flow

```
Application Event
    ↓
AuditLogger.log_event()
    ↓
CompositeAuditLogger (optional)
    ├→ FileAuditLogger (JSON)
    ├→ CSVAuditLogger (CSV)
    ├→ GoogleCloudAuditLogger (Cloud)
    └→ Custom Logger (SIEM, DB, etc.)
    ↓
Structured AuditEvent
    ├─ timestamp
    ├─ event_type
    ├─ category
    ├─ severity
    ├─ user_id
    ├─ session_id
    ├─ ip_address
    ├─ details
    └─ metadata
```

---

## 🚀 Quick Start

### Basic File Logging

```python
from security.audit_logger_plugins import FileAuditLogger

# Initialize logger
logger = FileAuditLogger(
    filepath="logs/audit.log",
    max_size_mb=100,
    backup_count=5
)

# Log authentication event
logger.log_authentication(
    event_type="login_success",
    user_id="alice",
    success=True,
    ip_address="192.168.1.100",
    details={"method": "password"}
)

# Log security event
logger.log_security_event(
    event_type="rate_limit_exceeded",
    severity=EventSeverity.WARNING,
    user_id="bob",
    ip_address="10.0.0.1"
)
```

### Multi-Destination Logging

```python
from security.audit_logger import CompositeAuditLogger
from security.audit_logger_plugins import (
    FileAuditLogger,
    CSVAuditLogger,
    GoogleCloudAuditLogger
)

# Log to multiple destinations
logger = CompositeAuditLogger([
    FileAuditLogger("logs/audit.log"),
    CSVAuditLogger("logs/audit.csv"),
    GoogleCloudAuditLogger(
        project_id="my-project",
        log_name="audit",
        enabled=True
    )
])

# Single call logs everywhere
logger.log_event(
    event_type="project_created",
    category=EventCategory.DATA_ACCESS,
    user_id="alice",
    details={"project_id": "proj-123"}
)
```

---

## 📦 Built-in Loggers

### 1. InMemoryAuditLogger

**Purpose**: Testing and development  
**Status**: ✅ Built-in

```python
from security.audit_logger import InMemoryAuditLogger

logger = InMemoryAuditLogger(max_events=10000)

# Query events
events = logger.query_events(
    user_id="alice",
    limit=50
)

# Get statistics
stats = logger.get_stats()
# Returns: total_events, by_category, by_severity
```

**Pros**:
- Fast (in-memory)
- Queryable
- No file I/O

**Cons**:
- Lost on restart
- Limited capacity
- Not for production

---

### 2. FileAuditLogger

**Purpose**: Local file logging (JSON Lines)  
**Status**: ✅ Production-ready

```python
from security.audit_logger_plugins import FileAuditLogger

logger = FileAuditLogger(
    filepath="logs/audit.log",
    max_size_mb=100,      # Rotate at 100 MB
    backup_count=5,       # Keep 5 backups
    buffer_size=10        # Buffer 10 events
)
```

**Features**:
- JSON Lines format (one JSON per line)
- Automatic file rotation
- Thread-safe writes
- Buffered writes with auto-flush
- Queryable

**File Structure**:
```
logs/
├── audit.log         # Current log
├── audit.log.1       # Previous
├── audit.log.2       # Older
├── audit.log.3
├── audit.log.4
└── audit.log.5       # Oldest
```

**Log Format**:
```json
{"timestamp": "2025-12-29T12:00:00Z", "event_type": "login_success", "category": "authentication", ...}
{"timestamp": "2025-12-29T12:01:00Z", "event_type": "project_created", "category": "data_access", ...}
```

---

### 3. CSVAuditLogger

**Purpose**: Spreadsheet-compatible logging  
**Status**: ✅ Production-ready

```python
from security.audit_logger_plugins import CSVAuditLogger

logger = CSVAuditLogger("logs/audit.csv")
```

**Features**:
- CSV format (Excel-compatible)
- Automatic header
- Thread-safe writes
- Easy analysis in Excel/tools

**CSV Format**:
```csv
timestamp,event_type,category,severity,user_id,session_id,ip_address,details
2025-12-29T12:00:00Z,login_success,authentication,info,alice,e3b0c442...,192.168.1.100,"{""method"":""password""}"
```

**Use Cases**:
- Quick analysis in Excel
- Data science workflows
- Simple compliance reports

---

### 4. GoogleCloudAuditLogger

**Purpose**: Cloud-based logging with GCP  
**Status**: ✅ Production-ready

```python
from security.audit_logger_plugins import GoogleCloudAuditLogger

logger = GoogleCloudAuditLogger(
    project_id="my-project",
    log_name="task-collaboration-audit",
    enabled=True
)
```

**Features**:
- Structured logging with labels
- Real-time streaming
- Advanced querying
- Log-based metrics & alerts
- BigQuery export
- Cloud Console integration

**Setup**:
```bash
# Install SDK
pip install google-cloud-logging

# Authenticate
gcloud auth application-default login
```

See [Cloud Integration](#cloud-integration) for details.

---

### 5. SyslogAuditLogger

**Purpose**: Syslog server integration  
**Status**: 📝 Template

```python
from security.audit_logger_plugins import SyslogAuditLogger

logger = SyslogAuditLogger(
    host="syslog.example.com",
    port=514,
    protocol="udp",
    enabled=True
)
```

**Use Cases**:
- Legacy systems
- SIEM integration
- Centralized syslog servers

---

## 🔌 Plugin System

### Creating Custom Loggers

Implement the `AuditLogger` interface:

```python
from security.audit_logger import AuditLogger, AuditEvent
from typing import List, Optional

class DatabaseAuditLogger(AuditLogger):
    """Log to database"""
    
    def __init__(self, connection_string: str):
        self.connection = connect(connection_string)
    
    def log_event(
        self,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
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
        
        # Insert into database
        self.connection.execute(
            "INSERT INTO audit_logs VALUES (...)",
            event.to_dict()
        )
        
        return True
    
    def query_events(self, *args, **kwargs) -> List[AuditEvent]:
        # Query database
        pass
    
    def get_logger_name(self) -> str:
        return "DatabaseAuditLogger"
    
    def flush(self) -> bool:
        self.connection.commit()
        return True
```

### Using Custom Loggers

```python
# Use standalone
db_logger = DatabaseAuditLogger("postgresql://...")

# Or in composite
logger = CompositeAuditLogger([
    FileAuditLogger("logs/audit.log"),
    DatabaseAuditLogger("postgresql://..."),
    GoogleCloudAuditLogger(project_id="my-project")
])
```

---

## 📊 Event Structure

### AuditEvent

```python
{
    "timestamp": "2025-12-29T12:00:00Z",      # ISO 8601 UTC
    "event_type": "login_success",             # Event identifier
    "category": "authentication",              # Event category
    "severity": "info",                        # Severity level
    "user_id": "alice",                        # User identifier
    "session_id": "e3b0c442...",              # Session ID
    "ip_address": "192.168.1.100",            # Client IP
    "details": {                               # Event-specific data
        "method": "password+mfa",
        "user_agent": "Mozilla/5.0..."
    },
    "metadata": {                              # System metadata
        "service": "coordinator",
        "version": "3.0.0",
        "hostname": "server-01"
    }
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string | ✅ | ISO 8601 UTC timestamp |
| `event_type` | string | ✅ | Event identifier (e.g., "login_success") |
| `category` | string | ✅ | EventCategory value |
| `severity` | string | ✅ | EventSeverity value |
| `user_id` | string | Optional | User who triggered event |
| `session_id` | string | Optional | Session identifier |
| `ip_address` | string | Optional | Client IP address |
| `details` | object | Optional | Event-specific details |
| `metadata` | object | Optional | System metadata |

---

## 🏷️ Categories & Severity

### EventCategory

```python
from security.audit_logger import EventCategory

EventCategory.AUTHENTICATION   # Login, logout, auth failures
EventCategory.AUTHORIZATION    # Permission checks, access denied
EventCategory.SESSION          # Session creation, expiration
EventCategory.DATA_ACCESS      # Data read/write operations
EventCategory.CONFIGURATION    # Config changes, admin actions
EventCategory.SECURITY         # Security events (replay, injection)
EventCategory.SYSTEM           # System events
```

### EventSeverity

```python
from security.audit_logger import EventSeverity

EventSeverity.DEBUG      # Detailed debugging info
EventSeverity.INFO       # Normal operations
EventSeverity.WARNING    # Potential issues
EventSeverity.ERROR      # Errors occurred
EventSeverity.CRITICAL   # Critical security events
```

### Severity Guidelines

| Level | Use For | Examples |
|-------|---------|----------|
| **DEBUG** | Detailed traces | Function calls, state changes |
| **INFO** | Normal operations | Successful logins, project created |
| **WARNING** | Potential issues | Failed login, rate limit exceeded |
| **ERROR** | Errors | Database error, API failure |
| **CRITICAL** | Security incidents | Replay attack, SQL injection detected |

---

## 💡 Usage Examples

### Authentication Events

```python
# Successful login
logger.log_authentication(
    event_type="login_success",
    user_id="alice",
    success=True,
    ip_address="192.168.1.100",
    details={
        "method": "password+mfa",
        "mfa_method": "totp"
    }
)

# Failed login
logger.log_authentication(
    event_type="login_failure",
    user_id="bob",
    success=False,
    ip_address="10.0.0.1",
    details={
        "reason": "invalid_password",
        "attempt_count": 3
    }
)

# Logout
logger.log_authentication(
    event_type="logout",
    user_id="alice",
    success=True,
    ip_address="192.168.1.100"
)
```

### Authorization Events

```python
# Access denied
logger.log_authorization(
    event_type="access_denied",
    user_id="bob",
    resource="project:123",
    action="delete",
    allowed=False,
    details={
        "reason": "not_owner",
        "required_role": "admin"
    }
)

# Access granted
logger.log_authorization(
    event_type="access_granted",
    user_id="alice",
    resource="project:123",
    action="update",
    allowed=True
)
```

### Security Events

```python
# Replay attack detected
logger.log_security_event(
    event_type="replay_attack_detected",
    severity=EventSeverity.CRITICAL,
    ip_address="192.168.1.200",
    details={
        "nonce": "abc123",
        "timestamp": "2025-12-29T10:00:00Z",
        "action": "blocked"
    }
)

# Rate limit exceeded
logger.log_security_event(
    event_type="rate_limit_exceeded",
    severity=EventSeverity.WARNING,
    user_id="charlie",
    ip_address="10.0.0.2",
    details={
        "endpoint": "login",
        "requests": 50,
        "limit": 5
    }
)

# SQL injection attempt
logger.log_security_event(
    event_type="sql_injection_detected",
    severity=EventSeverity.CRITICAL,
    user_id="mallory",
    ip_address="203.0.113.1",
    details={
        "input": "'; DROP TABLE users; --",
        "field": "username",
        "action": "blocked"
    }
)
```

### Custom Events

```python
# Project created
logger.log_event(
    event_type="project_created",
    category=EventCategory.DATA_ACCESS,
    severity=EventSeverity.INFO,
    user_id="alice",
    details={
        "project_id": "proj-123",
        "project_name": "My Project",
        "visibility": "private"
    }
)

# Configuration changed
logger.log_event(
    event_type="config_changed",
    category=EventCategory.CONFIGURATION,
    severity=EventSeverity.WARNING,
    user_id="admin",
    details={
        "setting": "max_file_size",
        "old_value": "10MB",
        "new_value": "100MB"
    }
)
```

---

## ☁️ Cloud Integration

### Google Cloud Logging

#### Setup

```bash
# Install SDK
pip install google-cloud-logging

# Authenticate
gcloud auth application-default login

# Or use service account
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```

#### Usage

```python
from security.audit_logger_plugins import GoogleCloudAuditLogger

logger = GoogleCloudAuditLogger(
    project_id="my-gcp-project",
    log_name="task-collaboration-audit",
    resource_type="global",  # or gce_instance, k8s_pod, etc.
    enabled=True
)

# Log events (same API)
logger.log_authentication(
    event_type="login_success",
    user_id="alice",
    success=True,
    ip_address="192.168.1.100"
)

# Get Cloud Console URL
url = logger.get_logs_url()
print(f"View logs: {url}")
```

#### Cloud Console Features

**Logs Explorer**:
- Real-time log streaming
- Advanced filtering
- Full-text search
- Histogram visualization

**Filtering Examples**:
```
# By event type
labels.event_type="login_failure"

# By user
labels.user_id="alice"

# By severity
severity>=WARNING

# Time range
timestamp>="2025-12-29T00:00:00Z"

# Combined
labels.category="authentication" AND severity=CRITICAL
```

**Log-Based Metrics**:
```
# Count failed logins
metric.type="logging.googleapis.com/user/login_failures"
filter: jsonPayload.event_type="login_failure"

# Security events rate
metric.type="logging.googleapis.com/user/security_events"
filter: labels.category="security"
```

**Alerts**:
```
# Alert on critical events
Condition: Log entry count > 5 in 5 minutes
Filter: severity=CRITICAL

# Alert on failed logins
Condition: Log entry count > 10 in 1 minute
Filter: jsonPayload.event_type="login_failure"
```

**Export to BigQuery**:
```sql
-- Analyze failed logins
SELECT 
  jsonPayload.user_id,
  COUNT(*) as failed_attempts,
  ARRAY_AGG(jsonPayload.ip_address LIMIT 5) as ip_addresses
FROM `project.dataset.audit_logs`
WHERE jsonPayload.event_type = 'login_failure'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY jsonPayload.user_id
HAVING failed_attempts > 10
ORDER BY failed_attempts DESC
```

#### Production Configuration

```python
from security.audit_logger import CompositeAuditLogger
from security.audit_logger_plugins import (
    FileAuditLogger,
    GoogleCloudAuditLogger
)

# Hybrid approach
logger = CompositeAuditLogger([
    # Local file for immediate access
    FileAuditLogger(
        filepath="/var/log/app/audit.log",
        max_size_mb=500,
        backup_count=10
    ),
    
    # Cloud for centralized monitoring
    GoogleCloudAuditLogger(
        project_id="production-project",
        log_name="task-collaboration-audit",
        resource_type="k8s_pod",
        enabled=True
    )
])
```

---

## 🔍 Querying Logs

### Query API

All loggers (except syslog) support querying:

```python
# Basic query
events = logger.query_events(limit=100)

# Filter by event type
events = logger.query_events(
    event_type="login_failure",
    limit=50
)

# Filter by category
events = logger.query_events(
    category=EventCategory.SECURITY,
    limit=100
)

# Filter by user
events = logger.query_events(
    user_id="alice",
    limit=50
)

# Time range query
from datetime import datetime, timedelta

events = logger.query_events(
    start_time=datetime.now() - timedelta(hours=24),
    end_time=datetime.now(),
    limit=1000
)

# Combined filters
events = logger.query_events(
    event_type="access_denied",
    user_id="bob",
    start_time=datetime.now() - timedelta(hours=1),
    limit=10
)
```

### Processing Results

```python
events = logger.query_events(
    category=EventCategory.AUTHENTICATION,
    limit=100
)

for event in events:
    print(f"{event.timestamp}: {event.event_type}")
    print(f"  User: {event.user_id}")
    print(f"  IP: {event.ip_address}")
    print(f"  Details: {event.details}")
```

---

## 🚀 Production Deployment

### Configuration

```python
import os
from security.audit_logger import CompositeAuditLogger
from security.audit_logger_plugins import (
    FileAuditLogger,
    GoogleCloudAuditLogger
)

def create_audit_logger():
    """Create production audit logger"""
    
    loggers = []
    
    # Always include file logger
    loggers.append(
        FileAuditLogger(
            filepath=os.getenv("AUDIT_LOG_PATH", "/var/log/app/audit.log"),
            max_size_mb=int(os.getenv("AUDIT_LOG_MAX_SIZE", "500")),
            backup_count=int(os.getenv("AUDIT_LOG_BACKUPS", "10"))
        )
    )
    
    # Add cloud logging if configured
    if os.getenv("GCP_PROJECT_ID"):
        loggers.append(
            GoogleCloudAuditLogger(
                project_id=os.getenv("GCP_PROJECT_ID"),
                log_name=os.getenv("GCP_LOG_NAME", "audit"),
                enabled=True
            )
        )
    
    return CompositeAuditLogger(loggers)

# Global logger instance
audit_logger = create_audit_logger()
```

### Environment Variables

```bash
# File logging
export AUDIT_LOG_PATH="/var/log/app/audit.log"
export AUDIT_LOG_MAX_SIZE="500"  # MB
export AUDIT_LOG_BACKUPS="10"

# Google Cloud Logging
export GCP_PROJECT_ID="production-project"
export GCP_LOG_NAME="task-collaboration-audit"
export GOOGLE_APPLICATION_CREDENTIALS="/etc/secrets/gcp-key.json"
```

### Integration with Application

```python
from audit_config import audit_logger

class TaskCoordinator:
    def __init__(self):
        self.audit = audit_logger
    
    def handle_login(self, username, password, request):
        # Authenticate...
        
        if success:
            self.audit.log_authentication(
                event_type="login_success",
                user_id=username,
                success=True,
                ip_address=request.remote_addr,
                details={
                    "method": "password+mfa" if mfa else "password",
                    "user_agent": request.user_agent.string
                }
            )
        else:
            self.audit.log_authentication(
                event_type="login_failure",
                user_id=username,
                success=False,
                ip_address=request.remote_addr,
                details={"reason": error_message}
            )
    
    def check_permission(self, user_id, resource, action):
        allowed = self.rbac.check_permission(...)
        
        if not allowed:
            self.audit.log_authorization(
                event_type="access_denied",
                user_id=user_id,
                resource=resource,
                action=action,
                allowed=False,
                details={"reason": "insufficient_permissions"}
            )
```

---

## 📜 Compliance

### SOC 2 Requirements

✅ **Access Logging**: All authentication events logged  
✅ **Authorization Logging**: All permission checks logged  
✅ **Change Logging**: All data modifications logged  
✅ **Security Events**: All security incidents logged  
✅ **Retention**: Configurable log retention  
✅ **Immutability**: Append-only log files  

### HIPAA Requirements

✅ **User Identification**: User ID in all events  
✅ **Access Tracking**: Read/write access logged  
✅ **Audit Trail**: Comprehensive audit trail  
✅ **Integrity**: Tamper-evident logging  
✅ **Availability**: Redundant logging  

### PCI-DSS Requirements

✅ **Requirement 10.1**: User access tracked  
✅ **Requirement 10.2**: All events logged  
✅ **Requirement 10.3**: Audit trail entries include user, type, date, success/failure  
✅ **Requirement 10.4**: Time synchronization (UTC timestamps)  
✅ **Requirement 10.5**: Secure audit trails  
✅ **Requirement 10.6**: Review logs regularly  

---

## 🎓 Best Practices

### 1. Use Structured Logging

```python
# ✅ Good: Structured details
logger.log_event(
    event_type="task_completed",
    category=EventCategory.DATA_ACCESS,
    details={
        "task_id": "task-123",
        "duration_ms": 4523,
        "status": "success"
    }
)

# ❌ Bad: Unstructured string
logger.log_event(
    event_type="task_completed",
    category=EventCategory.DATA_ACCESS,
    details={"message": "Task task-123 completed in 4523ms"}
)
```

### 2. Log Security Events Immediately

```python
# Critical events should log immediately
if replay_attack_detected:
    audit_logger.log_security_event(
        event_type="replay_attack_detected",
        severity=EventSeverity.CRITICAL,
        ip_address=ip,
        details={"nonce": nonce}
    )
    audit_logger.flush()  # Force immediate write
    block_request()
```

### 3. Include Context

```python
# Include relevant context
logger.log_authorization(
    event_type="access_denied",
    user_id=user_id,
    resource=f"project:{project_id}",
    action="delete",
    allowed=False,
    details={
        "reason": "not_owner",
        "project_owner": owner_id,
        "user_role": user_role
    }
)
```

### 4. Use Appropriate Severity

```python
# Match severity to impact
logger.log_event(
    event_type="config_changed",
    severity=EventSeverity.WARNING,  # Config changes are warnings
    ...
)

logger.log_event(
    event_type="sql_injection_detected",
    severity=EventSeverity.CRITICAL,  # Security events are critical
    ...
)
```

### 5. Sanitize Sensitive Data

```python
# ❌ Never log passwords, tokens, or secrets
logger.log_event(
    details={"password": password}  # NEVER DO THIS
)

# ✅ Log only non-sensitive data
logger.log_event(
    details={
        "username": username,
        "method": "password",
        "success": True
    }
)
```

### 6. Regular Log Review

```python
# Automated log analysis
def analyze_failed_logins():
    """Alert on unusual failed login patterns"""
    events = logger.query_events(
        event_type="login_failure",
        start_time=datetime.now() - timedelta(hours=1),
        limit=1000
    )
    
    # Count by user
    failures_by_user = {}
    for event in events:
        user = event.user_id
        failures_by_user[user] = failures_by_user.get(user, 0) + 1
    
    # Alert on threshold
    for user, count in failures_by_user.items():
        if count > 10:
            send_alert(f"User {user} has {count} failed logins")
```

---

## 📚 API Reference

### AuditLogger Interface

```python
class AuditLogger(ABC):
    
    @abstractmethod
    def log_event(
        event_type: str,
        category: EventCategory,
        severity: EventSeverity = EventSeverity.INFO,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> bool
    
    @abstractmethod
    def query_events(
        event_type: Optional[str] = None,
        category: Optional[EventCategory] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]
    
    @abstractmethod
    def get_logger_name() -> str
    
    @abstractmethod
    def flush() -> bool
    
    # Convenience methods
    def log_authentication(...)
    def log_authorization(...)
    def log_security_event(...)
```

### AuditEvent

```python
class AuditEvent:
    timestamp: str
    event_type: str
    category: str
    severity: str
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    details: Dict
    metadata: Dict
    
    def to_dict() -> Dict
    def to_json() -> str
```

---

## 📞 Support

For issues or questions:
1. Check this README
2. Review examples in `audit_logger.py`
3. See plugin examples in `audit_logger_plugins.py`
4. Check Cloud Console documentation (for GCP)

---

## 📄 License

Educational use only - Stage 3 production security demonstration.

---

**Version**: 3.0.0  
**Stage**: 3 (Production Security)  
**Status**: Production-ready  
**Last Updated**: 2025-12-29