# A2A Registry Architecture

## Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                      │
│                   (registry_server.py)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  REST API Endpoints:                                        │
│  • POST   /agents/register     → Register new agent        │
│  • GET    /agents/discover     → Find by capability        │
│  • GET    /agents/{id}         → Get agent details         │
│  • PUT    /agents/{id}/heartbeat → Health check            │
│  • DELETE /agents/{id}         → Unregister agent          │
│  • GET    /agents              → List all agents           │
│  • GET    /stats               → Statistics                │
│                                                             │
└──────────────┬──────────────────────┬───────────────────────┘
               │                      │
               ↓                      ↓
    ┌──────────────────┐   ┌──────────────────────┐
    │     Storage      │   │   Health Monitor     │
    │  (storage.py)    │   │(health_monitor.py)   │
    ├──────────────────┤   ├──────────────────────┤
    │                  │   │                      │
    │ • In-memory dict │   │ • Background thread  │
    │ • Thread-safe    │   │ • Checks every 30s   │
    │ • CRUD ops       │   │ • Marks stale agents │
    │ • Statistics     │   │ • Auto-cleanup       │
    │                  │   │                      │
    └──────────────────┘   └──────────────────────┘
```

## Data Flow - Registration

```
┌──────────┐                                    ┌──────────────┐
│  Agent   │                                    │   Registry   │
│ (Client) │                                    │   Server     │
└────┬─────┘                                    └──────┬───────┘
     │                                                 │
     │ 1. POST /agents/register                       │
     │    {agent_card, endpoint}                      │
     ├────────────────────────────────────────────────>│
     │                                                 │
     │                                        2. Validate data
     │                                           (models.py)
     │                                                 │
     │                                        3. Store in memory
     │                                           (storage.py)
     │                                                 │
     │ 4. Registration confirmation                   │
     │    {status: "registered", agent_id: "..."}     │
     │<────────────────────────────────────────────────┤
     │                                                 │
     │ 5. PUT /agents/{id}/heartbeat (every 30-60s)   │
     │────────────────────────────────────────────────>│
     │                                                 │
     │ 6. Acknowledgment                              │
     │<────────────────────────────────────────────────┤
     │                                                 │
```

## Data Flow - Discovery

```
┌──────────┐                                    ┌──────────────┐
│  Client  │                                    │   Registry   │
│  Agent   │                                    │   Server     │
└────┬─────┘                                    └──────┬───────┘
     │                                                 │
     │ 1. GET /agents/discover?capability=get_price   │
     ├────────────────────────────────────────────────>│
     │                                                 │
     │                                    2. Query storage
     │                                       Filter by:
     │                                       • Capability match
     │                                       • Health = "healthy"
     │                                                 │
     │ 3. Return matching agents                      │
     │    {agents: [...], count: 2}                   │
     │<────────────────────────────────────────────────┤
     │                                                 │
     │ 4. Connect to discovered agent endpoint        │
     │────────────────────────>┌────────────┐         │
     │                         │   Target   │         │
     │                         │   Agent    │         │
     │                         └────────────┘         │
     │                                                 │
```

## Health Monitoring Flow

```
Background Process (Every 30 seconds):

┌─────────────────┐
│ Health Monitor  │
│   Thread        │
└────────┬────────┘
         │
         │ 1. Get all agents from storage
         ↓
    ┌─────────────────┐
    │ For each agent: │
    └────────┬────────┘
             │
             │ 2. Check last_heartbeat timestamp
             │
             ↓
    ┌──────────────────────────┐
    │ Time since heartbeat?    │
    └────────┬─────────────────┘
             │
             ├─→ < 90 seconds → Mark "healthy"
             │
             └─→ > 90 seconds → Mark "unhealthy"
                                (won't appear in discovery)
```

## File Relationships

```
registry_server.py
├── imports models.py (AgentCard, AgentRegistration, etc.)
├── imports storage.py (RegistryStorage)
└── imports health_monitor.py (HealthMonitor)

models.py
└── Uses Pydantic for validation

storage.py
└── Independent (no external dependencies)

health_monitor.py
└── Uses storage.py (passed as parameter)

example_register.py
├── Uses httpx to call registry APIs
└── Demonstrates registration flow

test_registry_simple.py
├── Uses httpx to call registry APIs
└── Tests all endpoints
```

## Integration with Crypto Example

```
BEFORE (Direct Connection):
┌────────┐          ┌──────────────┐
│ Client │─────────→│ Crypto Agent │
└────────┘          └──────────────┘
              localhost:8888


AFTER (Registry-Based Discovery):
┌────────┐     1. Discover    ┌──────────┐
│ Client │────────────────────→│ Registry │
└───┬────┘                     └────┬─────┘
    │                               │
    │  2. Get endpoint              │
    │  "localhost:8888"             │
    │←──────────────────────────────┤
    │                               │
    │  3. Connect to agent          │
    │──────────────────→┌──────────────┐
    │                   │ Crypto Agent │
    │                   └──────────────┘
    │                          │
    │                          │ 4. Register on startup
    │                          └─────────────────→┌──────────┐
    │                                             │ Registry │
    │                                             └──────────┘
```

## Scaling Pattern

```
Multiple Agents Example:

┌──────────┐
│ Registry │
└────┬─────┘
     │
     ├─→ Crypto Agent #1 (BTC, ETH) - localhost:8888
     │
     ├─→ Crypto Agent #2 (XRP, DOGE) - localhost:8889
     │
     └─→ Weather Agent (forecasts) - localhost:8890


Client discovers all "get_price" agents:
→ Returns both Crypto Agent #1 and #2
→ Client can:
   • Use first available
   • Load balance between them
   • Try failover if one fails
```

## Key Design Decisions

### 1. In-Memory Storage (Training Version)
**Pros**: Fast, simple, no dependencies
**Cons**: Data lost on restart
**Production**: Use PostgreSQL, Redis, or MongoDB

### 2. Background Health Monitor
**Pros**: Automatic cleanup, no manual intervention
**Cons**: 30s latency before marking unhealthy
**Production**: Use distributed health checks

### 3. RESTful HTTP API
**Pros**: Universal, easy to test, browser-compatible
**Cons**: Not as efficient as gRPC for high volume
**Production**: Consider gRPC for internal services

### 4. Thread-Safe Operations
**Pros**: Handles concurrent requests correctly
**Cons**: Locks can be bottleneck at high scale
**Production**: Use connection pooling, async all the way

## Performance Characteristics

**Registration**: ~5ms (in-memory)
**Discovery**: ~10ms (in-memory scan)
**Heartbeat**: ~2ms (timestamp update)

**Scalability (Training Version)**:
- 100s of agents: ✅ Excellent
- 1000s of agents: ⚠️ Acceptable
- 10,000s+ agents: ❌ Need distributed solution

## Security Considerations

**Current Implementation** (Training):
- ❌ No authentication
- ❌ No encryption (HTTP only)
- ❌ No input sanitization beyond Pydantic
- ❌ No rate limiting

**Production Requirements**:
- ✅ API keys or OAuth 2.0
- ✅ HTTPS/TLS encryption
- ✅ Input sanitization for XSS/injection
- ✅ Rate limiting per client
- ✅ Agent certificate verification
- ✅ Audit logging