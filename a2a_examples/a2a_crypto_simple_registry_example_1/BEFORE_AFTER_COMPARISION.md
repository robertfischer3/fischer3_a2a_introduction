# Before & After: Registry Integration

## Architecture Comparison

### BEFORE (Original Crypto Example)
```
┌──────────┐
│  Client  │
└────┬─────┘
     │
     │ Hardcoded: localhost:8888
     │
     ↓
┌──────────────┐
│ Crypto Agent │
│ (Port 8888)  │
└──────────────┘
```

**Issues:**
- ❌ Client must know agent address in advance
- ❌ If agent moves, client code must change
- ❌ Can't add multiple agents easily
- ❌ No way to know if agent is alive
- ❌ Manual agent management

---

### AFTER (With Registry)
```
                 ┌──────────┐
                 │ Registry │
                 │ :8000    │
                 └────┬─────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        │ 1. Register │             │ 2. Discover
        │             │             │    "get_price"
        ↓             │             ↓
┌──────────────┐     │      ┌──────────┐
│ Crypto Agent │     │      │  Client  │
│ (Port 8888)  │     │      └────┬─────┘
│              │     │           │
│ 💓 Heartbeat │     │           │ 3. Connect
│   every 30s  ├─────┘           │    to discovered
└──────────────┘                 │    endpoint
                                 ↓
                          ┌──────────────┐
                          │ Crypto Agent │
                          │ (Port 8888)  │
                          └──────────────┘
```

**Benefits:**
- ✅ Dynamic service discovery
- ✅ Automatic health monitoring
- ✅ Support multiple agents
- ✅ Client discovers agents by capability
- ✅ Agents can come and go without client changes

---

## Code Changes Summary

### Server: crypto_agent_server.py

#### Added Dependencies
```python
import httpx  # For registry HTTP requests
```

#### Added Initialization
```python
def __init__(self, ..., registry_url: str = "http://localhost:8000"):
    # ...existing code...
    self.registry_url = registry_url
    self.heartbeat_task = None
    self.registered = False
```

#### Added 3 New Methods
```python
async def register_with_registry(self):
    """Register this agent with registry"""
    # POST to /agents/register
    
async def send_heartbeat(self):
    """Send heartbeats every 30 seconds"""
    # PUT to /agents/{id}/heartbeat
    
async def unregister_from_registry(self):
    """Unregister on shutdown"""
    # DELETE to /agents/{id}
```

#### Modified Lifecycle
```python
async def start(self):
    await self.register_with_registry()  # ← NEW
    if self.registered:
        self.heartbeat_task = asyncio.create_task(self.send_heartbeat())  # ← NEW
    # ...start server...

async def stop(self):  # ← NEW METHOD
    # Cancel heartbeat
    await self.unregister_from_registry()
    # Close server
```

**Total Changes: ~80 lines added**

---

### Client: a2a_client.py

#### Added Dependencies
```python
import httpx  # For registry HTTP requests
```

#### Added Initialization
```python
def __init__(self, ..., registry_url: str = "http://localhost:8000"):
    # ...existing code...
    self.registry_url = registry_url
```

#### Added 2 New Methods
```python
async def discover_agents(self, capability: str = None):
    """Query registry for agents"""
    # GET /agents/discover?capability=X
    
async def discover_and_connect(self, capability: str = "get_price"):
    """Discover and connect to an agent"""
    agents = await self.discover_agents(capability)
    # Connect to first available agent
```

#### Modified Connection
```python
# BEFORE:
await client.connect()  # Hardcoded localhost:8888

# AFTER:
await client.discover_and_connect(capability="get_price")  # Discovers dynamically
```

**Total Changes: ~50 lines added**

---

## File Structure

### Your Project (a2a_crypto_simple_registry_example_1)
```
a2a_crypto_simple_registry_example_1/
│
├── registry/                         # Registry implementation
│   ├── registry_server.py           # ← Start this first (port 8000)
│   ├── models.py
│   ├── storage.py
│   ├── health_monitor.py
│   ├── requirements.txt
│   └── ...
│
├── server/                           # Crypto agent server
│   └── crypto_agent_server.py       # ← Modify this file OR replace it
│                                     # ← Start this second (port 8888)
│
├── client/                           # Client application
│   └── a2a_client.py                # ← Modify this file OR replace it
│                                     # ← Run this last
│
└── shared/                           # A2A protocol (no changes)
    └── a2a_protocol.py
```

---

## Startup Sequence

### Terminal 1: Registry
```bash
cd registry
python registry_server.py

# Output:
# 🚀 Starting Agent Registry Server...
# ✅ Registry is ready
# INFO: Uvicorn running on http://0.0.0.0:8000
```

### Terminal 2: Crypto Agent
```bash
cd server
python crypto_agent_server.py

# Output:
# ✅ Registered with A2A Registry     ← NEW!
#    Status: registered
# 🚀 Crypto Agent Server started on 127.0.0.1:8888
# 💓 Heartbeat sent to registry       ← NEW! (every 30s)
```

### Terminal 3: Client
```bash
cd client
python a2a_client.py

# Output:
# 🔍 Discovering agents...            ← NEW!
# ✅ Found 1 agent(s)                  ← NEW!
# 📡 Selected: CryptoPriceAgent       ← NEW!
#    Endpoint: localhost:8888
# 🔗 Connecting to localhost:8888...
# ✅ Connected successfully
```

---

## Message Flow Comparison

### BEFORE: Direct Connection
```
1. Client starts
2. Client connects to localhost:8888 (hardcoded)
3. Client sends HANDSHAKE
4. Agent responds with HANDSHAKE_ACK
5. Client sends REQUEST (get_price)
6. Agent responds with RESPONSE (price)
```

### AFTER: Registry-Based Discovery
```
1. Registry starts (port 8000)

2. Agent starts
3. Agent → Registry: POST /agents/register
4. Registry → Agent: {"status": "registered"}
5. Agent starts heartbeat loop (every 30s)

6. Client starts
7. Client → Registry: GET /agents/discover?capability=get_price
8. Registry → Client: [{"agent_card": {...}, "endpoint": "localhost:8888"}]
9. Client connects to discovered endpoint (localhost:8888)
10. Client sends HANDSHAKE to Agent
11. Agent responds with HANDSHAKE_ACK
12. Client sends REQUEST (get_price)
13. Agent responds with RESPONSE (price)

Background: Agent → Registry: PUT /agents/{id}/heartbeat (every 30s)
```

---

## What Each Component Does

### Registry (Port 8000)
**Role:** Directory service for agents

**Endpoints:**
- `POST /agents/register` - Agents register here
- `GET /agents/discover` - Clients discover agents here
- `PUT /agents/{id}/heartbeat` - Agents send heartbeats
- `DELETE /agents/{id}` - Agents unregister
- `GET /agents` - List all agents

**Data Stored:**
- Agent cards (identity, capabilities)
- Endpoints (host:port)
- Last heartbeat time
- Health status

### Crypto Agent (Port 8888)
**Role:** Provides cryptocurrency prices

**Registry Interactions:**
1. **Startup:** Registers with registry
2. **Runtime:** Sends heartbeats every 30s
3. **Shutdown:** Unregisters from registry

**A2A Interactions:**
- Same as before (HANDSHAKE, REQUEST, RESPONSE)

### Client
**Role:** Requests crypto prices

**Registry Interactions:**
1. **Startup:** Discovers agents by capability
2. **Selects:** First available healthy agent

**A2A Interactions:**
- Same as before (connects to agent, sends requests)

---

## Testing Registry Integration

### Test 1: Verify Registry
```bash
curl http://localhost:8000/
# Should return registry info
```

### Test 2: Verify Agent Registration
```bash
curl http://localhost:8000/agents
# Should show crypto-agent-001
```

### Test 3: Test Discovery
```bash
curl "http://localhost:8000/agents/discover?capability=get_price"
# Should return crypto agent
```

### Test 4: List from Client
```bash
python a2a_client.py --list
# Should display:
# 1. CryptoPriceAgent (v1.0.0)
#    Capabilities: get_price, list_currencies...
```

---

## Key Benefits of Registry Pattern

### 1. Loose Coupling
**Before:** Client hardcoded to specific agent address  
**After:** Client only knows capability needed ("get_price")

### 2. Dynamic Scaling
**Before:** One agent, hardcoded  
**After:** Can have multiple agents, client picks one

```
Registry
├─→ Crypto Agent #1 (localhost:8888) - BTC, ETH
├─→ Crypto Agent #2 (localhost:8889) - XRP, DOGE  
└─→ Weather Agent (localhost:8890) - forecasts
```

Client discovers all agents with "get_price" capability.

### 3. Health Awareness
**Before:** No way to know if agent is alive  
**After:** Registry tracks health via heartbeats

If agent stops sending heartbeats for 90 seconds:
- Registry marks it as "unhealthy"
- Discovery excludes it from results
- Client automatically gets healthy agents only

### 4. Zero-Downtime Updates
**Before:** Stop agent → client breaks → update agent → restart  
**After:** Start new agent → register → stop old agent → seamless!

### 5. Service Discovery
**Before:** Need to communicate agent addresses  
**After:** Just deploy agents, they announce themselves

---

## Real-World Analogy

### Before (Hardcoded)
Like having someone's home address memorized. If they move, you're lost.

### After (Registry)
Like calling 411 (directory assistance). You ask for "pizza delivery near me" and get current, available options.

**Registry = Phone Book for Agents** 📞

---

## What to Do Next

1. **Start all three components** (registry, agent, client)
2. **Verify agent appears in registry**
3. **Run client and see discovery work**
4. **Stop agent and watch heartbeat stop**
5. **Restart agent and see it re-register**
6. **Add a second agent** on port 8889
7. **See client discover both agents**

---

## Common Pitfalls

❌ **Starting in wrong order**
→ Start registry first, then agent, then client

❌ **Port conflicts**
→ Registry: 8000, Crypto Agent: 8888

❌ **Missing httpx**
→ `pip install httpx`

❌ **Registry not running**
→ Client will fall back but won't discover agents

❌ **Agent not sending heartbeats**
→ Check for errors in agent console
→ Agent will be marked unhealthy after 90s

---

## Files Provided

In your outputs directory, you have:

1. **crypto_agent_server_with_registry.py** - Modified server
2. **a2a_client_with_registry.py** - Modified client
3. **INTEGRATION_GUIDE.md** - Detailed step-by-step guide
4. **BEFORE_AFTER_COMPARISON.md** - This file

**Choose your path:**
- **Quick:** Replace files with provided versions
- **Learning:** Follow manual modifications in INTEGRATION_GUIDE.md

Both paths lead to the same result! 🎯