# A2A Agent Registry - Complete Implementation

## 📁 File Structure

Copy these files to your `a2a_crypto_simple_registry_example` folder:

```
a2a_crypto_simple_registry_example/
├── registry_server.py          # Main FastAPI server (270 lines)
├── models.py                   # Pydantic data models (140 lines)
├── storage.py                  # In-memory storage (180 lines)
├── health_monitor.py           # Background health checks (110 lines)
├── example_register.py         # Example usage (150 lines)
├── test_registry_simple.py     # Simple test suite (250 lines)
├── requirements.txt            # Dependencies
└── README.md                   # Documentation

Total: ~1,100 lines of well-structured, documented code
```

## 🚀 Quick Start Guide

### Step 1: Install Dependencies

```bash
cd a2a_crypto_simple_registry_example
pip install -r requirements.txt
```

This installs:
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `pydantic` - Data validation
- `httpx` - HTTP client (for examples)

### Step 2: Start the Registry

```bash
python registry_server.py
```

Expected output:
```
==================================================
  A2A Agent Registry Server
==================================================

🚀 Starting Agent Registry Server...
💓 Health monitor initialized (check every 30s, stale after 90s)
📦 Initialized in-memory agent storage
💚 Health monitor started
✅ Registry is ready
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 3: Test the Registry

In a new terminal:

```bash
python test_registry_simple.py
```

Expected output:
```
==================================================
  A2A Agent Registry - Test Suite
==================================================

1️⃣  Testing registry info endpoint...
   ✅ Registry info endpoint works

2️⃣  Testing agent registration...
   ✅ Agent registration works

... [more tests] ...

==================================================
  Test Results
==================================================
✅ Passed: 8
❌ Failed: 0
📊 Total:  8

🎉 All tests passed!
```

### Step 4: Try the Example

```bash
python example_register.py
```

This will:
1. Register a crypto agent
2. Send a heartbeat
3. Retrieve agent details
4. Discover agents by capability

### Step 5: Explore the API

Open your browser to:
- **Interactive Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

Try the API directly from the browser!

## 🔌 Integration with Crypto Example

### Option 1: Modify Existing Crypto Agent

Add this to `crypto_agent_server.py` (from your original example):

```python
import httpx

async def register_with_registry():
    """Register this agent with the registry on startup"""
    agent_card = {
        "agent_id": self.agent_id,
        "name": self.name,
        "version": self.version,
        "description": "Cryptocurrency price agent",
        "capabilities": ["get_price", "list_currencies"],
        "supported_protocols": ["A2A/1.0"],
        "metadata": {
            "supported_currencies": ["BTC", "ETH", "XRP"],
            "data_type": "fictitious"
        }
    }
    
    registration = {
        "agent_card": agent_card,
        "endpoint": f"{self.host}:{self.port}"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            await client.post(
                "http://localhost:8000/agents/register",
                json=registration
            )
            print("✅ Registered with A2A Registry")
        except:
            print("⚠️  Could not register with registry")

# Call during startup
async def start(self):
    # ... existing code ...
    await register_with_registry()
    # ... existing code ...
```

### Option 2: Modify Client for Discovery

Add this to `a2a_client.py`:

```python
async def discover_crypto_agent():
    """Discover crypto agent via registry instead of hardcoding"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:8000/agents/discover",
            params={"capability": "get_price"}
        )
        
        agents = response.json()["agents"]
        if not agents:
            raise Exception("No crypto agents available")
        
        # Get first healthy agent
        agent = agents[0]
        endpoint = agent["endpoint"]
        host, port = endpoint.split(":")
        
        return host, int(port)

# Use in connection
async def connect(self):
    host, port = await discover_crypto_agent()
    self.reader, self.writer = await asyncio.open_connection(host, port)
```

## 📊 What Each File Does

### `registry_server.py`
The main FastAPI application with all REST endpoints:
- `/agents/register` - Register agents
- `/agents/discover` - Find agents by capability
- `/agents/{id}` - Get agent details
- `/agents/{id}/heartbeat` - Health check
- `/agents` - List all agents
- `/stats` - Registry statistics

### `models.py`
Pydantic models for data validation:
- `AgentCard` - Agent identity and capabilities
- `AgentRegistration` - Registration request
- `DiscoveryQuery` - Search parameters
- `HealthStatus` - Health information

### `storage.py`
Thread-safe in-memory storage:
- Stores registered agents
- Tracks heartbeats
- Manages health status
- Provides statistics

### `health_monitor.py`
Background monitoring service:
- Runs health checks every 30 seconds
- Marks stale agents as unhealthy
- Automatic cleanup
- Prevents discovery of dead agents

### `example_register.py`
Demonstrates how to:
- Register an agent
- Send heartbeats
- Retrieve agent details
- Discover agents by capability

### `test_registry_simple.py`
Complete test suite covering:
- All API endpoints
- Registration flow
- Discovery mechanism
- Health monitoring
- Error handling

## 🎯 Key Features Explained

### 1. Automatic Health Monitoring
Agents must send heartbeats every 30-60 seconds. If an agent doesn't send a heartbeat for 90 seconds, it's automatically marked as unhealthy and won't appear in discovery results.

### 2. Capability-Based Discovery
Instead of hardcoding agent addresses, clients can discover agents by asking: "Give me all agents with 'get_price' capability."

### 3. Thread-Safe Storage
Multiple clients can register and query simultaneously without conflicts.

### 4. Automatic API Documentation
FastAPI generates interactive documentation at `/docs` - try out the API directly in your browser!

### 5. Graceful Shutdown
Health monitor stops cleanly on server shutdown.

## 🔧 Configuration Options

### Change Registry Port

In `registry_server.py`:
```python
uvicorn.run(app, host="0.0.0.0", port=8000)  # Change to 9000, etc.
```

### Adjust Health Check Timing

In `health_monitor.py`:
```python
def __init__(self, storage, 
             check_interval=30,      # Check every 30 seconds
             stale_threshold=90):    # Unhealthy after 90 seconds
```

### Storage Persistence (Optional)

To add SQLite persistence, modify `storage.py` to use SQLite instead of in-memory dict. This is an optional enhancement for later.

## 💡 Next Steps

1. **Start the registry server**
2. **Run the test suite** to verify everything works
3. **Try the example** to see registration in action
4. **Explore the API docs** at http://localhost:8000/docs
5. **Integrate with your crypto example** (optional)
6. **Experiment with multiple agents** - register several and discover them

## 🎓 Learning Points

This implementation teaches:
- ✅ Building REST APIs with FastAPI
- ✅ Data validation with Pydantic
- ✅ Background tasks and monitoring
- ✅ Thread-safe in-memory storage
- ✅ Service discovery patterns
- ✅ Health monitoring in distributed systems
- ✅ API documentation best practices

## 🐛 Troubleshooting

**Port already in use?**
```bash
# Change port in registry_server.py or kill existing process
lsof -ti:8000 | xargs kill -9  # macOS/Linux
```

**Can't install dependencies?**
```bash
# Use a virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

**Tests failing?**
- Make sure the registry server is running first
- Check the registry is on port 8000
- Verify no firewall blocking localhost connections

## 📚 Resources

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Pydantic Documentation**: https://docs.pydantic.dev/
- **A2A Protocol Docs**: See main project README

---

**Ready to get started?** Copy all files to your `a2a_crypto_simple_registry_example` folder and run:

```bash
pip install -r requirements.txt
python registry_server.py
```

Happy coding! 🚀