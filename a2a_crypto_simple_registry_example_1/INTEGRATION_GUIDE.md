# Integration Guide: Crypto Agent + Registry

This guide shows you how to integrate the crypto agent example with the A2A Registry in your `a2a_crypto_simple_registry_example_1` project.

## Current Project Structure

```
a2a_crypto_simple_registry_example_1/
├── registry/                    # Registry implementation (already added)
│   ├── registry_server.py
│   ├── models.py
│   ├── storage.py
│   ├── health_monitor.py
│   ├── requirements.txt
│   └── ...
├── client/                      # Client application (needs modification)
│   └── a2a_client.py
├── server/                      # Crypto agent server (needs modification)
│   └── crypto_agent_server.py
└── shared/                      # A2A protocol (no changes needed)
    └── a2a_protocol.py
```

## Changes Required

You have **TWO options** for integrating the crypto example with the registry:

### Option 1: Replace Files (Easiest)
Replace the existing files with the new registry-enabled versions.

### Option 2: Modify Files (Learn More)
Make specific changes to understand how registry integration works.

---

## Option 1: Replace Files (Recommended)

This is the quickest way to get everything working.

### Step 1: Replace Server File

Replace `server/crypto_agent_server.py` with the new file:
- **New file**: `crypto_agent_server_with_registry.py` (provided in outputs)

**What changed:**
- ✅ Auto-registers with registry on startup
- ✅ Sends heartbeats every 30 seconds
- ✅ Unregisters on shutdown
- ✅ Added `httpx` for HTTP requests to registry

### Step 2: Replace Client File

Replace `client/a2a_client.py` with the new file:
- **New file**: `a2a_client_with_registry.py` (provided in outputs)

**What changed:**
- ✅ Discovers agents via registry instead of hardcoded address
- ✅ Can list all available agents
- ✅ Added `--list` flag to see registered agents
- ✅ Added `httpx` for HTTP requests to registry

### Step 3: Update Dependencies

Add to your `requirements.txt` (or create one in the project root):

```txt
# For registry HTTP requests (client and server)
httpx==0.25.0
```

Install:
```bash
pip install httpx
```

---

## Option 2: Modify Files Manually

If you want to understand the changes, follow these modifications:

### Modify `server/crypto_agent_server.py`

#### 1. Add import at the top:
```python
import httpx  # Add this
```

#### 2. Add to `__init__` method:
```python
def __init__(self, host: str = 'localhost', port: int = 8888, 
             registry_url: str = "http://localhost:8000"):  # Add registry_url parameter
    # ... existing code ...
    self.registry_url = registry_url  # Add this
    self.heartbeat_task = None        # Add this
    self.registered = False           # Add this
```

#### 3. Add these three new methods to the class:

```python
async def register_with_registry(self):
    """Register this agent with the A2A Registry"""
    registration_data = {
        "agent_card": {
            "agent_id": self.agent_card.agent_id,
            "name": self.agent_card.name,
            "version": self.agent_card.version,
            "description": self.agent_card.description,
            "capabilities": self.agent_card.capabilities,
            "supported_protocols": self.agent_card.supported_protocols,
            "metadata": self.agent_card.metadata
        },
        "endpoint": f"{self.host}:{self.port}"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.registry_url}/agents/register",
                json=registration_data,
                timeout=10.0
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Registered with A2A Registry")
                self.registered = True
                return True
            else:
                print(f"⚠️  Registry registration failed")
                return False
                
    except httpx.ConnectError:
        print(f"⚠️  Could not connect to registry at {self.registry_url}")
        print("   Agent will run without registry integration")
        return False

async def send_heartbeat(self):
    """Send periodic heartbeats to the registry"""
    if not self.registered:
        return
        
    while True:
        try:
            await asyncio.sleep(30)  # Every 30 seconds
            
            async with httpx.AsyncClient() as client:
                response = await client.put(
                    f"{self.registry_url}/agents/{self.agent_id}/heartbeat",
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    print("💓 Heartbeat sent to registry")
                    
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"⚠️  Heartbeat error: {e}")

async def unregister_from_registry(self):
    """Unregister from the registry on shutdown"""
    if not self.registered:
        return
        
    try:
        async with httpx.AsyncClient() as client:
            await client.delete(
                f"{self.registry_url}/agents/{self.agent_id}",
                timeout=5.0
            )
            print("✅ Unregistered from A2A Registry")
    except Exception as e:
        print(f"⚠️  Unregistration error: {e}")
```

#### 4. Modify the `start()` method:

**Before:**
```python
async def start(self):
    """Start the agent server"""
    self.server = await asyncio.start_server(
        self.handle_client, self.host, self.port
    )
    # ... rest of code ...
```

**After:**
```python
async def start(self):
    """Start the agent server"""
    # Register with registry first
    await self.register_with_registry()
    
    # Start heartbeat task if registered
    if self.registered:
        self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
    
    self.server = await asyncio.start_server(
        self.handle_client, self.host, self.port
    )
    # ... rest of code ...
```

#### 5. Add a `stop()` method:

```python
async def stop(self):
    """Stop the server gracefully"""
    print("\n🛑 Shutting down server...")
    
    # Cancel heartbeat task
    if self.heartbeat_task:
        self.heartbeat_task.cancel()
        try:
            await self.heartbeat_task
        except asyncio.CancelledError:
            pass
    
    # Unregister from registry
    await self.unregister_from_registry()
    
    # Close server
    if self.server:
        self.server.close()
        await self.server.wait_closed()
    
    print("✅ Server stopped")
```

#### 6. Update `main()` function:

**Before:**
```python
async def main():
    agent = CryptoAgent()
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n")
```

**After:**
```python
async def main():
    agent = CryptoAgent()
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n")
        await agent.stop()  # Add this
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        await agent.stop()  # Add this
```

### Modify `client/a2a_client.py`

#### 1. Add import at the top:
```python
import httpx  # Add this
from typing import List  # Update this import
```

#### 2. Add to `__init__` method:
```python
def __init__(self, client_id: str = None, 
             registry_url: str = "http://localhost:8000"):  # Add registry_url
    # ... existing code ...
    self.registry_url = registry_url  # Add this
```

#### 3. Add these new methods to the class:

```python
async def discover_agents(self, capability: str = None) -> List[Dict]:
    """Discover agents from the registry"""
    try:
        async with httpx.AsyncClient() as client:
            params = {}
            if capability:
                params["capability"] = capability
            
            response = await client.get(
                f"{self.registry_url}/agents/discover",
                params=params,
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("agents", [])
            else:
                print(f"⚠️  Discovery failed: {response.status_code}")
                return []
                
    except httpx.ConnectError:
        print(f"❌ Could not connect to registry at {self.registry_url}")
        return []
    except Exception as e:
        print(f"❌ Discovery error: {e}")
        return []

async def discover_and_connect(self, capability: str = "get_price"):
    """Discover an agent and connect to it"""
    print(f"🔍 Discovering agents with '{capability}' capability...")
    
    agents = await self.discover_agents(capability)
    
    if not agents:
        print(f"❌ No agents found with '{capability}' capability")
        raise Exception("No suitable agents available")
    
    print(f"✅ Found {len(agents)} agent(s)")
    
    # Select first healthy agent
    agent_info = agents[0]
    agent_card = agent_info["agent_card"]
    endpoint = agent_info["endpoint"]
    
    print(f"📡 Selected: {agent_card['name']}")
    print(f"   Endpoint: {endpoint}")
    
    # Parse endpoint and connect
    host, port = endpoint.split(":")
    await self.connect(host, int(port))
```

#### 4. Modify `interactive_client()` function:

**Change the connect line from:**
```python
await client.connect()  # Old way
```

**To:**
```python
await client.discover_and_connect(capability="get_price")  # New way
```

---

## Testing the Integration

### Step 1: Start the Registry Server

```bash
cd a2a_crypto_simple_registry_example_1/registry
python registry_server.py
```

Expected output:
```
🚀 Starting Agent Registry Server...
✅ Registry is ready
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 2: Start the Crypto Agent Server

In a new terminal:

```bash
cd a2a_crypto_simple_registry_example_1/server
python crypto_agent_server.py
```

Expected output:
```
✅ Registered with A2A Registry
   Status: registered
🚀 Crypto Agent Server started on 127.0.0.1:8888
💓 Heartbeat sent to registry
```

### Step 3: Run the Client

In a new terminal:

```bash
cd a2a_crypto_simple_registry_example_1/client
python a2a_client.py
```

Expected output:
```
🔍 Discovering agents with 'get_price' capability...
✅ Found 1 agent(s)
📡 Selected: CryptoPriceAgent
   Endpoint: localhost:8888
🔗 Connecting to localhost:8888...
✅ Connected successfully
🤝 Handshake complete with: CryptoPriceAgent
```

### Step 4: Test Discovery

List all registered agents:

```bash
python a2a_client.py --list
```

Expected output:
```
Found 1 agent(s):

1. CryptoPriceAgent (v1.0.0)
   ID: crypto-agent-001
   Description: AI Agent providing fictitious cryptocurrency prices
   Endpoint: localhost:8888
   Capabilities: get_price, list_currencies, get_agent_info
   Health: healthy
```

---

## Summary of Changes

### Server Changes (crypto_agent_server.py)
1. ✅ Added `httpx` import
2. ✅ Added `registry_url`, `heartbeat_task`, `registered` to `__init__`
3. ✅ Added `register_with_registry()` method
4. ✅ Added `send_heartbeat()` method
5. ✅ Added `unregister_from_registry()` method
6. ✅ Modified `start()` to register and start heartbeat
7. ✅ Added `stop()` method for graceful shutdown
8. ✅ Updated `main()` to call `stop()`

**Lines added: ~80**

### Client Changes (a2a_client.py)
1. ✅ Added `httpx` import
2. ✅ Added `registry_url` to `__init__`
3. ✅ Added `discover_agents()` method
4. ✅ Added `discover_and_connect()` method
5. ✅ Changed `interactive_client()` to use discovery

**Lines added: ~50**

---

## What You Get

### Without Registry (Original)
```
Client → hardcoded localhost:8888 → Crypto Agent
```

### With Registry (New)
```
Client → Registry (discover "get_price") → Get endpoint → Connect to Crypto Agent
                                           ↑
Crypto Agent → Register on startup ────────┘
            → Send heartbeats every 30s
```

### Benefits
✅ **Dynamic Discovery** - No hardcoded addresses  
✅ **Health Monitoring** - Registry knows if agents are alive  
✅ **Scalability** - Can have multiple agents  
✅ **Flexibility** - Add/remove agents without changing client code  

---

## Troubleshooting

### "Could not connect to registry"
- Make sure registry server is running on port 8000
- Check: `curl http://localhost:8000/`

### "No agents found"
- Make sure crypto agent server is running
- Check it registered: `curl http://localhost:8000/agents`

### "Agent shows as unhealthy"
- Check if heartbeats are being sent (look for 💓 in server output)
- Verify crypto agent is still running
- Wait 30 seconds for next heartbeat

### ImportError: No module named 'httpx'
```bash
pip install httpx
```

---

## Next Steps

After successful integration:

1. **Add a second crypto agent** on a different port (8889)
2. **Watch the client discover both** agents
3. **Stop one agent** and see the client use the other
4. **Experiment with capabilities** - add new agent types
5. **Build a dashboard** showing all registered agents

Happy coding! 🚀