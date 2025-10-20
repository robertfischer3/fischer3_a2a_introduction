# A2A Simple Agent Registry

A lightweight Agent Registry implementation for the Agent2Agent (A2A) protocol using FastAPI. This registry enables service discovery, health monitoring, and capability-based agent lookup.

## Overview

The Agent Registry serves as a central directory where A2A agents can:
- **Register** themselves with their capabilities
- **Discover** other agents by capability
- **Monitor** health status via heartbeats
- **Query** agent details and endpoints

## Features

✅ **Agent Registration** - Register agents with their Agent Cards  
✅ **Capability-Based Discovery** - Find agents by specific capabilities  
✅ **Health Monitoring** - Automatic health checks with heartbeat mechanism  
✅ **RESTful API** - Standard HTTP API with automatic documentation  
✅ **In-Memory Storage** - Fast, lightweight storage for training/development  
✅ **Thread-Safe** - Concurrent request handling  

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
# Navigate to the project directory
cd a2a_crypto_simple_registry_example

# Install required packages
pip install -r requirements.txt
```

## Quick Start

### 1. Start the Registry Server

```bash
python registry_server.py
```

The server will start on `http://localhost:8000`

You should see:
```
==================================================
  A2A Agent Registry Server
==================================================

🚀 Starting Agent Registry Server...
💓 Health monitor initialized (check every 30s, stale after 90s)
📦 Initialized in-memory agent storage
💚 Health monitor started
✅ Registry is ready
```

### 2. View API Documentation

Open your browser to:
- **Interactive API Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Registry Info**: http://localhost:8000/

### 3. Register an Agent

Run the example registration script:

```bash
python example_register.py
```

Or use curl:

```bash
curl -X POST "http://localhost:8000/agents/register" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_card": {
      "agent_id": "test-agent-001",
      "name": "TestAgent",
      "version": "1.0.0",
      "description": "A test agent",
      "capabilities": ["test_capability"],
      "supported_protocols": ["A2A/1.0"],
      "metadata": {}
    },
    "endpoint": "localhost:9000"
  }'
```

### 4. Discover Agents

Find agents by capability:

```bash
curl "http://localhost:8000/agents/discover?capability=get_price"
```

List all agents:

```bash
curl "http://localhost:8000/agents"
```

## API Endpoints

### Agent Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/agents/register` | Register a new agent |
| `GET` | `/agents/discover` | Discover agents by capability |
| `GET` | `/agents/{agent_id}` | Get specific agent details |
| `PUT` | `/agents/{agent_id}/heartbeat` | Send heartbeat (health check) |
| `DELETE` | `/agents/{agent_id}` | Unregister an agent |
| `GET` | `/agents` | List all registered agents |

### Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Registry service health |
| `GET` | `/stats` | Registry statistics |
| `GET` | `/` | Registry information |

## Usage Examples

### Register an Agent (Python)

```python
import httpx
import asyncio

async def register():
    agent_card = {
        "agent_id": "my-agent-001",
        "name": "MyAgent",
        "version": "1.0.0",
        "description": "My custom agent",
        "capabilities": ["capability1", "capability2"],
        "supported_protocols": ["A2A/1.0"],
        "metadata": {"key": "value"}
    }
    
    registration = {
        "agent_card": agent_card,
        "endpoint": "localhost:8888"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/agents/register",
            json=registration
        )
        print(response.json())

asyncio.run(register())
```

### Discover Agents (Python)

```python
import httpx
import asyncio

async def discover():
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "http://localhost:8000/agents/discover",
            params={"capability": "get_price", "limit": 10}
        )
        
        result = response.json()
        print(f"Found {result['count']} agents:")
        for agent in result['agents']:
            card = agent['agent_card']
            print(f"  - {card['name']} at {agent['endpoint']}")

asyncio.run(discover())
```

### Send Heartbeat (Python)

```python
import httpx
import asyncio

async def heartbeat(agent_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.put(
            f"http://localhost:8000/agents/{agent_id}/heartbeat"
        )
        print(response.json())

asyncio.run(heartbeat("my-agent-001"))
```

## Health Monitoring

The registry includes automatic health monitoring:

- **Heartbeat Interval**: Agents should send heartbeats every 30-60 seconds
- **Stale Threshold**: Agents without heartbeats for 90 seconds are marked unhealthy
- **Auto-Discovery**: Only healthy agents appear in discovery results (by default)
- **Background Monitoring**: Health checks run automatically every 30 seconds

### Keeping Your Agent Healthy

Agents should implement a heartbeat loop:

```python
import asyncio
import httpx

async def heartbeat_loop(agent_id: str, interval: int = 30):
    """Send periodic heartbeats to registry"""
    async with httpx.AsyncClient() as client:
        while True:
            try:
                await client.put(
                    f"http://localhost:8000/agents/{agent_id}/heartbeat"
                )
                print(f"💓 Heartbeat sent")
            except Exception as e:
                print(f"⚠️ Heartbeat failed: {e}")
            
            await asyncio.sleep(interval)
```

## Integration with A2A Crypto Example

To integrate with the existing crypto example:

### 1. Modify Crypto Agent Server

Add registration on startup:

```python
# In crypto_agent_server.py
async def register_with_registry():
    """Register this agent with the registry"""
    agent_card = {
        "agent_id": "crypto-agent-001",
        "name": "CryptoPriceAgent",
        "version": "1.0.0",
        "description": "Cryptocurrency price agent",
        "capabilities": ["get_price", "list_currencies"],
        "supported_protocols": ["A2A/1.0"],
        "metadata": {
            "supported_currencies": ["BTC", "ETH", "XRP"]
        }
    }
    
    registration = {
        "agent_card": agent_card,
        "endpoint": "localhost:8888"
    }
    
    async with httpx.AsyncClient() as client:
        await client.post(
            "http://localhost:8000/agents/register",
            json=registration
        )
```

### 2. Modify Client for Discovery

```python
# In a2a_client.py
async def discover_and_connect():
    """Discover crypto agent via registry"""
    async with httpx.AsyncClient() as client:
        # Discover agent
        response = await client.get(
            "http://localhost:8000/agents/discover",
            params={"capability": "get_price"}
        )
        
        agents = response.json()["agents"]
        if not agents:
            raise Exception("No crypto agents available")
        
        # Connect to first available agent
        endpoint = agents[0]["endpoint"]
        host, port = endpoint.split(":")
        await connect(host, int(port))
```

## Architecture

```
┌─────────────────────────────────┐
│     FastAPI Application         │
│  (registry_server.py)           │
├─────────────────────────────────┤
│  REST API Endpoints             │
│  - Register, Discover, Health   │
└────────┬───────────┬────────────┘
         │           │
         ↓           ↓
┌─────────────┐  ┌──────────────┐
│  Storage    │  │ Health       │
│  (memory)   │  │ Monitor      │
│             │  │ (background) │
└─────────────┘  └──────────────┘
```

## Configuration

### Health Monitor Settings

Edit `health_monitor.py`:

```python
# Check interval (seconds between health checks)
check_interval = 30

# Stale threshold (seconds without heartbeat = unhealthy)
stale_threshold = 90
```

### Server Settings

Edit `registry_server.py`:

```python
# Change host/port
uvicorn.run(
    app,
    host="0.0.0.0",  # Listen on all interfaces
    port=8000,       # Registry port
    log_level="info"
)
```

## Testing

### Manual Testing

1. Start the registry server
2. Run `example_register.py` to register test agents
3. Visit http://localhost:8000/docs to test API interactively
4. Use curl or httpx to test endpoints

### Automated Testing

Create `test_registry.py`:

```python
import pytest
from httpx import AsyncClient
from registry_server import app

@pytest.mark.asyncio
async def test_register_agent():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post("/agents/register", json={
            "agent_card": {
                "agent_id": "test-001",
                "name": "TestAgent",
                "version": "1.0.0",
                "description": "Test",
                "capabilities": ["test"],
                "supported_protocols": ["A2A/1.0"],
                "metadata": {}
            },
            "endpoint": "localhost:9000"
        })
        assert response.status_code == 201
```

Run tests:
```bash
pip install pytest pytest-asyncio httpx
pytest test_registry.py
```

## Limitations (Training Version)

This is a simplified registry for training purposes:

- ⚠️ **In-Memory Storage**: Data lost on restart (use SQLite/Redis for persistence)
- ⚠️ **No Authentication**: No API keys or auth (add for production)
- ⚠️ **Single Instance**: Not distributed (use Consul/etcd for HA)
- ⚠️ **Basic Validation**: Minimal security checks (enhance for production)

## Production Enhancements

For production use, consider:

1. **Persistent Storage**: PostgreSQL, MongoDB, or Redis
2. **Authentication**: OAuth 2.0, API keys, mTLS
3. **High Availability**: Multiple registry instances with consensus
4. **Rate Limiting**: Prevent abuse
5. **Monitoring**: Prometheus metrics, distributed tracing
6. **Caching**: Redis for faster lookups
7. **Security**: Input validation, certificate verification
8. **Logging**: Structured logging to ELK/Splunk

## Troubleshooting

### Registry won't start
- Check if port 8000 is available
- Verify Python 3.8+ is installed
- Ensure all dependencies are installed

### Can't register agent
- Verify registry is running on http://localhost:8000
- Check agent_card has required fields
- Ensure capabilities list is not empty

### Agent shows as unhealthy
- Send heartbeats every 30-60 seconds
- Check network connectivity to registry
- Verify agent_id matches registration

### Discovery returns no agents
- Agents might be unhealthy (check `/agents?include_unhealthy=true`)
- Capability name might not match exactly
- Agents might not be registered yet

## License

This implementation is provided as part of the A2A protocol training materials for educational purposes.

## Next Steps

1. **Start the registry server**
2. **Run the example registration script**
3. **Modify the crypto agent to auto-register**
4. **Update the client to use discovery**
5. **Experiment with multiple agents**

Happy agent orchestrating! 🤖✨