# Build Your First Agent

Learn to build a complete A2A agent from scratch in this hands-on tutorial.

## What You'll Build

A simple **Bond Market Agent** that:
- ✅ Registers with the A2A registry
- ✅ Provides Treasury bond yields and interest rates
- ✅ Sends health heartbeats
- ✅ Follows A2A protocol standards

**Time to complete**: 30-45 minutes

## Prerequisites

Before starting, make sure you have:
- [ ] Completed the [Installation Guide](installation.md)
- [ ] Basic Python knowledge (async/await, classes)
- [ ] Registry server running (from Quick Start)
- [ ] Text editor or IDE ready

---

## Architecture Overview

```
┌─────────────┐
│   Registry  │ ← Our agent will register here
└─────────────┘
       ↑
       │ (register, heartbeat)
       │
┌─────────────┐
│Bond Market  │ ← We'll build this
│    Agent    │
└─────────────┘
       ↑
       │ (discovery, queries)
       │
┌─────────────┐
│   Client    │ ← We'll build this too
└─────────────┘
```

---

## Part 1: Create the Agent

### Step 1: Set Up Project Structure

```bash
# Create project directory
mkdir my_bond_agent
cd my_bond_agent

# Create file structure
touch bond_agent.py
touch agent_client.py
touch requirements.txt
```

### Step 2: Define Dependencies

**requirements.txt:**
```txt
httpx==0.25.0
```

Install:
```bash
pip install -r requirements.txt
# or
uv pip install -r requirements.txt
```

### Step 3: Create the Agent Card

Open `bond_agent.py` and start coding:

```python
"""
Simple Bond Market Agent - A2A Protocol Example
Provides Treasury bond yields and interest rates
"""

import asyncio
import httpx
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List


class BondMarketAgent:
    """A simple A2A agent that provides bond yields and interest rates"""
    
    def __init__(
        self,
        agent_id: str = "bond-market-agent-001",
        host: str = "localhost",
        port: int = 9000,
        registry_url: str = "http://localhost:8000"
    ):
        self.agent_id = agent_id
        self.host = host
        self.port = port
        self.registry_url = registry_url
        
        # Agent Card - Our identity and capabilities
        self.agent_card = {
            "agent_id": self.agent_id,
            "name": "BondMarketAgent",
            "version": "1.0.0",
            "description": "Provides US Treasury bond yields and interest rate information",
            "capabilities": [
                "get_yield",
                "get_yield_curve",
                "list_maturities"
            ],
            "supported_protocols": ["A2A/1.0"],
            "metadata": {
                "market": "US Treasury",
                "supported_maturities": ["1M", "3M", "6M", "1Y", "2Y", "5Y", "10Y", "30Y"],
                "data_type": "simulated",
                "update_frequency": "real-time"
            }
        }
        
        # Treasury bond maturities
        self.maturities = {
            "1M": {"name": "1-Month", "base_yield": 5.25},
            "3M": {"name": "3-Month", "base_yield": 5.35},
            "6M": {"name": "6-Month", "base_yield": 5.40},
            "1Y": {"name": "1-Year", "base_yield": 5.10},
            "2Y": {"name": "2-Year", "base_yield": 4.85},
            "5Y": {"name": "5-Year", "base_yield": 4.50},
            "10Y": {"name": "10-Year", "base_yield": 4.35},
            "30Y": {"name": "30-Year", "base_yield": 4.55}
        }
        
        self.heartbeat_task = None
        self.registered = False
```

### Step 4: Implement Registry Integration

Add these methods to the `BondMarketAgent` class:

```python
    async def register_with_registry(self):
        """Register this agent with the A2A Registry"""
        registration_data = {
            "agent_card": self.agent_card,
            "endpoint": f"{self.host}:{self.port}"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.registry_url}/agents/register",
                    json=registration_data,
                    timeout=10.0
                )
                
                if response.status_code == 201:
                    result = response.json()
                    self.registered = True
                    print(f"✅ Registered with A2A Registry")
                    print(f"   Status: {result.get('message')}")
                    return True
                else:
                    print(f"⚠️  Registration failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            print(f"❌ Could not connect to registry: {e}")
            return False
    
    async def send_heartbeat(self):
        """Send periodic heartbeat to registry"""
        while self.registered:
            try:
                async with httpx.AsyncClient() as client:
                    await client.put(
                        f"{self.registry_url}/agents/{self.agent_id}/heartbeat",
                        timeout=5.0
                    )
                    print(f"💓 Heartbeat sent to registry")
            except Exception as e:
                print(f"⚠️  Heartbeat failed: {e}")
            
            # Wait 30 seconds before next heartbeat
            await asyncio.sleep(30)
    
    async def unregister(self):
        """Unregister from registry on shutdown"""
        if not self.registered:
            return
        
        try:
            async with httpx.AsyncClient() as client:
                await client.delete(
                    f"{self.registry_url}/agents/{self.agent_id}",
                    timeout=5.0
                )
                print(f"👋 Unregistered from registry")
                self.registered = False
        except Exception as e:
            print(f"⚠️  Unregister failed: {e}")
```

### Step 5: Implement Bond Market Logic

Add the core functionality:

```python
    def get_yield(self, maturity: str) -> Dict[str, Any]:
        """Get current yield for a specific maturity (simulated)"""
        if maturity not in self.maturities:
            return {
                "error": f"Maturity '{maturity}' not supported",
                "supported_maturities": list(self.maturities.keys())
            }
        
        bond_info = self.maturities[maturity]
        # Add small random variation to base yield
        current_yield = bond_info["base_yield"] + random.uniform(-0.15, 0.15)
        
        return {
            "maturity": maturity,
            "name": bond_info["name"],
            "yield": round(current_yield, 2),
            "yield_percentage": f"{round(current_yield, 2)}%",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "market": "US Treasury"
        }
    
    def get_yield_curve(self) -> Dict[str, Any]:
        """Get the entire yield curve"""
        curve = []
        
        for maturity, info in self.maturities.items():
            # Add small random variation
            current_yield = info["base_yield"] + random.uniform(-0.10, 0.10)
            curve.append({
                "maturity": maturity,
                "name": info["name"],
                "yield": round(current_yield, 2)
            })
        
        # Determine curve shape
        short_term = curve[0]["yield"]  # 1M
        long_term = curve[-1]["yield"]   # 30Y
        
        if long_term > short_term + 0.3:
            shape = "normal"  # Upward sloping
        elif short_term > long_term + 0.3:
            shape = "inverted"  # Downward sloping
        else:
            shape = "flat"
        
        return {
            "curve": curve,
            "shape": shape,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "market": "US Treasury"
        }
    
    def list_maturities(self) -> Dict[str, Any]:
        """List all supported bond maturities"""
        maturities = [
            {
                "code": maturity,
                "name": info["name"],
                "typical_yield_range": f"{info['base_yield'] - 0.5}% - {info['base_yield'] + 0.5}%"
            }
            for maturity, info in self.maturities.items()
        ]
        
        return {
            "maturities": maturities,
            "count": len(maturities),
            "market": "US Treasury"
        }
    
    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming A2A requests"""
        action = request.get("action")
        params = request.get("params", {})
        
        if action == "get_yield":
            maturity = params.get("maturity", "")
            return self.get_yield(maturity)
        
        elif action == "get_yield_curve":
            return self.get_yield_curve()
        
        elif action == "list_maturities":
            return self.list_maturities()
        
        elif action == "get_agent_info":
            return self.agent_card
        
        else:
            return {
                "error": f"Unknown action: {action}",
                "supported_actions": ["get_yield", "get_yield_curve", "list_maturities", "get_agent_info"]
            }
```

### Step 6: Add Start/Stop Methods

```python
    async def start(self):
        """Start the agent"""
        print("=" * 60)
        print(f"📊 {self.agent_card['name']} v{self.agent_card['version']}")
        print("=" * 60)
        print(f"Agent ID: {self.agent_id}")
        print(f"Endpoint: {self.host}:{self.port}")
        print(f"Capabilities: {', '.join(self.agent_card['capabilities'])}")
        print(f"Market: US Treasury Bonds")
        print()
        
        # Register with registry
        await self.register_with_registry()
        
        # Start heartbeat task
        if self.registered:
            self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
            print(f"✅ Agent started successfully")
            print(f"📡 Ready to provide bond market data")
        else:
            print(f"⚠️  Agent started but not registered")
    
    async def stop(self):
        """Stop the agent gracefully"""
        print("\n🛑 Shutting down agent...")
        
        # Cancel heartbeat
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Unregister from registry
        await self.unregister()
        print("✅ Agent stopped")


async def main():
    """Main entry point"""
    agent = BondMarketAgent()
    
    try:
        await agent.start()
        
        # Keep agent running
        print("\nPress Ctrl+C to stop the agent\n")
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("\n")  # New line after ^C
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

### Step 7: Test the Agent

```bash
# Make sure registry is running first
cd registry && python registry_server.py

# In a new terminal, start your agent
python bond_agent.py
```

You should see:
```
============================================================
📊 BondMarketAgent v1.0.0
============================================================
Agent ID: bond-market-agent-001
Endpoint: localhost:9000
Capabilities: get_yield, get_yield_curve, list_maturities
Market: US Treasury Bonds

✅ Registered with A2A Registry
   Status: Agent registered successfully
✅ Agent started successfully
📡 Ready to provide bond market data

Press Ctrl+C to stop the agent

💓 Heartbeat sent to registry
```

---

## Part 2: Create a Client

### Step 8: Build the Client

Create `agent_client.py`:

```python
"""
Bond Market Agent Client
Discovers and interacts with the Bond Market Agent via A2A Registry
"""

import asyncio
import httpx
from typing import Optional, Dict, Any


class BondMarketClient:
    """Client for interacting with Bond Market Agent"""
    
    def __init__(self, registry_url: str = "http://localhost:8000"):
        self.registry_url = registry_url
        self.agent_endpoint = None
    
    async def discover_bond_agent(self) -> Optional[str]:
        """Discover Bond Market Agent via registry"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.registry_url}/agents/discover",
                    params={"capability": "get_yield"},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    agents = result.get("agents", [])
                    
                    if agents:
                        agent = agents[0]  # Get first agent
                        endpoint = agent.get("endpoint")
                        name = agent["agent_card"]["name"]
                        
                        print(f"✅ Discovered: {name}")
                        print(f"   Endpoint: {endpoint}")
                        print(f"   Market: {agent['agent_card']['metadata']['market']}")
                        self.agent_endpoint = endpoint
                        return endpoint
                    else:
                        print("⚠️  No bond market agents found")
                        return None
                        
        except Exception as e:
            print(f"❌ Discovery failed: {e}")
            return None
    
    def send_request(self, action: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send request to agent
        
        Note: This is simplified - in real A2A, you'd establish a connection
        and use the A2A protocol message format
        """
        # For this tutorial, we'll simulate the request
        # In production, you'd connect to the agent and exchange A2A messages
        request = {
            "action": action,
            "params": params or {}
        }
        
        # Simulated response (in real implementation, send via network)
        print(f"\n📤 Request: {action} {params or ''}")
        return request
    
    async def get_yield(self, maturity: str):
        """Get yield for a specific maturity"""
        if not self.agent_endpoint:
            print("❌ No agent endpoint. Run discover_bond_agent() first")
            return
        
        print(f"\n📊 Getting yield for {maturity}...")
        # In production: send actual A2A request to agent
        # For tutorial: show the request structure
        request = self.send_request("get_yield", {"maturity": maturity})
        print(f"✅ Request would be sent to: {self.agent_endpoint}")
    
    async def get_yield_curve(self):
        """Get the entire yield curve"""
        if not self.agent_endpoint:
            print("❌ No agent endpoint. Run discover_bond_agent() first")
            return
        
        print(f"\n📈 Getting yield curve...")
        request = self.send_request("get_yield_curve")
        print(f"✅ Request would be sent to: {self.agent_endpoint}")
    
    async def list_maturities(self):
        """List supported maturities"""
        if not self.agent_endpoint:
            print("❌ No agent endpoint. Run discover_bond_agent() first")
            return
        
        print(f"\n📋 Listing supported maturities...")
        request = self.send_request("list_maturities")
        print(f"✅ Request would be sent to: {self.agent_endpoint}")


async def main():
    """Interactive client demo"""
    print("=" * 60)
    print("Bond Market Agent Client")
    print("=" * 60)
    print()
    
    client = BondMarketClient()
    
    # Discover agent
    print("🔍 Discovering Bond Market Agent...")
    endpoint = await client.discover_bond_agent()
    
    if not endpoint:
        print("\n❌ Could not find Bond Market Agent")
        print("Make sure:")
        print("  1. Registry is running (port 8000)")
        print("  2. Bond agent is running")
        return
    
    print("\n" + "=" * 60)
    print("Available Commands:")
    print("  yield <maturity>  - Get yield for maturity (e.g., 10Y)")
    print("  curve             - View entire yield curve")
    print("  maturities        - List supported maturities")
    print("  quit              - Exit")
    print("=" * 60)
    print("\nExample: yield 10Y")
    
    while True:
        try:
            cmd = input("\nbonds> ").strip()
            
            if not cmd:
                continue
            
            if cmd == "quit":
                break
            
            elif cmd == "maturities":
                await client.list_maturities()
            
            elif cmd == "curve":
                await client.get_yield_curve()
            
            elif cmd.startswith("yield "):
                maturity = cmd[6:].strip().upper()
                if maturity:
                    await client.get_yield(maturity)
                else:
                    print("Usage: yield <maturity> (e.g., yield 10Y)")
            
            else:
                print(f"Unknown command: {cmd}")
                print("Type 'maturities', 'curve', or 'yield <maturity>'")
        
        except KeyboardInterrupt:
            print("\n")
            break
    
    print("\n👋 Goodbye!")


if __name__ == "__main__":
    asyncio.run(main())
```

### Step 9: Test the Complete System

Terminal 1 - Start Registry:
```bash
cd registry && python registry_server.py
```

Terminal 2 - Start Bond Market Agent:
```bash
python bond_agent.py
```

Terminal 3 - Run Client:
```bash
python agent_client.py
```

Try these commands:
```
bonds> maturities
bonds> yield 10Y
bonds> yield 2Y
bonds> curve
```

---

## Part 3: Enhance Your Agent

### Add More Capabilities

Add a historical yield analysis capability:

```python
def get_historical_spread(self, short_term: str = "2Y", long_term: str = "10Y") -> Dict[str, Any]:
    """Calculate yield spread between two maturities"""
    if short_term not in self.maturities or long_term not in self.maturities:
        return {"error": "Invalid maturities"}
    
    short_yield = self.maturities[short_term]["base_yield"] + random.uniform(-0.10, 0.10)
    long_yield = self.maturities[long_term]["base_yield"] + random.uniform(-0.10, 0.10)
    spread = long_yield - short_yield
    
    # Interpret the spread
    if spread > 0.5:
        interpretation = "Normal steep curve - economic expansion expected"
    elif spread < -0.2:
        interpretation = "Inverted curve - potential recession signal"
    else:
        interpretation = "Flat curve - economic uncertainty"
    
    return {
        "short_term": {
            "maturity": short_term,
            "yield": round(short_yield, 2)
        },
        "long_term": {
            "maturity": long_term,
            "yield": round(long_yield, 2)
        },
        "spread": round(spread, 2),
        "spread_bps": int(spread * 100),  # Basis points
        "interpretation": interpretation,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
```

Update the agent card:
```python
"capabilities": [
    "get_yield",
    "get_yield_curve",
    "get_historical_spread",  # Add this
    "list_maturities"
],
```

---

## What You've Learned

✅ How to create an A2A agent from scratch  
✅ How to register with an A2A registry  
✅ How to implement health heartbeats  
✅ How to define capabilities in an Agent Card  
✅ How to build a client that discovers agents  
✅ Basic A2A architecture patterns  

## Next Steps

1. **Add Security**: Implement authentication tags
2. **Add Persistence**: Store historical yield data in a database
3. **Add Real Data**: Connect to Federal Reserve API for live rates
4. **Add Streaming**: Real-time yield updates via SSE
5. **Deploy**: Run your agent in production

## Further Reading

- **[A2A Protocol Overview](../a2a/00_A2A_OVERVIEW.md)** - Deep dive into the protocol
- **[Security Best Practices](../a2a/03_SECURITY/04_security_best_practices.md)** - Secure your agent
- **[Example Projects](../../examples/)** - More complete examples

---

**🎉 Congratulations!** You've built your first A2A agent with financial market capabilities.

Ready to learn more? Explore the [complete documentation](../a2a/INDEX.md).