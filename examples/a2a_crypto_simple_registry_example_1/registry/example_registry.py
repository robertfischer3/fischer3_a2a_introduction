"""
Example: Register an agent with the registry
Shows how agents can register themselves with the A2A Registry
"""

import asyncio
import httpx
from datetime import datetime


async def register_agent():
    """Example agent registration"""
    
    # Agent card data
    agent_card = {
        "agent_id": "crypto-agent-001",
        "name": "CryptoPriceAgent",
        "version": "1.0.0",
        "description": "Provides fictitious cryptocurrency prices for demonstration",
        "capabilities": ["get_price", "list_currencies", "get_agent_info"],
        "supported_protocols": ["A2A/1.0"],
        "metadata": {
            "supported_currencies": ["BTC", "ETH", "XRP"],
            "data_source": "fictitious",
            "update_frequency": "on_request"
        }
    }
    
    # Registration data
    registration_data = {
        "agent_card": agent_card,
        "endpoint": "localhost:8888"
    }
    
    # Registry endpoint
    registry_url = "http://localhost:8000"
    
    try:
        async with httpx.AsyncClient() as client:
            print("=" * 60)
            print("  Registering Agent with A2A Registry")
            print("=" * 60)
            print(f"\nAgent: {agent_card['name']}")
            print(f"ID: {agent_card['agent_id']}")
            print(f"Capabilities: {', '.join(agent_card['capabilities'])}")
            print(f"\nRegistry: {registry_url}")
            print("\nRegistering...")
            
            # Register agent
            response = await client.post(
                f"{registry_url}/agents/register",
                json=registration_data,
                timeout=10.0
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                print(f"\n✅ {result['message']}")
                print(f"Status: {result['status']}")
                print(f"Agent ID: {result['agent_id']}")
            else:
                print(f"\n❌ Registration failed: {response.status_code}")
                print(response.text)
            
            # Send a heartbeat
            print("\n" + "-" * 60)
            print("Sending heartbeat...")
            
            heartbeat_response = await client.put(
                f"{registry_url}/agents/{agent_card['agent_id']}/heartbeat",
                timeout=5.0
            )
            
            if heartbeat_response.status_code == 200:
                hb_result = heartbeat_response.json()
                print(f"✅ Heartbeat acknowledged")
                print(f"Timestamp: {hb_result['timestamp']}")
            
            # Get agent details back from registry
            print("\n" + "-" * 60)
            print("Retrieving agent details...")
            
            get_response = await client.get(
                f"{registry_url}/agents/{agent_card['agent_id']}",
                timeout=5.0
            )
            
            if get_response.status_code == 200:
                agent_info = get_response.json()
                print(f"✅ Agent found in registry")
                print(f"Health status: {agent_info['health_status']}")
                print(f"Registered at: {agent_info['registered_at']}")
                print(f"Endpoint: {agent_info['endpoint']}")
            
            print("\n" + "=" * 60)
            print("✅ Registration example complete!")
            print("=" * 60)
            
    except httpx.ConnectError:
        print("\n❌ Could not connect to registry!")
        print("Make sure the registry server is running on http://localhost:8000")
        print("Run: python registry_server.py")
    except Exception as e:
        print(f"\n❌ Error: {e}")


async def discover_agents():
    """Example agent discovery"""
    
    registry_url = "http://localhost:8000"
    
    try:
        async with httpx.AsyncClient() as client:
            print("\n" + "=" * 60)
            print("  Discovering Agents by Capability")
            print("=" * 60)
            
            # Search for agents with 'get_price' capability
            capability = "get_price"
            print(f"\nSearching for agents with '{capability}' capability...")
            
            response = await client.get(
                f"{registry_url}/agents/discover",
                params={"capability": capability},
                timeout=5.0
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n✅ Found {result['count']} agent(s):")
                
                for agent in result['agents']:
                    card = agent['agent_card']
                    print(f"\n  - {card['name']} (v{card['version']})")
                    print(f"    ID: {card['agent_id']}")
                    print(f"    Endpoint: {agent['endpoint']}")
                    print(f"    Capabilities: {', '.join(card['capabilities'])}")
                    print(f"    Status: {agent['health_status']}")
            
            print("\n" + "=" * 60)
            
    except httpx.ConnectError:
        print("\n❌ Could not connect to registry!")
        print("Make sure the registry server is running on http://localhost:8000")
    except Exception as e:
        print(f"\n❌ Error: {e}")


async def main():
    """Run examples"""
    # First register an agent
    await register_agent()
    
    # Wait a moment
    await asyncio.sleep(1)
    
    # Then discover agents
    await discover_agents()


if __name__ == "__main__":
    asyncio.run(main())