"""
A2A Client Application (Registry-Integrated)
Discovers and connects to agents via the A2A Registry
"""

import asyncio
import json
import httpx
import sys
import os
from typing import Optional, Dict, Any, List
from datetime import datetime

# Add shared module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.a2a_protocol import (
    A2AMessage,
    MessageType,
    AgentCard,
    RequestMethod,
    A2AProtocol
)


class A2AClient:
    """
    A2A Client with Registry Discovery
    """
    
    def __init__(self, client_id: str = None, registry_url: str = "http://localhost:8000"):
        self.client_id = client_id or f"client-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.registry_url = registry_url
        self.reader = None
        self.writer = None
        self.connected = False
        self.remote_agent: Optional[AgentCard] = None
        
    async def discover_agents(self, capability: str = None) -> List[Dict]:
        """
        Discover agents from the registry
        
        Args:
            capability: Optional capability filter (e.g., "get_price")
            
        Returns:
            List of available agents
        """
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
            print("   Make sure the registry server is running!")
            return []
        except Exception as e:
            print(f"❌ Discovery error: {e}")
            return []
    
    async def discover_and_connect(self, capability: str = "get_price"):
        """
        Discover an agent with the specified capability and connect to it
        
        Args:
            capability: Required capability (default: "get_price")
        """
        print(f"🔍 Discovering agents with '{capability}' capability...")
        
        agents = await self.discover_agents(capability)
        
        if not agents:
            print(f"❌ No agents found with '{capability}' capability")
            print("   Make sure:")
            print("   1. Registry server is running (python registry/registry_server.py)")
            print("   2. Crypto agent is running (python server/crypto_agent_server.py)")
            raise Exception("No suitable agents available")
        
        print(f"✅ Found {len(agents)} agent(s)")
        
        # Select first healthy agent
        agent_info = agents[0]
        agent_card = agent_info["agent_card"]
        endpoint = agent_info["endpoint"]
        
        print(f"📡 Selected: {agent_card['name']} (v{agent_card['version']})")
        print(f"   Endpoint: {endpoint}")
        print(f"   Capabilities: {', '.join(agent_card['capabilities'])}")
        
        # Parse endpoint
        if ":" in endpoint:
            host, port = endpoint.split(":")
            port = int(port)
        else:
            host = endpoint
            port = 8888  # Default port
        
        # Connect to agent
        await self.connect(host, port)
        
    async def connect(self, host: str = 'localhost', port: int = 8888):
        """Connect to an A2A agent server"""
        try:
            print(f"\n🔗 Connecting to {host}:{port}...")
            self.reader, self.writer = await asyncio.open_connection(host, port)
            self.connected = True
            print(f"✅ Connected successfully")
            
            # Send handshake
            await self.handshake()
            
        except ConnectionRefusedError:
            print(f"❌ Failed to connect to {host}:{port}")
            print("   Make sure the agent server is running!")
            raise
        except Exception as e:
            print(f"❌ Connection error: {e}")
            raise
    
    async def handshake(self):
        """Perform A2A handshake with the server"""
        # Create client agent card
        client_card = AgentCard(
            agent_id=self.client_id,
            name="A2A Client",
            version="1.0.0",
            description="Registry-aware A2A client application",
            capabilities=["request", "discovery"],
            supported_protocols=["A2A/1.0"],
            metadata={"registry_url": self.registry_url}
        )
        
        # Send handshake
        handshake_msg = A2AProtocol.create_handshake(self.client_id, client_card)
        await self.send_message(handshake_msg)
        
        # Wait for handshake response
        response = await self.receive_message()
        if response and response.message_type == MessageType.HANDSHAKE_ACK:
            agent_data = response.payload.get("agent_card")
            if agent_data:
                self.remote_agent = AgentCard.from_dict(agent_data)
                print(f"🤝 Handshake complete with: {self.remote_agent.name}")
                print(f"   Agent: {self.remote_agent.description}")
                print()
        else:
            print("⚠️  Handshake failed")
    
    async def send_message(self, message: A2AMessage):
        """Send a message to the server"""
        if not self.connected:
            raise ConnectionError("Not connected to server")
        
        data = message.to_json() + '\n'
        self.writer.write(data.encode('utf-8'))
        await self.writer.drain()
    
    async def receive_message(self) -> Optional[A2AMessage]:
        """Receive a message from the server"""
        if not self.connected:
            return None
        
        try:
            data = await self.reader.readline()
            if not data:
                return None
            
            return A2AMessage.from_json(data.decode('utf-8').strip())
        except Exception as e:
            print(f"⚠️  Error receiving message: {e}")
            return None
    
    async def get_price(self, currency: str) -> Optional[Dict]:
        """Get price for a cryptocurrency"""
        request = A2AProtocol.create_request(
            self.client_id,
            RequestMethod.GET_PRICE,
            {"currency": currency},
            self.remote_agent.agent_id if self.remote_agent else None
        )
        
        await self.send_message(request)
        response = await self.receive_message()
        
        if response:
            if response.message_type == MessageType.RESPONSE:
                return response.payload.get("result")
            elif response.message_type == MessageType.ERROR:
                error_code = response.payload.get("error_code")
                error_msg = response.payload.get("message")
                print(f"❌ Error: {error_code} - {error_msg}")
        
        return None
    
    async def get_supported_currencies(self) -> Optional[List[str]]:
        """Get list of supported currencies"""
        request = A2AProtocol.create_request(
            self.client_id,
            RequestMethod.GET_SUPPORTED_CURRENCIES,
            {},
            self.remote_agent.agent_id if self.remote_agent else None
        )
        
        await self.send_message(request)
        response = await self.receive_message()
        
        if response and response.message_type == MessageType.RESPONSE:
            return response.payload.get("result", {}).get("currencies", [])
        
        return None
    
    async def disconnect(self):
        """Disconnect from the server"""
        if self.connected:
            # Send goodbye message
            goodbye = A2AMessage.create_message(
                MessageType.GOODBYE,
                self.client_id,
                {},
                self.remote_agent.agent_id if self.remote_agent else None
            )
            await self.send_message(goodbye)
            
            # Close connection
            self.writer.close()
            await self.writer.wait_closed()
            self.connected = False
            print("👋 Disconnected from server")


async def list_available_agents(registry_url: str = "http://localhost:8000"):
    """List all available agents in the registry"""
    print("=" * 60)
    print("  Available Agents in Registry")
    print("=" * 60)
    print()
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{registry_url}/agents",
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                agents = result.get("agents", [])
                
                if not agents:
                    print("No agents currently registered.")
                    return
                
                print(f"Found {len(agents)} agent(s):\n")
                
                for i, agent_info in enumerate(agents, 1):
                    card = agent_info["agent_card"]
                    print(f"{i}. {card['name']} (v{card['version']})")
                    print(f"   ID: {card['agent_id']}")
                    print(f"   Description: {card['description']}")
                    print(f"   Endpoint: {agent_info['endpoint']}")
                    print(f"   Capabilities: {', '.join(card['capabilities'])}")
                    print(f"   Health: {agent_info['health_status']}")
                    print()
            else:
                print(f"Failed to fetch agents: {response.status_code}")
                
    except httpx.ConnectError:
        print("❌ Could not connect to registry")
        print(f"   Make sure the registry is running at {registry_url}")
    except Exception as e:
        print(f"❌ Error: {e}")


async def interactive_client():
    """Interactive client interface with registry discovery"""
    print("=" * 60)
    print("  A2A Crypto Price Client (Registry-Enabled)")
    print("=" * 60)
    print()
    
    # Check for --list flag
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        await list_available_agents()
        return
    
    client = A2AClient()
    
    try:
        # Discover and connect to crypto agent
        await client.discover_and_connect(capability="get_price")
        
        # Get supported currencies
        print("📋 Fetching supported currencies...")
        currencies = await client.get_supported_currencies()
        if currencies:
            print(f"   Available: {', '.join(currencies)}\n")
        
        # Interactive loop
        while True:
            print("\n" + "-" * 50)
            print("Options:")
            print("1. Get Bitcoin (BTC) price")
            print("2. Get Ethereum (ETH) price")
            print("3. Get Ripple (XRP) price")
            print("4. Custom currency query")
            print("5. Show all prices")
            print("6. List available agents")
            print("7. Quit")
            
            choice = input("\nEnter choice (1-7): ").strip()
            
            if choice == "1":
                price_data = await client.get_price("BTC")
                if price_data:
                    print(f"\n💰 Bitcoin Price: ${price_data['price']:,.2f}")
                    print(f"   {price_data.get('disclaimer', '')}")
            
            elif choice == "2":
                price_data = await client.get_price("ETH")
                if price_data:
                    print(f"\n💰 Ethereum Price: ${price_data['price']:,.2f}")
                    print(f"   {price_data.get('disclaimer', '')}")
            
            elif choice == "3":
                price_data = await client.get_price("XRP")
                if price_data:
                    print(f"\n💰 Ripple Price: ${price_data['price']:,.2f}")
                    print(f"   {price_data.get('disclaimer', '')}")
            
            elif choice == "4":
                currency = input("Enter currency symbol (BTC/ETH/XRP): ").strip().upper()
                price_data = await client.get_price(currency)
                if price_data:
                    print(f"\n💰 {currency} Price: ${price_data['price']:,.2f}")
                    print(f"   {price_data.get('disclaimer', '')}")
            
            elif choice == "5":
                print("\n📊 All Current Prices:")
                print("-" * 40)
                for currency in ["BTC", "ETH", "XRP"]:
                    price_data = await client.get_price(currency)
                    if price_data:
                        print(f"{currency:5} ${price_data['price']:>12,.2f}")
                print("-" * 40)
            
            elif choice == "6":
                print()
                await list_available_agents(client.registry_url)
            
            elif choice == "7":
                print("\n👋 Goodbye!")
                break
            
            else:
                print("⚠️  Invalid choice. Please enter 1-7.")
        
        await client.disconnect()
        
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user")
        if client.connected:
            await client.disconnect()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if client.connected:
            await client.disconnect()


async def demo_mode():
    """Automated demo mode"""
    print("=" * 60)
    print("  A2A Demo Mode (Registry-Enabled)")
    print("=" * 60)
    print()
    
    client = A2AClient()
    
    try:
        # Discover and connect
        await client.discover_and_connect(capability="get_price")
        
        # Demo sequence
        print("\n🎬 Running automated demo...\n")
        
        await asyncio.sleep(1)
        
        print("1️⃣  Getting Bitcoin price...")
        btc_data = await client.get_price("BTC")
        if btc_data:
            print(f"   💰 BTC: ${btc_data['price']:,.2f}\n")
        
        await asyncio.sleep(1)
        
        print("2️⃣  Getting Ethereum price...")
        eth_data = await client.get_price("ETH")
        if eth_data:
            print(f"   💰 ETH: ${eth_data['price']:,.2f}\n")
        
        await asyncio.sleep(1)
        
        print("3️⃣  Getting Ripple price...")
        xrp_data = await client.get_price("XRP")
        if xrp_data:
            print(f"   💰 XRP: ${xrp_data['price']:,.2f}\n")
        
        await asyncio.sleep(1)
        
        print("✅ Demo complete!")
        
        await client.disconnect()
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        if client.connected:
            await client.disconnect()


def print_usage():
    """Print usage information"""
    print("Usage:")
    print("  python a2a_client.py          # Interactive mode")
    print("  python a2a_client.py --demo   # Automated demo")
    print("  python a2a_client.py --list   # List available agents")


async def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            await demo_mode()
        elif sys.argv[1] == "--list":
            await list_available_agents()
        elif sys.argv[1] in ["-h", "--help"]:
            print_usage()
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print()
            print_usage()
    else:
        await interactive_client()


if __name__ == "__main__":
    asyncio.run(main())