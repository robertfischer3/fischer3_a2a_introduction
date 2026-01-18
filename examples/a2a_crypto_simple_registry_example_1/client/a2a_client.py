"""
A2A Client Application
Connects to the Cryptocurrency Agent to retrieve prices
"""

import asyncio
import json
import sys
import os
from typing import Optional, Dict, Any
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
    A2A Client for communicating with AI Agents
    """
    
    def __init__(self, client_id: str = None):
        self.client_id = client_id or f"client-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.reader = None
        self.writer = None
        self.connected = False
        self.remote_agent: Optional[AgentCard] = None
        
    async def connect(self, host: str = 'localhost', port: int = 8888):
        """Connect to an A2A agent server"""
        try:
            print(f"🔗 Connecting to {host}:{port}...")
            self.reader, self.writer = await asyncio.open_connection(host, port)
            self.connected = True
            print(f"✅ Connected successfully")
            
            # Send handshake
            await self.handshake()
            
        except ConnectionRefusedError:
            print(f"❌ Failed to connect to {host}:{port}")
            print("   Make sure the crypto agent server is running!")
            raise
        except Exception as e:
            print(f"❌ Connection error: {e}")
            raise
    
    async def handshake(self):
        """Perform A2A handshake with the server"""
        # Create client agent card (simplified)
        client_card = AgentCard(
            agent_id=self.client_id,
            name="A2A Client",
            version="1.0.0",
            description="Simple A2A client application",
            capabilities=["request"],
            supported_protocols=["A2A/1.0"],
            metadata={}
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
            if data:
                return A2AMessage.from_json(data.decode('utf-8').strip())
        except Exception as e:
            print(f"❌ Error receiving message: {e}")
        
        return None
    
    async def get_price(self, currency: str) -> Optional[Dict[str, Any]]:
        """Request price for a specific cryptocurrency"""
        request = A2AProtocol.create_request(
            self.client_id,
            self.remote_agent.agent_id if self.remote_agent else "crypto-agent",
            RequestMethod.GET_PRICE,
            {"currency": currency}
        )
        
        await self.send_message(request)
        response = await self.receive_message()
        
        if response and response.message_type == MessageType.RESPONSE:
            return response.payload.get("result")
        elif response and response.message_type == MessageType.ERROR:
            print(f"❌ Error: {response.payload.get('error')}")
            return None
        
        return None
    
    async def get_supported_currencies(self) -> Optional[list]:
        """Get list of supported currencies"""
        request = A2AProtocol.create_request(
            self.client_id,
            self.remote_agent.agent_id if self.remote_agent else "crypto-agent",
            RequestMethod.GET_SUPPORTED_CURRENCIES,
            {}
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


async def interactive_client():
    """Interactive client interface"""
    print("=" * 50)
    print("  A2A Crypto Price Client")
    print("=" * 50 + "\n")
    
    client = A2AClient()
    
    try:
        # Connect to server
        await client.connect()
        
        # Get supported currencies
        print("📋 Fetching supported currencies...")
        currencies = await client.get_supported_currencies()
        if currencies:
            print(f"   Available: {', '.join(currencies)}\n")
        
        # Interactive loop
        while True:
            print("\n" + "-" * 40)
            print("Options:")
            print("1. Get Bitcoin (BTC) price")
            print("2. Get Ethereum (ETH) price")
            print("3. Get Ripple (XRP) price")
            print("4. Custom currency query")
            print("5. Show all prices")
            print("6. Quit")
            print("-" * 40)
            
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                price_data = await client.get_price("BTC")
                if price_data:
                    print(f"\n💰 Bitcoin Price: ${price_data['price_usd']:,.2f}")
                    print(f"   ⚠️  {price_data['disclaimer']}")
            
            elif choice == '2':
                price_data = await client.get_price("ETH")
                if price_data:
                    print(f"\n💎 Ethereum Price: ${price_data['price_usd']:,.2f}")
                    print(f"   ⚠️  {price_data['disclaimer']}")
            
            elif choice == '3':
                price_data = await client.get_price("XRP")
                if price_data:
                    print(f"\n🌊 Ripple Price: ${price_data['price_usd']:.2f}")
                    print(f"   ⚠️  {price_data['disclaimer']}")
            
            elif choice == '4':
                currency = input("Enter currency symbol: ").strip().upper()
                price_data = await client.get_price(currency)
                if price_data:
                    print(f"\n📈 {currency} Price: ${price_data['price_usd']:,.2f}")
                    print(f"   ⚠️  {price_data['disclaimer']}")
            
            elif choice == '5':
                print("\n📊 All Cryptocurrency Prices:")
                print("-" * 30)
                for currency in ['BTC', 'ETH', 'XRP']:
                    price_data = await client.get_price(currency)
                    if price_data:
                        print(f"{currency:4} : ${price_data['price_usd']:>10,.2f}")
                print("-" * 30)
                print("⚠️  All prices are fictitious for demonstration only")
            
            elif choice == '6':
                print("\n✅ Exiting...")
                break
            
            else:
                print("❌ Invalid choice. Please try again.")
        
    except KeyboardInterrupt:
        print("\n\n✋ Client interrupted")
    except Exception as e:
        print(f"\n❌ Client error: {e}")
    finally:
        # Disconnect
        await client.disconnect()


async def automated_demo():
    """Automated demonstration of the client"""
    print("=" * 50)
    print("  A2A Crypto Client - Automated Demo")
    print("=" * 50 + "\n")
    
    client = A2AClient()
    
    try:
        # Connect to server
        await client.connect()
        
        # Demo sequence
        print("🎬 Running automated demonstration...\n")
        
        # Get all supported currencies
        print("1️⃣  Fetching supported currencies...")
        currencies = await client.get_supported_currencies()
        print(f"   Supported: {', '.join(currencies) if currencies else 'None'}\n")
        
        await asyncio.sleep(1)
        
        # Get prices for each currency
        for i, currency in enumerate(['BTC', 'ETH', 'XRP'], 2):
            print(f"{i}️⃣  Getting {currency} price...")
            price_data = await client.get_price(currency)
            
            if price_data:
                name = {'BTC': 'Bitcoin', 'ETH': 'Ethereum', 'XRP': 'Ripple'}[currency]
                print(f"   {name}: ${price_data['price_usd']:,.2f}")
                print(f"   Timestamp: {price_data['timestamp']}")
                print(f"   Note: {price_data['disclaimer']}\n")
            
            await asyncio.sleep(1)
        
        # Try an unsupported currency
        print("5️⃣  Testing unsupported currency (DOGE)...")
        price_data = await client.get_price("DOGE")
        if not price_data:
            print("   Expected error received for unsupported currency\n")
        
        print("✅ Demonstration complete!")
        
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
    finally:
        await client.disconnect()


async def main():
    """Main entry point for the client"""
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        await automated_demo()
    else:
        await interactive_client()


if __name__ == "__main__":
    asyncio.run(main())