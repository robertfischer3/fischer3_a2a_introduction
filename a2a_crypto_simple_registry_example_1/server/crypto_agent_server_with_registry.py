"""
Cryptocurrency Price Agent Server (Registry-Integrated)
A simple A2A-compliant agent that registers with the A2A Registry
"""

import asyncio
import json
import random
import httpx
from typing import Dict, Any, Optional
from datetime import datetime
import sys
import os

# Add shared module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.a2a_protocol import (
    A2AMessage, 
    MessageType, 
    AgentCard, 
    RequestMethod,
    PriceResponse,
    A2AProtocol
)


class CryptoAgent:
    """
    Cryptocurrency Price Agent with Registry Integration
    Provides fictitious prices for Bitcoin, Ethereum, and XRP
    Automatically registers with the A2A Registry
    """
    
    def __init__(self, host: str = 'localhost', port: int = 8888, registry_url: str = "http://localhost:8000"):
        self.host = host
        self.port = port
        self.registry_url = registry_url
        self.agent_id = "crypto-agent-001"
        self.name = "CryptoPriceAgent"
        self.version = "1.0.0"
        
        # Price ranges for each cryptocurrency
        self.price_ranges = {
            "BTC": (100000, 150000),
            "BITCOIN": (100000, 150000),
            "ETH": (3500, 4500),
            "ETHEREUM": (3500, 4500),
            "XRP": (2.00, 3.00),
            "RIPPLE": (2.00, 3.00)
        }
        
        # Create agent card
        self.agent_card = AgentCard(
            agent_id=self.agent_id,
            name=self.name,
            version=self.version,
            description="AI Agent providing fictitious cryptocurrency prices for demonstration",
            capabilities=["get_price", "list_currencies", "get_agent_info"],
            supported_protocols=["A2A/1.0"],
            metadata={
                "supported_currencies": ["BTC", "ETH", "XRP"],
                "update_frequency": "on_request",
                "data_type": "fictitious"
            }
        )
        
        self.server = None
        self.clients = {}
        self.heartbeat_task = None
        self.registered = False
        
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
                    result = response.json()
                    print(f"✅ Registered with A2A Registry")
                    print(f"   Status: {result['status']}")
                    self.registered = True
                    return True
                else:
                    print(f"⚠️  Registry registration failed: {response.status_code}")
                    return False
                    
        except httpx.ConnectError:
            print(f"⚠️  Could not connect to registry at {self.registry_url}")
            print("   Agent will run without registry integration")
            return False
        except Exception as e:
            print(f"⚠️  Registration error: {e}")
            return False
    
    async def send_heartbeat(self):
        """Send periodic heartbeats to the registry"""
        if not self.registered:
            return
            
        while True:
            try:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
                async with httpx.AsyncClient() as client:
                    response = await client.put(
                        f"{self.registry_url}/agents/{self.agent_id}/heartbeat",
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        print("💓 Heartbeat sent to registry")
                    else:
                        print(f"⚠️  Heartbeat failed: {response.status_code}")
                        
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
                response = await client.delete(
                    f"{self.registry_url}/agents/{self.agent_id}",
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    print("✅ Unregistered from A2A Registry")
                    
        except Exception as e:
            print(f"⚠️  Unregistration error: {e}")
    
    async def start(self):
        """Start the agent server"""
        # Register with registry first
        await self.register_with_registry()
        
        # Start heartbeat task if registered
        if self.registered:
            self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
        
        # Start TCP server
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = self.server.sockets[0].getsockname()
        print(f"🚀 Crypto Agent Server started on {addr[0]}:{addr[1]}")
        print(f"📋 Agent ID: {self.agent_id}")
        print(f"💰 Supported currencies: {', '.join(['BTC', 'ETH', 'XRP'])}")
        print(f"⚠️  Prices are fictitious for demonstration only\n")
        
        async with self.server:
            await self.server.serve_forever()
    
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
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a client connection"""
        addr = writer.get_extra_info('peername')
        client_id = f"{addr[0]}:{addr[1]}"
        
        print(f"📥 New connection from {addr}")
        
        self.clients[client_id] = {
            "reader": reader,
            "writer": writer,
            "agent_id": None
        }
        
        try:
            while True:
                # Read message
                data = await reader.readline()
                if not data:
                    break
                
                # Parse message
                try:
                    message = A2AMessage.from_json(data.decode('utf-8').strip())
                    print(f"📨 Received: {message.message_type} from {message.sender_id}")
                    
                    # Handle message
                    response = await self.handle_message(message, client_id)
                    
                    if response:
                        # Send response
                        response_data = response.to_json() + '\n'
                        writer.write(response_data.encode('utf-8'))
                        await writer.drain()
                        
                except json.JSONDecodeError:
                    print(f"⚠️  Invalid JSON received")
                    error = A2AProtocol.create_error(
                        self.agent_id,
                        "INVALID_JSON",
                        "Invalid JSON format"
                    )
                    writer.write((error.to_json() + '\n').encode('utf-8'))
                    await writer.drain()
                    
        except asyncio.IncompleteReadError:
            print(f"📤 Client {client_id} disconnected")
        except Exception as e:
            print(f"❌ Error handling client {client_id}: {e}")
        finally:
            # Cleanup
            del self.clients[client_id]
            writer.close()
            await writer.wait_closed()
    
    async def handle_message(self, message: A2AMessage, client_id: str) -> Optional[A2AMessage]:
        """Handle incoming A2A message"""
        
        if message.message_type == MessageType.HANDSHAKE:
            # Store client agent ID
            self.clients[client_id]["agent_id"] = message.sender_id
            
            # Send handshake acknowledgment with agent card
            return A2AProtocol.create_handshake_ack(
                self.agent_id,
                self.agent_card,
                message.sender_id
            )
        
        elif message.message_type == MessageType.REQUEST:
            return await self.handle_request(message)
        
        elif message.message_type == MessageType.GOODBYE:
            print(f"👋 Goodbye from {message.sender_id}")
            return None
        
        else:
            # Unsupported message type
            return A2AProtocol.create_error(
                self.agent_id,
                "UNSUPPORTED_MESSAGE",
                f"Message type {message.message_type} not supported",
                message.sender_id
            )
    
    async def handle_request(self, message: A2AMessage) -> A2AMessage:
        """Handle REQUEST messages"""
        method = message.payload.get("method")
        params = message.payload.get("params", {})
        
        if method == RequestMethod.GET_PRICE:
            return await self.handle_get_price(message, params)
        
        elif method == RequestMethod.GET_SUPPORTED_CURRENCIES:
            return self.handle_get_currencies(message)
        
        elif method == RequestMethod.GET_AGENT_INFO:
            return self.handle_get_agent_info(message)
        
        else:
            return A2AProtocol.create_error(
                self.agent_id,
                "UNSUPPORTED_METHOD",
                f"Method {method} not supported",
                message.sender_id
            )
    
    async def handle_get_price(self, message: A2AMessage, params: Dict) -> A2AMessage:
        """Handle get_price requests"""
        currency = params.get("currency", "").upper()
        
        if not currency:
            return A2AProtocol.create_error(
                self.agent_id,
                "MISSING_PARAMETER",
                "Currency parameter is required",
                message.sender_id
            )
        
        if currency not in self.price_ranges:
            return A2AProtocol.create_error(
                self.agent_id,
                "UNSUPPORTED_CURRENCY",
                f"Currency {currency} is not supported. Supported: BTC, ETH, XRP",
                message.sender_id
            )
        
        # Generate random price
        min_price, max_price = self.price_ranges[currency]
        price = round(random.uniform(min_price, max_price), 2)
        
        print(f"💵 Generated price for {currency}: ${price:,.2f}")
        
        # Create price response
        price_response = PriceResponse(
            currency=currency,
            price=price,
            timestamp=datetime.utcnow().isoformat(),
            disclaimer="This price is fictitious for demonstration only"
        )
        
        return A2AProtocol.create_response(
            self.agent_id,
            message.message_id,
            price_response.to_dict(),
            message.sender_id
        )
    
    def handle_get_currencies(self, message: A2AMessage) -> A2AMessage:
        """Handle get_supported_currencies requests"""
        currencies = ["BTC", "ETH", "XRP"]
        
        return A2AProtocol.create_response(
            self.agent_id,
            message.message_id,
            {"currencies": currencies},
            message.sender_id
        )
    
    def handle_get_agent_info(self, message: A2AMessage) -> A2AMessage:
        """Handle get_agent_info requests"""
        return A2AProtocol.create_response(
            self.agent_id,
            message.message_id,
            {"agent_card": self.agent_card.to_dict()},
            message.sender_id
        )


async def main():
    """Main entry point"""
    print("=" * 60)
    print("  Cryptocurrency Price Agent Server (A2A)")
    print("  with Registry Integration")
    print("=" * 60)
    print()
    
    # Create and start agent
    agent = CryptoAgent()
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n")
        await agent.stop()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())