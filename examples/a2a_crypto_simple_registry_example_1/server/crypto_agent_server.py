"""
Cryptocurrency Price Agent Server
A simple A2A-compliant agent that provides fictitious crypto prices
"""

import asyncio
import json
import random
import socket
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
    Cryptocurrency Price Agent
    Provides fictitious prices for Bitcoin, Ethereum, and XRP
    """
    
    def __init__(self, host: str = 'localhost', port: int = 8888):
        self.host = host
        self.port = port
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
            capabilities=["price_query", "currency_list", "no_streaming"],
            supported_protocols=["A2A/1.0"],
            metadata={
                "supported_currencies": ["BTC", "ETH", "XRP"],
                "update_frequency": "on_request",
                "data_type": "fictitious"
            }
        )
        
        self.server = None
        self.clients = {}
        
    async def start(self):
        """Start the agent server"""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = self.server.sockets[0].getsockname()
        print(f"🚀 Crypto Agent Server started on {addr[0]}:{addr[1]}")
        print(f"📋 Agent ID: {self.agent_id}")
        print(f"💰 Supported currencies: BTC, ETH, XRP")
        print(f"⚠️  Prices are fictitious for demonstration only\n")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        client_addr = writer.get_extra_info('peername')
        print(f"📥 New connection from {client_addr}")
        
        try:
            while True:
                # Read message (assuming newline-delimited JSON)
                data = await reader.readline()
                if not data:
                    break
                    
                # Parse and handle message
                try:
                    message = A2AMessage.from_json(data.decode('utf-8').strip())
                    response = await self.handle_message(message)
                    
                    if response:
                        # Send response
                        response_data = response.to_json() + '\n'
                        writer.write(response_data.encode('utf-8'))
                        await writer.drain()
                        
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON received: {e}")
                    error_msg = A2AProtocol.create_error(
                        self.agent_id,
                        None,
                        "Invalid JSON format",
                        400
                    )
                    writer.write((error_msg.to_json() + '\n').encode('utf-8'))
                    await writer.drain()
                    
        except asyncio.CancelledError:
            pass
        finally:
            print(f"📤 Connection closed from {client_addr}")
            writer.close()
            await writer.wait_closed()
    
    async def handle_message(self, message: A2AMessage) -> Optional[A2AMessage]:
        """Process incoming A2A messages"""
        print(f"📨 Received: {message.message_type.value} from {message.sender_id}")
        
        if message.message_type == MessageType.HANDSHAKE:
            # Respond with handshake acknowledgment
            return A2AMessage.create_message(
                MessageType.HANDSHAKE_ACK,
                self.agent_id,
                {"agent_card": self.agent_card.to_dict()},
                message.sender_id,
                message.message_id
            )
        
        elif message.message_type == MessageType.GET_CAPABILITIES:
            # Return agent capabilities
            return A2AMessage.create_message(
                MessageType.CAPABILITIES_RESPONSE,
                self.agent_id,
                {"agent_card": self.agent_card.to_dict()},
                message.sender_id,
                message.message_id
            )
        
        elif message.message_type == MessageType.REQUEST:
            # Handle specific requests
            return await self.handle_request(message)
        
        elif message.message_type == MessageType.GOODBYE:
            print(f"👋 Client {message.sender_id} disconnecting")
            return None
        
        else:
            # Unknown message type
            return A2AProtocol.create_error(
                self.agent_id,
                message.sender_id,
                f"Unknown message type: {message.message_type.value}",
                501,
                message.message_id
            )
    
    async def handle_request(self, message: A2AMessage) -> A2AMessage:
        """Handle REQUEST messages"""
        method = message.payload.get("method")
        params = message.payload.get("params", {})
        
        if method == RequestMethod.GET_PRICE.value:
            # Get price for specified currency
            currency = params.get("currency", "").upper()
            
            if currency in self.price_ranges:
                price = self.generate_price(currency)
                response = PriceResponse(
                    currency=currency,
                    price_usd=price,
                    timestamp=datetime.utcnow().isoformat()
                )
                
                print(f"💵 Generated price for {currency}: ${price:.2f}")
                
                return A2AProtocol.create_response(
                    self.agent_id,
                    message.sender_id,
                    response.to_dict(),
                    message.message_id
                )
            else:
                return A2AProtocol.create_error(
                    self.agent_id,
                    message.sender_id,
                    f"Unsupported currency: {currency}",
                    404,
                    message.message_id
                )
        
        elif method == RequestMethod.GET_SUPPORTED_CURRENCIES.value:
            # Return list of supported currencies
            currencies = ["BTC", "ETH", "XRP"]
            return A2AProtocol.create_response(
                self.agent_id,
                message.sender_id,
                {"currencies": currencies},
                message.message_id
            )
        
        elif method == RequestMethod.GET_AGENT_INFO.value:
            # Return agent information
            return A2AProtocol.create_response(
                self.agent_id,
                message.sender_id,
                {"agent_card": self.agent_card.to_dict()},
                message.message_id
            )
        
        else:
            return A2AProtocol.create_error(
                self.agent_id,
                message.sender_id,
                f"Unknown method: {method}",
                404,
                message.message_id
            )
    
    def generate_price(self, currency: str) -> float:
        """Generate a random price within the specified range"""
        min_price, max_price = self.price_ranges[currency]
        price = random.uniform(min_price, max_price)
        
        # Round to 2 decimal places for XRP, no decimals for BTC/ETH
        if currency in ["XRP", "RIPPLE"]:
            return round(price, 2)
        else:
            return round(price, 0)


async def main():
    """Main entry point"""
    print("=" * 50)
    print("  Cryptocurrency Price Agent Server (A2A)")
    print("=" * 50 + "\n")
    
    # Create and start the agent
    agent = CryptoAgent(host='localhost', port=8888)
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n✋ Server shutting down...")
    except Exception as e:
        print(f"❌ Server error: {e}")


if __name__ == "__main__":
    asyncio.run(main())