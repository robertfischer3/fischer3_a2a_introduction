# A2A Cryptocurrency Price Example

## Overview

This is a simple implementation of the Agent2Agent (A2A) protocol demonstrating communication between a client application and an AI agent that provides cryptocurrency prices. The prices are **fictitious and for demonstration purposes only**.

## Project Structure

```
a2a_crypto_example/
├── client/
│   └── a2a_client.py          # A2A client application
├── server/
│   └── crypto_agent_server.py # Cryptocurrency AI Agent server
├── shared/
│   └── a2a_protocol.py        # Shared A2A protocol definitions
└── README.md                   # This file
```

## Features

### Cryptocurrency Agent Server
- **Agent Card**: Provides agent identity and capabilities (no streaming/push notifications)
- **Supported Cryptocurrencies**:
  - Bitcoin (BTC): $100,000 - $150,000 USD
  - Ethereum (ETH): $3,500 - $4,500 USD
  - Ripple (XRP): $2.00 - $3.00 USD
- **A2A Protocol Messages**: Handshake, Request/Response, Error handling
- **Fictitious Prices**: All prices are randomly generated for demonstration

### A2A Client
- Interactive menu interface
- Automated demo mode
- Support for all A2A protocol messages
- Error handling for unsupported currencies

## A2A Protocol Implementation

### Message Types
- `HANDSHAKE` / `HANDSHAKE_ACK`: Initial connection and agent discovery
- `REQUEST` / `RESPONSE`: Price queries and responses
- `ERROR`: Error handling
- `GOODBYE`: Clean disconnection

### Request Methods
- `GET_PRICE`: Get price for a specific cryptocurrency
- `GET_SUPPORTED_CURRENCIES`: List available currencies
- `GET_AGENT_INFO`: Get agent card information

### Agent Card Structure
```python
{
    "agent_id": "crypto-agent-001",
    "name": "CryptoPriceAgent",
    "version": "1.0.0",
    "description": "AI Agent providing fictitious cryptocurrency prices",
    "capabilities": ["price_query", "currency_list", "no_streaming"],
    "supported_protocols": ["A2A/1.0"],
    "metadata": {
        "supported_currencies": ["BTC", "ETH", "XRP"],
        "update_frequency": "on_request",
        "data_type": "fictitious"
    }
}
```

## Installation

No external dependencies required! Uses only Python standard library (Python 3.7+).

## Usage

### Step 1: Start the Cryptocurrency Agent Server

Open a terminal and run:

```bash
cd a2a_crypto_example/server
python crypto_agent_server.py
```

You should see:
```
==================================================
  Cryptocurrency Price Agent Server (A2A)
==================================================

🚀 Crypto Agent Server started on 127.0.0.1:8888
📋 Agent ID: crypto-agent-001
💰 Supported currencies: BTC, ETH, XRP
⚠️  Prices are fictitious for demonstration only
```

### Step 2: Run the Client Application

In a new terminal:

```bash
cd a2a_crypto_example/client
python a2a_client.py
```

For automated demo:
```bash
python a2a_client.py --demo
```

### Interactive Client Options

```
Options:
1. Get Bitcoin (BTC) price
2. Get Ethereum (ETH) price
3. Get Ripple (XRP) price
4. Custom currency query
5. Show all prices
6. Quit
```

## Example Output

### Server Log
```
📥 New connection from ('127.0.0.1', 54321)
📨 Received: HANDSHAKE from client-20250101-120000
📨 Received: REQUEST from client-20250101-120000
💵 Generated price for BTC: $125432.00
```

### Client Output
```
🔗 Connecting to localhost:8888...
✅ Connected successfully
🤝 Handshake complete with: CryptoPriceAgent
   Agent: AI Agent providing fictitious cryptocurrency prices

💰 Bitcoin Price: $125,432.00
   ⚠️  This price is fictitious for demonstration only
```

## Protocol Flow

1. **Connection**: Client connects to server via TCP socket
2. **Handshake**: Exchange agent cards for capability discovery
3. **Request**: Client sends price request for specific currency
4. **Processing**: Server generates random price within defined range
5. **Response**: Server sends price with disclaimer
6. **Disconnect**: Clean goodbye message and connection closure

## Extending the Example

This simple example can be extended to:

1. **Add More Currencies**: Extend the `price_ranges` dictionary
2. **Implement Streaming**: Add WebSocket support for real-time updates
3. **Add Authentication**: Implement agent authentication/authorization
4. **Multiple Agents**: Create agent discovery and routing
5. **Persistent Storage**: Add price history and trends
6. **Real API Integration**: Connect to actual crypto price APIs
7. **Advanced Features**:
   - Price alerts and subscriptions
   - Historical data queries
   - Multi-agent aggregation
   - Load balancing between multiple price agents

## Key Learning Points

1. **Agent Identity**: Each agent has a unique ID and capability card
2. **Protocol Messages**: Structured communication using defined message types
3. **Request/Response Pattern**: Synchronous communication model
4. **Error Handling**: Graceful handling of unsupported operations
5. **Clean Separation**: Protocol logic separate from business logic

## Troubleshooting

### Connection Refused Error
- Make sure the server is running before starting the client
- Check if port 8888 is available
- Verify firewall settings

### Invalid Currency Error
- The demo only supports BTC, ETH, and XRP
- Currency symbols are case-insensitive

### Server Not Responding
- Check server console for error messages
- Ensure Python version is 3.7 or higher
- Try restarting both server and client

## Next Steps

After understanding this basic example, you can:

1. Implement more sophisticated message routing
2. Add agent discovery mechanisms
3. Create multi-agent workflows
4. Integrate with Model Context Protocol (MCP) for tool access
5. Build a full agent registry service
6. Add security layers (TLS, authentication)

## License

This example is provided for educational purposes. Feel free to modify and extend it for your needs.

## Disclaimer

⚠️ **All cryptocurrency prices in this example are fictitious and for demonstration purposes only.** This is not financial advice and should not be used for any real trading decisions.