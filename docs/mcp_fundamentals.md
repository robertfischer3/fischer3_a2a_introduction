# Model Context Protocol (MCP) - Fundamentals

> **Learning Path**: MCP Deep Dive  
> **Difficulty**: Intermediate  
> **Prerequisites**: [MCP Summary](../mcp_summary.md)  
> **Estimated Time**: 45-60 minutes

## Navigation
← Previous: [MCP Summary](../mcp_summary.md) | Next: [MCP Tools Deep Dive](../mcp_tools_deep_dive.md) →  
↑ Up: [Documentation Index](../index.md)

---

## 👋 Welcome!

If you're here, you've already read the [MCP Summary](../mcp_summary.md) and want to understand how MCP really works under the hood. Great choice! This document will take you from "I know what MCP is" to "I can build with MCP."

Don't worry if some concepts seem complex at first - we'll break everything down step by step. Think of this as a guided tour through the MCP protocol, with plenty of examples along the way.

## 🎯 What You'll Learn

By the end of this document, you will understand:
- [ ] Core MCP concepts and terminology
- [ ] How the MCP protocol works (JSON-RPC 2.0)
- [ ] The MCP connection lifecycle
- [ ] Different transport mechanisms (stdio, HTTP, SSE)
- [ ] How tools and resources fit together
- [ ] MCP server and client architecture
- [ ] SDK options and capabilities

**Reading Time**: 45-60 minutes  
**Hands-On Time**: 1-2 hours (with examples)

> 💡 **Learning Tip**: Don't try to memorize everything on the first read. Focus on understanding the flow and concepts. You can always come back to specific sections when you're implementing.

---

## 📖 Table of Contents

1. [Core Concepts](#core-concepts)
2. [The MCP Protocol](#protocol)
3. [Connection Lifecycle](#lifecycle)
4. [Transport Mechanisms](#transports)
5. [Architecture Overview](#architecture)
6. [SDK Options](#sdks)
7. [Practical Examples](#examples)
8. [Best Practices](#best-practices)
9. [Next Steps](#next-steps)

---

## 1. Core Concepts {#core-concepts}

Let's start with the basics. Before we dive into code and protocols, we need to make sure we're all speaking the same language. If you've worked with APIs before, you'll find many of these concepts familiar - MCP just standardizes them for AI tools.

### What is MCP?

The **Model Context Protocol (MCP)** is an open protocol that standardizes how AI applications connect to external data sources and tools. Think of it as **USB for AI** - a universal interface that works with any compatible tool or data source.

**Why does this matter?** Without MCP, every AI application would need custom code to connect to each tool. With MCP, you write the connection code once, and it works with any MCP-compatible AI application.

### Key Terminology

Before diving deeper, let's define the essential terms. Don't worry about memorizing these right now - they'll make more sense as we use them in examples throughout this guide. Think of this section as a reference you can come back to.

> 💡 **Quick Reference**: Bookmark this table! You'll probably refer back to it as you're learning.

| Term | Definition | Example |
|------|------------|---------|
| **MCP Server** | A program that exposes tools and resources via MCP | Database connector, weather API, file system |
| **MCP Client** | A program that connects to servers and uses their tools/resources | AI agent, LLM application, orchestrator |
| **Tool** | A callable function exposed by a server | `get_weather(city)`, `query_database(sql)` |
| **Resource** | Data/content exposed by a server | Files, database records, API responses |
| **Transport** | Communication mechanism between client and server | stdio, HTTP+SSE, WebSocket |
| **Host** | The application running the MCP client | Claude Desktop, custom agent, framework |
| **JSON-RPC** | Protocol used for message exchange | Request/response format |

### The Big Picture

Now that we know the terms, let's see how everything fits together. This diagram shows the complete MCP ecosystem from your AI application down to the actual external services. Take a moment to follow the flow from top to bottom - this is the architecture we'll be building throughout this guide.

```
┌──────────────────────────────────────────────────┐
│                                                   │
│              AI Application (Host)                │
│         (ChatGPT, Claude, Custom Agent)          │
│                                                   │
└────────────────────┬─────────────────────────────┘
                     │
                     │ Uses MCP Client SDK
                     │
            ┌────────▼────────┐
            │   MCP Client    │
            │  (Inside Host)  │
            └────────┬────────┘
                     │
                     │ MCP Protocol (JSON-RPC)
                     │ Over Transport (stdio/HTTP/etc)
                     │
         ┌───────────┼───────────┬─────────────┐
         │           │           │             │
    ┌────▼───┐  ┌───▼────┐  ┌───▼────┐   ┌───▼────┐
    │Server 1│  │Server 2│  │Server 3│   │Server N│
    │(Weather│  │  (DB)  │  │ (Files)│   │  (API) │
    └────┬───┘  └───┬────┘  └───┬────┘   └───┬────┘
         │          │           │             │
         ▼          ▼           ▼             ▼
     [Weather]   [MySQL]    [Docs]        [Search]
       API       Database   Folder          Engine
```

### MCP's Role in the Ecosystem

Here's where MCP really shines. Let's compare what life looks like with and without MCP. If you've ever written custom integrations for every single tool, you'll appreciate what MCP solves.

MCP sits **between** AI applications and external services:

**Without MCP:**
```
AI App → Custom Connector → Weather API
AI App → Custom Connector → Database
AI App → Custom Connector → File System
AI App → Custom Connector → Each new tool...
```

**With MCP:**
```
AI App → MCP Client → MCP Server (Weather)
                   → MCP Server (Database)
                   → MCP Server (File System)
                   → Any MCP-compatible tool
```

---

## 2. The MCP Protocol {#protocol}

Alright, time to get into the technical details! Don't let "JSON-RPC" intimidate you - it's just a fancy way of saying "structured messages." If you've ever made an API call or sent a JSON payload, you already understand the basics.

### JSON-RPC 2.0 Foundation

MCP uses **JSON-RPC 2.0** as its communication protocol. This is a simple, language-agnostic protocol for remote procedure calls.

**What does this mean in plain English?** It's just a standardized way to say "Hey server, please run this function with these parameters" and get back "Here's your result" or "Sorry, that didn't work."

Let's look at what these messages actually look like. You'll notice they're just plain JSON - nothing magical here!

#### Request Format

Every request from client to server follows this structure:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {
    // Optional parameters
  }
}
```

**Fields:**
- `jsonrpc`: Always "2.0" (protocol version)
- `id`: Unique identifier for this request (number or string)
- `method`: The operation to perform (e.g., "tools/list", "tools/call")
- `params`: Optional parameters object

> 💡 **Pro Tip**: The `id` field is how clients match responses to requests. In async systems, you might send multiple requests before getting responses back, so this ID keeps everything straight.

#### Response Format

Servers respond in one of two ways - success or error. It's always one or the other, which makes error handling straightforward.

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    // Result data
  }
}
```

**Error Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32601,
    "message": "Method not found"
  }
}
```

### Standard MCP Methods

Now we get to the actual operations MCP defines. Think of these as the "verbs" in the MCP language - they're the things you can ask a server to do.

**Don't panic about memorizing this table!** The most important ones are `initialize` (to connect) and `tools/call` (to actually do something). The rest you'll learn as you need them.

> 🎯 **Focus on These First**: Start with just `initialize`, `tools/list`, and `tools/call`. Once you're comfortable with those, the others will make more sense.

| Method | Required | Purpose |
|--------|----------|---------|
| `initialize` | ✅ Yes | Establish connection and capabilities |
| `initialized` | ✅ Yes | Acknowledge initialization complete |
| `tools/list` | ⚠️ If tools | List available tools |
| `tools/call` | ⚠️ If tools | Execute a specific tool |
| `resources/list` | ⚠️ If resources | List available resources |
| `resources/read` | ⚠️ If resources | Read a specific resource |
| `resources/subscribe` | ❌ Optional | Subscribe to resource updates |
| `prompts/list` | ❌ Optional | List available prompts |
| `prompts/get` | ❌ Optional | Get a specific prompt |

### Example: Complete Tool Call Flow

Let's put everything together with a real example. This shows the complete conversation between a client and server. Follow along with the comments - this is the pattern you'll use constantly when working with MCP.

**Here's the scenario**: An AI wants to know the weather in San Francisco. Watch how the client discovers the tool, then calls it.

**1. Client Requests Tool List:**
```json
// Request
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}

// Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "get_weather",
        "description": "Get current weather for a location",
        "inputSchema": {
          "type": "object",
          "properties": {
            "location": {
              "type": "string",
              "description": "City name"
            }
          },
          "required": ["location"]
        }
      }
    ]
  }
}
```

**2. Client Calls Tool:**
```json
// Request
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_weather",
    "arguments": {
      "location": "San Francisco"
    }
  }
}

// Response
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Weather in San Francisco: Sunny, 72°F, Light breeze"
      }
    ]
  }
}
```

---

## 3. Connection Lifecycle {#lifecycle}

Great! Now you understand the message format. But how does a connection actually start? Every MCP connection goes through a specific series of steps - kind of like a handshake protocol. Let's walk through it.

**Think of it like meeting someone new**: First you introduce yourself, they introduce themselves, you figure out what you have in common, then you can actually start collaborating.

### The MCP Handshake

Every MCP connection follows this lifecycle. You'll see this pattern in every client implementation:

```
┌──────────────────────────────────────────────────┐
│              CONNECTION LIFECYCLE                 │
└──────────────────────────────────────────────────┘

1. CONNECT
   Client starts server process (stdio)
   or connects to HTTP endpoint
          │
          ▼
2. INITIALIZE
   Client → Server: initialize request
   - Client capabilities
   - Client info
          │
          ▼
3. SERVER RESPONSE
   Server → Client: initialize response
   - Server capabilities
   - Server info
   - Protocol version
          │
          ▼
4. INITIALIZED
   Client → Server: initialized notification
   Connection ready for use
          │
          ▼
5. ACTIVE USE
   Client calls tools/reads resources
   Server responds
          │
          ▼
6. SHUTDOWN
   Client disconnects
   Server process exits (stdio)
```

### Step-by-Step Example

Let's see what these messages actually look like. I've included all three steps so you can see the complete handshake. In practice, your SDK will handle most of this for you, but it's good to understand what's happening under the hood.

**Step 1: Initialize Request**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "roots": {
        "listChanged": true
      },
      "sampling": {}
    },
    "clientInfo": {
      "name": "my-mcp-client",
      "version": "1.0.0"
    }
  }
}
```

**Step 2: Server Responds**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {
        "subscribe": true,
        "listChanged": true
      }
    },
    "serverInfo": {
      "name": "weather-server",
      "version": "1.0.0"
    }
  }
}
```

**Step 3: Client Sends Initialized Notification**
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/initialized"
}
```

**Now the connection is ready!**

### Capability Negotiation

During initialization, client and server **negotiate capabilities**. This is where they figure out what features they both support. It's like two people meeting and discovering they both speak English - or finding out one speaks English and the other speaks Spanish, so they'll need to work around that.

**Why does this matter?** Not all servers support all features. Capability negotiation lets them work together even if they don't have identical feature sets.

> 💡 **Real-World Example**: Imagine a server that only provides tools (no resources). During initialization, the client sees this and knows not to try calling `resources/list`.

**Client Capabilities:**
- `roots`: Can the client provide root directories?
- `sampling`: Can the client generate AI responses?
- `experimental`: Experimental features

**Server Capabilities:**
- `tools`: Does server expose tools?
- `resources`: Does server expose resources?
- `prompts`: Does server provide prompts?
- `logging`: Does server support logging?

This allows clients and servers to understand what features are available.

---

## 4. Transport Mechanisms {#transports}

Now let's talk about how the actual bytes get from client to server. MCP supports multiple transport mechanisms, and choosing the right one depends on your use case.

**Think of transports like different ways to send a letter**: You could hand-deliver it (stdio - fast and direct), mail it (HTTP - works across distances), or use a courier service (custom transport - specialized needs).

MCP supports multiple transport mechanisms. Each has different use cases - let's explore when to use each one.

### stdio (Standard Input/Output)

**Use Case:** Local processes, simple setup, maximum compatibility

**How it Works:**
1. Client launches server as a subprocess
2. Server reads JSON-RPC from stdin
3. Server writes JSON-RPC to stdout
4. Server logs/errors go to stderr

**In plain English**: Your client starts the server as a child process and talks to it through standard Unix pipes. It's like having a conversation through walkie-talkies - simple, direct, and it just works.

> 🎯 **Best for Beginners**: Start with stdio! It's the easiest to set up and debug. You can run both client and server on your laptop without any network configuration.

**Example (Python):**
```python
import subprocess
import json

# Start MCP server
server = subprocess.Popen(
    ["python", "my_mcp_server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Send request
request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
server.stdin.write(json.dumps(request) + "\n")
server.stdin.flush()

# Read response
response = json.loads(server.stdout.readline())
print(response)
```

**Pros:**
- ✅ Simple to implement
- ✅ No network configuration
- ✅ Works everywhere
- ✅ Automatic process management

**Cons:**
- ❌ Local only (same machine)
- ❌ One client per server instance
- ❌ Process overhead

### HTTP + SSE (Server-Sent Events)

**Use Case:** Network services, multiple clients, production deployments

**How it Works:**
1. Server runs as HTTP service
2. Client sends HTTP POST for requests
3. Server responds with JSON-RPC via HTTP
4. Optional: SSE for server→client events

**In plain English**: The server runs like a normal web service. Clients can connect from anywhere on the network, and you can have multiple clients talking to the same server. This is what you'd use in production.

> 🏢 **Production Ready**: Once you're comfortable with stdio, graduate to HTTP when you need to deploy your server for real use or support multiple clients.

**Example (Client):**
```python
import requests

# Send request
response = requests.post(
    "http://localhost:8080/mcp",
    json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    }
)

result = response.json()
print(result)
```

**Pros:**
- ✅ Network accessible
- ✅ Multiple concurrent clients
- ✅ Standard HTTP infrastructure
- ✅ Scalable

**Cons:**
- ❌ More complex setup
- ❌ Requires network configuration
- ❌ Authentication needed

### Custom Transports

MCP protocol is transport-agnostic. You can implement:
- WebSockets
- gRPC
- Message queues (RabbitMQ, etc.)
- Any bidirectional communication channel

---

## 5. Architecture Overview {#architecture}

Let's zoom out and look at the big picture of how MCP systems are structured. Understanding the architecture will help you design better servers and clients.

**These diagrams show layers** - like a layer cake. Each layer has a specific job, and layers only talk to the layers directly above or below them. This separation makes the system easier to build and maintain.

### MCP Server Architecture

A typical MCP server has these components:

```
┌───────────────────────────────────────────┐
│           MCP SERVER                       │
├───────────────────────────────────────────┤
│                                            │
│  ┌──────────────────────────────────┐    │
│  │   Transport Layer                 │    │
│  │   (stdio/HTTP/etc)                │    │
│  └─────────────┬─────────────────────┘    │
│                │                           │
│  ┌─────────────▼─────────────────────┐    │
│  │   Protocol Handler                 │    │
│  │   (JSON-RPC parsing/routing)       │    │
│  └─────────────┬─────────────────────┘    │
│                │                           │
│       ┌────────┼────────┐                 │
│       │        │        │                 │
│  ┌────▼───┐ ┌─▼────┐ ┌─▼──────┐          │
│  │ Tools  │ │Resrc │ │Prompts │          │
│  │Manager │ │Mangr │ │Manager │          │
│  └────┬───┘ └─┬────┘ └─┬──────┘          │
│       │       │        │                  │
│  ┌────▼───────▼────────▼───────┐         │
│  │   Business Logic             │         │
│  │   (Your actual functionality)│         │
│  └──────────────┬────────────────┘        │
│                 │                          │
│  ┌──────────────▼────────────────┐        │
│  │   External Services            │        │
│  │   (APIs, DBs, Files, etc)      │        │
│  └────────────────────────────────┘        │
│                                            │
└───────────────────────────────────────────┘
```

### MCP Client Architecture

A typical MCP client has these components:

```
┌───────────────────────────────────────────┐
│         AI APPLICATION (HOST)              │
├───────────────────────────────────────────┤
│                                            │
│  ┌──────────────────────────────────┐    │
│  │   Application Logic               │    │
│  │   (LLM, Agent, Framework)         │    │
│  └─────────────┬─────────────────────┘    │
│                │                           │
│  ┌─────────────▼─────────────────────┐    │
│  │   MCP Client SDK                   │    │
│  │   - Connection management          │    │
│  │   - Request/response handling      │    │
│  │   - Tool/resource discovery        │    │
│  └─────────────┬─────────────────────┘    │
│                │                           │
│  ┌─────────────▼─────────────────────┐    │
│  │   Transport Layer                  │    │
│  │   (stdio/HTTP/etc)                 │    │
│  └─────────────┬─────────────────────┘    │
│                │                           │
└────────────────┼───────────────────────────┘
                 │
                 │ MCP Protocol
                 │
                 ▼
          [MCP Servers]
```

---

## 6. SDK Options {#sdks}

Great news! You don't have to implement all of this from scratch. Anthropic provides official SDKs that handle the protocol details for you. You just focus on building your tools and business logic.

**Which SDK should you use?** Pick based on your preferred language. Both SDKs are equally capable - it's just a matter of what you're comfortable with.

> 🚀 **Quick Start Recommendation**: If you're proficient in both languages, start with Python - it's slightly more beginner-friendly for MCP development.

### Official SDKs

Anthropic provides official SDKs in two languages:

#### Python SDK

**Installation:**
```bash
pip install mcp
```

**Server Example:**
```python
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("my-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="add_numbers",
            description="Add two numbers",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                },
                "required": ["a", "b"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "add_numbers":
        result = arguments["a"] + arguments["b"]
        return [TextContent(type="text", text=str(result))]

# Run with: mcp.run(app)
```

**Client Example:**
```python
from mcp.client import Client
from mcp.client.stdio import stdio_client

async with stdio_client(["python", "server.py"]) as (read, write):
    async with Client(read, write) as client:
        await client.initialize()
        
        tools = await client.list_tools()
        print(f"Available tools: {tools}")
        
        result = await client.call_tool("add_numbers", {"a": 5, "b": 3})
        print(f"Result: {result}")
```

#### TypeScript SDK

**Installation:**
```bash
npm install @modelcontextprotocol/sdk
```

**Server Example:**
```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "my-server",
  version: "1.0.0",
}, {
  capabilities: {
    tools: {},
  },
});

server.setRequestHandler("tools/list", async () => {
  return {
    tools: [
      {
        name: "add_numbers",
        description: "Add two numbers",
        inputSchema: {
          type: "object",
          properties: {
            a: { type: "number" },
            b: { type: "number" },
          },
          required: ["a", "b"],
        },
      },
    ],
  };
});

server.setRequestHandler("tools/call", async (request) => {
  if (request.params.name === "add_numbers") {
    const result = request.params.arguments.a + request.params.arguments.b;
    return {
      content: [
        {
          type: "text",
          text: String(result),
        },
      ],
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
```

### SDK Features

Both SDKs provide the same core functionality. Here's what you get out of the box:

> 💡 **Good News**: Whichever SDK you choose, you're not missing out on features. The main difference is syntax and type system - pick the language you know best.

| Feature | Python SDK | TypeScript SDK |
|---------|-----------|----------------|
| Server creation | ✅ | ✅ |
| Client connection | ✅ | ✅ |
| stdio transport | ✅ | ✅ |
| HTTP transport | ✅ | ✅ |
| Tool management | ✅ | ✅ |
| Resource management | ✅ | ✅ |
| Type safety | Good | Excellent |
| Async support | ✅ asyncio | ✅ Promises |

---

## 7. Practical Examples {#examples}

Alright, enough theory! Let's build some actual servers. These examples progress from simple to more complex. I recommend working through them in order - each one teaches important concepts.

**Don't just read these - type them out and run them!** The best way to learn MCP is by actually building something. Even if you make mistakes (you will!), that's where the real learning happens.

> 🎯 **Learning Strategy**: Start with Example 1. Get it working. Then modify it to do something different. Once you're comfortable, move to Example 2.

### Example 1: Simple Calculator Server

Complete stdio server that adds numbers. This is your "Hello World" for MCP - the simplest possible server that does something useful.

**Why start here?** This example has just one tool and minimal complexity. Perfect for understanding the basic structure without getting overwhelmed.

```python
#!/usr/bin/env python3
from mcp.server import Server
from mcp.types import Tool, TextContent
import json
import sys

app = Server("calculator-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="add",
            description="Add two numbers",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {"type": "number", "description": "First number"},
                    "b": {"type": "number", "description": "Second number"}
                },
                "required": ["a", "b"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "add":
        result = arguments["a"] + arguments["b"]
        return [TextContent(
            type="text",
            text=f"The sum of {arguments['a']} and {arguments['b']} is {result}"
        )]
    raise ValueError(f"Unknown tool: {name}")

if __name__ == "__main__":
    import mcp.server.stdio
    mcp.server.stdio.run(app)
```

### Example 2: Weather API Server

Server that fetches weather data. This example shows how to integrate external APIs - a very common pattern you'll use often.

**What's new here?** This demonstrates calling external APIs from your tool. Notice how the tool definition promises to return weather data, and the implementation delivers on that promise.

```python
from mcp.server import Server
from mcp.types import Tool, TextContent
import requests

app = Server("weather-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_weather",
            description="Get current weather for a city",
            inputSchema={
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name"
                    }
                },
                "required": ["city"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "get_weather":
        city = arguments["city"]
        # Call weather API (simplified)
        response = requests.get(
            f"https://api.weather.com/v1/current?city={city}"
        )
        data = response.json()
        
        return [TextContent(
            type="text",
            text=f"Weather in {city}: {data['condition']}, {data['temp']}°F"
        )]
```

### Example 3: File System Resource Server

Server that exposes files as resources. This is different from the previous examples - instead of tools (actions), we're exposing resources (data).

**Key difference**: Tools are for *doing things* (add numbers, get weather). Resources are for *providing data* (files, documents, database records). Many servers provide both!

```python
from mcp.server import Server
from mcp.types import Resource, TextContent
import os
from pathlib import Path

app = Server("filesystem-server")

@app.list_resources()
async def list_resources() -> list[Resource]:
    """List all markdown files in current directory"""
    resources = []
    for file in Path(".").glob("*.md"):
        resources.append(Resource(
            uri=f"file://{file.absolute()}",
            name=file.name,
            description=f"Markdown file: {file.name}",
            mimeType="text/markdown"
        ))
    return resources

@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read content of a file resource"""
    path = uri.replace("file://", "")
    with open(path, 'r') as f:
        return f.read()
```

---

## 8. Best Practices {#best-practices}

You've learned how MCP works - great! But knowing *how* something works isn't the same as knowing how to build it *well*. This section covers the lessons learned from real-world MCP implementations.

**Think of these as guardrails** - they'll help you avoid common pitfalls and build servers that are reliable, secure, and maintainable.

> 💡 **Don't Skip This!** I know best practices sections can seem boring, but these will save you hours of debugging later. Learn from others' mistakes instead of making them yourself.

### Server Development

**✅ DO:**
- Validate all input parameters
- Provide clear, descriptive tool/resource descriptions
- Use proper JSON Schema for inputSchema
- Handle errors gracefully
- Log important events
- Test with multiple clients
- Document your tools and resources

**❌ DON'T:**
- Assume input is valid
- Use overly generic descriptions
- Skip error handling
- Block indefinitely on operations
- Hardcode sensitive credentials
- Ignore client capabilities

### Client Development

**✅ DO:**
- Handle connection failures gracefully
- Validate server responses
- Implement timeout mechanisms
- Cache tool/resource lists when appropriate
- Properly close connections
- Handle server restarts

**❌ DON'T:**
- Assume server is always available
- Make unbounded requests
- Ignore server capabilities
- Leave connections open indefinitely
- Trust server responses blindly

### Security Considerations

Security matters, especially when your MCP server has access to sensitive data or can perform actions on behalf of users. Let's cover the most important security practices.

**Remember**: Your MCP server is part of an AI system. That means potentially untrusted input from AI models. Always validate, always authenticate, always authorize.

> ⚠️ **Security First**: If you only remember one thing from this section, make it this: Never trust input, even from AI models. Always validate.

**Important Security Practices:**

1. **Input Validation**
   - Validate all tool parameters
   - Sanitize file paths
   - Check parameter types and ranges

2. **Authentication**
   - Implement authentication for network transports
   - Use API keys or tokens
   - Consider OAuth for user-specific access

3. **Authorization**
   - Check permissions before executing tools
   - Limit resource access based on client
   - Implement rate limiting

4. **Data Privacy**
   - Don't log sensitive data
   - Encrypt network communications (HTTPS)
   - Handle PII appropriately

---

## 9. Next Steps {#next-steps}

Congratulations! You've made it through the fundamentals. You now understand:
- ✅ How MCP works at the protocol level
- ✅ The different transport mechanisms
- ✅ Server and client architecture
- ✅ How to use the official SDKs
- ✅ Best practices for building reliable servers

**But this is just the beginning!** Understanding fundamentals is great, but there's so much more to explore. Here's where to go from here based on what you want to learn next.

### Continue Learning

Now that you understand MCP fundamentals, explore these topics:

1. **[MCP Tools Deep Dive](../mcp_tools_deep_dive.md)** - Master tool creation and invocation
2. **[MCP Resources Deep Dive](../mcp_resources_deep_dive.md)** - Learn resource management patterns
3. **[MCP Implementation Guide](../mcp_implementation_guide.md)** - Build production servers and clients

### Hands-On Practice

Reading is one thing, but you learn by doing. Here are some exercises to cement your understanding. Start with #1 and work your way up. Don't skip ahead - each builds on the previous one!

> 🎯 **Challenge Yourself**: Try to complete these without looking at the examples. Struggle a bit - that's where the learning happens. But don't spin your wheels forever - if you're stuck for more than 15 minutes, look at the examples.

1. **Build a Calculator Server**
   - Implement basic math operations
   - Add validation
   - Test with a client

2. **Create a File Reader**
   - Expose files as resources
   - Support multiple file types
   - Add filtering capabilities

3. **Integrate an API**
   - Wrap an external API as MCP tools
   - Handle rate limiting
   - Cache responses appropriately

### Real Projects

Ready to build something that matters? Here are project ideas that solve real problems. Pick one that interests you - motivation is key to finishing!

**Pro tip**: Start small. Don't try to build the perfect, production-ready system on day one. Get something working, then improve it. Progress > perfection.

- Build an MCP server for your company's API
- Create a database query tool
- Implement a code analysis server
- Develop a documentation search resource

---

## 📚 Additional Resources

### Official Documentation
- **[MCP Specification](https://spec.modelcontextprotocol.io)** - Complete protocol spec
- **[Python SDK Docs](https://github.com/modelcontextprotocol/python-sdk)** - Python implementation
- **[TypeScript SDK Docs](https://github.com/modelcontextprotocol/typescript-sdk)** - TypeScript implementation

### Code Examples
- **[MCP Examples Repository](../../mcp_examples/)** - Working code examples
- **[Basic Client & Server](../../mcp_examples/mcp_client_w_sql_lite/)** - Complete example
- **[Your First MCP Server](../../mcp_examples/your_first_mcp_server/)** - Step-by-step tutorial

### Community Resources
- **[MCP GitHub](https://github.com/modelcontextprotocol)** - Official repositories
- **[MCP Discussion Forum](https://github.com/modelcontextprotocol/specification/discussions)** - Community Q&A

---

## 🎯 Key Takeaways

You've covered a lot of ground! Let's make sure the most important concepts stuck. Before moving on, take a moment to review these key points. If any of them feel fuzzy, that's okay - revisit that section, or come back to it after working through some examples.

Before moving on, ensure you understand:

1. ✅ **MCP Role**: Universal interface between AI and tools/data
2. ✅ **JSON-RPC Protocol**: Request/response message format
3. ✅ **Connection Lifecycle**: Initialize → Active → Shutdown
4. ✅ **Transports**: stdio (local), HTTP (network), custom
5. ✅ **Architecture**: Client SDK, Protocol Layer, Server, Business Logic
6. ✅ **SDK Options**: Python and TypeScript official implementations
7. ✅ **Best Practices**: Validation, error handling, security

**You did it!** 🎉 You now have a solid foundation in MCP. The concepts might still feel a bit abstract, but that's normal. They'll click into place as you start building.

---

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Complete  
**Maintained By**: Robert Fischer (robert@fischer3.net)

---

**Ready for more?** Continue to [MCP Tools Deep Dive](../mcp_tools_deep_dive.md) →

> 💪 **You've Got This!** Remember, every expert was once a beginner. Keep building, keep learning, and don't be afraid to make mistakes. That's how we all learn!