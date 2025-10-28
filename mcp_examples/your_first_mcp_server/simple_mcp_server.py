#!/usr/bin/env python3
"""
Simple MCP Server Example
A basic MCP server that provides simple tools for testing with Claude Desktop.
"""

import asyncio
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import random

# Create an MCP server
app = Server("simple-demo-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="get_current_time",
            description="Get the current date and time",
            inputSchema={
                "type": "object",
                "properties": {
                    "timezone": {
                        "type": "string",
                        "description": "Timezone (optional, defaults to system timezone)",
                    }
                },
            }
        ),
        Tool(
            name="add_numbers",
            description="Add two numbers together",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {
                        "type": "number",
                        "description": "First number",
                    },
                    "b": {
                        "type": "number",
                        "description": "Second number",
                    }
                },
                "required": ["a", "b"]
            }
        ),
        Tool(
            name="random_joke",
            description="Get a random programming joke",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="reverse_string",
            description="Reverse a string",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to reverse",
                    }
                },
                "required": ["text"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""
    
    if name == "get_current_time":
        current_time = datetime.now()
        timezone = arguments.get("timezone", "system")
        result = f"Current time ({timezone}): {current_time.strftime('%Y-%m-%d %H:%M:%S')}"
        return [TextContent(type="text", text=result)]
    
    elif name == "add_numbers":
        a = arguments["a"]
        b = arguments["b"]
        result = a + b
        return [TextContent(type="text", text=f"{a} + {b} = {result}")]
    
    elif name == "random_joke":
        jokes = [
            "Why do programmers prefer dark mode? Because light attracts bugs!",
            "Why do Python programmers prefer snakes? Because they're indent-ented creatures!",
            "How many programmers does it take to change a light bulb? None, that's a hardware problem!",
            "Why did the developer go broke? Because he used up all his cache!",
            "What's a programmer's favorite hangout place? Foo Bar!"
        ]
        joke = random.choice(jokes)
        return [TextContent(type="text", text=joke)]
    
    elif name == "reverse_string":
        text = arguments["text"]
        reversed_text = text[::-1]
        return [TextContent(type="text", text=f"Original: {text}\nReversed: {reversed_text}")]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
