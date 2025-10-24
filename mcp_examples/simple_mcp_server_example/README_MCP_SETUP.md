# Simple MCP Server for Claude Desktop (Ubuntu Setup)

This is a basic MCP (Model Context Protocol) server that provides simple tools for testing with Claude Desktop on Ubuntu.

## Features

The server provides 4 simple tools:

1. **get_current_time** - Get the current date and time
2. **add_numbers** - Add two numbers together
3. **random_joke** - Get a random programming joke
4. **reverse_string** - Reverse a text string

## Setup Instructions

### 1. Make the server executable
```bash
chmod +x simple_mcp_server.py
```

### 2. Test the server locally (optional)
You can test if the server starts correctly:
```bash
python3 simple_mcp_server.py
```
Press Ctrl+C to stop it.

### 3. Configure Claude Desktop

Claude Desktop's configuration file is located at:
```
~/.config/Claude/claude_desktop_config.json
```

Create or edit this file with the following content:

```json
{
  "mcpServers": {
    "simple-demo": {
      "command": "python3",
      "args": [
        "/home/claude/simple_mcp_server.py"
      ]
    }
  }
}
```

**Important:** Replace `/home/claude/simple_mcp_server.py` with the actual full path to where you saved the server file.

To get the full path, run:
```bash
readlink -f simple_mcp_server.py
```

### 4. Restart Claude Desktop

After updating the configuration:
1. Completely quit Claude Desktop (not just close the window)
2. Restart Claude Desktop

### 5. Verify the Server is Connected

In Claude Desktop, you should see a small hammer/tool icon or an indicator that MCP servers are connected. You can ask Claude to:
- "What's the current time?"
- "Add 15 and 27"
- "Tell me a programming joke"
- "Reverse the string 'Hello World'"

## Troubleshooting

### Server not connecting
1. Check that the path in the config file is correct
2. Ensure Python 3 is installed: `python3 --version`
3. Verify the MCP package is installed: `pip list | grep mcp`

### Permission issues
Make sure the script is executable:
```bash
chmod +x simple_mcp_server.py
```

### Check logs
Claude Desktop logs are typically in:
```
~/.config/Claude/logs/
```

## Next Steps

Once this basic server is working, you can:
1. Add more complex tools
2. Integrate with external APIs
3. Access files or databases
4. Create specialized tools for your workflow

## Example Modifications

### Adding a new tool

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ... existing tools ...
        Tool(
            name="your_new_tool",
            description="What your tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "Description of parameter",
                    }
                },
                "required": ["param1"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    # ... existing tool handlers ...
    if name == "your_new_tool":
        result = f"You called: {arguments['param1']}"
        return [TextContent(type="text", text=result)]
```

## Resources

- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [Official MCP Documentation](https://modelcontextprotocol.io)