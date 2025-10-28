# Testing MCP Servers on Ubuntu (Without Claude Desktop)

Since Claude Desktop is not available for Linux/Ubuntu, here are several alternatives for testing your MCP server locally.

---

## Option 1: MCP Inspector (Recommended) ⭐

The **MCP Inspector** is the official testing tool from Anthropic that works on all platforms.

### Installation

```bash
# Using npx (no installation needed)
npx @modelcontextprotocol/inspector

# Or install globally with npm
npm install -g @modelcontextprotocol/inspector

# Or using uvx (if you have uv installed)
uvx mcp-inspector
```

### Usage

```bash
# Run the inspector
npx @modelcontextprotocol/inspector python /path/to/your/simple_mcp_server.py

# Or if you installed globally
mcp-inspector python /path/to/your/simple_mcp_server.py
```

This opens a web interface where you can:
- See available tools
- Test tool calls interactively
- View request/response data
- Debug issues

### Web Interface
The inspector runs at `http://localhost:6274` by default.

---

## Option 2: Python Test Client

Create your own simple test client to interact with your MCP server.

### Create Test Client

```python
#!/usr/bin/env python3
"""
Simple MCP test client for local testing
"""

import asyncio
import json
from mcp.client import Client
from mcp.client.stdio import stdio_client

async def test_mcp_server(server_script_path):
    """Test an MCP server."""
    
    # Connect to the server
    async with stdio_client(["python", server_script_path]) as (read, write):
        async with Client(read, write) as client:
            
            # Initialize the connection
            await client.initialize()
            
            print("=" * 60)
            print("MCP Server Test Client")
            print("=" * 60)
            print()
            
            # List available tools
            print("📋 Available Tools:")
            print("-" * 60)
            tools_result = await client.list_tools()
            
            for tool in tools_result.tools:
                print(f"\n🔧 {tool.name}")
                print(f"   Description: {tool.description}")
                print(f"   Parameters: {json.dumps(tool.inputSchema, indent=6)}")
            
            print("\n" + "=" * 60)
            print("🧪 Testing Tools")
            print("=" * 60)
            
            # Test each tool
            for tool in tools_result.tools:
                print(f"\n Testing: {tool.name}")
                print("-" * 40)
                
                # Example arguments for each tool
                test_args = {}
                
                if tool.name == "get_current_time":
                    test_args = {"timezone": "UTC"}
                elif tool.name == "add_numbers":
                    test_args = {"a": 10, "b": 32}
                elif tool.name == "random_joke":
                    test_args = {}
                elif tool.name == "reverse_string":
                    test_args = {"text": "Hello MCP!"}
                
                try:
                    result = await client.call_tool(tool.name, test_args)
                    print(f"✓ Success!")
                    for content in result.content:
                        print(f"  Result: {content.text}")
                except Exception as e:
                    print(f"✗ Error: {e}")
            
            print("\n" + "=" * 60)
            print("✅ Testing Complete!")
            print("=" * 60)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python test_client.py <path_to_server.py>")
        sys.exit(1)
    
    server_path = sys.argv[1]
    asyncio.run(test_mcp_server(server_path))
```

### Usage

```bash
python test_client.py simple_mcp_server.py
```

---

## Option 3: HTTP/SSE Testing with curl

If your MCP server supports HTTP transport, you can test with curl.

### Testing with curl

```bash
# List available tools
curl -X POST http://localhost:3000/mcp/v1/tools/list \
  -H "Content-Type: application/json" \
  -d '{}'

# Call a tool
curl -X POST http://localhost:3000/mcp/v1/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "add_numbers",
    "arguments": {
      "a": 5,
      "b": 10
    }
  }'
```

---

## Option 4: Browser-Based Testing

Create a simple web interface to test your MCP server.

### Simple HTML Test Interface

```html
<!DOCTYPE html>
<html>
<head>
    <title>MCP Server Tester</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        .tool {
            border: 1px solid #ccc;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        .result {
            background: #f0f0f0;
            padding: 10px;
            margin-top: 10px;
            border-radius: 5px;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <h1>MCP Server Tester</h1>
    
    <div class="tool">
        <h3>Get Current Time</h3>
        <button onclick="testTool('get_current_time', {})">Test</button>
        <div id="result-time" class="result"></div>
    </div>
    
    <div class="tool">
        <h3>Add Numbers</h3>
        <input type="number" id="num-a" placeholder="First number" value="10">
        <input type="number" id="num-b" placeholder="Second number" value="20">
        <button onclick="testAdd()">Test</button>
        <div id="result-add" class="result"></div>
    </div>
    
    <div class="tool">
        <h3>Random Joke</h3>
        <button onclick="testTool('random_joke', {})">Test</button>
        <div id="result-joke" class="result"></div>
    </div>
    
    <div class="tool">
        <h3>Reverse String</h3>
        <input type="text" id="text-input" placeholder="Enter text" value="Hello World">
        <button onclick="testReverse()">Test</button>
        <div id="result-reverse" class="result"></div>
    </div>
    
    <script>
        const SERVER_URL = 'http://localhost:3000/mcp/v1';
        
        async function testTool(toolName, args) {
            const resultDiv = document.getElementById(`result-${toolName.replace('_', '-')}`);
            resultDiv.textContent = 'Testing...';
            
            try {
                const response = await fetch(`${SERVER_URL}/tools/call`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        name: toolName,
                        arguments: args
                    })
                });
                
                const data = await response.json();
                resultDiv.textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                resultDiv.textContent = `Error: ${error.message}`;
            }
        }
        
        function testAdd() {
            const a = parseInt(document.getElementById('num-a').value);
            const b = parseInt(document.getElementById('num-b').value);
            testTool('add_numbers', { a, b });
        }
        
        function testReverse() {
            const text = document.getElementById('text-input').value;
            testTool('reverse_string', { text });
        }
    </script>
</body>
</html>
```

Save as `test_interface.html` and open in a browser.

---

## Option 5: Use VS Code with MCP Extension

Visual Studio Code has extensions for testing MCP servers.

### Installation

1. Install VS Code
2. Search for "MCP" in the extensions marketplace
3. Install an MCP extension (if available)
4. Configure your server path
5. Use the extension's UI to test tools

---

## Option 6: Postman/Insomnia

Use API testing tools like Postman or Insomnia to test HTTP-based MCP servers.

### Setup in Postman

1. Create a new collection
2. Add requests for each tool
3. Set up environment variables
4. Test and save responses

---

## Comparison Table

| Option | Pros | Cons | Best For |
|--------|------|------|----------|
| **MCP Inspector** | Official, Web UI, Full features | Requires Node.js | General testing |
| **Python Client** | Simple, Customizable | Need to write code | Automated testing |
| **curl** | No dependencies | Manual, Limited | Quick tests |
| **Browser UI** | Visual, Interactive | Need HTTP server | Demos |
| **VS Code** | IDE integration | Extension dependent | Development |
| **Postman** | Professional UI | Overkill for simple tests | API testing |

---

## Recommended Workflow for Ubuntu

### Step 1: Install Node.js (for MCP Inspector)

```bash
# Using NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### Step 2: Test with MCP Inspector

```bash
# Run inspector
npx @modelcontextprotocol/inspector python /path/to/simple_mcp_server.py
```

### Step 3: Create automated tests

```bash
# Create test client
python test_client.py simple_mcp_server.py
```

### Step 4: (Optional) Browser testing

Create HTML interface for demos and presentations.

---

## Example: Complete Testing Session

```bash
# 1. Start your MCP server test
cd ~/mcp-server

# 2. Run MCP Inspector
npx @modelcontextprotocol/inspector python simple_mcp_server.py

# 3. Open browser to http://localhost:6274

# 4. In another terminal, run Python test client
python test_client.py simple_mcp_server.py

# 5. Check server logs
# Watch for any errors or warnings
```

---

## Debugging Tips

### Enable Logging

Add logging to your MCP server:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    logger.info(f"Tool called: {name} with args: {arguments}")
    # ... rest of your code
```

### Check Server Output

Your server should print debug information:

```bash
python simple_mcp_server.py 2>&1 | tee server.log
```

### Validate JSON

Ensure your server returns valid JSON:

```bash
# Test with jq
curl http://localhost:3000/tools/list | jq .
```

---

## Conclusion

**Best option for Ubuntu**: Use **MCP Inspector** - it's the official tool and works great on Linux.

For automated testing and CI/CD, create a **Python test client**.

For demonstrations, build a simple **browser-based interface**.

All of these options work excellently on Ubuntu without needing Claude Desktop!
