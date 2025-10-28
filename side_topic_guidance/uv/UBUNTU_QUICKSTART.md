# Quick Start: MCP Server Testing on Ubuntu

Since Claude Desktop is not available for Ubuntu, here's how to test your MCP servers locally.

---

## ✅ What You Have

All files are in `/mnt/user-data/outputs/`:

1. **simple_mcp_server.py** - Example MCP server with 4 tools
2. **simple_mcp_test.py** - Direct testing script (EASIEST ⭐)
3. **mcp_test_client.py** - Full-featured test client
4. **test_server.py** - Basic functionality test
5. **MCP_TESTING_UBUNTU.md** - Complete testing guide

---

## 🚀 Quickest Way to Test (30 seconds)

```bash
cd /mnt/user-data/outputs

# Test the MCP server
python3 simple_mcp_test.py simple_mcp_server.py
```

That's it! You'll see:
- ✓ List of available tools
- ✓ Test results for each tool
- ✓ Summary of successes/failures

---

## 📋 Available Testing Methods

### Method 1: Direct Testing (Easiest) ⭐
```bash
python3 simple_mcp_test.py simple_mcp_server.py
```

**Pros:** 
- No dependencies
- Fast
- Clear output

**Cons:**
- Not a full client
- Tests by importing the module

---

### Method 2: MCP Inspector (Most Professional)

The official tool from Anthropic:

```bash
# Install Node.js first (if not installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Run the inspector
npx @modelcontextprotocol/inspector python simple_mcp_server.py
```

Then open http://localhost:6274 in your browser

**Pros:**
- Official tool
- Web interface
- Full MCP protocol testing

**Cons:**
- Requires Node.js
- More setup

---

### Method 3: Your Own Client

Use the provided `mcp_test_client.py` (requires MCP client library):

```bash
# Install dependencies
pip install mcp --break-system-packages

# Run tests
python3 mcp_test_client.py simple_mcp_server.py

# Or interactive mode
python3 mcp_test_client.py simple_mcp_server.py --interactive
```

**Pros:**
- Full MCP client
- Interactive mode available
- Colorful output

**Cons:**
- Requires MCP client library
- More dependencies

---

## 🎯 Recommended Workflow

1. **Start with simple_mcp_test.py** - Quick validation
2. **Use MCP Inspector** for thorough testing
3. **Create custom tests** as your server grows

---

## 📝 Creating Your Own MCP Server

### Step 1: Copy the Template

```bash
cp simple_mcp_server.py my_server.py
```

### Step 2: Add Your Tools

```python
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="my_new_tool",
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
    if name == "my_new_tool":
        result = f"You called with: {arguments['param1']}"
        return [TextContent(type="text", text=result)]
```

### Step 3: Test It

```bash
python3 simple_mcp_test.py my_server.py
```

---

## 🔧 Common Issues & Solutions

### Issue: "Module not found: mcp"
```bash
# Solution:
pip install mcp --break-system-packages
```

### Issue: "Server file not found"
```bash
# Make sure you're in the right directory:
cd /mnt/user-data/outputs

# Or use full path:
python3 simple_mcp_test.py /full/path/to/server.py
```

### Issue: "Port already in use"
```bash
# If testing HTTP servers:
lsof -ti:3000 | xargs kill -9
```

---

## 💡 Tips

1. **Use virtual environments** for each project:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install mcp
   ```

2. **Add logging** to debug:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

3. **Test incrementally** - add one tool at a time

4. **Check the examples** in the project knowledge

---

## 📚 Next Steps

1. ✅ Test the example server
2. ✅ Create your own server
3. ✅ Add custom tools
4. ✅ Test with different methods
5. ✅ Integrate with your applications

---

## 🌐 Using MCP Servers in Applications

### With LangChain

```python
from langchain.tools import StructuredTool
# ... integrate MCP tools
```

### With Your Own Code

```python
import subprocess
import json

# Start MCP server process
process = subprocess.Popen(
    ["python3", "simple_mcp_server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE
)

# Send JSON-RPC requests
# ... handle responses
```

---

## 📖 More Resources

- **MCP Specification**: https://spec.modelcontextprotocol.io
- **Python SDK**: https://github.com/modelcontextprotocol/python-sdk  
- **MCP Docs**: https://modelcontextprotocol.io

---

## ✨ Summary

**For Ubuntu users:**

1. **Quick test**: `python3 simple_mcp_test.py simple_mcp_server.py` ✅
2. **Professional testing**: Install Node.js + use MCP Inspector
3. **Development**: Use the template and iterate

**No Claude Desktop needed!** You have everything you need to develop and test MCP servers on Ubuntu.

Happy coding! 🚀
