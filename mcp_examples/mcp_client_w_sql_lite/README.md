# Basic MCP Client & Server Example with Gemini API

This is a foundational example demonstrating the Model Context Protocol (MCP) using Python. It's designed for developers learning MCP fundamentals before moving to framework implementations like LangChain.

## 📚 What This Example Demonstrates

This example shows the **basic building blocks** of MCP:

1. **MCP Server** (`mcp_server.py`) - Exposes database tools via the MCP protocol
2. **MCP Client** (`mcp_client.py`) - Connects to the server and facilitates LLM communication
3. **LLM Integration** - Uses Google's Gemini API as the "host" that orchestrates tool calls

### Architecture Overview

```
┌─────────────────┐
│  User Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│   Gemini API (LLM)      │  ◄── Decides which tools to call
│   - Understands intent  │
│   - Plans tool usage    │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│   MCP Client            │  ◄── Manages communication
│   - JSON-RPC protocol   │
│   - Tool conversion     │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│   MCP Server            │  ◄── Executes operations
│   - SQLite operations   │
│   - read_records        │
│   - add_record          │
│   - delete_record       │
└─────────────────────────┘
```

## 🎯 Key MCP Concepts Demonstrated

### 1. **JSON-RPC Protocol**
MCP uses JSON-RPC 2.0 for communication:
- Each request has: `jsonrpc`, `id`, `method`, `params`
- Each response has: `jsonrpc`, `id`, `result` (or `error`)

### 2. **Standard MCP Methods**
- `initialize` - Establishes connection and capabilities
- `tools/list` - Returns available tools
- `tools/call` - Executes a specific tool

### 3. **Tool Definitions**
Tools follow a standard schema:
- `name` - Tool identifier
- `description` - What the tool does
- `inputSchema` - JSON Schema for parameters

### 4. **Server Communication**
The server runs as a subprocess and communicates via stdin/stdout, making it:
- Language-agnostic (server could be in any language)
- Process-isolated
- Easy to test and debug

## 🛠️ Setup Instructions

### Prerequisites
- Python 3.8 or higher
- Google Gemini API key (free tier available)

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

Or install directly:
```bash
pip install google-generativeai
```

### Step 2: Get Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Create API Key"
3. Copy your API key

### Step 3: Set Environment Variable

**Linux/Mac:**
```bash
export GEMINI_API_KEY='your-api-key-here'
```

**Windows (Command Prompt):**
```cmd
set GEMINI_API_KEY=your-api-key-here
```

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY='your-api-key-here'
```

### Step 4: Run the Demo

```bash
python mcp_client.py
```

## 📖 What Happens When You Run It

The demo performs 5 operations:

1. **Read Records** - Lists all contacts in the database
2. **Add Record** - Adds "David Brown" to the database
3. **Confirm Addition** - Reads records again to verify
4. **Delete Record** - Removes contact with ID 2
5. **Final Verification** - Shows the final state

Each operation demonstrates:
- Natural language → LLM understanding
- LLM → Tool selection
- Tool execution → Database operation
- Result → Natural language response

## 🔍 Code Walkthrough

### MCP Server (`mcp_server.py`)

The server is intentionally simple and demonstrates:

**Core Functions:**
- `initialize_database()` - Sets up SQLite with sample data
- `read_records()` - Returns all contacts
- `add_record(name, email, phone)` - Inserts new contact
- `delete_record(id)` - Removes contact by ID

**MCP Protocol Handlers:**
- `handle_initialize()` - Returns server capabilities
- `handle_list_tools()` - Describes available tools
- `handle_call_tool()` - Executes tool and returns result

**Communication:**
- Reads JSON-RPC requests from stdin
- Writes JSON-RPC responses to stdout
- Errors go to stderr

### MCP Client (`mcp_client.py`)

The client has two main classes:

**MCPClient:**
- Manages the server subprocess
- Sends JSON-RPC requests
- Receives and parses responses
- Implements basic MCP methods

**GeminiMCPHost:**
- Configures Gemini API
- Converts MCP tools to Gemini function declarations
- Handles the conversation loop
- Executes tools when Gemini requests them

## 🎓 Teaching Notes

### Why This Design?

1. **No Frameworks** - Shows raw MCP protocol without abstractions
2. **Clear Separation** - Client, Server, and LLM are distinct components
3. **Observable** - Print statements show each step
4. **Extensible** - Easy to add new tools or modify behavior

### Key Learning Points

**For Students:**
- How MCP protocol works at the JSON-RPC level
- How LLMs decide when to call tools
- How tool schemas enable LLM understanding
- Process-based architecture benefits

**For Next Steps (LangChain):**
- This example shows what LangChain abstracts away
- Understanding these basics makes framework usage clearer
- Same concepts apply: tools, schemas, execution flow

## 🔧 Customization Ideas

### Add New Tools
In `mcp_server.py`, add a new function and register it:

```python
def update_record(record_id, name=None, email=None, phone=None):
    """Update an existing record"""
    # Implementation here
    pass

# Add to handle_list_tools():
{
    "name": "update_record",
    "description": "Update a contact's information",
    "inputSchema": {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "description": "Record ID"},
            "name": {"type": "string", "description": "New name"},
            # ... more fields
        },
        "required": ["id"]
    }
}
```

### Different Database Operations
- Search/filter records
- Bulk operations
- Aggregations and reports

### Different LLM Providers
- Replace Gemini with OpenAI
- Use Anthropic's Claude API
- Try local models (Ollama, etc.)

## 🐛 Troubleshooting

### "GEMINI_API_KEY not set"
Make sure you've exported the environment variable in your current terminal session.

### "Module not found: google.generativeai"
Run: `pip install google-generativeai`

### Server doesn't respond
Check that `mcp_server.py` is in the same directory and has no syntax errors.

### Database locked
SQLite database might be locked if a previous run didn't clean up. Delete `example.db` and try again.

## 📚 Additional Resources

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Google Gemini API Docs](https://ai.google.dev/docs)
- [JSON-RPC 2.0 Spec](https://www.jsonrpc.org/specification)

## 📝 License

This is educational code - use it freely for learning and teaching!

## 🤝 Contributing

This is a teaching example. Feel free to fork and adapt for your own lessons!
 