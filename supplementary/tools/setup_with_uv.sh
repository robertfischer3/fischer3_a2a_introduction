#!/bin/bash

# Complete Example: Setting up MCP Server with UV
# This script demonstrates a full workflow using uv

echo "=========================================="
echo "MCP Server Setup with UV"
echo "=========================================="
echo ""

# Step 1: Create project directory
echo "Step 1: Creating project directory..."
mkdir -p ~/mcp-demo-project
cd ~/mcp-demo-project
echo "✓ Created ~/mcp-demo-project"
echo ""

# Step 2: Create virtual environment with uv
echo "Step 2: Creating virtual environment with uv..."
uv venv
echo "✓ Virtual environment created in .venv/"
echo ""

# Step 3: Activate virtual environment
echo "Step 3: Activating virtual environment..."
source .venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Step 4: Install dependencies using uv
echo "Step 4: Installing dependencies..."
echo "Installing: mcp, httpx, pydantic..."
uv pip install mcp httpx pydantic
echo "✓ Dependencies installed"
echo ""

# Step 5: Create requirements.txt
echo "Step 5: Creating requirements.txt..."
uv pip freeze > requirements.txt
echo "✓ requirements.txt created"
echo ""

# Step 6: Show installed packages
echo "Step 6: Showing installed packages..."
uv pip list
echo ""

# Step 7: Create a simple MCP server file
echo "Step 7: Creating sample MCP server..."
cat > server.py << 'EOF'
#!/usr/bin/env python3
"""Simple MCP Server using UV-managed dependencies"""

import asyncio
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

app = Server("uv-demo-server")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="greet",
            description="Greet someone",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name to greet"}
                },
                "required": ["name"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "greet":
        greeting = f"Hello, {arguments['name']}! 👋"
        return [TextContent(type="text", text=greeting)]
    return [TextContent(type="text", text="Unknown tool")]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
EOF

chmod +x server.py
echo "✓ server.py created"
echo ""

# Step 8: Create README
echo "Step 8: Creating README..."
cat > README.md << 'EOF'
# MCP Demo Project (UV-managed)

This project demonstrates using UV for dependency management.

## Setup

```bash
# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt
```

## Run

```bash
python server.py
```

## Add More Dependencies

```bash
uv pip install <package-name>
uv pip freeze > requirements.txt
```
EOF

echo "✓ README.md created"
echo ""

# Summary
echo "=========================================="
echo "Setup Complete! 🎉"
echo "=========================================="
echo ""
echo "Project structure:"
tree -L 2 -a ~/mcp-demo-project 2>/dev/null || ls -la ~/mcp-demo-project
echo ""
echo "To use this project:"
echo "1. cd ~/mcp-demo-project"
echo "2. source .venv/bin/activate"
echo "3. python server.py"
echo ""
echo "To add more packages:"
echo "  uv pip install <package>"
echo ""
echo "To update requirements.txt:"
echo "  uv pip freeze > requirements.txt"
echo ""

# Deactivate
deactivate
echo "Virtual environment deactivated."
echo "Done! ✨"
