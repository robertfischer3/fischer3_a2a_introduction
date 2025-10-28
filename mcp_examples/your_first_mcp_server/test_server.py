#!/usr/bin/env python3
"""
Test script for the simple MCP server.
This verifies that the server can be imported and started without errors.
"""

import sys
import asyncio

try:
    from mcp.server import Server
    print("✓ MCP package installed correctly")
except ImportError as e:
    print("✗ MCP package not found. Please install with:")
    print("  pip install mcp --break-system-packages")
    sys.exit(1)

try:
    import simple_mcp_server
    print("✓ Server module can be imported")
except Exception as e:
    print(f"✗ Error importing server: {e}")
    sys.exit(1)

async def test_tools():
    """Test that tools can be listed."""
    try:
        tools = await simple_mcp_server.list_tools()
        print(f"✓ Server provides {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
        return True
    except Exception as e:
        print(f"✗ Error listing tools: {e}")
        return False

async def test_tool_calls():
    """Test that tools can be called."""
    print("\n Testing tool calls:")
    
    tests = [
        ("get_current_time", {}),
        ("add_numbers", {"a": 5, "b": 3}),
        ("random_joke", {}),
        ("reverse_string", {"text": "MCP Server"}),
    ]
    
    for name, args in tests:
        try:
            result = await simple_mcp_server.call_tool(name, args)
            print(f"✓ {name}: {result[0].text[:50]}...")
        except Exception as e:
            print(f"✗ {name} failed: {e}")
            return False
    
    return True

async def main():
    print("=" * 60)
    print("MCP Server Test Suite")
    print("=" * 60)
    print()
    
    if await test_tools():
        print()
        if await test_tool_calls():
            print("\n" + "=" * 60)
            print("✓ All tests passed! Server is ready to use.")
            print("=" * 60)
            return 0
    
    print("\n" + "=" * 60)
    print("✗ Some tests failed. Please check the errors above.")
    print("=" * 60)
    return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
