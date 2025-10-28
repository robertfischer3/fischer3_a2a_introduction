#!/usr/bin/env python3
"""
Simple MCP Server Tester
Works by directly calling the server's functions for testing
"""

import sys
import asyncio
from pathlib import Path


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_section(text):
    """Print a section header."""
    print(f"\n{text}")
    print("-" * 50)


async def test_server_module(server_path):
    """Test an MCP server by importing and calling its functions."""
    
    print_header("MCP Server Direct Tester")
    print(f"\nTesting: {server_path}\n")
    
    # Add server directory to path
    server_file = Path(server_path)
    if not server_file.exists():
        print(f"❌ Error: Server file not found: {server_path}")
        return False
    
    sys.path.insert(0, str(server_file.parent))
    
    try:
        # Import the server module
        module_name = server_file.stem
        server_module = __import__(module_name)
        
        print("✓ Server module loaded successfully")
        
        # Test list_tools
        print_section("📋 Testing list_tools()")
        
        if hasattr(server_module, 'list_tools'):
            tools = await server_module.list_tools()
            print(f"✓ Found {len(tools)} tools:\n")
            
            for i, tool in enumerate(tools, 1):
                print(f"{i}. {tool.name}")
                print(f"   Description: {tool.description}")
                if tool.inputSchema and 'properties' in tool.inputSchema:
                    props = tool.inputSchema['properties']
                    if props:
                        print(f"   Parameters:")
                        for param_name, param_info in props.items():
                            param_type = param_info.get('type', 'unknown')
                            required = param_name in tool.inputSchema.get('required', [])
                            req_str = " (required)" if required else ""
                            print(f"      - {param_name}: {param_type}{req_str}")
                print()
        else:
            print("❌ No list_tools function found")
            return False
        
        # Test call_tool
        print_section("🧪 Testing call_tool()")
        
        if not hasattr(server_module, 'call_tool'):
            print("❌ No call_tool function found")
            return False
        
        # Define test cases
        test_cases = [
            ("get_current_time", {}),
            ("add_numbers", {"a": 15, "b": 27}),
            ("random_joke", {}),
            ("reverse_string", {"text": "MCP Testing!"}),
            ("greet", {"name": "Ubuntu"}),
        ]
        
        success_count = 0
        fail_count = 0
        
        for tool_name, args in test_cases:
            # Check if this tool exists
            tool_exists = any(t.name == tool_name for t in tools)
            if not tool_exists:
                continue
            
            print(f"\nTesting: {tool_name}")
            if args:
                print(f"  Args: {args}")
            
            try:
                result = await server_module.call_tool(tool_name, args)
                print(f"  ✓ Success!")
                
                # Print result
                if result and len(result) > 0:
                    text = result[0].text
                    if len(text) > 100:
                        text = text[:100] + "..."
                    print(f"  Result: {text}")
                
                success_count += 1
            except Exception as e:
                print(f"  ✗ Error: {e}")
                fail_count += 1
        
        # Summary
        print_header("📊 Test Summary")
        print(f"\nTotal tools: {len(tools)}")
        print(f"Tests run: {success_count + fail_count}")
        print(f"✓ Passed: {success_count}")
        if fail_count > 0:
            print(f"✗ Failed: {fail_count}")
        
        if fail_count == 0 and success_count > 0:
            print("\n✅ All tests passed!")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"\n❌ Error testing server:")
        print(f"   {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    
    if len(sys.argv) < 2:
        print("Usage: python simple_test.py <path_to_server.py>")
        print("\nExample:")
        print("  python simple_test.py simple_mcp_server.py")
        sys.exit(1)
    
    server_path = sys.argv[1]
    result = asyncio.run(test_server_module(server_path))
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
