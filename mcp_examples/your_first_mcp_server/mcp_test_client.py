#!/usr/bin/env python3
"""
MCP Test Client for Ubuntu
A simple client to test MCP servers locally without Claude Desktop
"""

import asyncio
import json
import sys
from pathlib import Path

try:
    from mcp.client import Client
    from mcp.client.stdio import stdio_client
except ImportError:
    print("❌ MCP client library not found!")
    print("\nPlease install it:")
    print("  pip install mcp --break-system-packages")
    print("\nOr with uv:")
    print("  uv pip install mcp")
    sys.exit(1)


class Colors:
    """ANSI color codes for pretty output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


async def test_mcp_server(server_script_path: str):
    """Test an MCP server."""
    
    # Verify server file exists
    server_path = Path(server_script_path)
    if not server_path.exists():
        print(f"{Colors.FAIL}❌ Server file not found: {server_script_path}{Colors.ENDC}")
        return False
    
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 70)
    print("                    MCP Server Test Client")
    print("=" * 70)
    print(f"{Colors.ENDC}")
    print(f"Testing server: {Colors.OKCYAN}{server_script_path}{Colors.ENDC}\n")
    
    try:
        # Connect to the server
        async with stdio_client(["python3", str(server_path)]) as (read, write):
            async with Client(read, write) as client:
                
                # Initialize the connection
                print(f"{Colors.OKBLUE}🔌 Initializing connection...{Colors.ENDC}")
                await client.initialize()
                print(f"{Colors.OKGREEN}✓ Connected successfully{Colors.ENDC}\n")
                
                # List available tools
                print(f"{Colors.HEADER}📋 Available Tools:{Colors.ENDC}")
                print("-" * 70)
                tools_result = await client.list_tools()
                
                if not tools_result.tools:
                    print(f"{Colors.WARNING}⚠ No tools found in server{Colors.ENDC}")
                    return False
                
                for i, tool in enumerate(tools_result.tools, 1):
                    print(f"\n{Colors.BOLD}{i}. {tool.name}{Colors.ENDC}")
                    print(f"   {Colors.OKCYAN}Description:{Colors.ENDC} {tool.description}")
                    
                    # Show parameters in a readable format
                    if tool.inputSchema and 'properties' in tool.inputSchema:
                        props = tool.inputSchema['properties']
                        if props:
                            print(f"   {Colors.OKCYAN}Parameters:{Colors.ENDC}")
                            for param_name, param_info in props.items():
                                param_type = param_info.get('type', 'unknown')
                                param_desc = param_info.get('description', '')
                                required = param_name in tool.inputSchema.get('required', [])
                                req_marker = f"{Colors.WARNING}*{Colors.ENDC}" if required else " "
                                print(f"      {req_marker} {param_name} ({param_type}): {param_desc}")
                
                print("\n" + "=" * 70)
                print(f"{Colors.HEADER}🧪 Testing Tools{Colors.ENDC}")
                print("=" * 70)
                
                # Test each tool
                test_cases = {
                    "get_current_time": {"timezone": "UTC"},
                    "add_numbers": {"a": 15, "b": 27},
                    "random_joke": {},
                    "reverse_string": {"text": "Hello MCP on Ubuntu!"},
                    "greet": {"name": "Ubuntu User"},
                }
                
                success_count = 0
                fail_count = 0
                
                for tool in tools_result.tools:
                    print(f"\n{Colors.OKBLUE}Testing: {tool.name}{Colors.ENDC}")
                    print("-" * 50)
                    
                    # Get test arguments
                    test_args = test_cases.get(tool.name, {})
                    
                    # Show what we're testing with
                    if test_args:
                        print(f"   Arguments: {json.dumps(test_args)}")
                    
                    try:
                        result = await client.call_tool(tool.name, test_args)
                        print(f"   {Colors.OKGREEN}✓ Success!{Colors.ENDC}")
                        
                        for content in result.content:
                            # Truncate long responses
                            text = content.text
                            if len(text) > 200:
                                text = text[:200] + "..."
                            print(f"   {Colors.OKCYAN}Result:{Colors.ENDC} {text}")
                        
                        success_count += 1
                    except Exception as e:
                        print(f"   {Colors.FAIL}✗ Error: {e}{Colors.ENDC}")
                        fail_count += 1
                
                # Summary
                print("\n" + "=" * 70)
                print(f"{Colors.HEADER}📊 Test Summary{Colors.ENDC}")
                print("=" * 70)
                print(f"Total tools: {len(tools_result.tools)}")
                print(f"{Colors.OKGREEN}Successful: {success_count}{Colors.ENDC}")
                if fail_count > 0:
                    print(f"{Colors.FAIL}Failed: {fail_count}{Colors.ENDC}")
                
                if fail_count == 0:
                    print(f"\n{Colors.OKGREEN}{Colors.BOLD}✅ All tests passed!{Colors.ENDC}")
                    return True
                else:
                    print(f"\n{Colors.WARNING}⚠ Some tests failed{Colors.ENDC}")
                    return False
                    
    except Exception as e:
        print(f"\n{Colors.FAIL}❌ Error connecting to server:{Colors.ENDC}")
        print(f"   {e}")
        print(f"\n{Colors.WARNING}Troubleshooting tips:{Colors.ENDC}")
        print("   1. Make sure the server file is a valid Python script")
        print("   2. Check that the server uses stdio transport")
        print("   3. Verify MCP library is installed: pip show mcp")
        print("   4. Try running the server directly: python3", server_script_path)
        return False


async def interactive_mode(server_script_path: str):
    """Interactive mode to manually test tools."""
    
    server_path = Path(server_script_path)
    if not server_path.exists():
        print(f"{Colors.FAIL}❌ Server file not found: {server_script_path}{Colors.ENDC}")
        return
    
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 70)
    print("              MCP Server Interactive Test Mode")
    print("=" * 70)
    print(f"{Colors.ENDC}")
    
    async with stdio_client(["python3", str(server_path)]) as (read, write):
        async with Client(read, write) as client:
            await client.initialize()
            
            tools_result = await client.list_tools()
            
            while True:
                print(f"\n{Colors.OKBLUE}Available tools:{Colors.ENDC}")
                for i, tool in enumerate(tools_result.tools, 1):
                    print(f"  {i}. {tool.name} - {tool.description}")
                
                print(f"\n{Colors.OKCYAN}Enter tool number to test (or 'q' to quit):{Colors.ENDC} ", end='')
                choice = input().strip()
                
                if choice.lower() == 'q':
                    print("Goodbye!")
                    break
                
                try:
                    tool_idx = int(choice) - 1
                    if 0 <= tool_idx < len(tools_result.tools):
                        tool = tools_result.tools[tool_idx]
                        
                        # Get arguments
                        args = {}
                        if tool.inputSchema and 'properties' in tool.inputSchema:
                            print(f"\n{Colors.OKCYAN}Enter arguments (JSON format):{Colors.ENDC}")
                            print(f"Example: {{'param': 'value'}}")
                            print("Or press Enter for empty arguments: ", end='')
                            args_input = input().strip()
                            if args_input:
                                args = json.loads(args_input)
                        
                        # Call tool
                        result = await client.call_tool(tool.name, args)
                        print(f"\n{Colors.OKGREEN}✓ Result:{Colors.ENDC}")
                        for content in result.content:
                            print(f"  {content.text}")
                    else:
                        print(f"{Colors.FAIL}Invalid tool number{Colors.ENDC}")
                except (ValueError, json.JSONDecodeError) as e:
                    print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}Error calling tool: {e}{Colors.ENDC}")


def main():
    """Main entry point."""
    
    if len(sys.argv) < 2:
        print(f"{Colors.FAIL}Usage:{Colors.ENDC}")
        print(f"  {sys.argv[0]} <path_to_server.py> [--interactive]")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} simple_mcp_server.py")
        print(f"  {sys.argv[0]} simple_mcp_server.py --interactive")
        sys.exit(1)
    
    server_path = sys.argv[1]
    interactive = "--interactive" in sys.argv or "-i" in sys.argv
    
    if interactive:
        asyncio.run(interactive_mode(server_path))
    else:
        result = asyncio.run(test_mcp_server(server_path))
        sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
