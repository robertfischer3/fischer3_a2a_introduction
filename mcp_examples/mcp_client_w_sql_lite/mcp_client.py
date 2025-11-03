"""
MCP Client - Connects to MCP Server and uses Gemini as the LLM host
Demonstrates basic MCP protocol communication
"""

import json
import subprocess
import os
import google.generativeai as genai


class MCPClient:
    """Basic MCP Client that communicates with an MCP Server"""
    
    def __init__(self, server_script):
        """Initialize the client and start the MCP server process"""
        self.request_id = 0
        self.server_process = subprocess.Popen(
            ["python", server_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        print("✓ MCP Server started")
    
    def send_request(self, method, params=None):
        """Send a JSON-RPC request to the MCP server"""
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method
        }
        if params:
            request["params"] = params
        
        # Send request
        request_json = json.dumps(request) + "\n"
        self.server_process.stdin.write(request_json)
        self.server_process.stdin.flush()
        
        # Read response
        response_line = self.server_process.stdout.readline()
        response = json.loads(response_line)
        
        if "error" in response:
            raise Exception(f"Server error: {response['error']}")
        
        return response.get("result")
    
    def initialize(self):
        """Initialize the MCP connection"""
        result = self.send_request("initialize", {
            "protocolVersion": "0.1.0",
            "capabilities": {},
            "clientInfo": {
                "name": "basic-mcp-client",
                "version": "1.0.0"
            }
        })
        print("✓ MCP Connection initialized")
        return result
    
    def list_tools(self):
        """Get list of available tools from the server"""
        result = self.send_request("tools/list")
        print(f"✓ Found {len(result['tools'])} tools")
        return result["tools"]
    
    def call_tool(self, tool_name, arguments=None):
        """Call a tool on the MCP server"""
        result = self.send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments or {}
        })
        return result
    
    def close(self):
        """Close the connection to the server"""
        self.server_process.stdin.close()
        self.server_process.terminate()
        self.server_process.wait()
        print("✓ MCP Server stopped")


class GeminiMCPHost:
    """Host that uses Gemini API to interact with MCP tools"""
    
    def __init__(self, api_key, mcp_client):
        """Initialize Gemini with MCP client"""
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.mcp_client = mcp_client
        self.tools = []
        self.conversation_history = []
    
    def load_tools(self):
        """Load available tools from MCP server"""
        self.tools = self.mcp_client.list_tools()
        print(f"✓ Loaded {len(self.tools)} tools for Gemini")
        for tool in self.tools:
            print(f"  - {tool['name']}: {tool['description']}")
    
    def _convert_to_gemini_tools(self):
        """Convert MCP tool definitions to Gemini function declarations"""
        gemini_tools = []
        for tool in self.tools:
            gemini_tool = {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["inputSchema"]
            }
            gemini_tools.append(gemini_tool)
        return gemini_tools
    
    def _execute_tool_call(self, function_call):
        """Execute a tool call via MCP client"""
        tool_name = function_call.name
        arguments = dict(function_call.args)
        
        print(f"\n🔧 Executing tool: {tool_name}")
        print(f"   Arguments: {json.dumps(arguments, indent=2)}")
        
        result = self.mcp_client.call_tool(tool_name, arguments)
        result_text = result["content"][0]["text"]
        
        print(f"✓ Tool result received")
        return result_text
    
    def chat(self, user_message):
        """Send a message and handle tool calls automatically"""
        print(f"\n💬 User: {user_message}")
        
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "parts": [user_message]
        })
        
        # Convert MCP tools to Gemini format
        gemini_tools = self._convert_to_gemini_tools()
        
        # Start chat with tools
        chat = self.model.start_chat(
            history=self.conversation_history[:-1]  # All but the last message
        )
        
        # Send message with available tools
        response = chat.send_message(
            user_message,
            tools=[{"function_declarations": gemini_tools}]
        )
        
        # Handle function calls in a loop
        while response.candidates[0].content.parts[0].function_call:
            function_call = response.candidates[0].content.parts[0].function_call
            
            # Execute the function
            tool_result = self._execute_tool_call(function_call)
            
            # Send result back to Gemini
            response = chat.send_message(
                genai.protos.Content(
                    parts=[genai.protos.Part(
                        function_response=genai.protos.FunctionResponse(
                            name=function_call.name,
                            response={"result": tool_result}
                        )
                    )]
                )
            )
        
        # Get final text response
        final_response = response.text
        print(f"\n🤖 Assistant: {final_response}")
        
        # Update conversation history
        self.conversation_history = chat.history
        
        return final_response


def main():
    """Main demonstration of MCP Client with Gemini"""
    print("=" * 60)
    print("MCP Client with Gemini API Demo")
    print("=" * 60)
    
    # Get API key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("\n❌ Error: GEMINI_API_KEY environment variable not set")
        print("Please set it with: export GEMINI_API_KEY='your-api-key'")
        return
    
    print("\n[1] Starting MCP Server...")
    mcp_client = MCPClient("mcp_server.py")
    
    try:
        print("\n[2] Initializing MCP Connection...")
        mcp_client.initialize()
        
        print("\n[3] Initializing Gemini Host...")
        host = GeminiMCPHost(api_key, mcp_client)
        host.load_tools()
        
        print("\n" + "=" * 60)
        print("Demo Conversations")
        print("=" * 60)
        
        # Demo 1: Read all records
        print("\n--- Demo 1: Reading all records ---")
        host.chat("Can you show me all the contacts in the database?")
        
        # Demo 2: Add a new record
        print("\n\n--- Demo 2: Adding a new record ---")
        host.chat("Please add a new contact: David Brown, email david@example.com, phone 555-0104")
        
        # Demo 3: Read records again to confirm
        print("\n\n--- Demo 3: Confirming the addition ---")
        host.chat("Show me all contacts again to confirm David was added")
        
        # Demo 4: Delete a record
        print("\n\n--- Demo 4: Deleting a record ---")
        host.chat("Delete the contact with ID 2")
        
        # Demo 5: Final read
        print("\n\n--- Demo 5: Final verification ---")
        host.chat("Show me the final list of contacts")
        
        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n[Cleanup] Shutting down...")
        mcp_client.close()


if __name__ == "__main__":
    main()
