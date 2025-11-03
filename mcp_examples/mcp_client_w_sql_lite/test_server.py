"""
Simple MCP Server Test - No API Key Required
Tests the MCP server directly without using an LLM
"""

import json
import subprocess
import sys


def send_request(process, method, params=None, request_id=1):
    """Send a JSON-RPC request and get response"""
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method
    }
    if params:
        request["params"] = params
    
    # Send request
    request_json = json.dumps(request) + "\n"
    process.stdin.write(request_json)
    process.stdin.flush()
    
    # Read response
    response_line = process.stdout.readline()
    response = json.loads(response_line)
    
    return response


def main():
    """Test the MCP server functionality"""
    print("=" * 60)
    print("MCP Server Direct Test (No API Key Needed)")
    print("=" * 60)
    
    # Start server
    print("\n[1] Starting MCP Server...")
    server = subprocess.Popen(
        ["python", "mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    print("✓ Server started")
    
    try:
        # Test 1: Initialize
        print("\n[2] Testing initialize...")
        response = send_request(server, "initialize", {
            "protocolVersion": "0.1.0",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        })
        print(f"✓ Initialize response: {response['result']['serverInfo']['name']}")
        
        # Test 2: List tools
        print("\n[3] Testing tools/list...")
        response = send_request(server, "tools/list", request_id=2)
        tools = response['result']['tools']
        print(f"✓ Found {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['description']}")
        
        # Test 3: Read records
        print("\n[4] Testing read_records...")
        response = send_request(server, "tools/call", {
            "name": "read_records",
            "arguments": {}
        }, request_id=3)
        result = json.loads(response['result']['content'][0]['text'])
        print(f"✓ Read {result['count']} records:")
        for record in result['records']:
            print(f"  ID {record['id']}: {record['name']} - {record['email']}")
        
        # Test 4: Add a record
        print("\n[5] Testing add_record...")
        response = send_request(server, "tools/call", {
            "name": "add_record",
            "arguments": {
                "name": "Test User",
                "email": "test@example.com",
                "phone": "555-9999"
            }
        }, request_id=4)
        result = json.loads(response['result']['content'][0]['text'])
        new_id = result['id']
        print(f"✓ {result['message']}")
        
        # Test 5: Read records again
        print("\n[6] Verifying addition...")
        response = send_request(server, "tools/call", {
            "name": "read_records",
            "arguments": {}
        }, request_id=5)
        result = json.loads(response['result']['content'][0]['text'])
        print(f"✓ Now have {result['count']} records")
        
        # Test 6: Delete the record we just added
        print("\n[7] Testing delete_record...")
        response = send_request(server, "tools/call", {
            "name": "delete_record",
            "arguments": {"id": new_id}
        }, request_id=6)
        result = json.loads(response['result']['content'][0]['text'])
        print(f"✓ {result['message']}")
        
        # Test 7: Final verification
        print("\n[8] Final verification...")
        response = send_request(server, "tools/call", {
            "name": "read_records",
            "arguments": {}
        }, request_id=7)
        result = json.loads(response['result']['content'][0]['text'])
        print(f"✓ Final count: {result['count']} records")
        
        print("\n" + "=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        print("\nThe MCP server is working correctly.")
        print("You can now run 'python mcp_client.py' to see it with Gemini.")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        # Cleanup
        server.stdin.close()
        server.terminate()
        server.wait()
        print("\n✓ Server stopped")


if __name__ == "__main__":
    main()
