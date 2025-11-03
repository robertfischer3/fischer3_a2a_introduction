"""
MCP Server - SQLite Database Manager
Provides tools to read, add, and delete records from a SQLite database
"""

import json
import sqlite3
import sys
from contextlib import contextmanager

# Database file
DB_FILE = "example.db"


@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    try:
        yield conn
    finally:
        conn.close()


def initialize_database():
    """Create the database and sample table if they don't exist"""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT
            )
        """)
        conn.commit()
        
        # Add sample data if table is empty
        cursor = conn.execute("SELECT COUNT(*) as count FROM contacts")
        if cursor.fetchone()["count"] == 0:
            sample_data = [
                ("Alice Smith", "alice@example.com", "555-0101"),
                ("Bob Johnson", "bob@example.com", "555-0102"),
                ("Carol White", "carol@example.com", "555-0103")
            ]
            conn.executemany(
                "INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)",
                sample_data
            )
            conn.commit()


def read_records():
    """Read all records from the database"""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM contacts ORDER BY id")
        records = [dict(row) for row in cursor.fetchall()]
        return {
            "success": True,
            "records": records,
            "count": len(records)
        }


def add_record(name, email, phone=""):
    """Add a new record to the database"""
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)",
                (name, email, phone)
            )
            conn.commit()
            return {
                "success": True,
                "message": f"Record added successfully with ID {cursor.lastrowid}",
                "id": cursor.lastrowid
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def delete_record(record_id):
    """Delete a record by ID"""
    try:
        with get_db() as conn:
            cursor = conn.execute("DELETE FROM contacts WHERE id = ?", (record_id,))
            conn.commit()
            if cursor.rowcount > 0:
                return {
                    "success": True,
                    "message": f"Record {record_id} deleted successfully"
                }
            else:
                return {
                    "success": False,
                    "error": f"Record {record_id} not found"
                }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def handle_tool_call(tool_name, arguments):
    """Route tool calls to appropriate functions"""
    if tool_name == "read_records":
        return read_records()
    elif tool_name == "add_record":
        return add_record(
            arguments.get("name"),
            arguments.get("email"),
            arguments.get("phone", "")
        )
    elif tool_name == "delete_record":
        return delete_record(arguments.get("id"))
    else:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}


def handle_initialize():
    """Handle MCP initialize request"""
    return {
        "protocolVersion": "0.1.0",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "sqlite-database-server",
            "version": "1.0.0"
        }
    }


def handle_list_tools():
    """Handle MCP tools/list request"""
    return {
        "tools": [
            {
                "name": "read_records",
                "description": "Read all records from the contacts database",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "add_record",
                "description": "Add a new contact record to the database",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Contact's full name"
                        },
                        "email": {
                            "type": "string",
                            "description": "Contact's email address"
                        },
                        "phone": {
                            "type": "string",
                            "description": "Contact's phone number (optional)"
                        }
                    },
                    "required": ["name", "email"]
                }
            },
            {
                "name": "delete_record",
                "description": "Delete a contact record by ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "integer",
                            "description": "The ID of the record to delete"
                        }
                    },
                    "required": ["id"]
                }
            }
        ]
    }


def handle_call_tool(tool_name, arguments):
    """Handle MCP tools/call request"""
    result = handle_tool_call(tool_name, arguments)
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(result, indent=2)
            }
        ]
    }


def process_request(request):
    """Process incoming MCP request"""
    method = request.get("method")
    
    if method == "initialize":
        return handle_initialize()
    elif method == "tools/list":
        return handle_list_tools()
    elif method == "tools/call":
        params = request.get("params", {})
        return handle_call_tool(
            params.get("name"),
            params.get("arguments", {})
        )
    else:
        return {"error": f"Unknown method: {method}"}


def main():
    """Main server loop - reads JSON-RPC requests from stdin"""
    # Initialize database
    initialize_database()
    
    print("MCP Server started. Waiting for requests...", file=sys.stderr)
    
    # Read requests from stdin (JSON-RPC format)
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = process_request(request)
            
            # Send response
            response_obj = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": response
            }
            print(json.dumps(response_obj), flush=True)
            
        except json.JSONDecodeError as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"}
            }
            print(json.dumps(error_response), flush=True)
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if 'request' in locals() else None,
                "error": {"code": -32603, "message": f"Internal error: {e}"}
            }
            print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    main()