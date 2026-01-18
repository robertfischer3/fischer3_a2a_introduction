"""
Simple Task Queue using SQLite

Stage 1: INSECURE - No access controls, no validation

VULNERABILITIES:
- No authentication
- No authorization 
- No input validation
- Anyone can read/write/delete any task
- No audit logging
"""

import sqlite3
import json
from typing import List, Dict, Optional
from datetime import datetime

class TaskQueue:
    """
    Simple SQLite-based task queue
    
    Stage 1: Completely open - no security whatsoever
    """
    
    def __init__(self, db_path: str = ":memory:"):
        """
        Initialize task queue
        
        Args:
            db_path: Path to SQLite database (default: in-memory)
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        
        print(f"📦 Task queue initialized (database: {db_path})")
    
    def _create_tables(self):
        """Create database tables"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                task_data TEXT NOT NULL,
                status TEXT NOT NULL,
                assigned_to TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()
    
    def add_task(self, task: Dict) -> str:
        """
        Add task to queue
        
        Stage 1: ❌ No validation, no authorization
        Anyone can add any task!
        """
        task_id = task["task_id"]
        task_data = json.dumps(task)
        status = task.get("status", "pending")
        assigned_to = task.get("assigned_to")
        
        # ❌ No validation of task structure
        # ❌ No authorization check
        # ❌ No limits on task creation
        
        self.conn.execute(
            """
            INSERT INTO tasks (task_id, task_data, status, assigned_to) 
            VALUES (?, ?, ?, ?)
            """,
            (task_id, task_data, status, assigned_to)
        )
        self.conn.commit()
        
        return task_id
    
    def get_task(self, task_id: str) -> Optional[Dict]:
        """
        Get task by ID
        
        Stage 1: ❌ No access control
        Anyone can read any task!
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE task_id = ?",
            (task_id,)
        )
        row = cursor.fetchone()
        
        if row:
            return json.loads(row["task_data"])
        return None
    
    def update_task(self, task_id: str, task: Dict):
        """
        Update task data
        
        Stage 1: ❌ No authorization check
        Anyone can modify any task!
        """
        task_data = json.dumps(task)
        status = task.get("status", "pending")
        assigned_to = task.get("assigned_to")
        
        # ❌ No check if requester can modify this task
        # ❌ No validation of updates
        # ❌ No audit trail of changes
        
        self.conn.execute(
            """
            UPDATE tasks 
            SET task_data = ?, 
                status = ?, 
                assigned_to = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE task_id = ?
            """,
            (task_data, status, assigned_to, task_id)
        )
        self.conn.commit()
    
    def delete_task(self, task_id: str):
        """
        Delete task
        
        Stage 1: ❌ No authorization
        Anyone can delete any task!
        """
        # ❌ No check if requester can delete
        # ❌ No soft delete or recovery
        # ❌ No audit trail
        
        self.conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
        self.conn.commit()
    
    def get_all_tasks(self) -> List[Dict]:
        """
        Get all tasks
        
        Stage 1: ❌ No access control
        Anyone can see everything!
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks ORDER BY created_at DESC"
        )
        
        return [json.loads(row["task_data"]) for row in cursor.fetchall()]
    
    def get_tasks_by_status(self, status: str) -> List[Dict]:
        """
        Get tasks by status
        
        Stage 1: ❌ No access control
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE status = ? ORDER BY created_at DESC",
            (status,)
        )
        
        return [json.loads(row["task_data"]) for row in cursor.fetchall()]
    
    def get_tasks_by_agent(self, agent_id: str) -> List[Dict]:
        """
        Get tasks assigned to specific agent
        
        Stage 1: ❌ No verification of requester
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE assigned_to = ? ORDER BY created_at DESC",
            (agent_id,)
        )
        
        return [json.loads(row["task_data"]) for row in cursor.fetchall()]
    
    def get_completed_tasks(self) -> List[Dict]:
        """
        Get all completed tasks
        
        Stage 1: ❌ No access control
        Perfect for attackers to find tasks to steal credit for!
        """
        return self.get_tasks_by_status("completed")
    
    def count_tasks(self) -> int:
        """Get total number of tasks"""
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM tasks")
        return cursor.fetchone()["count"]
    
    def clear_all_tasks(self):
        """
        Clear all tasks from queue
        
        Stage 1: ❌ No authorization
        Anyone can wipe the entire queue!
        """
        self.conn.execute("DELETE FROM tasks")
        self.conn.commit()
        print("🗑️  All tasks cleared")
    
    def get_statistics(self) -> Dict:
        """Get queue statistics"""
        cursor = self.conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
            FROM tasks
        """)
        
        row = cursor.fetchone()
        return {
            "total": row["total"],
            "pending": row["pending"],
            "in_progress": row["in_progress"],
            "completed": row["completed"]
        }
    
    def close(self):
        """Close database connection"""
        self.conn.close()
    
    def __del__(self):
        """Cleanup on deletion"""
        if hasattr(self, 'conn'):
            self.conn.close()

# Stage 1 Summary:
# - No authentication: Anyone can use the queue
# - No authorization: Anyone can do anything
# - No validation: Any data is accepted
# - No auditing: No trace of who did what
# - No rate limiting: Can be overwhelmed
# 
# This is INTENTIONALLY VULNERABLE for educational purposes!