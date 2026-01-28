"""
Task Queue with Access Control

Stage 2: IMPROVED - Permission checking integrated

IMPROVEMENTS OVER STAGE 1:
✅ Permission checks before read/write/delete
✅ Ownership tracking
✅ Basic access logging
✅ Integration with PermissionManager

REMAINING VULNERABILITIES:
⚠️ No encryption of stored data
⚠️ No integrity protection on tasks
⚠️ No audit trail of changes
⚠️ Can still modify if have WRITE_ALL_TASKS
⚠️ No task-level security labels
"""

import sqlite3
import json
from typing import List, Dict, Optional

class TaskQueue:
    """
    SQLite-based task queue with access control
    
    Stage 2: Basic permission checking added
    """
    
    def __init__(self, db_path: str = ":memory:", permission_manager=None):
        """
        Initialize task queue
        
        Args:
            db_path: Path to SQLite database
            permission_manager: PermissionManager instance for access control
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.permission_manager = permission_manager
        
        self._create_tables()
        
        print(f"📦 Task queue initialized (database: {db_path})")
        if permission_manager:
            print(f"   ✅ Access control enabled")
        else:
            print(f"   ⚠️  Access control disabled")
    
    def _create_tables(self):
        """Create database tables"""
        # Tasks table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                task_data TEXT NOT NULL,
                status TEXT NOT NULL,
                assigned_to TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT
            )
        """)
        
        # Access log table (Stage 2: NEW)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                task_id TEXT,
                allowed BOOLEAN,
                reason TEXT
            )
        """)
        
        self.conn.commit()
    
    def add_task(self, task: Dict, agent_id: str) -> str:
        """
        Add task to queue
        
        Stage 2: ✅ Checks CREATE_TASKS permission
        ⚠️ But doesn't validate task content
        
        Args:
            task: Task dictionary
            agent_id: Agent creating the task
        
        Returns:
            Task ID if successful
        
        Raises:
            PermissionError: If agent lacks permission
        """
        task_id = task["task_id"]
        
        # Check permission (Stage 2: NEW)
        if self.permission_manager:
            if not self.permission_manager.can_create_task(agent_id):
                self._log_access(agent_id, "create", task_id, False, 
                               "No CREATE_TASKS permission")
                raise PermissionError(f"Agent {agent_id} cannot create tasks")
        
        # Add created_by if not present
        if "created_by" not in task:
            task["created_by"] = agent_id
        
        task_data = json.dumps(task)
        status = task.get("status", "pending")
        assigned_to = task.get("assigned_to")
        
        self.conn.execute(
            """
            INSERT INTO tasks (task_id, task_data, status, assigned_to, created_by, updated_by) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (task_id, task_data, status, assigned_to, agent_id, agent_id)
        )
        self.conn.commit()
        
        self._log_access(agent_id, "create", task_id, True, "Task created")
        
        return task_id
    
    def get_task(self, task_id: str, agent_id: str) -> Optional[Dict]:
        """
        Get task by ID
        
        Stage 2: ✅ Checks read permission
        
        Args:
            task_id: Task identifier
            agent_id: Agent requesting task
        
        Returns:
            Task dict if allowed and exists, None otherwise
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE task_id = ?",
            (task_id,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        task = json.loads(row["task_data"])
        
        # Check read permission (Stage 2: NEW)
        if self.permission_manager:
            if not self.permission_manager.can_read_task(agent_id, task):
                self._log_access(agent_id, "read", task_id, False, 
                               "No read permission")
                return None
        
        self._log_access(agent_id, "read", task_id, True, "Task read")
        return task
    
    def update_task(self, task_id: str, task: Dict, agent_id: str):
        """
        Update task data
        
        Stage 2: ✅ Checks modify permission
        ⚠️ Doesn't prevent malicious updates to completed tasks
        ⚠️ No integrity check on modifications
        
        Args:
            task_id: Task identifier
            task: Updated task dict
            agent_id: Agent updating task
        
        Raises:
            PermissionError: If agent lacks permission
        """
        # Check permission (Stage 2: NEW)
        if self.permission_manager:
            if not self.permission_manager.can_modify_task(agent_id, task):
                self._log_access(agent_id, "update", task_id, False, 
                               "No modify permission")
                raise PermissionError(f"Agent {agent_id} cannot modify task {task_id}")
        
        task_data = json.dumps(task)
        status = task.get("status", "pending")
        assigned_to = task.get("assigned_to")
        
        # ⚠️ VULNERABILITY: No validation that update is legitimate
        # ⚠️ Can modify completed_by, metrics, etc.
        
        self.conn.execute(
            """
            UPDATE tasks 
            SET task_data = ?, 
                status = ?, 
                assigned_to = ?,
                updated_at = CURRENT_TIMESTAMP,
                updated_by = ?
            WHERE task_id = ?
            """,
            (task_data, status, assigned_to, agent_id, task_id)
        )
        self.conn.commit()
        
        self._log_access(agent_id, "update", task_id, True, "Task updated")
    
    def delete_task(self, task_id: str, agent_id: str):
        """
        Delete task
        
        Stage 2: ✅ Checks delete permission
        ⚠️ Hard delete, no recovery
        
        Args:
            task_id: Task identifier
            agent_id: Agent deleting task
        
        Raises:
            PermissionError: If agent lacks permission
        """
        # Get task first to check permission
        task = self.get_task(task_id, agent_id)
        if not task:
            raise PermissionError(f"Agent {agent_id} cannot access task {task_id}")
        
        # Check delete permission (Stage 2: NEW)
        if self.permission_manager:
            if not self.permission_manager.can_delete_task(agent_id, task):
                self._log_access(agent_id, "delete", task_id, False, 
                               "No delete permission")
                raise PermissionError(f"Agent {agent_id} cannot delete tasks")
        
        # ⚠️ Hard delete - no soft delete or recovery
        self.conn.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
        self.conn.commit()
        
        self._log_access(agent_id, "delete", task_id, True, "Task deleted")
    
    def get_all_tasks(self, agent_id: str) -> List[Dict]:
        """
        Get all tasks visible to agent
        
        Stage 2: ✅ Filters by read permission
        
        Args:
            agent_id: Agent requesting tasks
        
        Returns:
            List of tasks agent can read
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks ORDER BY created_at DESC"
        )
        
        all_tasks = [json.loads(row["task_data"]) for row in cursor.fetchall()]
        
        # Filter by read permission (Stage 2: NEW)
        if self.permission_manager:
            visible_tasks = []
            for task in all_tasks:
                if self.permission_manager.can_read_task(agent_id, task):
                    visible_tasks.append(task)
            return visible_tasks
        
        return all_tasks
    
    def get_tasks_by_status(self, status: str, agent_id: str) -> List[Dict]:
        """
        Get tasks by status
        
        Stage 2: ✅ Filters by permission
        
        Args:
            status: Task status
            agent_id: Agent requesting tasks
        
        Returns:
            List of tasks with given status that agent can read
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE status = ? ORDER BY created_at DESC",
            (status,)
        )
        
        all_tasks = [json.loads(row["task_data"]) for row in cursor.fetchall()]
        
        # Filter by permission (Stage 2: NEW)
        if self.permission_manager:
            return [t for t in all_tasks 
                   if self.permission_manager.can_read_task(agent_id, t)]
        
        return all_tasks
    
    def get_tasks_by_agent(self, assigned_agent_id: str) -> List[Dict]:
        """
        Get tasks assigned to specific agent
        
        Args:
            assigned_agent_id: Agent identifier
        
        Returns:
            List of tasks assigned to agent
        """
        cursor = self.conn.execute(
            "SELECT task_data FROM tasks WHERE assigned_to = ? ORDER BY created_at DESC",
            (assigned_agent_id,)
        )
        
        return [json.loads(row["task_data"]) for row in cursor.fetchall()]
    
    def _log_access(self, agent_id: str, action: str, task_id: str,
                   allowed: bool, reason: str):
        """
        Log access attempt
        
        Stage 2: ✅ NEW - Basic access logging
        ⚠️ In-memory only, not encrypted
        
        Args:
            agent_id: Agent attempting access
            action: Action attempted (create/read/update/delete)
            task_id: Task ID
            allowed: Whether access was allowed
            reason: Reason for decision
        """
        self.conn.execute(
            """
            INSERT INTO access_log (agent_id, action, task_id, allowed, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (agent_id, action, task_id, allowed, reason)
        )
        self.conn.commit()
    
    def get_access_log(self, agent_id: str = None, limit: int = 100) -> List[Dict]:
        """
        Get access log
        
        Stage 2: ✅ NEW - View audit trail
        
        Args:
            agent_id: Filter by agent (None for all)
            limit: Maximum entries to return
        
        Returns:
            List of access log entries
        """
        if agent_id:
            cursor = self.conn.execute(
                """
                SELECT * FROM access_log 
                WHERE agent_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
                """,
                (agent_id, limit)
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
        
        return [dict(row) for row in cursor.fetchall()]
    
    def count_tasks(self) -> int:
        """Get total number of tasks"""
        cursor = self.conn.execute("SELECT COUNT(*) as count FROM tasks")
        return cursor.fetchone()["count"]
    
    def get_statistics(self) -> Dict:
        """
        Get queue statistics
        
        Returns:
            Dictionary with task counts by status
        """
        cursor = self.conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM tasks
        """)
        
        row = cursor.fetchone()
        return {
            "total": row["total"] or 0,
            "pending": row["pending"] or 0,
            "in_progress": row["in_progress"] or 0,
            "completed": row["completed"] or 0,
            "failed": row["failed"] or 0
        }
    
    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()
    
    def __del__(self):
        """Cleanup on deletion"""
        self.close()


# Stage 2 Summary:
# 
# ✅ Improvements over Stage 1:
# - Permission checks before all operations
# - Ownership-based access control
# - Basic access logging
# - Integration with PermissionManager
# - Tracks who created/updated tasks
# - Read operations filtered by permission
# 
# ⚠️ Remaining Vulnerabilities:
# 1. No encryption of task data at rest
# 2. No integrity protection (tasks can be tampered with)
# 3. No prevention of malicious updates to completed tasks
# 4. Access log not encrypted or integrity-protected
# 5. Hard deletes (no soft delete or recovery)
# 6. No task-level security labels or classifications
# 7. Can still modify any field if have WRITE_ALL_TASKS permission
# 8. No validation of update legitimacy (can change completed_by, etc.)
# 9. No size limits on task data
# 10. No rate limiting on operations
# 
# These vulnerabilities are INTENTIONAL for Stage 2 teaching.
# They will be addressed in Stage 3!