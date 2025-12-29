"""
Session Manager - Stage 2: Improved

Manages user sessions with basic security improvements over Stage 1.

Stage 2 Improvements:
✅ UUID4 session IDs (unpredictable)
✅ Client ID binding
✅ Idle timeout (30 minutes)
✅ Session invalidation support
✅ IP address logging

Still Missing (Fixed in Stage 3):
❌ No absolute timeout
❌ IP mismatch only logs (doesn't block)
❌ No state encryption
❌ No concurrent session limits
❌ No session binding to multiple factors

Security Rating: Stage 2 = 4/10 (better than Stage 1's 0/10)
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import json


class SessionManager:
    """
    Session management with basic security improvements
    
    Improvements over Stage 1:
    - Uses UUID4 instead of sequential IDs
    - Validates client_id binding
    - Implements idle timeout
    - Supports session invalidation
    - Logs IP address changes
    
    Usage:
        session_mgr = SessionManager(idle_timeout=1800)
        
        # Create session
        session_id = session_mgr.create_session(
            client_id="alice",
            client_ip="192.168.1.100",
            user_agent="Mozilla/5.0...",
            session_data={"roles": ["user"]}
        )
        
        # Validate session
        valid, session = session_mgr.validate_session(
            session_id,
            client_id="alice",
            client_ip="192.168.1.100"
        )
        
        # Invalidate session
        session_mgr.invalidate_session(session_id)
    """
    
    def __init__(self, idle_timeout: int = 1800):
        """
        Initialize session manager
        
        Args:
            idle_timeout: Idle timeout in seconds (default 30 minutes)
        """
        # ✅ In-memory session storage
        # ❌ Stage 2: Not encrypted (fixed in Stage 3)
        # ❌ Stage 2: Not persistent (fixed in Stage 4)
        self.sessions: Dict[str, Dict] = {}
        
        # ✅ Idle timeout
        self.idle_timeout = idle_timeout
        
        # ❌ Stage 2: No absolute timeout (fixed in Stage 3)
        # self.absolute_timeout = 86400  # 24 hours (Stage 3)
        
        print(f"✅ SessionManager initialized")
        print(f"   Idle timeout: {idle_timeout} seconds ({idle_timeout//60} minutes)")
        print(f"   ⚠️  Stage 2: No absolute timeout (added in Stage 3)")
        print(f"   ⚠️  Stage 2: IP mismatch logged but not enforced")
    
    def create_session(
        self,
        client_id: str,
        client_ip: str,
        user_agent: Optional[str] = None,
        session_data: Optional[Dict] = None
    ) -> str:
        """
        Create a new session
        
        ✅ Stage 2: Uses UUID4 (unpredictable)
        ❌ Stage 1: Used sequential IDs (predictable)
        
        Args:
            client_id: User/client identifier
            client_ip: Client IP address
            user_agent: Client user agent string
            session_data: Additional data to store in session
        
        Returns:
            Session ID (UUID4 string)
        
        Example:
            session_id = session_mgr.create_session(
                client_id="alice",
                client_ip="192.168.1.100",
                user_agent="Mozilla/5.0...",
                session_data={
                    "username": "alice",
                    "email": "alice@example.com",
                    "roles": ["user"]
                }
            )
        """
        # ✅ Generate UUID4 session ID
        # Much better than Stage 1's "session-0001"
        session_id = str(uuid.uuid4())
        
        now = datetime.now()
        
        # ✅ Create session with binding information
        self.sessions[session_id] = {
            "session_id": session_id,
            "client_id": client_id,
            
            # ✅ Store IP address for logging
            "client_ip": client_ip,
            "user_agent": user_agent,
            
            # ✅ Timestamps
            "created_at": now,
            "last_activity": now,
            "expires_at": now + timedelta(seconds=self.idle_timeout),
            
            # ❌ Stage 2: No absolute expiration (added in Stage 3)
            # "absolute_expires_at": now + timedelta(seconds=self.absolute_timeout),
            
            # ✅ Custom session data
            "data": session_data or {}
        }
        
        print(f"✅ Session created: {session_id[:8]}... for {client_id}")
        print(f"   IP: {client_ip}")
        print(f"   Expires: {self.sessions[session_id]['expires_at'].strftime('%H:%M:%S')}")
        
        return session_id
    
    def validate_session(
        self,
        session_id: str,
        client_id: str,
        client_ip: str
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Validate a session
        
        ✅ Stage 2 checks:
        1. Session exists
        2. Client ID matches
        3. Not expired (idle timeout)
        
        ⚠️  Stage 2 warnings:
        - IP mismatch logged but not blocked
        
        ❌ Stage 2 missing:
        - No absolute timeout check
        - No state encryption
        - IP not enforced
        
        Args:
            session_id: Session ID to validate
            client_id: Client ID making the request
            client_ip: Client IP address
        
        Returns:
            Tuple of (valid, session_data)
            - valid: True if session is valid
            - session_data: Session data dict if valid, None otherwise
        
        Example:
            valid, session = session_mgr.validate_session(
                session_id,
                client_id="alice",
                client_ip="192.168.1.100"
            )
            
            if valid:
                print(f"User: {session['data']['username']}")
                print(f"Roles: {session['data']['roles']}")
        """
        # 1. ✅ Check if session exists
        if session_id not in self.sessions:
            print(f"❌ Session not found: {session_id[:8]}...")
            return False, None
        
        session = self.sessions[session_id]
        
        # 2. ✅ Check client ID binding
        if session["client_id"] != client_id:
            print(f"❌ Client ID mismatch for session {session_id[:8]}...")
            print(f"   Expected: {session['client_id']}")
            print(f"   Got: {client_id}")
            return False, None
        
        # 3. ✅ Check idle timeout
        now = datetime.now()
        if now > session["expires_at"]:
            print(f"❌ Session expired: {session_id[:8]}...")
            print(f"   Expired at: {session['expires_at'].strftime('%H:%M:%S')}")
            self.invalidate_session(session_id)
            return False, None
        
        # 4. ⚠️  Check IP address (log only, don't block)
        if session["client_ip"] != client_ip:
            print(f"⚠️  IP address mismatch for session {session_id[:8]}...")
            print(f"   Original IP: {session['client_ip']}")
            print(f"   Current IP: {client_ip}")
            print(f"   ⚠️  Stage 2: Logging only (will block in Stage 3)")
            # ❌ In Stage 2, we just log and continue
            # ✅ In Stage 3, this will invalidate the session
        
        # ✅ All checks passed - update activity
        self._touch_session(session_id)
        
        return True, session
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate (destroy) a session
        
        ✅ Stage 2: Supports logout
        ❌ Stage 1: Sessions persisted forever
        
        Args:
            session_id: Session ID to invalidate
        
        Returns:
            True if session was found and invalidated
        
        Example:
            # User logs out
            session_mgr.invalidate_session(session_id)
        """
        if session_id in self.sessions:
            client_id = self.sessions[session_id]["client_id"]
            del self.sessions[session_id]
            print(f"✅ Session invalidated: {session_id[:8]}... ({client_id})")
            return True
        else:
            print(f"⚠️  Session not found for invalidation: {session_id[:8]}...")
            return False
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """
        Get session data without validation
        
        Args:
            session_id: Session ID
        
        Returns:
            Session dict if exists, None otherwise
        
        Note:
            This does NOT validate the session (no expiry check, no binding check)
            Use validate_session() for security checks
        """
        return self.sessions.get(session_id)
    
    def update_session_data(
        self,
        session_id: str,
        data: Dict
    ) -> bool:
        """
        Update session data
        
        Args:
            session_id: Session ID
            data: Data to update (merged with existing)
        
        Returns:
            True if session exists and was updated
        
        Example:
            # Update user's role
            session_mgr.update_session_data(
                session_id,
                {"roles": ["user", "admin"]}
            )
        """
        if session_id not in self.sessions:
            return False
        
        # Merge with existing data
        self.sessions[session_id]["data"].update(data)
        
        # Update activity time
        self._touch_session(session_id)
        
        return True
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions
        
        Should be called periodically (e.g., every 5 minutes)
        
        Returns:
            Number of sessions cleaned up
        
        Example:
            # In a background thread
            while True:
                count = session_mgr.cleanup_expired_sessions()
                if count > 0:
                    print(f"Cleaned up {count} expired sessions")
                time.sleep(300)  # 5 minutes
        """
        now = datetime.now()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            # Check idle timeout
            if now > session["expires_at"]:
                expired_sessions.append(session_id)
            
            # ❌ Stage 2: No absolute timeout check
            # ✅ Stage 3: Will add absolute timeout
            # elif now > session["absolute_expires_at"]:
            #     expired_sessions.append(session_id)
        
        # Remove expired sessions
        for session_id in expired_sessions:
            client_id = self.sessions[session_id]["client_id"]
            del self.sessions[session_id]
            print(f"🗑️  Cleaned up expired session: {session_id[:8]}... ({client_id})")
        
        if expired_sessions:
            print(f"✅ Cleaned up {len(expired_sessions)} expired session(s)")
        
        return len(expired_sessions)
    
    def get_active_session_count(self) -> int:
        """
        Get count of active sessions
        
        Returns:
            Number of active sessions
        """
        return len(self.sessions)
    
    def get_sessions_by_client(self, client_id: str) -> list:
        """
        Get all sessions for a specific client
        
        Args:
            client_id: Client identifier
        
        Returns:
            List of session IDs for this client
        
        Example:
            sessions = session_mgr.get_sessions_by_client("alice")
            print(f"Alice has {len(sessions)} active session(s)")
        """
        return [
            session_id
            for session_id, session in self.sessions.items()
            if session["client_id"] == client_id
        ]
    
    def _touch_session(self, session_id: str):
        """
        Update session activity time and extend expiration
        
        ✅ Stage 2: Extends idle timeout
        
        Args:
            session_id: Session ID to touch
        """
        if session_id not in self.sessions:
            return
        
        now = datetime.now()
        self.sessions[session_id]["last_activity"] = now
        self.sessions[session_id]["expires_at"] = (
            now + timedelta(seconds=self.idle_timeout)
        )
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """
        Get session information (for debugging/monitoring)
        
        ⚠️  Stage 2: Returns sensitive data
        ❌ This should be restricted in production
        
        Args:
            session_id: Session ID
        
        Returns:
            Session information dict
        """
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        # ⚠️  Returning session internals
        # ❌ Stage 2: No access control on this
        # ✅ Stage 3: Will restrict access
        return {
            "session_id": session["session_id"],
            "client_id": session["client_id"],
            "client_ip": session["client_ip"],
            "created_at": session["created_at"].isoformat(),
            "last_activity": session["last_activity"].isoformat(),
            "expires_at": session["expires_at"].isoformat(),
            "idle_timeout": self.idle_timeout,
            "data": session["data"]
        }


if __name__ == "__main__":
    """
    Test the SessionManager
    
    Usage:
        python -m security.session_manager
    """
    import time
    
    print("=" * 60)
    print("SessionManager Test")
    print("=" * 60)
    
    # Create session manager with short timeout for testing
    session_mgr = SessionManager(idle_timeout=10)  # 10 seconds for testing
    
    print("\n--- Test 1: Create Session ---")
    session_id = session_mgr.create_session(
        client_id="alice",
        client_ip="192.168.1.100",
        user_agent="Mozilla/5.0 (Test)",
        session_data={
            "username": "alice",
            "email": "alice@example.com",
            "roles": ["user"]
        }
    )
    print(f"Session ID: {session_id}")
    
    print("\n--- Test 2: Validate Session (Valid) ---")
    valid, session = session_mgr.validate_session(
        session_id,
        client_id="alice",
        client_ip="192.168.1.100"
    )
    print(f"Valid: {valid}")
    if valid:
        print(f"Username: {session['data']['username']}")
        print(f"Roles: {session['data']['roles']}")
    
    print("\n--- Test 3: Wrong Client ID ---")
    valid, session = session_mgr.validate_session(
        session_id,
        client_id="bob",  # Wrong client ID
        client_ip="192.168.1.100"
    )
    print(f"Valid: {valid} (should be False)")
    
    print("\n--- Test 4: IP Address Mismatch ---")
    valid, session = session_mgr.validate_session(
        session_id,
        client_id="alice",
        client_ip="192.168.1.200"  # Different IP
    )
    print(f"Valid: {valid} (Stage 2: still True, Stage 3: would be False)")
    
    print("\n--- Test 5: Multiple Sessions ---")
    session_id2 = session_mgr.create_session(
        client_id="alice",
        client_ip="192.168.1.100",
        session_data={"username": "alice"}
    )
    
    sessions = session_mgr.get_sessions_by_client("alice")
    print(f"Alice has {len(sessions)} active session(s)")
    print(f"Active sessions total: {session_mgr.get_active_session_count()}")
    
    print("\n--- Test 6: Session Expiration ---")
    print("Waiting 11 seconds for session to expire...")
    time.sleep(11)
    
    valid, session = session_mgr.validate_session(
        session_id,
        client_id="alice",
        client_ip="192.168.1.100"
    )
    print(f"Valid: {valid} (should be False - expired)")
    
    print("\n--- Test 7: Cleanup Expired Sessions ---")
    count = session_mgr.cleanup_expired_sessions()
    print(f"Cleaned up {count} session(s)")
    print(f"Active sessions remaining: {session_mgr.get_active_session_count()}")
    
    print("\n--- Test 8: Invalidate Session ---")
    if session_mgr.get_active_session_count() > 0:
        session_mgr.invalidate_session(session_id2)
        print(f"Active sessions: {session_mgr.get_active_session_count()}")
    
    print("\n" + "=" * 60)
    print("Test complete!")