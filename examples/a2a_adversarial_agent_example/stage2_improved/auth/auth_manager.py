"""
JWT-based Authentication Manager

Stage 2: IMPROVED - Basic JWT authentication

IMPROVEMENTS OVER STAGE 1:
✅ Token-based authentication
✅ Password hashing (bcrypt)
✅ Token expiration (24 hours)
✅ Token verification

REMAINING VULNERABILITIES:
⚠️ Symmetric key (HS256) - not asymmetric
⚠️ No token refresh mechanism
⚠️ No token revocation (weak blacklist)
⚠️ No MFA
⚠️ No request signing (messages can be replayed)
⚠️ Weak password requirements
"""

import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Set
import json

class AuthManager:
    """
    Manages JWT-based authentication
    
    Stage 2: Basic but incomplete authentication
    """
    
    def __init__(self, secret_key: str = None):
        """
        Initialize AuthManager
        
        Args:
            secret_key: Secret for JWT signing (generated if not provided)
        """
        # ⚠️ Stage 2: Uses symmetric HS256
        # Stage 3 will use asymmetric RS256
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        
        # Store registered agents
        self.registered_agents: Dict[str, Dict] = {}
        
        # Simple token blacklist (in-memory)
        # ⚠️ VULNERABILITY: Doesn't persist across restarts
        self.token_blacklist: Set[str] = set()
        
        print(f"🔐 AuthManager initialized (HS256)")
    
    def register_agent(self, agent_id: str, password: str, 
                      role: str = "worker") -> str:
        """
        Register a new agent and issue JWT token
        
        Stage 2: ✅ Requires password, hashes with bcrypt
        ⚠️ No password strength requirements
        ⚠️ Trusts requested role without verification
        
        Args:
            agent_id: Unique agent identifier
            password: Agent's password
            role: Requested role (worker/manager/admin)
        
        Returns:
            JWT token string
        
        Raises:
            ValueError: If agent already registered
        """
        # Check if already registered
        if agent_id in self.registered_agents:
            raise ValueError(f"Agent {agent_id} already registered")
        
        # ⚠️ Stage 2: No password strength validation
        # Should check: length, complexity, common passwords
        if len(password) < 3:  # Very weak check
            raise ValueError("Password too short (min 3 chars)")
        
        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )
        
        # Store agent info
        self.registered_agents[agent_id] = {
            "password_hash": password_hash,
            "role": role,  # ⚠️ Trust requested role!
            "registered_at": datetime.utcnow().isoformat(),
            "login_attempts": 0
        }
        
        # Generate and return JWT token
        token = self._generate_token(agent_id, role)
        
        print(f"✅ Registered agent: {agent_id} (role: {role})")
        return token
    
    def login(self, agent_id: str, password: str) -> Optional[str]:
        """
        Authenticate agent and issue new token
        
        Stage 2: ✅ Verifies password with bcrypt
        ⚠️ No rate limiting on failed attempts
        ⚠️ No account lockout
        
        Args:
            agent_id: Agent identifier
            password: Agent's password
        
        Returns:
            JWT token if successful, None if failed
        """
        # Check if agent exists
        if agent_id not in self.registered_agents:
            # ⚠️ Timing attack possible - reveals if user exists
            # Should use constant-time comparison
            return None
        
        agent = self.registered_agents[agent_id]
        
        # Verify password
        try:
            if bcrypt.checkpw(password.encode('utf-8'), agent["password_hash"]):
                # ⚠️ No rate limiting - can brute force
                agent["login_attempts"] = 0
                agent["last_login"] = datetime.utcnow().isoformat()
                
                # Generate new token
                token = self._generate_token(agent_id, agent["role"])
                print(f"✅ Login successful: {agent_id}")
                return token
            else:
                # Track failed attempts (but no lockout)
                agent["login_attempts"] += 1
                print(f"❌ Login failed: {agent_id} (attempt {agent['login_attempts']})")
                return None
                
        except Exception as e:
            print(f"❌ Login error for {agent_id}: {e}")
            return None
    
    def _generate_token(self, agent_id: str, role: str) -> str:
        """
        Generate JWT token
        
        Stage 2: ✅ Includes expiration
        ⚠️ Uses symmetric HS256 (shared secret)
        ⚠️ No refresh token mechanism
        
        Args:
            agent_id: Agent identifier
            role: Agent role
        
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        
        payload = {
            "agent_id": agent_id,
            "role": role,
            "iat": now,  # Issued at
            "exp": now + timedelta(hours=24)  # Expires in 24 hours
        }
        
        # ⚠️ HS256 is symmetric - anyone with secret can forge tokens
        # Stage 3 will use RS256 (asymmetric)
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
        
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """
        Verify JWT token and return payload
        
        Stage 2: ✅ Checks signature and expiration
        ⚠️ Simple blacklist (doesn't persist)
        
        Args:
            token: JWT token string
        
        Returns:
            Payload dict if valid, None if invalid
        """
        try:
            # Check blacklist
            if token in self.token_blacklist:
                print(f"❌ Token is blacklisted")
                return None
            
            # Decode and verify
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=["HS256"]
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            print(f"❌ Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"❌ Invalid token: {e}")
            return None
    
    def authenticate_message(self, message: Dict) -> Optional[str]:
        """
        Authenticate a message via JWT token
        
        Stage 2: ✅ Verifies token
        ⚠️ No request signing - messages can be replayed
        ⚠️ No nonce - same token can be used multiple times
        
        Args:
            message: Message dict with 'auth_token' field
        
        Returns:
            Agent ID if authenticated, None if not
        """
        # Extract token from message
        token = message.get("auth_token")
        
        if not token:
            print(f"❌ No auth token in message")
            return None
        
        # Verify token
        payload = self.verify_token(token)
        
        if not payload:
            return None
        
        # Extract agent_id from payload
        token_agent_id = payload.get("agent_id")
        message_agent_id = message.get("agent_id")
        
        # Verify agent_id in token matches message
        if token_agent_id != message_agent_id:
            print(f"❌ Agent ID mismatch: token={token_agent_id}, message={message_agent_id}")
            return None
        
        return token_agent_id
    
    def revoke_token(self, token: str):
        """
        Revoke a token by adding to blacklist
        
        Stage 2: ⚠️ Simple in-memory blacklist
        ⚠️ Doesn't persist across restarts
        ⚠️ Can grow unbounded
        
        Args:
            token: Token to revoke
        """
        self.token_blacklist.add(token)
        print(f"🔴 Token revoked (blacklist size: {len(self.token_blacklist)})")
    
    def get_agent_role(self, agent_id: str) -> Optional[str]:
        """Get agent's role"""
        if agent_id in self.registered_agents:
            return self.registered_agents[agent_id]["role"]
        return None
    
    def agent_exists(self, agent_id: str) -> bool:
        """Check if agent is registered"""
        return agent_id in self.registered_agents
    
    def get_statistics(self) -> Dict:
        """Get authentication statistics"""
        return {
            "total_agents": len(self.registered_agents),
            "blacklisted_tokens": len(self.token_blacklist),
            "roles": {
                "worker": sum(1 for a in self.registered_agents.values() if a["role"] == "worker"),
                "manager": sum(1 for a in self.registered_agents.values() if a["role"] == "manager"),
                "admin": sum(1 for a in self.registered_agents.values() if a["role"] == "admin")
            }
        }

# Stage 2 Summary:
# 
# ✅ Improvements:
# - JWT token authentication
# - Password hashing with bcrypt
# - Token expiration
# - Basic token verification
# 
# ⚠️ Remaining Vulnerabilities:
# 1. Symmetric keys (HS256) - less secure than asymmetric
# 2. No token refresh - must re-login after 24h
# 3. Weak blacklist - doesn't persist
# 4. No MFA - single factor only
# 5. No request signing - messages can be replayed
# 6. No rate limiting - brute force possible
# 7. Weak password requirements
# 8. No role verification - trusts requested role
# 
# These will be addressed in Stage 3!