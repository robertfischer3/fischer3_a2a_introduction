"""
Storage module for Agent Registry
In-memory storage with optional SQLite persistence
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import json
from threading import Lock


class RegistryStorage:
    """
    In-memory storage for agent registrations
    
    For training purposes, we use simple in-memory storage.
    In production, this would use a database like PostgreSQL, Redis, or MongoDB.
    """
    
    def __init__(self):
        """Initialize storage"""
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()  # Thread safety for concurrent access
        
        print("📦 Initialized in-memory agent storage")
    
    def register_agent(self, agent_id: str, agent_card: Dict, endpoint: str) -> bool:
        """
        Register a new agent
        
        Args:
            agent_id: Unique agent identifier
            agent_card: Agent card data
            endpoint: Agent's network endpoint
            
        Returns:
            True if registration successful
        """
        with self._lock:
            now = datetime.utcnow().isoformat()
            
            self._agents[agent_id] = {
                "agent_card": agent_card,
                "endpoint": endpoint,
                "registered_at": now,
                "last_heartbeat": now,
                "health_status": "healthy"
            }
            
            print(f"✅ Registered agent: {agent_card.get('name')} ({agent_id})")
            return True
    
    def update_agent(self, agent_id: str, agent_card: Dict, endpoint: str) -> bool:
        """
        Update existing agent registration
        
        Args:
            agent_id: Unique agent identifier
            agent_card: Updated agent card data
            endpoint: Updated endpoint
            
        Returns:
            True if update successful
        """
        with self._lock:
            if agent_id not in self._agents:
                return False
            
            # Preserve registration time and update other fields
            registered_at = self._agents[agent_id]["registered_at"]
            now = datetime.utcnow().isoformat()
            
            self._agents[agent_id] = {
                "agent_card": agent_card,
                "endpoint": endpoint,
                "registered_at": registered_at,
                "last_heartbeat": now,
                "health_status": "healthy"
            }
            
            print(f"🔄 Updated agent: {agent_card.get('name')} ({agent_id})")
            return True
    
    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Get agent information
        
        Args:
            agent_id: Unique agent identifier
            
        Returns:
            Agent information or None if not found
        """
        with self._lock:
            return self._agents.get(agent_id)
    
    def unregister_agent(self, agent_id: str) -> bool:
        """
        Remove agent from registry
        
        Args:
            agent_id: Unique agent identifier
            
        Returns:
            True if agent was removed, False if not found
        """
        with self._lock:
            if agent_id in self._agents:
                agent_name = self._agents[agent_id]["agent_card"].get("name", "Unknown")
                del self._agents[agent_id]
                print(f"❌ Unregistered agent: {agent_name} ({agent_id})")
                return True
            return False
    
    def list_agents(self) -> List[Dict[str, Any]]:
        """
        Get list of all registered agents
        
        Returns:
            List of agent information dictionaries
        """
        with self._lock:
            return list(self._agents.values())
    
    def update_heartbeat(self, agent_id: str) -> bool:
        """
        Update agent's last heartbeat time
        
        Args:
            agent_id: Unique agent identifier
            
        Returns:
            True if updated, False if agent not found
        """
        with self._lock:
            if agent_id not in self._agents:
                return False
            
            self._agents[agent_id]["last_heartbeat"] = datetime.utcnow().isoformat()
            self._agents[agent_id]["health_status"] = "healthy"
            return True
    
    def update_health_status(self, agent_id: str, status: str) -> bool:
        """
        Update agent's health status
        
        Args:
            agent_id: Unique agent identifier
            status: Health status (healthy, unhealthy, unknown)
            
        Returns:
            True if updated, False if agent not found
        """
        with self._lock:
            if agent_id not in self._agents:
                return False
            
            old_status = self._agents[agent_id].get("health_status", "unknown")
            self._agents[agent_id]["health_status"] = status
            
            # Log status changes
            if old_status != status:
                agent_name = self._agents[agent_id]["agent_card"].get("name", "Unknown")
                if status == "unhealthy":
                    print(f"⚠️  Agent became unhealthy: {agent_name} ({agent_id})")
                elif status == "healthy":
                    print(f"✅ Agent recovered: {agent_name} ({agent_id})")
            
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics
        
        Returns:
            Dictionary of statistics
        """
        with self._lock:
            total = len(self._agents)
            healthy = sum(1 for a in self._agents.values() if a.get("health_status") == "healthy")
            unhealthy = total - healthy
            
            # Collect unique capabilities
            all_capabilities = set()
            for agent in self._agents.values():
                caps = agent.get("agent_card", {}).get("capabilities", [])
                all_capabilities.update(caps)
            
            return {
                "total_agents": total,
                "healthy_agents": healthy,
                "unhealthy_agents": unhealthy,
                "unique_capabilities": len(all_capabilities),
                "capabilities_list": sorted(all_capabilities)
            }
    
    def clear(self):
        """Clear all stored data (for testing)"""
        with self._lock:
            self._agents.clear()
            print("🧹 Cleared all agent registrations")
    
    def export_to_json(self) -> str:
        """
        Export all registrations to JSON
        
        Returns:
            JSON string of all agents
        """
        with self._lock:
            return json.dumps(self._agents, indent=2)
    
    def import_from_json(self, json_data: str) -> int:
        """
        Import registrations from JSON
        
        Args:
            json_data: JSON string of agent data
            
        Returns:
            Number of agents imported
        """
        with self._lock:
            data = json.loads(json_data)
            self._agents = data
            return len(self._agents)