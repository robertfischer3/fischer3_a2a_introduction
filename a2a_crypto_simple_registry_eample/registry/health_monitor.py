"""
Health Monitor for Agent Registry
Monitors agent health and marks stale agents as unhealthy
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional
import threading


class HealthMonitor:
    """
    Background health monitor for registered agents
    
    Periodically checks agent heartbeat times and marks stale agents
    as unhealthy. This prevents discovery of dead agents.
    """
    
    def __init__(self, storage, check_interval: int = 30, stale_threshold: int = 90):
        """
        Initialize health monitor
        
        Args:
            storage: RegistryStorage instance
            check_interval: Seconds between health checks
            stale_threshold: Seconds without heartbeat before marking unhealthy
        """
        self.storage = storage
        self.check_interval = check_interval
        self.stale_threshold = stale_threshold
        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        
        print(f"💓 Health monitor initialized (check every {check_interval}s, "
              f"stale after {stale_threshold}s)")
    
    def start(self):
        """Start the health monitor"""
        if not self.running:
            self.running = True
            # Create a new event loop in a background thread
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            print("💚 Health monitor started")
    
    def stop(self):
        """Stop the health monitor"""
        if self.running:
            self.running = False
            if self.loop:
                self.loop.call_soon_threadsafe(self.loop.stop)
            print("💔 Health monitor stopped")
    
    def _run_loop(self):
        """Run the event loop in background thread"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._monitor_loop())
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                await self._check_agent_health()
            except Exception as e:
                print(f"⚠️  Health check error: {e}")
            
            # Wait before next check
            await asyncio.sleep(self.check_interval)
    
    async def _check_agent_health(self):
        """Check health of all registered agents"""
        agents = self.storage.list_agents()
        
        if not agents:
            return
        
        now = datetime.utcnow()
        stale_count = 0
        healthy_count = 0
        
        for agent in agents:
            agent_id = agent["agent_card"]["agent_id"]
            last_heartbeat_str = agent.get("last_heartbeat")
            
            if not last_heartbeat_str:
                # No heartbeat recorded, mark as unhealthy
                self.storage.update_health_status(agent_id, "unhealthy")
                stale_count += 1
                continue
            
            try:
                last_heartbeat = datetime.fromisoformat(last_heartbeat_str)
                time_since_heartbeat = (now - last_heartbeat).total_seconds()
                
                if time_since_heartbeat > self.stale_threshold:
                    # Agent is stale
                    if agent.get("health_status") != "unhealthy":
                        self.storage.update_health_status(agent_id, "unhealthy")
                        stale_count += 1
                else:
                    # Agent is healthy
                    if agent.get("health_status") != "healthy":
                        self.storage.update_health_status(agent_id, "healthy")
                    healthy_count += 1
                    
            except (ValueError, AttributeError) as e:
                # Invalid timestamp, mark as unhealthy
                self.storage.update_health_status(agent_id, "unhealthy")
                stale_count += 1
        
        # Log summary if there were changes
        if stale_count > 0:
            print(f"💓 Health check: {healthy_count} healthy, {stale_count} unhealthy")
    
    def get_status(self) -> dict:
        """
        Get health monitor status
        
        Returns:
            Dictionary with monitor status information
        """
        return {
            "running": self.running,
            "check_interval": self.check_interval,
            "stale_threshold": self.stale_threshold
        }