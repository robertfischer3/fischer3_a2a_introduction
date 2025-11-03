"""
A2A Agent Registry Server
A simple registry service for Agent2Agent protocol using FastAPI
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager

from models import AgentCard, AgentRegistration, DiscoveryQuery, HealthStatus
from storage import RegistryStorage
from health_monitor import HealthMonitor


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Startup
    print("🚀 Starting Agent Registry Server...")
    health_monitor.start()
    print("✅ Registry is ready")
    
    yield
    
    # Shutdown
    print("\n🛑 Shutting down Agent Registry Server...")
    health_monitor.stop()
    print("✅ Registry shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="A2A Agent Registry",
    description="Service discovery and registration for Agent2Agent protocol",
    version="1.0.0",
    lifespan=lifespan
)

# Initialize storage and health monitor
storage = RegistryStorage()
health_monitor = HealthMonitor(storage)


@app.get("/")
async def root():
    """Root endpoint - registry information"""
    return {
        "service": "A2A Agent Registry",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "register": "POST /agents/register",
            "discover": "GET /agents/discover",
            "heartbeat": "PUT /agents/{agent_id}/heartbeat",
            "get_agent": "GET /agents/{agent_id}",
            "unregister": "DELETE /agents/{agent_id}",
            "list_all": "GET /agents"
        }
    }


@app.post("/agents/register", status_code=201)
async def register_agent(registration: AgentRegistration):
    """
    Register a new agent in the registry
    
    Args:
        registration: Agent registration data including Agent Card
        
    Returns:
        Registration confirmation with agent details
    """
    try:
        # Validate agent card
        if not registration.agent_card.agent_id:
            raise HTTPException(
                status_code=400,
                detail="Agent ID is required"
            )
        
        # Check if already registered
        existing = storage.get_agent(registration.agent_card.agent_id)
        if existing:
            # Update existing registration
            storage.update_agent(
                registration.agent_card.agent_id,
                registration.agent_card.dict(),
                registration.endpoint
            )
            return {
                "status": "updated",
                "agent_id": registration.agent_card.agent_id,
                "message": "Agent registration updated successfully"
            }
        
        # Register new agent
        storage.register_agent(
            registration.agent_card.agent_id,
            registration.agent_card.dict(),
            registration.endpoint
        )
        
        return {
            "status": "registered",
            "agent_id": registration.agent_card.agent_id,
            "message": "Agent registered successfully",
            "registered_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )


@app.get("/agents/discover")
async def discover_agents(
    capability: Optional[str] = Query(None, description="Capability to search for"),
    name: Optional[str] = Query(None, description="Agent name to search for"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of results")
):
    """
    Discover agents by capability or name
    
    Args:
        capability: Specific capability to search for
        name: Agent name to search for (partial match)
        limit: Maximum number of results to return
        
    Returns:
        List of matching agents
    """
    try:
        all_agents = storage.list_agents()
        
        # Filter by health status - only return healthy agents
        healthy_agents = [
            agent for agent in all_agents
            if agent.get("health_status") == "healthy"
        ]
        
        # Apply capability filter
        if capability:
            healthy_agents = [
                agent for agent in healthy_agents
                if capability in agent.get("agent_card", {}).get("capabilities", [])
            ]
        
        # Apply name filter (case-insensitive partial match)
        if name:
            name_lower = name.lower()
            healthy_agents = [
                agent for agent in healthy_agents
                if name_lower in agent.get("agent_card", {}).get("name", "").lower()
            ]
        
        # Apply limit
        results = healthy_agents[:limit]
        
        return {
            "agents": results,
            "count": len(results),
            "total_registered": len(all_agents),
            "query": {
                "capability": capability,
                "name": name,
                "limit": limit
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Discovery failed: {str(e)}"
        )


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str):
    """
    Get detailed information about a specific agent
    
    Args:
        agent_id: The unique agent identifier
        
    Returns:
        Agent details including card, endpoint, and health status
    """
    agent = storage.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent not found: {agent_id}"
        )
    
    return agent


@app.put("/agents/{agent_id}/heartbeat")
async def heartbeat(agent_id: str):
    """
    Update agent heartbeat (health check)
    
    Args:
        agent_id: The unique agent identifier
        
    Returns:
        Heartbeat acknowledgment
    """
    agent = storage.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent not found: {agent_id}. Please register first."
        )
    
    # Update last heartbeat time
    storage.update_heartbeat(agent_id)
    
    return {
        "status": "acknowledged",
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.delete("/agents/{agent_id}")
async def unregister_agent(agent_id: str):
    """
    Unregister an agent from the registry
    
    Args:
        agent_id: The unique agent identifier
        
    Returns:
        Unregistration confirmation
    """
    agent = storage.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent not found: {agent_id}"
        )
    
    storage.unregister_agent(agent_id)
    
    return {
        "status": "unregistered",
        "agent_id": agent_id,
        "message": "Agent unregistered successfully"
    }


@app.get("/agents")
async def list_all_agents(
    include_unhealthy: bool = Query(False, description="Include unhealthy agents")
):
    """
    List all registered agents
    
    Args:
        include_unhealthy: Whether to include unhealthy agents
        
    Returns:
        List of all agents with their status
    """
    agents = storage.list_agents()
    
    if not include_unhealthy:
        agents = [
            agent for agent in agents
            if agent.get("health_status") == "healthy"
        ]
    
    return {
        "agents": agents,
        "count": len(agents),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
async def health_check():
    """
    Registry service health check
    
    Returns:
        Service health status
    """
    return {
        "status": "healthy",
        "service": "A2A Agent Registry",
        "timestamp": datetime.utcnow().isoformat(),
        "registered_agents": len(storage.list_agents())
    }


@app.get("/stats")
async def get_statistics():
    """
    Get registry statistics
    
    Returns:
        Statistics about registered agents
    """
    agents = storage.list_agents()
    
    # Count by health status
    healthy = sum(1 for a in agents if a.get("health_status") == "healthy")
    unhealthy = len(agents) - healthy
    
    # Count by capabilities
    capabilities = {}
    for agent in agents:
        for cap in agent.get("agent_card", {}).get("capabilities", []):
            capabilities[cap] = capabilities.get(cap, 0) + 1
    
    return {
        "total_agents": len(agents),
        "healthy_agents": healthy,
        "unhealthy_agents": unhealthy,
        "capabilities": capabilities,
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("  A2A Agent Registry Server")
    print("=" * 60)
    print()
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )