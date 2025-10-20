"""
Data models for A2A Agent Registry
Using Pydantic for validation and serialization
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from datetime import datetime


class AgentCard(BaseModel):
    """
    Agent Card model - describes an agent's identity and capabilities
    """
    agent_id: str = Field(..., description="Unique agent identifier")
    name: str = Field(..., min_length=1, max_length=100, description="Agent name")
    version: str = Field(..., description="Agent version (semantic versioning)")
    description: str = Field(..., max_length=500, description="Agent description")
    capabilities: List[str] = Field(default_factory=list, description="List of capabilities")
    supported_protocols: List[str] = Field(
        default_factory=lambda: ["A2A/1.0"],
        description="Supported protocols"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )
    
    @validator('capabilities')
    def validate_capabilities(cls, v):
        """Ensure capabilities list is not empty and items are strings"""
        if not v:
            raise ValueError("Agent must declare at least one capability")
        if not all(isinstance(cap, str) for cap in v):
            raise ValueError("All capabilities must be strings")
        return v
    
    @validator('version')
    def validate_version(cls, v):
        """Basic semantic version validation"""
        parts = v.split('.')
        if len(parts) < 2:
            raise ValueError("Version must follow semantic versioning (e.g., 1.0.0)")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "crypto-agent-001",
                "name": "CryptoPriceAgent",
                "version": "1.0.0",
                "description": "Provides cryptocurrency price information",
                "capabilities": ["get_price", "list_currencies"],
                "supported_protocols": ["A2A/1.0"],
                "metadata": {
                    "supported_currencies": ["BTC", "ETH", "XRP"],
                    "data_type": "fictitious"
                }
            }
        }


class AgentRegistration(BaseModel):
    """
    Agent registration request
    """
    agent_card: AgentCard = Field(..., description="Agent card with identity and capabilities")
    endpoint: str = Field(..., description="Agent's network endpoint (host:port or URL)")
    
    @validator('endpoint')
    def validate_endpoint(cls, v):
        """Basic endpoint validation"""
        if not v or len(v) < 3:
            raise ValueError("Valid endpoint is required")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_card": {
                    "agent_id": "crypto-agent-001",
                    "name": "CryptoPriceAgent",
                    "version": "1.0.0",
                    "description": "Provides cryptocurrency price information",
                    "capabilities": ["get_price", "list_currencies"],
                    "supported_protocols": ["A2A/1.0"],
                    "metadata": {
                        "supported_currencies": ["BTC", "ETH", "XRP"]
                    }
                },
                "endpoint": "localhost:8888"
            }
        }


class DiscoveryQuery(BaseModel):
    """
    Agent discovery query
    """
    capability: Optional[str] = Field(None, description="Required capability")
    name: Optional[str] = Field(None, description="Agent name (partial match)")
    limit: int = Field(10, ge=1, le=100, description="Maximum results")
    
    class Config:
        json_schema_extra = {
            "example": {
                "capability": "get_price",
                "limit": 10
            }
        }


class HealthStatus(BaseModel):
    """
    Agent health status
    """
    agent_id: str
    status: str = Field(..., description="Health status: healthy, unhealthy, unknown")
    last_heartbeat: Optional[str] = Field(None, description="Last heartbeat timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_id": "crypto-agent-001",
                "status": "healthy",
                "last_heartbeat": "2024-10-20T12:34:56.789Z"
            }
        }


class AgentInfo(BaseModel):
    """
    Complete agent information stored in registry
    """
    agent_card: AgentCard
    endpoint: str
    registered_at: str
    last_heartbeat: Optional[str] = None
    health_status: str = "unknown"
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_card": {
                    "agent_id": "crypto-agent-001",
                    "name": "CryptoPriceAgent",
                    "version": "1.0.0",
                    "description": "Provides cryptocurrency price information",
                    "capabilities": ["get_price", "list_currencies"],
                    "supported_protocols": ["A2A/1.0"],
                    "metadata": {}
                },
                "endpoint": "localhost:8888",
                "registered_at": "2024-10-20T12:00:00.000Z",
                "last_heartbeat": "2024-10-20T12:34:56.789Z",
                "health_status": "healthy"
            }
        }