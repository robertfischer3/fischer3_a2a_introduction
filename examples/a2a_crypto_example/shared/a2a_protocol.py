"""
Agent2Agent (A2A) Protocol Definitions
Simple implementation for crypto price demonstration
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from enum import Enum
import json
import uuid
from datetime import datetime


class MessageType(Enum):
    """A2A Message Types"""
    # Discovery messages
    DISCOVER_AGENTS = "discover_agents"
    AGENT_ANNOUNCEMENT = "agent_announcement"
    
    # Capability messages
    GET_CAPABILITIES = "get_capabilities"
    CAPABILITIES_RESPONSE = "capabilities_response"
    
    # Request/Response messages
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    
    # Session management
    HANDSHAKE = "handshake"
    HANDSHAKE_ACK = "handshake_ack"
    GOODBYE = "goodbye"


class RequestMethod(Enum):
    """Available request methods for crypto agent"""
    GET_PRICE = "get_price"
    GET_SUPPORTED_CURRENCIES = "get_supported_currencies"
    GET_AGENT_INFO = "get_agent_info"


@dataclass
class AgentCard:
    """
    Agent Card - describes an agent's identity and capabilities
    Similar to a business card for AI agents
    """
    agent_id: str
    name: str
    version: str
    description: str
    capabilities: List[str]
    supported_protocols: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AgentCard':
        return cls(**data)


@dataclass
class A2AMessage:
    """
    Base A2A Message structure
    All messages in the A2A protocol follow this format
    """
    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_id: Optional[str]
    timestamp: str
    payload: Dict[str, Any]
    correlation_id: Optional[str] = None
    
    def to_json(self) -> str:
        """Serialize message to JSON"""
        data = asdict(self)
        data['message_type'] = self.message_type.value
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'A2AMessage':
        """Deserialize message from JSON"""
        data = json.loads(json_str)
        data['message_type'] = MessageType(data['message_type'])
        return cls(**data)
    
    @staticmethod
    def create_message(
        message_type: MessageType,
        sender_id: str,
        payload: Dict[str, Any],
        recipient_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> 'A2AMessage':
        """Factory method to create a new message"""
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            message_type=message_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=datetime.utcnow().isoformat(),
            payload=payload,
            correlation_id=correlation_id
        )


@dataclass
class PriceResponse:
    """Structure for crypto price responses"""
    currency: str
    price_usd: float
    timestamp: str
    disclaimer: str = "This price is fictitious for demonstration only"
    
    def to_dict(self) -> Dict:
        return asdict(self)


class A2AProtocol:
    """Protocol helper methods"""
    
    @staticmethod
    def create_handshake(sender_id: str, agent_card: AgentCard) -> A2AMessage:
        """Create a handshake message"""
        return A2AMessage.create_message(
            MessageType.HANDSHAKE,
            sender_id,
            {"agent_card": agent_card.to_dict()}
        )
    
    @staticmethod
    def create_request(
        sender_id: str,
        recipient_id: str,
        method: RequestMethod,
        params: Dict[str, Any]
    ) -> A2AMessage:
        """Create a request message"""
        return A2AMessage.create_message(
            MessageType.REQUEST,
            sender_id,
            {
                "method": method.value,
                "params": params
            },
            recipient_id
        )
    
    @staticmethod
    def create_response(
        sender_id: str,
        recipient_id: str,
        result: Any,
        correlation_id: str
    ) -> A2AMessage:
        """Create a response message"""
        return A2AMessage.create_message(
            MessageType.RESPONSE,
            sender_id,
            {"result": result},
            recipient_id,
            correlation_id
        )
    
    @staticmethod
    def create_error(
        sender_id: str,
        recipient_id: str,
        error_message: str,
        error_code: int,
        correlation_id: Optional[str] = None
    ) -> A2AMessage:
        """Create an error message"""
        return A2AMessage.create_message(
            MessageType.ERROR,
            sender_id,
            {
                "error": error_message,
                "code": error_code
            },
            recipient_id,
            correlation_id
        )