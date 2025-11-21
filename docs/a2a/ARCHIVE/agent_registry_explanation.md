# Agent Registry: How It Works

## Overview

The Agent Registry serves as a centralized or distributed directory service that enables dynamic agent discovery in multi-agent systems. When an agent starts up, it registers itself by submitting its Agent Card to the registry, which indexes the agent by capabilities, domain, and other metadata. Other agents can then query the registry using capability-based searches (e.g., "find agents with 'price_query' capability") to discover suitable collaboration partners without prior knowledge of their existence or location. The registry maintains health checks on registered agents, automatically removing or marking as unavailable those that become unresponsive.

## Hosting Options

**Centralized Registry**: Deployed as a dedicated service within an organization's infrastructure (cloud or on-premise), providing a single source of truth for agent discovery. This is simplest to implement and manage but creates a single point of failure.

**Federated Registry**: Multiple registry instances synchronized across different domains or organizations, allowing cross-organizational agent discovery while maintaining local control. Each organization runs its own registry that shares public agent information with trusted partners.

**Distributed Registry**: Implemented using distributed consensus protocols (like Raft or blockchain-based systems), where multiple nodes maintain replicated copies of the registry. This provides high availability and fault tolerance but adds complexity.

**Hybrid Approach**: Combining local registries for internal agents with gateway services that expose selected agents to external registries, balancing security with discoverability.

## Security Concerns

**1. Authentication & Authorization**: The registry must verify that agents are who they claim to be before registration (using Agent Card signatures and certificates) and enforce access controls on who can query for different agent types. Unauthorized agents should not be able to discover or access internal corporate agents.

**2. Agent Card Validation**: All submitted Agent Cards must be validated against security policies to prevent malicious agents from registering with false capabilities or injecting malicious metadata that could compromise other agents.

**3. Denial of Service**: The registry is a high-value target for DoS attacks. Rate limiting on registration and query operations, along with reputation-based throttling, helps prevent registry flooding or exhaustion attacks.

**4. Information Disclosure**: The registry must implement context-aware information disclosure, showing different levels of agent detail based on the requester's trust level (similar to the SecureAgentCard's context-aware serialization in the crypto example).

**5. Poisoning Attacks**: Malicious actors might attempt to register fake agents or modify existing registrations to redirect traffic. The registry must use cryptographic signatures to verify Agent Card authenticity and maintain immutable audit logs of all registration changes.

**6. Privacy**: Agent metadata might reveal sensitive business logic or infrastructure details. The registry should support private/internal agents that are only discoverable within specific trust boundaries and never exposed externally.

**7. Revocation & Blocklists**: The registry needs mechanisms to quickly revoke compromised agent certificates and maintain blocklists of known malicious agents, with distribution of these lists to all querying agents.

## Implementation Considerations

A production Agent Registry would typically be implemented as a RESTful API or gRPC service with endpoints for:
- `POST /agents/register` - Register new agent
- `GET /agents/discover?capabilities=X,Y` - Discover agents by capability
- `PUT /agents/{id}/heartbeat` - Health check
- `DELETE /agents/{id}` - Deregister agent
- `GET /agents/{id}/status` - Get agent status

The registry would integrate with existing authentication systems (OAuth 2.0, mTLS), use encrypted storage for Agent Cards, and provide real-time notifications when agents matching specific criteria become available or unavailable.