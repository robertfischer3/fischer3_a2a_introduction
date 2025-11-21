
# Agent Card Structure Documentation

## Understanding the Agent Card

The Agent Card is a fundamental concept in the Agent2Agent (A2A) protocol, serving as a standardized identity and capability declaration for AI agents. Much like a business card in human interactions, an Agent Card provides essential information about an agent's identity, capabilities, and interaction protocols in a machine-readable format. This self-describing metadata structure enables autonomous agent discovery, capability matching, and protocol negotiation without requiring prior knowledge or hard-coded integrations.

## Purpose and Design Philosophy

The Agent Card acts as a **contract of capabilities** between agents, allowing them to understand what services each agent offers and how to interact with them. By standardizing this information exchange, agents can dynamically discover and collaborate with other agents they've never encountered before. The card structure is designed to be both human-readable for debugging and development, and machine-parseable for automated processing. This dual nature ensures that developers can easily understand agent capabilities while enabling agents to make autonomous decisions about task delegation and collaboration.

## Core Components

### Identity Fields

The identity section establishes the unique presence of an agent in the A2A ecosystem:

- **`agent_id`**: A globally unique identifier (typically a UUID or similar) that distinguishes this agent from all others. This ID remains constant throughout the agent's lifecycle and serves as the primary addressing mechanism for agent-to-agent communication.

- **`name`**: A human-friendly name for the agent (e.g., "CryptoPriceAgent", "WeatherService", "DocumentAnalyzer"). This field aids in logging, debugging, and user interfaces where human operators need to understand which agents are involved in a workflow.

- **`version`**: Semantic versioning of the agent implementation (e.g., "1.0.0", "2.1.3-beta"). Version information enables compatibility checking, allowing agents to adapt their interaction patterns based on the capabilities of different agent versions.

### Capability Declaration

The capability section defines what the agent can do:

- **`description`**: A clear, concise explanation of the agent's purpose and primary functions. This human-readable description helps developers and other agents understand the agent's role in the ecosystem at a high level.

- **`capabilities`**: An array of standardized capability tags that indicate the agent's functional abilities. These tags follow a controlled vocabulary (e.g., "price_query", "streaming", "batch_processing", "async_response") that allows for programmatic capability matching. Agents can query for specific capabilities when discovering partners for task delegation.

- **`supported_protocols`**: Lists the communication protocols and versions the agent can handle (e.g., ["A2A/1.0", "A2A/1.1", "REST/2.0"]). This enables protocol negotiation, ensuring agents can establish compatible communication channels.

### Metadata and Extensions

The metadata section provides flexibility for domain-specific information:

- **`metadata`**: A key-value dictionary containing additional agent-specific information that doesn't fit into the standardized fields. This extensible structure allows agents to share domain-specific details without breaking protocol compatibility. For example:
  - A crypto agent might include: `{"supported_currencies": ["BTC", "ETH"], "data_source": "simulated", "update_frequency": "real-time"}`
  - A document processor might specify: `{"supported_formats": ["pdf", "docx"], "max_file_size": "10MB", "ocr_enabled": true}`
  - A weather service could declare: `{"coverage_regions": ["US", "EU"], "forecast_range_days": 7, "historical_data": false}`

## Capability Negotiation Pattern

When agents interact, they exchange Agent Cards during the handshake phase, enabling intelligent interaction patterns. For instance, if a client agent needs real-time data but discovers through the Agent Card that the server agent only supports "no_streaming" capability, it can automatically adjust to use polling instead. This negotiation happens transparently, allowing the system to adapt to available capabilities rather than failing when optional features aren't present.

## Evolution and Versioning

The Agent Card structure is designed to evolve over time while maintaining backward compatibility. New fields can be added to the metadata section without breaking existing implementations. The version field allows agents to expose new capabilities while still supporting older interaction patterns for compatibility with legacy agents. This evolutionary approach ensures that the A2A ecosystem can grow and improve without requiring synchronized updates across all agents.

## Security and Trust Considerations

Agent Cards can be extended to include security-related information such as:
- **Authentication methods** supported (OAuth, API keys, certificates)
- **Rate limiting** policies and quotas
- **Data handling** certifications and compliance standards
- **Trust scores** or reputation metrics from agent registries

This information helps agents make informed decisions about which agents to trust with sensitive operations and how to properly authenticate and authorize interactions.

## Example Use Cases

### Service Discovery
When an orchestrator agent needs to process a PDF document, it can query available agents for those with "document_processing" capability and "pdf" in their supported formats metadata. The Agent Cards allow for precise matching of requirements to capabilities.

### Load Balancing
Multiple agents with identical capabilities can be distinguished by their metadata (e.g., current load, response time, geographic location), allowing intelligent routing decisions based on Agent Card information.

### Fallback Strategies
By examining the capabilities array, a client can identify alternative agents that might provide similar services if the primary agent becomes unavailable, enabling automatic failover patterns.

## Best Practices

1. **Keep Cards Concise**: Include only information relevant for agent discovery and interaction. Detailed API documentation should be referenced, not embedded.

2. **Use Standard Vocabularies**: Adopt community-standard capability tags when possible to maximize interoperability.

3. **Version Carefully**: Follow semantic versioning principles and clearly document capability changes between versions.

4. **Validate on Exchange**: Always validate received Agent Cards against the expected schema to ensure compatibility and security.

5. **Cache Appropriately**: Agent Cards can be cached for performance, but implement appropriate TTLs and refresh mechanisms for dynamic capabilities.

## Future Directions

The Agent Card concept continues to evolve with the A2A protocol. Future enhancements might include:
- **Capability ontologies** for richer semantic matching
- **Dynamic capability updates** for agents that adapt over time
- **Cryptographic signatures** for verifiable agent identity
- **Standardized quality-of-service** metrics
- **Machine learning model** descriptions for AI-specific capabilities

The Agent Card structure provides the foundation for an interoperable multi-agent ecosystem, where agents can discover, understand, and collaborate with each other autonomously while maintaining clear contracts of capability and behavior.