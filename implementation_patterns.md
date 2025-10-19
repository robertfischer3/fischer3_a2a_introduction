# Implementation Patterns

## Common Architectural Patterns

---

## Pattern 1: Hierarchical Agent Network

```
         ┌────────────┐
         │ Supervisor │
         │   Agent    │
         └─────┬──────┘
               │ A2A
     ┌─────────┼─────────┐
     ↓         ↓         ↓
┌─────────┐ ┌─────────┐ ┌─────────┐
│Research │ │Analysis │ │ Report  │
│  Agent  │ │  Agent  │ │  Agent  │
└────┬────┘ └────┬────┘ └────┬────┘
     │ MCP       │ MCP       │ MCP
     ↓           ↓           ↓
  [Search]   [Compute]   [Document]
  [Tools]     [Tools]     [Tools]
```

### When to Use
- Clear task decomposition possible
- Need for specialized sub-agents
- Centralized coordination required

### Example Implementation
```python
# Supervisor agent coordinates via A2A
async def handle_complex_request(request):
    # Discover available agents
    agents = await a2a_client.discover_agents(
        capabilities=["research", "analysis", "reporting"]
    )
    
    # Delegate subtasks via A2A
    research_result = await a2a_client.delegate(
        agent_id=agents["research"],
        task="gather market data"
    )
    
    analysis_result = await a2a_client.delegate(
        agent_id=agents["analysis"],
        task="analyze trends",
        context=research_result
    )
    
    # Each agent uses MCP for tool access
    # (handled internally by each agent)
```

---

## Pattern 2: Peer-to-Peer Collaboration

```
┌─────────┐ A2A  ┌─────────┐ A2A  ┌─────────┐
│ Agent A │ ←──→ │ Agent B │ ←──→ │ Agent C │
└────┬────┘      └────┬────┘      └────┬────┘
     │ MCP            │ MCP            │ MCP
     ↓                ↓                ↓
  [Tools A]       [Tools B]       [Tools C]
```

### When to Use
- Agents need to negotiate and collaborate
- No natural hierarchy exists
- Dynamic team formation required

### Example Implementation
```python
# Agent negotiates with peers
async def collaborative_solve(problem):
    # Broadcast capability request via A2A
    responses = await a2a_client.broadcast({
        "type": "capability_query",
        "required": problem.requirements
    })
    
    # Form collaborative team
    team = await a2a_client.form_team(
        agents=responses.capable_agents,
        consensus_model="majority"
    )
    
    # Collaborate on solution
    solution = await team.collaborate(problem)
    return solution
```

---

## Pattern 3: Service Mesh Architecture

```
┌───────────────────────────────┐
│     A2A Service Registry      │
├───────────────────────────────┤
│  - Agent Discovery            │
│  - Load Balancing             │
│  - Health Monitoring          │
└──────────┬────────────────────┘
           │
    ┌──────┼──────┐
    ↓      ↓      ↓
[Agent] [Agent] [Agent]
    │      │      │
   MCP    MCP    MCP
    │      │      │
[Shared Tool Infrastructure]
```

### When to Use
- Large-scale deployments
- Need for resilience and redundancy
- Shared resource management

### Example Implementation
```python
class ServiceMeshAgent:
    def __init__(self):
        # Register with A2A mesh
        self.a2a_mesh = A2AMesh.register(
            agent_id=self.id,
            capabilities=self.capabilities
        )
        
        # Setup MCP connections
        self.mcp_client = MCP.connect(
            tools=self.required_tools
        )
    
    async def handle_request(self, request):
        # Check if can handle locally
        if self.can_handle(request):
            # Use MCP tools directly
            return await self.mcp_client.execute(request)
        
        # Otherwise delegate via A2A mesh
        return await self.a2a_mesh.route(request)
```

---

## Pattern 4: Gateway Pattern

```
┌─────────────────┐
│   API Gateway   │
│  (A2A Router)   │
└────────┬────────┘
         │ A2A
    ┌────┼────┐
    ↓    ↓    ↓
[Agents with MCP tools]
```

### When to Use
- External API exposure needed
- Centralized authentication/authorization
- Rate limiting and monitoring

---

## Best Practices

### For A2A Implementation
1. **Agent Discovery**
   - Implement capability-based discovery
   - Cache agent registry for performance
   - Handle agent unavailability gracefully

2. **Message Design**
   - Keep messages lightweight
   - Include correlation IDs for tracking
   - Version your message schemas

3. **Error Handling**
   - Implement retry mechanisms
   - Provide fallback agents
   - Log all inter-agent communications

### For MCP Integration
1. **Tool Management**
   - Lazy-load MCP connections
   - Pool and reuse connections
   - Monitor tool availability

2. **Resource Access**
   - Cache frequently accessed resources
   - Implement access control at MCP level
   - Batch operations when possible

3. **Performance**
   - Minimize MCP round-trips
   - Use streaming for large datasets
   - Implement timeouts appropriately

### For Combined Usage
1. **Clear Boundaries**
   - A2A for orchestration decisions
   - MCP for tool execution
   - Never bypass protocols

2. **State Management**
   - A2A maintains conversation state
   - MCP maintains tool session state
   - Synchronize when necessary

3. **Security Layers**
   - Authenticate at A2A level (agent identity)
   - Authorize at MCP level (tool permissions)
   - Audit at both levels

---

## Next: [References & Resources →](./references.md)
