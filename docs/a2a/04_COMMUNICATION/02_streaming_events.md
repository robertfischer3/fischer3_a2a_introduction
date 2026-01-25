# Beginner's Guide to Agent2Agent Streaming and Events

## Does an Agent Have the Ability to Send Messages Based on Events?

**Yes!** In the Agent2Agent (A2A) protocol, agents have the ability to send event-based messages to provide real-time updates and asynchronous communication. This capability enables agents to proactively notify clients about state changes, data updates, or important occurrences without requiring constant polling.

Event-based messaging is a core feature that distinguishes reactive, streaming agents from simple request-response agents. When an agent advertises streaming or notification capabilities in its Agent Card, clients can subscribe to receive automatic updates whenever relevant events occur.

---

## How A2A Streaming Works

A2A streaming enables continuous, real-time communication between agents through an event-driven architecture. Rather than requiring clients to repeatedly poll for updates, streaming allows servers to push information as it becomes available.

### Core Streaming Concepts

**1. Server-Sent Events (SSE) Protocol**

A2A streaming commonly uses the Server-Sent Events (SSE) standard, a simple HTTP-based protocol designed for one-way server-to-client communication. SSE provides:

- Automatic reconnection on connection loss
- Event IDs for tracking message delivery
- UTF-8 text-based data format
- Built-in browser support

**2. Persistent Connections**

Once established, a streaming connection remains open indefinitely, allowing the server to send multiple messages over time:

```
Client                          Agent Server
  |                                  |
  |------ HTTP GET /stream -------->|
  |                                  |
  |<===== Connection Open ==========|
  |                                  |
  |<----- Event: price_update ------| 
  |<----- Event: price_update ------|
  |<----- Event: alert --------------|
  |        ... continuous ...        |
```

**3. Subscribe/Notify Pattern**

Agents implement a publish-subscribe model:

- **Subscribe**: Client registers interest in specific event types
- **Notify**: Server sends events to all subscribed clients
- **Unsubscribe**: Client terminates subscription when done

---

## Main Event Messages an Agent Can Send

The A2A protocol defines several standard event message types that agents use to communicate asynchronously. These messages enable real-time interactions between agents.

### 1. Subscribe/Notify Messages

**Purpose**: Establish and manage event subscriptions

**Subscribe Message**
```json
{
  "message_type": "SUBSCRIBE",
  "sender_id": "client-12345",
  "recipient_id": "crypto-agent-001",
  "payload": {
    "event_types": ["price_update", "alert"],
    "filters": {
      "currencies": ["BTC", "ETH"]
    }
  }
}
```

**Notify Message**
```json
{
  "message_type": "NOTIFY",
  "sender_id": "crypto-agent-001",
  "recipient_id": "client-12345",
  "payload": {
    "event_type": "price_update",
    "data": {
      "currency": "BTC",
      "price": 125430.50,
      "timestamp": "2025-10-22T14:30:00Z"
    }
  }
}
```

### 2. Data Update Events

**Purpose**: Push real-time data changes to subscribers

**Examples**:
- `price_update`: Cryptocurrency price changes
- `status_change`: Agent or service status updates
- `data_refresh`: New data available
- `metrics_update`: Performance or analytics data

### 3. State Change Events

**Purpose**: Notify clients when agent state changes

**Examples**:
- `agent_online`: Agent becomes available
- `agent_offline`: Agent going offline
- `capability_changed`: Agent capabilities modified
- `maintenance_mode`: Agent entering maintenance

### 4. Alert Events

**Purpose**: Communicate important conditions requiring attention

**Examples**:
- `threshold_exceeded`: Value crosses configured threshold
- `error_occurred`: Error condition detected
- `warning`: Non-critical issue
- `anomaly_detected`: Unusual pattern identified

### 5. Progress Events

**Purpose**: Report progress on long-running operations

**Examples**:
- `task_started`: Operation initiated
- `progress_update`: Percentage complete
- `task_completed`: Operation finished
- `task_failed`: Operation encountered error

### 6. Heartbeat Events

**Purpose**: Maintain connection health and detect failures

**Example**:
```json
{
  "message_type": "HEARTBEAT",
  "sender_id": "crypto-agent-001",
  "timestamp": "2025-10-22T14:30:00Z",
  "payload": {
    "status": "healthy",
    "uptime_seconds": 86400
  }
}
```

---

## Message Format Examples

Event messages in A2A streaming follow the Server-Sent Events (SSE) specification. Each event consists of one or more lines, with each line having a specific purpose. Let's examine both the raw SSE format and human-readable interpretations.

### Basic Event Structure

An SSE event message consists of fields, each on its own line:

- `event:` - The event type/name
- `data:` - The event payload (can span multiple lines)
- `id:` - Optional unique identifier for the event
- `retry:` - Optional reconnection time in milliseconds
- Empty line - Marks the end of an event

### Example 1: Price Update Event

**Raw SSE Format:**
```
event: price_update
data: {"currency":"BTC","price_usd":125430.50,"timestamp":"2025-10-22T14:30:00Z","change_percent":2.3}

```

**Human-Readable Interpretation:**
```
Event Type: price_update
Currency: Bitcoin (BTC)
Current Price: $125,430.50 USD
Timestamp: October 22, 2025 at 2:30 PM UTC
Price Change: +2.3%
```

### Example 2: Alert Event with ID

**Raw SSE Format:**
```
event: alert
id: alert-20251022-001
data: {"severity":"high","message":"BTC price exceeded $125,000 threshold","currency":"BTC","trigger_price":125000,"current_price":125430.50}

```

**Human-Readable Interpretation:**
```
Event Type: alert
Event ID: alert-20251022-001
Severity: High
Alert Message: BTC price exceeded $125,000 threshold
Currency: Bitcoin (BTC)
Threshold: $125,000
Current Price: $125,430.50
```

### Example 3: Multi-Line Data Event

**Raw SSE Format:**
```
event: market_summary
id: summary-1234
data: {
data:   "markets": [
data:     {"currency": "BTC", "price": 125430.50, "volume": 28500000000},
data:     {"currency": "ETH", "price": 4200.75, "volume": 15200000000}
data:   ],
data:   "timestamp": "2025-10-22T14:30:00Z",
data:   "total_market_cap": 2500000000000
data: }

```

**Human-Readable Interpretation:**
```
Event Type: market_summary
Event ID: summary-1234

Market Overview:
├─ Bitcoin (BTC)
│  ├─ Price: $125,430.50
│  └─ 24h Volume: $28.5 billion
│
├─ Ethereum (ETH)
│  ├─ Price: $4,200.75
│  └─ 24h Volume: $15.2 billion
│
└─ Total Market Cap: $2.5 trillion

Updated: October 22, 2025 at 2:30 PM UTC
```

### Example 4: Agent Status Change

**Raw SSE Format:**
```
event: status_change
data: {"agent_id":"crypto-agent-001","previous_status":"maintenance","current_status":"online","timestamp":"2025-10-22T14:31:00Z"}

```

**Human-Readable Interpretation:**
```
Event Type: status_change
Agent: crypto-agent-001 (CryptoPriceAgent)
Previous Status: Maintenance Mode
Current Status: Online and Available
Time of Change: October 22, 2025 at 2:31 PM UTC
Status: Agent is now accepting requests
```

### Example 5: Progress Update

**Raw SSE Format:**
```
event: progress_update
id: task-9876
data: {"task_id":"historical_data_export","operation":"export","progress_percent":65,"items_processed":6500,"total_items":10000,"estimated_completion":"2025-10-22T14:35:00Z"}

```

**Human-Readable Interpretation:**
```
Event Type: progress_update
Task ID: task-9876 (historical_data_export)
Operation: Data Export

Progress:
  [████████████████████░░░░░░░░] 65%
  
Items Processed: 6,500 / 10,000
Estimated Completion: 4 minutes remaining
Expected Finish: October 22, 2025 at 2:35 PM UTC
```

### Example 6: Error Event

**Raw SSE Format:**
```
event: error
data: {"error_code":"RATE_LIMIT_EXCEEDED","message":"Request rate limit exceeded","agent_id":"crypto-agent-001","retry_after_seconds":60,"current_rate":150,"limit":100}

```

**Human-Readable Interpretation:**
```
Event Type: error
Error Code: RATE_LIMIT_EXCEEDED
Agent: crypto-agent-001

⚠️  Rate Limit Exceeded
    
Your request rate: 150 requests/minute
Allowed limit: 100 requests/minute
Action Required: Please wait 60 seconds before retrying

The agent will resume accepting requests at:
2:32 PM UTC (in 1 minute)
```

### Example 7: Heartbeat/Keep-Alive

**Raw SSE Format:**
```
event: heartbeat
data: {"timestamp":"2025-10-22T14:30:15Z","status":"healthy","uptime_seconds":86415}

```

**Human-Readable Interpretation:**
```
Event Type: heartbeat
Status: Healthy ✓
Server Time: October 22, 2025 at 2:30:15 PM UTC
Uptime: 24 hours, 15 seconds
Connection: Active
```

### Example 8: Subscription Confirmation

**Raw SSE Format:**
```
event: subscription_confirmed
data: {"subscription_id":"sub-abc123","event_types":["price_update","alert"],"filters":{"currencies":["BTC","ETH"]},"created_at":"2025-10-22T14:30:00Z"}

```

**Human-Readable Interpretation:**
```
Event Type: subscription_confirmed
Subscription ID: sub-abc123
Created: October 22, 2025 at 2:30 PM UTC

Subscribed Events:
  • price_update - Real-time price changes
  • alert - Important notifications

Filters Applied:
  Currencies: BTC, ETH only

Your subscription is active and you will receive events matching these criteria.
```

---

## Streaming vs. Push Notifications: Comparison Table

| **Aspect** | **A2A Streaming (SSE)** | **Push Notifications** |
|------------|-------------------------|------------------------|
| **Connection Type** | Persistent HTTP connection | Connectionless (message-based) |
| **Communication Direction** | Server → Client (one-way) | Server → Client (one-way) |
| **Protocol** | HTTP with SSE | Platform-specific (APNs, FCM, WebPush) |
| **Real-time Performance** | Immediate (<100ms latency) | Near real-time (seconds to minutes) |
| **Reliability** | High - automatic reconnection | Variable - depends on platform |
| **Data Volume** | Unlimited high-frequency updates | Limited by rate limits and payload size |
| **Delivery Guarantee** | Best effort while connected | Best effort with retry mechanisms |
| **Client State Required** | Active connection | Can reach offline devices |
| **Battery Impact** | Moderate (persistent connection) | Low (wake on receive) |
| **Network Efficiency** | High for frequent updates | High for infrequent updates |
| **Setup Complexity** | Simple (standard HTTP) | Complex (requires platform integration) |
| **Cross-Platform** | Universal (HTTP standard) | Platform-specific implementations |
| **Use Case: High-Frequency** | ✅ Excellent - designed for this | ❌ Poor - rate limits |
| **Use Case: Low-Frequency** | ⚠️ Acceptable but inefficient | ✅ Excellent - efficient |
| **Use Case: Rich Data** | ✅ Excellent - unlimited size | ❌ Limited - small payloads |
| **Use Case: Mobile Background** | ❌ Connection drops in background | ✅ Excellent - works when app closed |
| **Use Case: Web Applications** | ✅ Excellent - native support | ⚠️ Limited browser support |
| **Use Case: Real-Time Trading** | ✅ Excellent - continuous updates | ❌ Too slow for trading |
| **Use Case: Daily Digests** | ❌ Wasteful for infrequent data | ✅ Perfect for periodic updates |
| **Use Case: User Engagement** | ⚠️ Requires app to be open | ✅ Great for re-engagement |
| **Scalability** | Moderate - one connection per client | High - decoupled from connections |
| **Message Ordering** | ✅ Guaranteed in-order delivery | ⚠️ Not guaranteed |
| **Backpressure Handling** | ✅ Client controls consumption rate | ❌ Server controls send rate |
| **Error Recovery** | ✅ Automatic with last event ID | ⚠️ Manual retry logic needed |
| **Infrastructure Requirements** | Standard web server | Push notification service provider |
| **Authentication** | HTTP headers/cookies | Device tokens and certificates |
| **Cost Model** | Server resources (connections) | Per-notification fees |
| **Best for A2A Protocol** | ✅ Primary choice for agent communication | ⚠️ Secondary/supplementary |

### Decision Guide: When to Use Each

**Choose A2A Streaming (SSE) when:**
- Clients need continuous, real-time updates
- High-frequency data changes (multiple times per second)
- Rich, structured data payloads
- Order of events matters
- Client is actively engaged with the application
- Building agent-to-agent communication systems
- Low-latency requirements (<1 second)
- Need bidirectional communication (combine with WebSockets)

**Choose Push Notifications when:**
- Updates are infrequent (minutes to hours apart)
- Need to reach offline or background applications
- Mobile app engagement and re-activation
- Critical alerts that must reach users
- Small, simple message payloads
- Users need to be notified when app is closed
- Cross-platform mobile notification delivery
- Budget constraints on server resources

**Use Both Together when:**
- Real-time updates while app is active (streaming)
- Critical alerts when app is inactive (push)
- Example: Trading app uses streaming for live prices, push for price alerts
- Example: Monitoring agent streams metrics, pushes critical failures

---

## Summary

Agent2Agent streaming and events enable powerful real-time communication patterns:

1. **Event-based messaging** allows agents to proactively notify clients without polling
2. **SSE provides a simple, standard protocol** for server-to-client streaming
3. **Multiple event types** support various communication patterns (data updates, alerts, progress, etc.)
4. **Raw SSE format** is simple and efficient for machines
5. **Human-readable interpretations** make debugging and monitoring easier
6. **Choose the right tool**: Streaming for real-time, Push for offline reach

By understanding these patterns, you can build responsive, efficient agent systems that provide excellent real-time experiences while managing resources effectively.

---

## Next Steps

- Explore the [A2A Cryptocurrency Example](../a2a_crypto_example/) to see basic agent communication
- Learn about [Agent Cards](../02_DISCOVERY/01_agent_cards.md) for capability discovery
- Review [Security Best Practices](../../../README.md) for production deployments
- Implement streaming in your own agents using the patterns shown here