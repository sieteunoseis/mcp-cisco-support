# Server-Sent Events Integration

The Cisco Support MCP Server provides comprehensive Server-Sent Events (SSE) support for real-time communication with web applications and MCP clients.

## MCP over SSE Protocol

The server implements proper MCP (Model Context Protocol) over SSE with session management:

### 1. Connect to SSE Endpoint
```javascript
const eventSource = new EventSource('http://localhost:3000/sse');
```

### 2. Handle Endpoint Event
On connection, the server sends an `endpoint` event with session information:

```javascript
eventSource.addEventListener('endpoint', (event) => {
  const data = JSON.parse(event.data);
  console.log('Session info:', data);
  // Example: { sessionId: "abc123", endpoint: "/sse/session/abc123", timestamp: "..." }
  
  // Store the session endpoint for making requests
  window.sessionEndpoint = data.endpoint;
});
```

### 3. Send MCP Messages
Use the session-specific endpoint to send JSON-RPC messages:

```javascript
async function listTools() {
  const response = await fetch(`http://localhost:3000${window.sessionEndpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list'
    })
  });
  return response.json();
}

async function callTool(toolName, args) {
  const response = await fetch(`http://localhost:3000${window.sessionEndpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: toolName, arguments: args }
    })
  });
  return response.json();
}
```

### 4. Handle Real-time Events
Listen for real-time updates during tool execution:

```javascript
eventSource.addEventListener('tool_start', (event) => {
  const data = JSON.parse(event.data);
  console.log('Tool execution started:', data);
});

eventSource.addEventListener('tool_complete', (event) => {
  const data = JSON.parse(event.data);
  console.log('Tool execution completed:', data);
});

eventSource.addEventListener('tool_error', (event) => {
  const data = JSON.parse(event.data);
  console.log('Tool execution failed:', data);
});

eventSource.addEventListener('message', (event) => {
  const data = JSON.parse(event.data);
  console.log('MCP response:', data);
});

eventSource.addEventListener('ping', (event) => {
  const data = JSON.parse(event.data);
  console.log('Heartbeat:', data);
});
```

## Legacy SSE Support

For backward compatibility, the server also supports direct POST to `/sse`:

```javascript
// Legacy approach (deprecated)
const response = await fetch('http://localhost:3000/sse', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/list'
  })
});
```

## N8N Integration

For N8N's MCP client tool, use the SSE endpoint:
- **URL**: `http://localhost:3000/sse`
- **Transport Type**: SSE
- The server automatically handles session management and provides proper MCP protocol support.

## JavaScript Client Example

```javascript
async function searchBugs(keyword) {
  const response = await fetch('http://localhost:3000/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'tools/call',
      params: {
        name: 'search_bugs_by_keyword',
        arguments: {
          keyword: keyword,
          page_index: 1,
          status: 'open'
        }
      }
    })
  });
  
  const result = await response.json();
  return result;
}
```

## SSE Event Types

The server broadcasts these event types:

- **`endpoint`** - Initial connection with session information
- **`tool_start`** - Tool execution beginning
- **`tool_complete`** - Tool execution completed successfully
- **`tool_error`** - Tool execution failed
- **`message`** - MCP protocol responses
- **`ping`** - Heartbeat messages (every 30 seconds)

## Connection Management  

- **Heartbeat**: Server sends ping events every 30 seconds to keep connections alive
- **Session Management**: Each SSE connection gets a unique session ID
- **Graceful Disconnect**: Proper cleanup when connections are closed
- **Error Handling**: Automatic reconnection support for dropped connections