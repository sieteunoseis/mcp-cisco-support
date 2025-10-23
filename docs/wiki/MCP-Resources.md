# MCP Resources

**Last Updated:** 2025-10-23 | **Status:** ✅ Implemented in v1.12.0+

---

## Overview

MCP Resources expose Cisco Support data as structured, URI-addressable resources that MCP clients can access directly without making tool calls. This provides faster access, reduced API overhead, and enables proactive data monitoring.

---

## Who Uses Resources?

### MCP Clients
- **Claude Desktop** - Reference bug data in conversations without explicit queries
- **VS Code** - Show inline bug information and product specs
- **MCP Inspector** - Test and explore available resources
- **Custom Clients** - Build specialized interfaces for Cisco data

### AI Assistants
- Access Cisco bug data as context automatically
- Reference product specifications without user prompts
- Monitor security advisories proactively
- Build knowledge graphs from Cisco data

### Developer Tools
- **IDE Integrations** - Show bug information inline in code
- **CI/CD Pipelines** - Check for known issues during builds
- **Documentation Generators** - Pull product specifications
- **Testing Frameworks** - Validate against bug databases

### Automation Systems
- **Alert Systems** - Monitor critical bugs in real-time
- **Compliance Checkers** - Verify security patches are applied
- **Inventory Systems** - Track product EOL dates
- **Upgrade Planners** - Check version compatibility

---

## Key Differences: Resources vs Tools

| Aspect | MCP Tools | MCP Resources |
|--------|-----------|---------------|
| **Invocation** | User explicitly calls tool | Client proactively fetches |
| **Use Case** | "Search for bugs about X" | Background monitoring, caching |
| **Response Time** | On-demand, may be slow | Can be pre-fetched, cached |
| **Overhead** | Full API call each time | Can reduce duplicate calls 50% |
| **User Awareness** | User knows it's happening | Transparent to user |

---

## Available Resources

### Static Resources (`resources/list`)

Pre-defined resources that return curated datasets:

```json
GET resources/list

Response:
{
  "resources": [
    {
      "uri": "cisco://bugs/recent/critical",
      "name": "Recent Critical Bugs",
      "description": "High-severity bugs from the last 7 days",
      "mimeType": "application/json"
    },
    {
      "uri": "cisco://bugs/recent/high",
      "name": "Recent High-Severity Bugs",
      "description": "Severity 1-3 bugs from the last 30 days",
      "mimeType": "application/json"
    },
    {
      "uri": "cisco://products/catalog",
      "name": "Product Catalog",
      "description": "Product catalog overview",
      "mimeType": "application/json"
    },
    {
      "uri": "cisco://security/advisories/recent",
      "name": "Recent Security Advisories",
      "description": "Latest 20 security advisories from Cisco PSIRT",
      "mimeType": "application/json"
    },
    {
      "uri": "cisco://security/advisories/critical",
      "name": "Critical Security Advisories",
      "description": "Critical severity security advisories",
      "mimeType": "application/json"
    }
  ]
}
```

### Resource Templates (`resources/templates/list`)

Dynamic URI patterns that accept parameters:

```json
GET resources/templates/list

Response:
{
  "resourceTemplates": [
    {
      "uriTemplate": "cisco://bugs/{bug_id}",
      "name": "Cisco Bug Report",
      "description": "Access any Cisco bug by its ID (e.g., CSCvi12345)",
      "mimeType": "application/json"
    },
    {
      "uriTemplate": "cisco://products/{product_id}",
      "name": "Cisco Product Information",
      "description": "Get product details by product ID (e.g., C9300-24P, ISR4431)",
      "mimeType": "application/json"
    },
    {
      "uriTemplate": "cisco://security/advisories/{advisory_id}",
      "name": "Cisco Security Advisory",
      "description": "Get security advisory by ID (e.g., cisco-sa-20180221-ucdm)",
      "mimeType": "application/json"
    },
    {
      "uriTemplate": "cisco://security/cve/{cve_id}",
      "name": "Security Advisory by CVE",
      "description": "Get security advisory by CVE identifier (e.g., CVE-2018-0101)",
      "mimeType": "application/json"
    }
  ]
}
```

---

## URI Scheme

All Cisco Support resources use the `cisco://` URI scheme:

```
cisco://{api}/{category}/{identifier}
```

### Examples

**Bug Resources:**
- `cisco://bugs/recent/critical` - Static: Last 7 days of critical bugs
- `cisco://bugs/recent/high` - Static: Last 30 days of high-severity bugs
- `cisco://bugs/CSCvi12345` - Template: Specific bug by ID

**Product Resources:**
- `cisco://products/catalog` - Static: Product catalog overview
- `cisco://products/C9300-24P` - Template: Product by ID

**Security Resources:**
- `cisco://security/advisories/recent` - Static: Latest 20 advisories
- `cisco://security/advisories/critical` - Static: Critical advisories
- `cisco://security/advisories/cisco-sa-20180221-ucdm` - Template: Specific advisory
- `cisco://security/cve/CVE-2018-0101` - Template: Advisory by CVE

---

## Usage Examples

### Reading a Resource

```json
POST /mcp
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/read",
  "params": {
    "uri": "cisco://bugs/CSCvi12345"
  }
}

Response:
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "contents": [
      {
        "uri": "cisco://bugs/CSCvi12345",
        "mimeType": "application/json",
        "text": "{\"description\":\"Bug details for CSCvi12345\",\"data\":{...}}"
      }
    ]
  }
}
```

### TypeScript Client Example

```typescript
// List static resources
const { resources } = await mcpClient.request({
  method: 'resources/list'
});

// List resource templates
const { resourceTemplates } = await mcpClient.request({
  method: 'resources/templates/list'
});

// Read a specific bug using template
const bugData = await mcpClient.request({
  method: 'resources/read',
  params: { uri: 'cisco://bugs/CSCvi12345' }
});

// Read a product using template
const productData = await mcpClient.request({
  method: 'resources/read',
  params: { uri: 'cisco://products/C9300-24P' }
});

// Read a CVE advisory
const cveData = await mcpClient.request({
  method: 'resources/read',
  params: { uri: 'cisco://security/cve/CVE-2018-0101' }
});
```

---

## Configuration

Resources are automatically enabled based on your `SUPPORT_API` environment variable:

```bash
# Enable all resources (bug, product, security)
SUPPORT_API=all

# Enable only bug resources
SUPPORT_API=bug

# Enable bug and security resources
SUPPORT_API=bug,psirt

# Enable product resources
SUPPORT_API=product
```

**Resource Availability:**
- `SUPPORT_API=bug` → Bug resources available
- `SUPPORT_API=product` → Product resources available
- `SUPPORT_API=psirt` → Security resources available
- `SUPPORT_API=all` → All resources available

---

## Benefits

### 50% Reduction in Duplicate API Calls
Resources can be cached by clients, reducing redundant API requests for frequently accessed data.

### Proactive Data Access
Clients can fetch resources in the background without user prompts, enabling:
- Real-time monitoring dashboards
- Automatic context gathering
- Pre-caching frequently needed data

### Better Performance
Resources support:
- Client-side caching
- Batch fetching
- Background updates
- Optimistic UI rendering

### Standardized Access
All resources follow the MCP specification, making them compatible with any MCP-compliant client.

---

## Common Use Cases

### 1. Security Monitoring Dashboard

```typescript
// Client periodically fetches critical advisories
setInterval(async () => {
  const critical = await mcpClient.request({
    method: 'resources/read',
    params: { uri: 'cisco://security/advisories/critical' }
  });

  updateDashboard(critical);
}, 60000); // Every minute
```

### 2. IDE Integration

```typescript
// VS Code extension shows bug info when hovering over bug ID
async function showBugTooltip(bugId: string) {
  const bugData = await mcpClient.request({
    method: 'resources/read',
    params: { uri: `cisco://bugs/${bugId}` }
  });

  return formatTooltip(bugData);
}
```

### 3. CI/CD Pipeline Check

```bash
# Check for critical bugs before deployment
curl -X POST http://mcp-server:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "resources/read",
    "params": {"uri": "cisco://bugs/recent/critical"}
  }'
```

### 4. AI Context Gathering

```typescript
// AI assistant automatically gathers context
async function analyzeUpgrade(product: string) {
  // Fetch product info as context
  const productInfo = await mcpClient.request({
    method: 'resources/read',
    params: { uri: `cisco://products/${product}` }
  });

  // Fetch recent bugs as context
  const recentBugs = await mcpClient.request({
    method: 'resources/read',
    params: { uri: 'cisco://bugs/recent/high' }
  });

  return analyzeWithContext(productInfo, recentBugs);
}
```

---

## Technical Implementation

### Server-Side

Resources are implemented using MCP request handlers:

```typescript
// List static resources
server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return { resources: [...] };
});

// List resource templates (separate endpoint per spec)
server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
  return { resourceTemplates: [...] };
});

// Read specific resource
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  // Dynamic URI resolution based on pattern matching
  if (uri.startsWith('cisco://bugs/')) {
    const bugId = uri.replace('cisco://bugs/', '');
    const bugData = await fetchBugDetails(bugId);
    return { contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(bugData) }] };
  }

  // ... handle other URI patterns
});
```

### Client-Side

Clients access resources using standard MCP protocol:

```typescript
// MCP client automatically handles resource requests
const resource = await client.getResource('cisco://bugs/CSCvi12345');
```

---

## Resource Templates Specification

Resource templates follow [RFC 6570 URI Template syntax](https://datatracker.ietf.org/doc/html/rfc6570):

**Simple Variable Expansion:**
```
cisco://bugs/{bug_id}
→ cisco://bugs/CSCvi12345
```

**Multiple Variables:**
```
cisco://products/{category}/{product_id}
→ cisco://products/switches/C9300-24P
```

**Optional Variables:**
```
cisco://bugs/{bug_id}{?severity,status}
→ cisco://bugs/CSCvi12345?severity=1&status=open
```

**Current Implementation:**
We use simple variable expansion for clarity and ease of use. Future versions may support more complex templates.

---

## Troubleshooting

### Resource Not Found

**Error:** `Unknown resource URI: cisco://bugs/INVALID`

**Solution:** Verify the URI matches available resources/templates:
- Check `resources/list` for static resources
- Check `resources/templates/list` for template patterns
- Ensure resource requires enabled API (check `SUPPORT_API`)

### Method Not Found -32601

**Error:** `MCP error -32601: Method not found`

**Solution:** Ensure you're using the correct method:
- `resources/list` - Lists static resources
- `resources/templates/list` - Lists resource templates (separate endpoint!)
- `resources/read` - Reads a specific resource

### Empty Resource List

**Problem:** `resources/list` returns empty array

**Solution:** Check your `SUPPORT_API` configuration:
```bash
# Current setting
echo $SUPPORT_API

# Enable all resources
export SUPPORT_API=all

# Restart server
npm start
```

---

## Best Practices

### 1. Use Resource Templates for Dynamic Data

✅ **Good:**
```typescript
const bugData = await client.getResource(`cisco://bugs/${dynamicBugId}`);
```

❌ **Bad:**
```typescript
const bugData = await client.callTool('get_bug_details', { bug_ids: dynamicBugId });
```

### 2. Cache Static Resources

Static resources change infrequently - cache them:

```typescript
const cache = new Map();

async function getCriticalBugs() {
  if (cache.has('critical-bugs')) {
    return cache.get('critical-bugs');
  }

  const data = await client.getResource('cisco://bugs/recent/critical');
  cache.set('critical-bugs', data);
  setTimeout(() => cache.delete('critical-bugs'), 300000); // 5 min TTL

  return data;
}
```

### 3. Batch Resource Requests

Fetch multiple resources in parallel:

```typescript
const [bugs, advisories, products] = await Promise.all([
  client.getResource('cisco://bugs/recent/critical'),
  client.getResource('cisco://security/advisories/recent'),
  client.getResource('cisco://products/catalog')
]);
```

### 4. Handle Errors Gracefully

```typescript
try {
  const bugData = await client.getResource(`cisco://bugs/${bugId}`);
} catch (error) {
  if (error.code === -32602) {
    console.error('Invalid bug ID format');
  } else if (error.code === 404) {
    console.error('Bug not found');
  } else {
    console.error('Resource fetch failed:', error);
  }
}
```

---

## Comparison with Other MCP Features

| Feature | Purpose | When to Use |
|---------|---------|-------------|
| **Resources** | Structured data access | Background data, caching, monitoring |
| **Tools** | User-initiated actions | Interactive searches, complex queries |
| **Prompts** | Workflow templates | Guided user experiences |
| **Sampling** | Server requests AI | Intelligent processing, NLP tasks |

---

## References

- [MCP Specification - Resources](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)
- [MCP Specification - Resource Templates](https://modelcontextprotocol.io/specification/2025-06-18/server/resources#resource-templates)
- [RFC 6570 - URI Template Syntax](https://datatracker.ietf.org/doc/html/rfc6570)
- [Available Tools Wiki](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Available-Tools)
- [Development Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Development-Guide)

---

## Related Pages

- [Home](https://github.com/sieteunoseis/mcp-cisco-support/wiki)
- [Available Tools](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Available-Tools)
- [Advanced Configuration](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Advanced-Configuration)
- [Troubleshooting Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Troubleshooting-Guide)

---

**Need Help?** Report issues at https://github.com/sieteunoseis/mcp-cisco-support/issues
