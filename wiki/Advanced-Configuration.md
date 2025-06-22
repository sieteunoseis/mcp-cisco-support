# Advanced Configuration

Comprehensive configuration guide for the Cisco Support MCP Server covering environment variables, deployment scenarios, and advanced settings.

## Environment Variables

### Core Configuration

Create a `.env` file with your configuration:

```bash
# 🔑 Cisco API OAuth2 Configuration (REQUIRED)
CISCO_CLIENT_ID=your_client_id_here
CISCO_CLIENT_SECRET=your_client_secret_here

# 🌐 Server Configuration
PORT=3000
NODE_ENV=development

# 🚀 API Support Configuration
# Enable specific Cisco Support APIs you have access to
# Options: bug, case, eox, psirt, product, software (plus planned: serial, rma)
SUPPORT_API=bug,case,eox,psirt,product,software    # All implemented APIs (recommended)
# SUPPORT_API=all                                  # All available APIs (includes placeholders)
# SUPPORT_API=bug                                  # Single API (default)

# 🔐 HTTP Authentication Configuration (HTTP mode only)
# Custom Bearer token for HTTP authentication (optional - generates random if not set)
MCP_BEARER_TOKEN=your_custom_secure_token_here

# ⚠️ SECURITY WARNING: Only use in development/testing
# DANGEROUSLY_OMIT_AUTH=true                       # Disables HTTP authentication entirely
```

### API Configuration Examples

```bash
# Development/Testing - Bug API only
SUPPORT_API=bug

# Support Engineer - Case management focus
SUPPORT_API=bug,case,eox

# Security Team - Vulnerability focus
SUPPORT_API=bug,psirt

# Product Manager - Product lifecycle focus  
SUPPORT_API=bug,eox,product,software

# Administrator - Full access
SUPPORT_API=bug,case,eox,psirt,product,software
```

## Claude Desktop Integration

### Basic Configuration

```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "bug"
      }
    }
  }
}
```

### Advanced Configuration

```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "bug,case,eox,psirt,product,software",
        "NODE_ENV": "production"
      }
    }
  }
}
```

### Multiple Instances

You can configure multiple instances for different purposes:

```json
{
  "mcpServers": {
    "cisco-bugs": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "bug"
      }
    },
    "cisco-security": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "psirt"
      }
    }
  }
}
```

## Docker Configuration

### Basic Docker Run

```bash
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e SUPPORT_API=bug,case,eox \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Docker Compose

```yaml
version: '3.8'

services:
  cisco-support:
    image: ghcr.io/sieteunoseis/mcp-cisco-support:latest
    ports:
      - "3000:3000"
    environment:
      - CISCO_CLIENT_ID=your_client_id_here
      - CISCO_CLIENT_SECRET=your_client_secret_here
      - SUPPORT_API=bug,case,eox,psirt,product,software
      - MCP_BEARER_TOKEN=your_secure_token
      - NODE_ENV=production
    command: ["--http"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Docker with Authentication

```bash
# With custom bearer token
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e SUPPORT_API=bug,case,eox \
  -e MCP_BEARER_TOKEN=your_secure_token \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http

# Without authentication (development only)
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e DANGEROUSLY_OMIT_AUTH=true \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

## Global Installation Configuration

### Install Globally

```bash
npm install -g mcp-cisco-support
```

### Claude Desktop Config for Global Install

```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "mcp-cisco-support",
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "bug"
      }
    }
  }
}
```

## Local Development Configuration

### Clone and Setup

```bash
git clone https://github.com/sieteunoseis/mcp-cisco-support.git
cd mcp-cisco-support
npm install
npm run build
```

### Claude Desktop Config for Local Development

```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "node",
      "args": ["/path/to/mcp-cisco-support/dist/index.js"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "bug"
      }
    }
  }
}
```

## Transport Configuration

### stdio Mode (Default)

```bash
# For Claude Desktop and local MCP clients
npx mcp-cisco-support
# or
npx mcp-cisco-support --stdio
```

### HTTP Mode

```bash
# For remote access and web applications
npx mcp-cisco-support --http

# With custom port
PORT=8080 npx mcp-cisco-support --http

# Generate and display bearer token
npx mcp-cisco-support --generate-token
```

## API Endpoint Configuration

When running in HTTP mode, the server exposes these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server information and available endpoints |
| `/mcp` | POST | Main MCP endpoint (JSON-RPC over HTTP) |
| `/messages` | POST | Alternative MCP endpoint for N8N compatibility |
| `/sse` | GET | SSE connection with session management |
| `/sse` | POST | Legacy SSE message endpoint (deprecated) |
| `/sse/session/{sessionId}` | POST | Session-specific MCP message endpoint |
| `/ping` | GET | Simple ping endpoint for connectivity testing |
| `/health` | GET | Health check with detailed status |

## Performance Configuration

### Memory Usage

The server is optimized for minimal memory usage:
- OAuth2 tokens cached in memory (not persisted)
- No database requirements
- Stateless request handling

### Timeout Configuration

Default timeouts can be configured via environment:

```bash
# API request timeout (default: 30 seconds)
CISCO_API_TIMEOUT=30000

# SSE heartbeat interval (default: 30 seconds)
SSE_HEARTBEAT_INTERVAL=30000
```

### Rate Limiting

Built-in rate limiting for production deployments:
- Per-IP request limiting
- Token bucket algorithm
- Configurable thresholds

## Logging Configuration

### Log Levels

```bash
# Set log level
LOG_LEVEL=info    # debug, info, warn, error

# Enable structured JSON logging
NODE_ENV=production
```

### Log Output

```bash
# Pretty print logs in development
npm run dev 2>&1 | jq '.'

# Log to file in production
npm start > /var/log/cisco-support.log 2>&1
```

## Health Check Configuration

The `/health` endpoint provides comprehensive status:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "uptime": 3600,
  "memory": {
    "used": 45.2,
    "total": 128.0
  },
  "oauth": {
    "status": "valid",
    "expiresIn": "11h 30m"
  },
  "apis": [
    "bug",
    "case", 
    "eox"
  ],
  "activeConnections": 3
}
```

## Troubleshooting Configuration

### Debug Mode

```bash
# Enable debug logging
DEBUG=cisco-support:* npm run dev

# Node.js debug mode
NODE_OPTIONS="--inspect" npm run dev
```

### Configuration Validation

```bash
# Test configuration
npx mcp-cisco-support --validate-config

# Check health
curl http://localhost:3000/health

# Test authentication
curl -H "Authorization: Bearer your_token" http://localhost:3000/ping
```