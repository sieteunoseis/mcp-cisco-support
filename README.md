# Cisco Support MCP Server

A comprehensive TypeScript MCP (Model Context Protocol) server for Cisco Support APIs with dual transport support. This extensible server currently provides access to Cisco's Bug Search API and is designed to support additional Cisco Support tools in the future.

## Current Features

- **Bug Search API**: 8 MCP tools for comprehensive Cisco bug searching
- **Dual Transport**: stdio (local MCP clients) and HTTP (remote server)
- **OAuth2 Authentication**: Automatic token management with Cisco API
- **Real-time Updates**: Server-Sent Events for HTTP mode
- **TypeScript**: Full type safety and MCP SDK integration
- **Security**: Helmet, CORS, input validation, and non-root Docker execution
- **Docker Support**: Containerized deployment with health checks
- **Comprehensive Logging**: Structured logging with timestamps

## Planned Features

- **Case Management API**: Tools for Cisco support case operations
- **Product Alerts API**: Access to product notifications and alerts  
- **Field Notices API**: Retrieve field notices and advisories
- **Additional Support Tools**: Expanding Cisco Support API coverage

## Quick Start

### NPX (Recommended)
```bash
npx mcp-cisco-support
```

### Local Installation
```bash
npm install
npm run build
npm start
```

### With Claude Desktop
Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id",
        "CISCO_CLIENT_SECRET": "your_client_secret"
      }
    }
  }
}
```

### Docker Deployment

```bash
# Use pre-built image
docker pull ghcr.io/sieteunoseis/mcp-cisco-support:latest
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_id \
  -e CISCO_CLIENT_SECRET=your_secret \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http

# Or build locally
docker-compose up -d
```

## Configuration

Create a `.env` file with your credentials:

```bash
CISCO_CLIENT_ID=your_client_id_here
CISCO_CLIENT_SECRET=your_client_secret_here
PORT=3000
NODE_ENV=development
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server information |
| `/mcp` | POST | Main MCP endpoint (tools/list, tools/call, initialize) |
| `/sse` | GET | Server-Sent Events stream |
| `/health` | GET | Health check |

## MCP Tools

### 1. get_bug_details
Get details for up to 5 specific bug IDs.

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "get_bug_details",
    "arguments": {
      "bug_ids": "CSCab12345,CSCcd67890"
    }
  }
}
```

### 2. search_bugs_by_keyword
Search bugs by keywords in descriptions and headlines.

```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_keyword",
    "arguments": {
      "keyword": "memory leak",
      "page_index": 1,
      "status": "open",
      "severity": "2"
    }
  }
}
```

### 3. search_bugs_by_product_id
Search bugs by base product ID.

```json
{
  "jsonrpc": "2.0",
  "id": "3",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_id",
    "arguments": {
      "base_pid": "WS-C3560-48PS-S"
    }
  }
}
```

### 4. search_bugs_by_product_and_release
Search bugs by product ID and software releases.

```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_and_release",
    "arguments": {
      "base_pid": "WS-C3560-48PS-S",
      "software_releases": "15.2(4)S,15.2(4)S1"
    }
  }
}
```

### 5. search_bugs_by_product_series_affected
Search bugs by product series and affected releases.

```json
{
  "jsonrpc": "2.0",
  "id": "5",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_series_affected",
    "arguments": {
      "product_series": "Cisco Catalyst 3560 Series Switches",
      "affected_releases": "15.2(4)S"
    }
  }
}
```

### 6. search_bugs_by_product_series_fixed
Search bugs by product series and fixed releases.

```json
{
  "jsonrpc": "2.0",
  "id": "6",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_series_fixed",
    "arguments": {
      "product_series": "Cisco Catalyst 3560 Series Switches",
      "fixed_releases": "15.2(4)S2"
    }
  }
}
```

### 7. search_bugs_by_product_name_affected
Search bugs by exact product name and affected releases.

```json
{
  "jsonrpc": "2.0",
  "id": "7",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_name_affected",
    "arguments": {
      "product_name": "Cisco Catalyst 3560-48PS Switch",
      "affected_releases": "15.2(4)S"
    }
  }
}
```

### 8. search_bugs_by_product_name_fixed
Search bugs by exact product name and fixed releases.

```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_name_fixed",
    "arguments": {
      "product_name": "Cisco Catalyst 3560-48PS Switch",
      "fixed_releases": "15.2(4)S2"
    }
  }
}
```

## Common Parameters

All search tools support these optional parameters:

- `page_index`: Page number (10 results per page, default: 1)
- `status`: Bug status filter (`open`, `resolved`, `closed`)
- `severity`: Bug severity filter (`1`, `2`, `3`, `4`, `5`, `6`)
- `modified_date`: Date filter (`2023-01-01` or range `2023-01-01..2023-12-31`)
- `sort_by`: Sort order (`modified_date`, `bug_id`, `severity`)

## Server-Sent Events

Connect to `/sse` for real-time updates:

```javascript
const eventSource = new EventSource('http://localhost:3000/sse');

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
```

## Usage Examples

### cURL Examples

```bash
# List available tools
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tools/list"
  }'

# Search for bugs by keyword
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "tools/call",
    "params": {
      "name": "search_bugs_by_keyword",
      "arguments": {
        "keyword": "crash",
        "severity": "1",
        "status": "open"
      }
    }
  }'

# Get specific bug details
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "3",
    "method": "tools/call",
    "params": {
      "name": "get_bug_details",
      "arguments": {
        "bug_ids": "CSCab12345"
      }
    }
  }'
```

### JavaScript Client Example

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

## Health Monitoring

The server provides a comprehensive health check endpoint:

```bash
curl http://localhost:3000/health
```

Response includes:
- Server status
- OAuth2 token status
- Memory usage
- Uptime
- Active SSE connections

## Security Features

- **Helmet**: Security headers
- **CORS**: Cross-origin resource sharing
- **Input Validation**: Schema-based validation
- **Non-root Execution**: Docker security
- **Environment Variables**: Secure credential storage

## Troubleshooting

### Common Issues

1. **OAuth2 Authentication Failed**
   - Verify `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET`
   - Check network connectivity to `https://id.cisco.com`

2. **API Calls Failing**
   - Check token validity at `/health`
   - Verify network access to `https://apix.cisco.com`

3. **Docker Issues**
   - Ensure environment variables are set
   - Check Docker logs: `docker-compose logs`

### Logs

Structured JSON logs include:
- Timestamp
- Log level (info, error, warn)
- Message
- Additional context data

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test suite
npx jest tests/auth.test.js
npx jest tests/mcp-tools.test.js
```

### Test Structure

The test suite includes:
- **Authentication Tests** (`tests/auth.test.js`): OAuth2 authentication, token management, error handling
- **MCP Tools Tests** (`tests/mcp-tools.test.js`): All 8 MCP tools, error handling, pagination
- **Setup** (`tests/setup.js`): Test environment configuration

## Recent Test Fixes

The following issues were identified and resolved in the test suite:

### ✅ Fixed Issues

1. **Token Refresh Logic**
   - **Problem**: Token expiry calculation was incorrect in `getValidToken()`
   - **Solution**: Fixed condition to properly check if token is within refresh margin
   - **Impact**: Proper token caching and refresh behavior

2. **Multiple Bug IDs Handling**
   - **Problem**: State leakage between tests causing mock sequence mismatches
   - **Solution**: Implemented `resetServerState()` function for proper cleanup
   - **Impact**: Consistent test results across multiple runs

3. **Search Tools Implementation**
   - **Problem**: Same state management issue affecting keyword search and other tools
   - **Solution**: Proper server state reset between tests
   - **Impact**: All 8 MCP tools now work correctly

4. **Error Handling**
   - **Problem**: API errors and network timeouts not properly converted to MCP error responses
   - **Solution**: Enhanced error handling in `handleMCPMessage()` function
   - **Impact**: Proper error responses for client applications

5. **Authentication Failure Scenarios**
   - **Problem**: Health endpoint returning 200 instead of 503 on auth failures
   - **Solution**: Module cache clearing and proper state isolation
   - **Impact**: Correct health status reporting

6. **Test State Management**
   - **Problem**: Module-level variables persisting between tests
   - **Solution**: Added `resetServerState()` export and proper module cache clearing
   - **Impact**: True test isolation and reliable test results

### Test Configuration

- **Jest**: Using Jest with `--forceExit` flag for main test runs
- **State Reset**: Each test gets a fresh server instance with clean state
- **Mock Management**: Proper fetch mocking with correct sequence handling
- **Test Isolation**: Module cache clearing prevents state leakage

### Key Implementation Details

- **Native fetch**: Uses Node.js native fetch instead of external libraries
- **Token Management**: 12-hour token validity with 30-minute refresh margin
- **Error Handling**: Comprehensive error handling with proper MCP error responses
- **Security**: Helmet security headers, CORS support, input validation
- **Logging**: Structured JSON logging with timestamps

## Development

### Project Structure

```
cisco-bug-mcp-server/
├── server.js           # Main server implementation
├── package.json        # Dependencies and scripts
├── .env.example       # Environment variables template
├── .env               # Actual environment variables
├── .gitignore         # Git ignore rules
├── Dockerfile         # Docker configuration
├── docker-compose.yml # Docker Compose setup
├── jest.config.js     # Jest test configuration
├── tests/             # Test files
│   ├── auth.test.js   # Authentication tests
│   ├── mcp-tools.test.js # MCP tools tests
│   └── setup.js       # Test setup
└── README.md          # This file
```

### Development Commands

```bash
# Install dependencies
npm install

# Start development server with auto-reload
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Build Docker image
docker build -t cisco-bug-mcp-server .

# View logs in development
npm run dev 2>&1 | jq '.'  # Pretty print JSON logs
```

### Performance Considerations

- Token caching reduces API calls
- Pagination limits results to 10 per page
- SSE heartbeat every 30 seconds keeps connections alive
- Request timeout set to 30 seconds

### Security Notes

- Never commit `.env` file to version control
- Use environment variables for all secrets
- Review Cisco API usage limits and terms
- Monitor logs for suspicious activity

## API Reference

### Authentication

- **OAuth2 URL**: `https://id.cisco.com/oauth2/default/v1/token`
- **Grant Type**: `client_credentials`
- **Token Validity**: 12 hours
- **Auto-refresh**: 30 minutes before expiry

### Bug API Base URL

- **Base URL**: `https://apix.cisco.com/bug/v2.0`

### MCP Protocol

The server implements the Model Context Protocol with these methods:
- `initialize`: Initialize MCP connection
- `tools/list`: List available tools
- `tools/call`: Execute a tool

Example MCP message:
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_keyword",
    "arguments": {
      "keyword": "memory leak",
      "status": "open"
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify your `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET`
   - Check that your credentials have access to the Bug API
   - Review logs for specific OAuth2 error messages

2. **Network Timeouts**
   - Default timeout is 30 seconds
   - Check your network connectivity to Cisco APIs
   - Verify firewall settings allow outbound HTTPS

3. **Test Failures**
   - Run tests individually to isolate issues: `npx jest tests/auth.test.js`
   - Check that environment variables are set correctly in test mode
   - Verify mock setup in test files

4. **SSE Connection Issues**
   - Check that client properly handles event stream format
   - Verify CORS settings if connecting from browser
   - Monitor connection logs for disconnect events

### Debugging

```bash
# Enable debug logging
NODE_ENV=development npm run dev

# Check health status
curl http://localhost:3000/health

# View Docker logs
docker-compose logs -f

# Test specific MCP tool
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"test","method":"tools/list"}'
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `npm test`
6. Submit a pull request

## Support

For detailed documentation, see [CLAUDE.md](./CLAUDE.md).

For issues related to:
- **Server**: Create an issue in this repository
- **Cisco API**: Refer to [Cisco Developer Documentation](https://developer.cisco.com/docs/support-apis/)
- **MCP Protocol**: Check the [Model Context Protocol specification](https://modelcontextprotocol.io/)