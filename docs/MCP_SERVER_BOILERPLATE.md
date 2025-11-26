# MCP Server Boilerplate Template

This document serves as a comprehensive template for creating production-ready MCP (Model Context Protocol) servers. Use this as a prompt or reference when building new MCP servers for any API.

---

## Prompt Template

Copy and customize the following prompt when asking Claude to create a new MCP server:

```
Create a comprehensive TypeScript MCP (Model Context Protocol) server for [API_NAME] APIs. This server should mirror the architecture of the mcp-cisco-support server with the following features:

## Core Requirements

### 1. Dual Transport Support
- **stdio transport**: For local MCP clients (Claude Desktop, etc.)
- **HTTP transport**: For remote server deployments with Express.js
- Command-line argument parsing: `--stdio` (default) and `--http`

### 2. Authentication
- OAuth2 client credentials flow for the target API
- Automatic token management with refresh before expiry
- Token caching in memory with expiry tracking
- Handle 401 responses by refreshing token automatically

### 3. MCP Protocol Compliance
- Full MCP SDK integration (@modelcontextprotocol/sdk ^1.12.1)
- Support for:
  - `initialize` / `initialized` handshake
  - `tools/list` and `tools/call` methods
  - `resources/list` and `resources/read` methods
  - `resources/templates/list` for dynamic URI patterns
  - `ping` method for connectivity testing
  - MCP Sampling (optional, for AI-powered tools)

### 4. TypeScript Implementation
- Strict mode enabled
- Full type safety with interfaces
- JSDoc comments for documentation
- ES2022 target with CommonJS modules

## Project Structure

```
mcp-[api-name]/
├── src/
│   └── index.ts           # Main TypeScript server implementation
├── tests/
│   ├── setup.ts           # Jest configuration and global mocks
│   ├── mockData.ts        # Mock API responses for unit tests
│   ├── simple.test.ts     # Basic functionality tests
│   ├── [api].test.ts      # API-specific tool tests
│   └── integration.test.ts # Real API integration tests
├── dist/                  # Compiled JavaScript (generated)
├── config/                # Configuration files
├── .github/
│   └── workflows/
│       ├── docker-build.yml  # Docker build and push
│       └── npm-publish.yml   # NPM package publishing
├── package.json
├── tsconfig.json
├── jest.config.js
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── CLAUDE.md              # Claude Code instructions
└── README.md
```

## Dependencies

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.12.1",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "uuid": "^9.0.1",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "@types/cors": "^2.8.17",
    "@types/express": "^4.17.21",
    "@types/jest": "^29.5.14",
    "@types/morgan": "^1.9.9",
    "@types/node": "^20.19.24",
    "@types/uuid": "^9.0.7",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.2",
    "tsx": "^4.6.2",
    "typescript": "^5.8.3"
  }
}
```

## Tool Architecture

### Tool Definition Pattern
Each tool should follow this structure:

```typescript
interface Tool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, PropertySchema>;
    required: string[];
  };
}

// Example tool definition
const exampleTool: Tool = {
  name: 'search_items_by_keyword',
  description: 'Search for items using keywords. Returns paginated results.',
  inputSchema: {
    type: 'object',
    properties: {
      keyword: {
        type: 'string',
        description: 'Keywords to search for'
      },
      page_index: {
        type: 'integer',
        default: 1,
        description: 'Page number (results per page configurable)'
      },
      status: {
        type: 'string',
        enum: ['active', 'inactive', 'all'],
        description: 'Filter by status'
      }
    },
    required: ['keyword']
  }
};
```

### Tool Handler Pattern
```typescript
async function handleToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  try {
    // Validate required parameters
    if (!args.keyword) {
      throw new Error('keyword is required');
    }

    // Make API call
    const result = await callExternalAPI(name, args);

    // Format and return response
    return {
      content: [{
        type: 'text',
        text: formatResponse(result)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      }],
      isError: true
    };
  }
}
```

## MCP Resources

### Static Resources
```typescript
const staticResources = [
  {
    uri: 'api://items/recent/critical',
    name: 'Recent Critical Items',
    description: 'Critical items from the last 7 days',
    mimeType: 'application/json'
  }
];
```

### Resource Templates (Dynamic URIs)
```typescript
const resourceTemplates = [
  {
    uriTemplate: 'api://items/{item_id}',
    name: 'Item Details',
    description: 'Access any item by its ID'
  },
  {
    uriTemplate: 'api://products/{product_id}',
    name: 'Product Information',
    description: 'Get product details by product ID'
  }
];
```

## HTTP Server Features

### Required Endpoints
- `GET /` - Server info and available endpoints
- `GET /health` - Health check endpoint
- `GET /ping` - Simple connectivity test
- `POST /mcp` - MCP JSON-RPC endpoint
- `GET /sse` - Server-Sent Events stream (legacy)
- `DELETE /mcp` - Session termination

### Security Middleware
- Helmet for security headers
- CORS configuration
- Morgan for request logging
- Input validation on all endpoints

### Authentication Options

#### 1. Bearer Token (Default)
```typescript
// Auto-generate or use environment variable
const bearerToken = process.env.MCP_BEARER_TOKEN || generateSecureToken();

// Validate on requests
if (req.headers.authorization !== `Bearer ${bearerToken}`) {
  return res.status(401).json({ error: 'Unauthorized' });
}
```

#### 2. OAuth 2.1 (Advanced)
- PKCE required for all clients
- Dynamic client registration (RFC 7591)
- Server metadata discovery (RFC 8414)
- Endpoints: `/authorize`, `/token`, `/register`
- Token refresh support

## Environment Configuration

### .env.example
```bash
# API OAuth2 Configuration
API_CLIENT_ID=your_client_id_here
API_CLIENT_SECRET=your_client_secret_here

# Server Configuration
PORT=3000
NODE_ENV=development

# API Selection (comma-separated)
# Options: all, api1, api2, api3, enhanced_analysis
SUPPORT_API=all

# HTTP Authentication (for --http mode)
AUTH_TYPE=bearer
# MCP_BEARER_TOKEN=custom_token_here

# OAuth 2.1 (when AUTH_TYPE=oauth2.1)
# OAUTH2_ISSUER_URL=https://your-server.com

# Disable auth (DEVELOPMENT ONLY)
# DANGEROUSLY_OMIT_AUTH=true
```

## Docker Configuration

### Dockerfile (Multi-stage)
```dockerfile
# Build stage
FROM node:18-alpine AS builder
WORKDIR /usr/src/app
COPY package*.json tsconfig.json ./
RUN npm ci && npm cache clean --force
COPY src/ ./src/
RUN npm run build

# Production stage
FROM node:18-alpine AS production
RUN addgroup -g 1001 -S nodejs && adduser -S nodeuser -u 1001
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY --from=builder /usr/src/app/dist ./dist
USER nodeuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1));"
CMD ["node", "dist/index.js", "--http"]
```

### docker-compose.yml
```yaml
version: '3.8'
services:
  mcp-server:
    build: .
    container_name: mcp-[api-name]
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - API_CLIENT_ID=${API_CLIENT_ID}
      - API_CLIENT_SECRET=${API_CLIENT_SECRET}
    volumes:
      - ./logs:/usr/src/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:3000/health')..."]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
```

## CI/CD Workflows

### Docker Build (.github/workflows/docker-build.yml)
- Triggers: Push to main/master, manual dispatch
- Multi-platform: linux/amd64 and linux/arm64
- Registry: GitHub Container Registry (ghcr.io)
- Build caching with GitHub Actions cache
- Provenance attestation

### NPM Publish (.github/workflows/npm-publish.yml)
- Triggers: GitHub releases, manual dispatch with dry-run
- TypeScript compilation
- NPM provenance for supply chain security

## Testing Framework

### Jest Configuration (jest.config.js)
```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/*.test.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { useESM: false }],
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 30000,
  verbose: true,
};
```

### Test Structure
- **Unit tests**: Mock all external API calls
- **Integration tests**: Use real API credentials (skipped by default)
- **Error handling tests**: Timeout, auth failures, validation errors

## Package.json Scripts

```json
{
  "scripts": {
    "build": "tsc",
    "start": "node dist/src/index.js",
    "dev": "tsx watch src/index.ts",
    "dev:http": "tsx watch src/index.ts -- --http",
    "stdio": "node dist/src/index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:integration": "npm test -- --testNamePattern=\"Integration\"",
    "prepublishOnly": "npm run build",
    "token:generate": "npm start -- --generate-token",
    "inspector": "npx -y @modelcontextprotocol/inspector"
  }
}
```

## TypeScript Configuration (tsconfig.json)

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "types": ["node", "jest"]
  },
  "include": ["src/**/*", "tests/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## MCP Client Configuration (Claude Desktop)

```json
{
  "mcpServers": {
    "[api-name]": {
      "command": "npx",
      "args": ["-y", "mcp-[api-name]"],
      "env": {
        "API_CLIENT_ID": "your_client_id_here",
        "API_CLIENT_SECRET": "your_client_secret_here",
        "SUPPORT_API": "all"
      }
    }
  }
}
```

## Implementation Checklist

### Phase 1: Core Setup
- [ ] Initialize npm project with TypeScript
- [ ] Configure tsconfig.json with strict mode
- [ ] Set up project structure
- [ ] Add core dependencies

### Phase 2: MCP Implementation
- [ ] Implement stdio transport handler
- [ ] Implement HTTP transport with Express
- [ ] Add MCP protocol handlers (initialize, tools/list, tools/call)
- [ ] Add ping support for connectivity testing

### Phase 3: API Integration
- [ ] Implement OAuth2 authentication
- [ ] Create token management with auto-refresh
- [ ] Define tool schemas with JSON Schema validation
- [ ] Implement tool handlers
- [ ] Add proper error handling

### Phase 4: Advanced Features
- [ ] Add MCP Resources (static and templates)
- [ ] Implement MCP Sampling (optional)
- [ ] Add HTTP authentication (bearer/OAuth 2.1)
- [ ] Implement Server-Sent Events

### Phase 5: Testing & Quality
- [ ] Set up Jest with ts-jest
- [ ] Create mock data for unit tests
- [ ] Write unit tests for all tools
- [ ] Add integration tests (optional)
- [ ] Type checking passes

### Phase 6: Deployment
- [ ] Create Dockerfile with multi-stage build
- [ ] Add docker-compose.yml
- [ ] Set up GitHub Actions for Docker builds
- [ ] Set up GitHub Actions for NPM publishing
- [ ] Create comprehensive documentation

## Best Practices

### Error Handling
- Return structured error responses with isError flag
- Log errors with timestamps and context
- Handle network timeouts (default 30 seconds)
- Implement retry logic for transient failures

### Security
- Never log credentials or tokens
- Use environment variables for sensitive data
- Implement proper CORS configuration
- Add security headers with Helmet
- Validate all input parameters

### Performance
- Cache authentication tokens
- Use connection pooling for HTTP clients
- Implement pagination for large result sets
- Add request timeout handling

### Logging
- Disable console output in stdio mode (interferes with JSON-RPC)
- Use structured logging in HTTP mode
- Include timestamps and correlation IDs
- Log API calls and responses (sanitized)
```

---

## Quick Start Command

When starting a new MCP server project, use this command:

```bash
mkdir mcp-[api-name] && cd mcp-[api-name]
npm init -y
npm install @modelcontextprotocol/sdk express cors helmet morgan uuid dotenv
npm install -D typescript tsx ts-jest jest @types/node @types/express @types/cors @types/morgan @types/uuid @types/jest
npx tsc --init
```

Then provide Claude with this template along with the target API documentation to generate the complete implementation.

---

## Customization Points

When adapting this template for a new API:

1. **API Base URL**: Replace with your target API endpoint
2. **Authentication**: Adapt OAuth2 flow or use API keys as needed
3. **Tool Definitions**: Create tools matching the API's endpoints
4. **Resource URIs**: Design URI scheme for your data model
5. **Error Messages**: Customize for API-specific error codes
6. **Rate Limiting**: Implement based on API limits
7. **Pagination**: Match the API's pagination style

---

## Reference Implementation

This template is based on the [mcp-cisco-support](https://github.com/sieteunoseis/mcp-cisco-support) server, which provides:
- 50+ MCP tools for Cisco Support APIs
- Full OAuth 2.1 implementation
- MCP Resources with templates
- MCP Sampling for AI-powered tools
- Comprehensive test suite
- Docker and NPX deployment options
