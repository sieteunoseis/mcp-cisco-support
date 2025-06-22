# Development Guide

Comprehensive guide for developers working on the Cisco Support MCP Server.

## Project Structure

```
mcp-cisco-support/
├── src/
│   ├── apis/                  # API implementations
│   │   ├── base-api.ts       # Base API class with common functionality
│   │   ├── bug-api.ts        # Bug API implementation
│   │   ├── case-api.ts       # Case API implementation
│   │   ├── eox-api.ts        # End-of-Life API implementation
│   │   ├── psirt-api.ts      # Security Advisory API implementation
│   │   ├── product-api.ts    # Product Information API implementation
│   │   ├── software-api.ts   # Software Suggestion API implementation
│   │   └── index.ts          # API exports and configuration
│   ├── utils/                # Utility modules
│   │   ├── auth.ts           # OAuth2 authentication
│   │   ├── formatting.ts     # Response formatting and hyperlinks
│   │   ├── logger.ts         # Structured logging
│   │   └── validation.ts     # Input validation and schemas
│   ├── index.ts              # Main server entry point
│   ├── mcp-server.ts         # MCP protocol implementation
│   └── sse-server.ts         # Server-Sent Events implementation
├── tests/                    # Test suite
│   ├── *.test.ts            # Test files
│   ├── mockData.ts          # Mock API responses
│   └── setup.ts             # Jest configuration
├── wiki/                     # Documentation
├── api_docs/                 # Official API specifications (WADL)
├── scripts/                  # Development and build scripts
├── dist/                     # Compiled JavaScript (generated)
├── package.json              # Dependencies and scripts
├── tsconfig.json            # TypeScript configuration
├── jest.config.js           # Jest test configuration
├── Dockerfile               # Docker container configuration
└── docker-compose.yml       # Docker Compose setup
```

## Development Setup

### Prerequisites

- **Node.js**: Version 18 or higher
- **npm**: Version 8 or higher
- **TypeScript**: Version 5.x
- **Git**: For version control

### Installation

```bash
# Clone the repository
git clone https://github.com/sieteunoseis/mcp-cisco-support.git
cd mcp-cisco-support

# Install dependencies
npm install

# Build the project
npm run build

# Run in development mode
npm run dev
```

### Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit with your credentials
nano .env
```

Required environment variables:
```bash
CISCO_CLIENT_ID=your_client_id_here
CISCO_CLIENT_SECRET=your_client_secret_here
SUPPORT_API=bug,case,eox  # APIs to enable
```

## Development Commands

### Build and Development

```bash
# Development server with auto-reload
npm run dev

# Build TypeScript to JavaScript
npm run build

# Start production server
npm start

# Type checking without compilation
npx tsc --noEmit

# Watch mode for continuous compilation
npx tsc --watch
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Test specific file
npm test -- tests/bugApi.test.ts

# Test with real API (requires credentials)
CISCO_CLIENT_ID=your_id CISCO_CLIENT_SECRET=your_secret npm test
```

### Code Quality

```bash
# Lint code (if configured)
npm run lint

# Format code (if configured)
npm run format

# Check for security vulnerabilities
npm audit

# Update dependencies
npm update
```

## Architecture Overview

### MCP Server Implementation

The server implements the Model Context Protocol with these key components:

```typescript
// Main server interfaces
interface MCPServer {
  initialize(): Promise<void>;
  listTools(): Promise<Tool[]>;
  callTool(name: string, args: any): Promise<any>;
}

// Tool interface
interface Tool {
  name: string;
  description: string;
  inputSchema: JSONSchema;
}
```

### API Architecture

All APIs follow a consistent pattern using a base class:

```typescript
// Base API class
abstract class BaseAPI {
  protected abstract getTools(): Tool[];
  protected abstract callTool(name: string, args: any): Promise<any>;
  
  // Common functionality
  protected async authenticatedFetch(url: string, options?: RequestInit): Promise<Response>;
  protected formatResponse(data: any): string;
  protected validateInput(args: any, schema: JSONSchema): void;
}

// Example API implementation
class BugAPI extends BaseAPI {
  getTools(): Tool[] {
    return [
      {
        name: 'search_bugs_by_keyword',
        description: 'Search bugs by keyword',
        inputSchema: { /* JSON Schema */ }
      }
      // ... more tools
    ];
  }
  
  async callTool(name: string, args: any): Promise<any> {
    switch (name) {
      case 'search_bugs_by_keyword':
        return this.searchBugsByKeyword(args);
      // ... other tools
    }
  }
}
```

### Authentication Flow

OAuth2 implementation with automatic token management:

```typescript
class AuthManager {
  private token: string | null = null;
  private tokenExpiry: Date | null = null;
  
  async getValidToken(): Promise<string> {
    if (!this.token || this.isTokenExpiring()) {
      await this.refreshToken();
    }
    return this.token!;
  }
  
  private async refreshToken(): Promise<void> {
    const response = await fetch('https://id.cisco.com/oauth2/default/v1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: process.env.CISCO_CLIENT_ID!,
        client_secret: process.env.CISCO_CLIENT_SECRET!
      })
    });
    
    const data = await response.json();
    this.token = data.access_token;
    this.tokenExpiry = new Date(Date.now() + (data.expires_in * 1000));
  }
}
```

## Adding New APIs

### 1. Create API Class

```typescript
// src/apis/new-api.ts
import { BaseAPI } from './base-api';
import { Tool } from '../types';

export class NewAPI extends BaseAPI {
  getTools(): Tool[] {
    return [
      {
        name: 'new_tool',
        description: 'Description of the new tool',
        inputSchema: {
          type: 'object',
          properties: {
            param1: { type: 'string', description: 'First parameter' },
            param2: { type: 'number', description: 'Second parameter' }
          },
          required: ['param1']
        }
      }
    ];
  }
  
  async callTool(name: string, args: any): Promise<any> {
    this.validateInput(args, this.getTools().find(t => t.name === name)!.inputSchema);
    
    switch (name) {
      case 'new_tool':
        return this.newTool(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
  
  private async newTool(args: { param1: string; param2?: number }): Promise<any> {
    const url = `https://apix.cisco.com/new/v1.0/endpoint/${args.param1}`;
    const response = await this.authenticatedFetch(url);
    const data = await response.json();
    
    return this.formatResponse(data);
  }
}
```

### 2. Register API

```typescript
// src/apis/index.ts
import { NewAPI } from './new-api';

export const APIs = {
  bug: () => new BugAPI(),
  case: () => new CaseAPI(),
  new: () => new NewAPI(),  // Add new API
  // ... other APIs
};

export type SupportedAPI = keyof typeof APIs;
```

### 3. Add Tests

```typescript
// tests/newApi.test.ts
import { NewAPI } from '../src/apis/new-api';

describe('New API', () => {
  let api: NewAPI;
  
  beforeEach(() => {
    api = new NewAPI();
  });
  
  test('should have correct tools', () => {
    const tools = api.getTools();
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('new_tool');
  });
  
  test('should call new_tool successfully', async () => {
    // Mock fetch
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ result: 'success' })
    });
    
    const result = await api.callTool('new_tool', { param1: 'test' });
    expect(result).toContain('success');
  });
});
```

## Response Formatting

All API responses are formatted with hyperlinks and structured output:

```typescript
// src/utils/formatting.ts
export function formatAPIResponse(data: any, context: { apiName: string }): string {
  let formatted = `## ${context.apiName} Results\n\n`;
  
  if (data.items && Array.isArray(data.items)) {
    data.items.forEach((item: any, index: number) => {
      formatted += `### ${index + 1}. ${item.title || item.name || 'Item'}\n\n`;
      
      // Add clickable links
      if (item.id) {
        formatted += `**ID**: [${item.id}](https://example.com/item/${item.id})\n`;
      }
      
      // Add other fields
      Object.entries(item).forEach(([key, value]) => {
        if (key !== 'id' && key !== 'title' && key !== 'name') {
          formatted += `**${formatFieldName(key)}**: ${value}\n`;
        }
      });
      
      formatted += '\n';
    });
  }
  
  return formatted;
}
```

## Input Validation

All tools use JSON Schema validation:

```typescript
// Example schema
const searchSchema = {
  type: 'object',
  properties: {
    keyword: {
      type: 'string',
      description: 'Search keyword',
      minLength: 1
    },
    page_index: {
      type: 'integer',
      minimum: 1,
      default: 1,
      description: 'Page number'
    },
    severity: {
      type: 'string',
      enum: ['1', '2', '3', '4', '5', '6'],
      description: 'Bug severity level'
    }
  },
  required: ['keyword']
};

// Validation function
function validateInput(args: any, schema: JSONSchema): void {
  const ajv = new Ajv();
  const validate = ajv.compile(schema);
  
  if (!validate(args)) {
    throw new Error(`Invalid input: ${ajv.errorsText(validate.errors)}`);
  }
}
```

## Error Handling

Comprehensive error handling throughout the application:

```typescript
// Error types
class APIError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'APIError';
  }
}

class AuthenticationError extends APIError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401);
    this.name = 'AuthenticationError';
  }
}

// Error handling in API calls
async function handleAPICall<T>(
  operation: () => Promise<T>,
  context: string
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof Response) {
      if (error.status === 401) {
        throw new AuthenticationError(`Authentication failed in ${context}`);
      }
      throw new APIError(
        `API error in ${context}: ${error.statusText}`,
        error.status
      );
    }
    
    if (error instanceof Error) {
      throw new APIError(`Error in ${context}: ${error.message}`, 500, error);
    }
    
    throw new APIError(`Unknown error in ${context}`, 500);
  }
}
```

## Logging

Structured logging with context:

```typescript
// src/utils/logger.ts
interface LogContext {
  requestId?: string;
  userId?: string;
  operation?: string;
  [key: string]: any;
}

class Logger {
  private context: LogContext = {};
  
  withContext(context: LogContext): Logger {
    const newLogger = new Logger();
    newLogger.context = { ...this.context, ...context };
    return newLogger;
  }
  
  info(message: string, data?: any): void {
    this.log('info', message, data);
  }
  
  error(message: string, error?: Error, data?: any): void {
    this.log('error', message, { error: error?.message, stack: error?.stack, ...data });
  }
  
  private log(level: string, message: string, data?: any): void {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: this.context,
      ...data
    };
    
    console.log(JSON.stringify(logEntry));
  }
}

export const logger = new Logger();
```

## Performance Considerations

### Memory Management

- **Token Caching**: OAuth2 tokens cached in memory, not persisted
- **Request Pooling**: Reuse HTTP connections where possible
- **Garbage Collection**: Avoid memory leaks in long-running processes

### API Rate Limiting

```typescript
class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  
  async checkLimit(key: string, limit: number, windowMs: number): Promise<boolean> {
    const now = Date.now();
    const requests = this.requests.get(key) || [];
    
    // Remove old requests outside the window
    const validRequests = requests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= limit) {
      return false;
    }
    
    validRequests.push(now);
    this.requests.set(key, validRequests);
    return true;
  }
}
```

### Caching Strategy

```typescript
class CacheManager {
  private cache: Map<string, { data: any; expiry: number }> = new Map();
  
  get(key: string): any | null {
    const entry = this.cache.get(key);
    if (!entry || Date.now() > entry.expiry) {
      this.cache.delete(key);
      return null;
    }
    return entry.data;
  }
  
  set(key: string, data: any, ttlMs: number): void {
    this.cache.set(key, {
      data,
      expiry: Date.now() + ttlMs
    });
  }
}
```

## Contributing Guidelines

### Code Style

- Use TypeScript strict mode
- Follow ESLint configuration
- Use Prettier for formatting
- Write descriptive variable and function names
- Add JSDoc comments for public APIs

### Git Workflow

```bash
# Create feature branch
git checkout -b feature/new-api-implementation

# Make changes and commit
git add .
git commit -m "feat: add new API implementation with 3 tools"

# Push and create PR
git push origin feature/new-api-implementation
```

### Pull Request Process

1. **Code Review**: All changes require review
2. **Tests**: New features must include tests
3. **Documentation**: Update wiki pages as needed
4. **Backwards Compatibility**: Maintain API compatibility
5. **Performance**: Consider performance impact

### Release Process

```bash
# Update version
npm version patch|minor|major

# Build and test
npm run build
npm test

# Create release
git tag v1.x.x
git push origin v1.x.x

# Publish to NPM
npm publish
```