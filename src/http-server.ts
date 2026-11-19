import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID, timingSafeEqual } from 'node:crypto';
import express from "express";
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { logger } from './mcp-server.js';

// Generate a secure session token for authentication
function generateAuthToken(): string {
  // Check if token is provided via environment variable
  const envToken = process.env.MCP_BEARER_TOKEN;
  if (envToken) {
    return envToken;
  }
  
  // Generate a new random token
  return randomUUID().replace(/-/g, '');
}

// Constant-time token comparison
function tokensMatch(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Origins allowed to call the MCP endpoints from a browser (DNS-rebinding protection).
// Requests without an Origin header (CLI tools, server-side clients) are always allowed.
function getAllowedOrigins(): string[] {
  return (process.env.MCP_ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);
}

function isOriginAllowed(origin: string, allowed: string[]): boolean {
  if (allowed.includes('*') || allowed.includes(origin)) return true;
  try {
    const { hostname } = new URL(origin);
    // Local browser tools (e.g. MCP Inspector) are allowed by default
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  } catch {
    return false;
  }
}

// Create authentication middleware
function createAuthMiddleware(authToken: string, enableAuth: boolean) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!enableAuth) {
      return next();
    }

    // Skip auth for public endpoints
    if (req.path === '/health' || req.path === '/') {
      return next();
    }

    // Bearer token in the Authorization header only (tokens in URLs end up in logs)
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : undefined;

    if (!token || !tokensMatch(token, authToken)) {
      logger.warn('Unauthorized request', {
        path: req.path,
        method: req.method,
        hasToken: !!token
      });

      res.status(401).json({
        error: 'Unauthorized',
        message: 'Valid Bearer token required',
        hint: 'Include an "Authorization: Bearer <token>" header'
      });
      return;
    }

    next();
  };
}

export function createHttpServer(createServer: () => Server) {
  const app = express();

  // Check environment variables for auth configuration
  const enableAuth = process.env.DANGEROUSLY_OMIT_AUTH !== 'true';
  const authToken = generateAuthToken();
  const port = process.env.PORT || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const allowedOrigins = getAllowedOrigins();

  // Display authentication info prominently
  if (enableAuth) {
    console.log('Starting MCP Cisco Support server...');
    console.log(`⚙️  Server listening on ${host}:${port}`);
    console.log('🔐 Authentication Type: BEARER');
    if (process.env.MCP_BEARER_TOKEN) {
      console.log('   ✅ Using token from MCP_BEARER_TOKEN environment variable');
    } else {
      // Only a generated token is printed, since the operator has no other way to learn it
      console.log(`🔑 Generated bearer token: ${authToken}`);
      console.log('   Set MCP_BEARER_TOKEN to use your own token (it will not be printed)');
    }
    console.log('');
    console.log(`🌐 MCP Server is up and running at http://${host}:${port} 🚀`);
    console.log('');
  } else {
    console.log('⚠️  HTTP authentication DISABLED (DANGEROUSLY_OMIT_AUTH=true)');
    console.log('   This is not recommended for production use');
  }

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "form-action": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"]
      }
    }
  }));
  // CORS: only reflect allowed origins (no wildcard)
  app.use(cors({
    origin: (origin, cb) => cb(null, !origin || isOriginAllowed(origin, allowedOrigins)),
  }));

  // Access log without query strings (they can carry secrets)
  morgan.token('path-only', (req: express.Request) => req.path);
  app.use(morgan(':remote-addr - :method :path-only :status :res[content-length] - :response-time ms'));
  // Tool arguments are small; the 10 MB limit was for the removed Smart Bonding uploads
  app.use(express.json({ limit: '1mb' }));

  // Reject browser requests from unexpected origins (DNS rebinding protection)
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && !isOriginAllowed(origin, allowedOrigins)) {
      logger.warn('Rejected request from disallowed origin', { origin, path: req.path });
      res.status(403).json({ error: 'Forbidden', message: 'Origin not allowed' });
      return;
    }
    next();
  });


  // No OAuth in this server (bearer token only; see issue #14). Answer OAuth
  // discovery with 404 before auth runs, so clients see "no OAuth here"
  // instead of a 401 that looks like broken OAuth and stop probing.
  app.use('/.well-known', (_req, res) => {
    res.status(404).json({ error: 'not_found', message: 'OAuth is not supported; use an Authorization: Bearer token' });
  });

  // Apply bearer token authentication middleware
  if (enableAuth) {
    app.use(createAuthMiddleware(authToken, enableAuth));
    logger.info('Bearer token authentication middleware enabled');
  }

  // Stateless Streamable HTTP: every POST gets its own MCP server and
  // transport (no session IDs, nothing kept between requests), so any
  // instance can answer any request and there is no session state to leak.
  app.post("/mcp", async (req, res) => {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      transport.close().catch(() => { /* already closed */ });
      server.close().catch(() => { /* already closed */ });
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error('Failed to handle MCP request', { error: error instanceof Error ? error.message : error });
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
      }
    }
  });

  // No sessions, so no server-initiated GET stream and nothing to DELETE
  const methodNotAllowed = (_req: express.Request, res: express.Response) => {
    res.status(405).set('Allow', 'POST').json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed: this server is stateless; use POST /mcp' },
      id: null,
    });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      mode: 'stateless',
      server: 'mcp-cisco-support'
    });
  });

  // Server info endpoint (publicly accessible to show auth info)
  app.get('/', (_req, res) => {
    const baseEndpoints: Record<string, string> = {
      mcp: '/mcp (POST) - MCP Streamable HTTP endpoint (stateless)',
      health: '/health (GET) - Health check (no auth required)'
    };

    const responseData: any = {
      name: 'Cisco Support MCP Server',
      description: 'MCP Streamable HTTP transport for Cisco Support APIs',
      authentication: {
        enabled: enableAuth,
        type: enableAuth ? 'BEARER' : 'None',
        note: enableAuth
          ? 'Bearer token - Token displayed in console logs on startup'
          : 'Authentication disabled via DANGEROUSLY_OMIT_AUTH=true'
      },
      endpoints: baseEndpoints,
      mode: 'stateless',
      timestamp: new Date().toISOString()
    };

    // Add examples based on auth type
    if (enableAuth) {
      responseData.examples = {
        curl: `curl -H "Authorization: Bearer <token>" http://localhost:${port}/mcp`,
        javascript: `fetch('http://localhost:${port}/mcp', { headers: { 'Authorization': 'Bearer <token>' } })`
      };
    }

    res.json(responseData);
  });

  // Error handling middleware
  app.use((error: Error & { status?: number; type?: string }, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    // Body-parser errors (too large, malformed JSON) are client errors: keep their status
    const status = error.status && error.status >= 400 && error.status < 500 ? error.status : 500;
    logger[status === 500 ? 'error' : 'warn']('HTTP request error', {
      error: error.message,
      type: error.type,
      path: req.path,
      method: req.method,
    });
    res.status(status).json({
      error: status === 413 ? 'Request body too large' : status === 400 ? 'Invalid request body' : 'Internal server error',
      timestamp: new Date().toISOString(),
    });
  });

  // 404 handler
  app.use((req: express.Request, res: express.Response) => {
    res.status(404).json({
      error: 'Endpoint not found',
      path: req.path,
      availableEndpoints: ['/mcp (POST)', '/health', '/'],
      timestamp: new Date().toISOString()
    });
  });

  return app;
}