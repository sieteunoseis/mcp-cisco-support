import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
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
    exposedHeaders: ['Mcp-Session-Id']
  }));

  // Access log without query strings (they can carry secrets)
  morgan.token('path-only', (req: express.Request) => req.path);
  app.use(morgan(':remote-addr - :method :path-only :status :res[content-length] - :response-time ms'));
  app.use(express.json({ limit: '10mb' }));

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

  // Streamable HTTP sessions (each with its own MCP server)
  const streamableTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  // MCP JSON-RPC endpoint - handles direct MCP calls using StreamableHTTP
  app.post("/mcp", async (req, res) => {
    try {
      logger.info('Direct MCP call received', { method: req.body?.method });

      // Check for existing session ID
      const sessionId = req.headers['mcp-session-id'] as string;
      let transport: StreamableHTTPServerTransport;
      
      if (sessionId && streamableTransports[sessionId]) {
        // Reuse existing transport
        transport = streamableTransports[sessionId];
        logger.info('Reusing existing transport', { sessionId });
      } else if (!sessionId && isInitializeRequest(req.body)) {
        // New initialization request
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sessionId: string) => {
            logger.info('Session initialized', { sessionId });
            streamableTransports[sessionId] = transport;
          }
        });
        
        // Each session gets its own MCP server instance
        const sessionServer = createServer();

        // Set up cleanup handler
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && streamableTransports[sid]) {
            logger.info('Transport closed, cleaning up', { sessionId: sid });
            delete streamableTransports[sid];
          }
          sessionServer.close().catch(() => { /* already closed */ });
        };

        await sessionServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return; // Already handled
      } else {
        // Invalid request - no session ID or not initialization request
        logger.error('Invalid MCP request', { sessionId, isInit: isInitializeRequest(req.body) });
        res.status(400).json({
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: 'Bad Request: No valid session ID provided',
          },
          id: null,
        });
        return;
      }
      
      // Handle the request with existing transport
      await transport.handleRequest(req, res, req.body);
      
    } catch (error) {
      logger.error('Failed to handle MCP call', { error });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
          },
          id: null,
        });
      }
    }
  });

  // MCP GET endpoint - handles SSE streams for StreamableHTTP
  app.get("/mcp", async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string;
      
      if (!sessionId || !streamableTransports[sessionId]) {
        logger.error('Invalid session ID for GET request', { sessionId });
        res.status(400).send('Invalid or missing session ID');
        return;
      }
      
      logger.info('SSE stream request', { sessionId });
      const transport = streamableTransports[sessionId];
      await transport.handleRequest(req, res);
      
    } catch (error) {
      logger.error('Failed to handle SSE stream', { error });
      if (!res.headersSent) {
        res.status(500).send('Error establishing SSE stream');
      }
    }
  });

  // MCP DELETE endpoint - handles session termination
  app.delete("/mcp", async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string;
      
      if (!sessionId || !streamableTransports[sessionId]) {
        logger.error('Invalid session ID for DELETE request', { sessionId });
        res.status(400).send('Invalid or missing session ID');
        return;
      }
      
      logger.info('Session termination request', { sessionId });
      const transport = streamableTransports[sessionId];
      await transport.handleRequest(req, res);
      
    } catch (error) {
      logger.error('Failed to handle session termination', { error });
      if (!res.headersSent) {
        res.status(500).send('Error processing session termination');
      }
    }
  });

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      activeSessions: Object.keys(streamableTransports).length,
      server: 'mcp-cisco-support'
    });
  });

  // Server info endpoint (publicly accessible to show auth info)
  app.get('/', (_req, res) => {
    const baseEndpoints: Record<string, string> = {
      mcp: '/mcp (POST/GET/DELETE) - MCP Streamable HTTP endpoint',
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
      activeSessions: Object.keys(streamableTransports).length,
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
  app.use((error: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error('Unhandled HTTP server error', { 
      error: error.message,
      path: req.path,
      method: req.method
    });
    
    res.status(500).json({
      error: 'Internal server error',
      timestamp: new Date().toISOString()
    });
  });

  // 404 handler
  app.use((req: express.Request, res: express.Response) => {
    res.status(404).json({
      error: 'Endpoint not found',
      path: req.path,
      availableEndpoints: ['/mcp (POST/GET/DELETE)', '/health', '/'],
      timestamp: new Date().toISOString()
    });
  });

  // Graceful shutdown: close every open session
  function gracefulShutdown() {
    const sessions = Object.values(streamableTransports);
    logger.info('Shutting down HTTP server, closing sessions', { activeSessions: sessions.length });
    for (const transport of sessions) {
      transport.close().catch(() => { /* already closed */ });
    }
  }

  // Handle process termination
  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);

  return app;
}