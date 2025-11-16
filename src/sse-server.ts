import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from 'node:crypto';
import express from "express";
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { logger } from './mcp-server.js';
import {
  generateAuthorizationServerMetadata,
  registerClient,
  handleAuthorizeRequest,
  handleAuthorizeApproval,
  handleTokenRequest,
  createOAuth2Middleware,
  type OAuth2Config
} from './oauth2.js';
import { setCurrentRequestScopes } from './apis/index.js';

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

    // Skip auth for OAuth 2.1 discovery and registration endpoints (RFC 8414, RFC 7591)
    const publicOAuth2Paths = [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-protected-resource',
      '/.well-known/openid-configuration',
      '/register',
      '/authorize',  // User will be redirected here, needs to show UI
      '/token'       // Client credentials are verified within the endpoint
    ];

    if (publicOAuth2Paths.some(path => req.path === path || req.path.startsWith(path + '/'))) {
      return next();
    }

    // Check for Bearer token in Authorization header (primary method)
    const authHeader = req.headers['authorization'];
    let token: string | undefined;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.replace('Bearer ', '');
    } else {
      // Fallback: check query parameter for convenience (less secure)
      token = req.query.token as string;
    }

    if (!token || token !== authToken) {
      logger.warn('Unauthorized request', { 
        path: req.path, 
        method: req.method,
        hasToken: !!token,
        tokenMatch: token === authToken,
        authHeader: !!authHeader
      });
      
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Valid Bearer token required',
        hint: 'Include "Authorization: Bearer <token>" header or ?token=<token> query parameter'
      });
      return;
    }

    next();
  };
}

export function createSSEServer(mcpServer: Server) {
  const app = express();

  // Check environment variables for auth configuration
  const enableAuth = process.env.DANGEROUSLY_OMIT_AUTH !== 'true';
  const authType = (process.env.AUTH_TYPE || 'bearer').toLowerCase();
  const authToken = generateAuthToken();
  const port = process.env.PORT || 3000;

  // OAuth 2.1 configuration
  const oauth2Config: OAuth2Config = {
    issuerUrl: process.env.OAUTH2_ISSUER_URL || `http://localhost:${port}`,
    allowDynamicRegistration: process.env.OAUTH2_ALLOW_DYNAMIC_REGISTRATION !== 'false',
    requirePKCE: true
  };

  // Display authentication info prominently
  if (enableAuth) {
    console.log('Starting MCP Cisco Support server...');
    console.log(`⚙️  Server listening on 127.0.0.1:${port}`);
    console.log(`🔐 Authentication Type: ${authType.toUpperCase()}`);
    console.log('');

    if (authType === 'bearer') {
      const isEnvToken = !!process.env.MCP_BEARER_TOKEN;
      console.log(`🔑 Bearer token: ${authToken}`);

      if (isEnvToken) {
        console.log('   ✅ Using token from MCP_BEARER_TOKEN environment variable');
      } else {
        console.log('   🎲 Generated random token (set MCP_BEARER_TOKEN to use custom token)');
      }

      console.log('Use this token to authenticate requests or set DANGEROUSLY_OMIT_AUTH=true to disable auth');
      console.log('');
      console.log('🔗 Access with Bearer token:');
      console.log(`   curl -H "Authorization: Bearer ${authToken}" http://localhost:${port}/mcp`);
      console.log(`   (Query parameter also supported: ?token=${authToken})`);
    } else if (authType === 'oauth2.1') {
      console.log('📋 OAuth 2.1 Authorization Server Configuration:');
      console.log(`   Issuer: ${oauth2Config.issuerUrl}`);
      console.log(`   Authorization Endpoint: ${oauth2Config.issuerUrl}/authorize`);
      console.log(`   Token Endpoint: ${oauth2Config.issuerUrl}/token`);
      console.log(`   Registration Endpoint: ${oauth2Config.allowDynamicRegistration ? oauth2Config.issuerUrl + '/register' : 'Disabled'}`);
      console.log(`   Metadata: ${oauth2Config.issuerUrl}/.well-known/oauth-authorization-server`);
      console.log('');
      console.log('📝 To register a client:');
      console.log(`   curl -X POST ${oauth2Config.issuerUrl}/register \\`);
      console.log(`     -H "Content-Type: application/json" \\`);
      console.log(`     -d '{"redirect_uris":["http://localhost:3001/callback"],"client_name":"My MCP Client"}'`);
      console.log('');
      console.log('🔐 OAuth 2.1 Flow:');
      console.log('   1. Register client (POST /register)');
      console.log('   2. Get authorization code (GET /authorize)');
      console.log('   3. Exchange code for token (POST /token)');
      console.log('   4. Use token in requests (Authorization: Bearer <token>)');
    } else {
      console.log(`⚠️  Unknown AUTH_TYPE: ${authType}`);
      console.log('   Valid options: bearer (default), oauth2.1');
      console.log('   Falling back to bearer authentication');
    }

    console.log('');
    console.log(`🌐 MCP Server is up and running at http://127.0.0.1:${port} 🚀`);
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
  app.use(cors());
  app.use(morgan('combined'));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // MCP Protocol Version header middleware
  app.use((req, res, next) => {
    res.setHeader('MCP-Protocol-Version', '2025-06-18');
    next();
  });

  // OAuth 2.1 endpoints (before auth middleware)
  if (enableAuth && authType === 'oauth2.1') {
    // Authorization Server Metadata (RFC 8414)
    app.get('/.well-known/oauth-authorization-server', (req, res) => {
      logger.info('Authorization server metadata requested');
      res.json(generateAuthorizationServerMetadata(oauth2Config));
    });

    // OAuth Protected Resource Metadata (RFC 9728)
    // This tells clients which authorization server protects this resource
    app.get('/.well-known/oauth-protected-resource', (req, res) => {
      logger.info('Protected resource metadata requested');
      res.json({
        resource: oauth2Config.issuerUrl,
        authorization_servers: [oauth2Config.issuerUrl],
        scopes_supported: ['mcp'],
        bearer_methods_supported: ['header', 'query'],
        resource_documentation: `${oauth2Config.issuerUrl}/`,
        'mcp-protocol-version': '2025-06-18'
      });
    });

    // OAuth Protected Resource Metadata for /mcp endpoint specifically
    app.get('/.well-known/oauth-protected-resource/mcp', (req, res) => {
      logger.info('Protected resource metadata for /mcp requested');
      res.json({
        resource: `${oauth2Config.issuerUrl}/mcp`,
        authorization_servers: [oauth2Config.issuerUrl],
        scopes_supported: ['mcp'],
        bearer_methods_supported: ['header'],
        resource_documentation: `${oauth2Config.issuerUrl}/`,
        'mcp-protocol-version': '2025-06-18'
      });
    });

    // Dynamic Client Registration (RFC 7591)
    app.post('/register', (req, res) => {
      registerClient(req, res, oauth2Config);
    });

    // Authorization endpoint
    app.get('/authorize', async (req, res) => {
      await handleAuthorizeRequest(req, res);
    });

    // Authorization approval endpoint
    app.post('/authorize/approve', (req, res) => {
      handleAuthorizeApproval(req, res);
    });

    // Token endpoint
    app.post('/token', (req, res) => {
      handleTokenRequest(req, res);
    });
  }

  // Apply authentication middleware based on type
  if (enableAuth) {
    if (authType === 'oauth2.1') {
      app.use(createOAuth2Middleware());
      logger.info('OAuth 2.1 authentication middleware enabled');
    } else {
      // Default to bearer token authentication
      app.use(createAuthMiddleware(authToken, enableAuth));
      logger.info('Bearer token authentication middleware enabled');
    }
  }

  const transportMap = new Map<string, SSEServerTransport>();
  const streamableTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
  
  // Heartbeat configuration
  const HEARTBEAT_INTERVAL = 30000; // 30 seconds
  const CONNECTION_TIMEOUT = 120000; // 2 minutes
  const heartbeatIntervals = new Map<string, NodeJS.Timeout>();

  // Helper function to start heartbeat for SSE connection
  function startHeartbeat(sessionId: string, res: express.Response): NodeJS.Timeout {
    return setInterval(() => {
      try {
        // Send heartbeat message to keep connection alive
        res.write('event: heartbeat\n');
        res.write(`data: {"type":"heartbeat","timestamp":"${new Date().toISOString()}"}\n\n`);
        logger.info('Heartbeat sent', { sessionId });
      } catch (error) {
        logger.warn('Heartbeat failed, cleaning up connection', { sessionId, error });
        stopHeartbeat(sessionId);
        cleanupConnection(sessionId, res);
      }
    }, HEARTBEAT_INTERVAL);
  }

  // Helper function to stop heartbeat
  function stopHeartbeat(sessionId: string) {
    const interval = heartbeatIntervals.get(sessionId);
    if (interval) {
      clearInterval(interval);
      heartbeatIntervals.delete(sessionId);
      logger.info('Heartbeat stopped', { sessionId });
    }
  }

  // Helper function to cleanup connection
  function cleanupConnection(sessionId: string, res?: express.Response) {
    transportMap.delete(sessionId);
    stopHeartbeat(sessionId);
    
    if (res && !res.destroyed) {
      try {
        res.end();
      } catch (error) {
        logger.info('Response already ended', { sessionId });
      }
    }
    
    logger.info('SSE connection cleaned up', { 
      sessionId,
      remainingConnections: transportMap.size
    });
  }

  // SSE endpoint - establishes SSE connection and connects to MCP server
  app.get("/sse", async (req, res) => {
    let sessionId: string | undefined;
    
    try {
      logger.info('SSE connection request received');
      
      // Set connection timeout
      req.setTimeout(CONNECTION_TIMEOUT, () => {
        logger.warn('SSE connection timeout', { sessionId });
        if (sessionId) {
          cleanupConnection(sessionId, res);
        }
      });
      
      // Create SSE transport with proper endpoint - it will set the headers
      const transport = new SSEServerTransport("/messages", res);
      sessionId = transport.sessionId;
      
      // Store transport for message handling
      transportMap.set(sessionId, transport);
      
      // Start heartbeat to keep connection alive
      const heartbeatInterval = startHeartbeat(sessionId, res);
      heartbeatIntervals.set(sessionId, heartbeatInterval);
      
      logger.info('SSE transport created', { sessionId: transport.sessionId });
      
      // Connect MCP server to transport
      await mcpServer.connect(transport);
      
      logger.info('MCP server connected to SSE transport', { 
        sessionId: transport.sessionId,
        totalTransports: transportMap.size
      });
      
      // Set up cleanup handlers before connecting
      transport.onclose = () => {
        logger.info('SSE connection closed', { sessionId });
        if (sessionId) {
          cleanupConnection(sessionId);
        }
      };

      // Enhanced error handling with detailed logging
      transport.onerror = (error) => {
        logger.error('SSE transport error', { 
          sessionId: sessionId,
          error: error.message,
          errorType: typeof error,
          stack: error instanceof Error ? error.stack : undefined
        });
        
        // Clean up on transport error
        if (sessionId) {
          cleanupConnection(sessionId, res);
        }
      };

      // Handle cleanup when connection closes
      req.on('close', () => {
        logger.info('SSE request closed by client', { sessionId });
        if (sessionId) {
          cleanupConnection(sessionId);
        }
      });
      
      // Handle errors on response stream
      res.on('error', (error) => {
        logger.error('SSE response stream error', { 
          sessionId: sessionId,
          error: error.message,
          code: (error as any).code,
          errno: (error as any).errno
        });
        if (sessionId) {
          cleanupConnection(sessionId);
        }
      });
      
      // Handle connection timeout
      res.on('timeout', () => {
        logger.warn('SSE response timeout', { sessionId });
        if (sessionId) {
          cleanupConnection(sessionId, res);
        }
      });
      
    } catch (error) {
      logger.error('Failed to establish SSE connection', { 
        sessionId,
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined
      });
      
      // Cleanup on error
      if (sessionId) {
        cleanupConnection(sessionId, res);
      }
      
      if (!res.headersSent) {
        res.status(500).json({ 
          error: 'Failed to establish SSE connection',
          message: error instanceof Error ? error.message : 'Unknown error',
          retryAfter: '5' // Suggest client retry after 5 seconds
        });
      }
    }
  });

  // MCP JSON-RPC endpoint - handles direct MCP calls using StreamableHTTP
  app.post("/mcp", async (req, res) => {
    try {
      logger.info('Direct MCP call received', { method: req.body?.method });

      // Set OAuth scopes for this request (if available)
      // This allows the API registry to filter tools based on token scopes
      setCurrentRequestScopes(req.oauth_scopes);

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
        
        // Set up cleanup handler
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && streamableTransports[sid]) {
            logger.info('Transport closed, cleaning up', { sessionId: sid });
            delete streamableTransports[sid];
          }
        };
        
        // Connect the transport to the MCP server
        await mcpServer.connect(transport);
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

  // Messages endpoint - handles MCP JSON-RPC messages
  app.post("/messages", async (req, res) => {
    const sessionId = req.query.sessionId as string;
    
    if (!sessionId) {
      logger.error('Message received without sessionId');
      res.status(400).json({ error: 'sessionId is required' });
      return;
    }

    logger.info('Message received for session', { sessionId, method: req.body?.method });

    const transport = transportMap.get(sessionId);

    if (transport) {
      try {
        // Let the transport handle the message - must await and pass req.body
        await transport.handlePostMessage(req, res, req.body);
      } catch (error) {
        logger.error('Failed to handle message', { 
          sessionId, 
          error: error instanceof Error ? error.message : error 
        });
        if (!res.headersSent) {
          res.status(500).json({ 
            error: 'Failed to handle message',
            message: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
    } else {
      logger.error('Transport not found for session', { sessionId });
      res.status(404).json({ 
        error: 'Session not found',
        sessionId 
      });
    }
  });

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      activeTransports: transportMap.size,
      server: 'mcp-cisco-support-sse'
    });
  });

  // Server info endpoint (publicly accessible to show auth info)
  app.get('/', (_req, res) => {
    const baseEndpoints: Record<string, string> = {
      mcp: '/mcp (POST/GET/DELETE) - MCP StreamableHTTP endpoint',
      sse: '/sse (GET) - Legacy SSE connection',
      messages: '/messages (POST) - Legacy SSE messages',
      health: '/health (GET) - Health check (no auth required)'
    };

    const oauth2Endpoints: Record<string, string> = {
      metadata: '/.well-known/oauth-authorization-server (GET) - OAuth 2.1 server metadata',
      register: '/register (POST) - Dynamic client registration',
      authorize: '/authorize (GET) - Authorization endpoint',
      token: '/token (POST) - Token endpoint'
    };

    const responseData: any = {
      name: 'Cisco Support MCP SSE Server',
      description: 'MCP Server-Sent Events transport for Cisco Support APIs',
      authentication: {
        enabled: enableAuth,
        type: enableAuth ? authType.toUpperCase() : 'None',
        note: enableAuth
          ? (authType === 'oauth2.1'
              ? 'OAuth 2.1 with PKCE - Register client, get authorization code, exchange for token'
              : 'Bearer token - Token displayed in console logs on startup')
          : 'Authentication disabled via DANGEROUSLY_OMIT_AUTH=true'
      },
      endpoints: enableAuth && authType === 'oauth2.1'
        ? { ...baseEndpoints, ...oauth2Endpoints }
        : baseEndpoints,
      activeTransports: transportMap.size + Object.keys(streamableTransports).length,
      timestamp: new Date().toISOString()
    };

    // Add examples based on auth type
    if (enableAuth && authType === 'bearer') {
      responseData.examples = {
        curl: `curl -H "Authorization: Bearer <token>" http://localhost:${port}/mcp`,
        curlQuery: `curl http://localhost:${port}/mcp?token=<token>`,
        javascript: `fetch('http://localhost:${port}/mcp', { headers: { 'Authorization': 'Bearer <token>' } })`
      };
    } else if (enableAuth && authType === 'oauth2.1') {
      responseData.oauth2Flow = {
        issuer: oauth2Config.issuerUrl,
        metadata: `${oauth2Config.issuerUrl}/.well-known/oauth-authorization-server`,
        steps: [
          '1. Register client: POST /register',
          '2. Get authorization code: GET /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256',
          '3. Exchange code: POST /token with grant_type=authorization_code&code=...&code_verifier=...',
          '4. Use access token: Include "Authorization: Bearer <access_token>" in all requests'
        ]
      };
    }

    res.json(responseData);
  });

  // Error handling middleware
  app.use((error: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error('Unhandled SSE server error', { 
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
      availableEndpoints: ['/mcp (POST/GET/DELETE)', '/sse', '/messages', '/health', '/'],
      timestamp: new Date().toISOString()
    });
  });

  // Graceful shutdown handler
  function gracefulShutdown() {
    logger.info('Shutting down SSE server, cleaning up connections', { 
      activeConnections: transportMap.size,
      activeHeartbeats: heartbeatIntervals.size
    });
    
    // Clean up all connections
    for (const sessionId of transportMap.keys()) {
      cleanupConnection(sessionId);
    }
    
    // Clear any remaining heartbeat intervals
    for (const [sessionId, interval] of heartbeatIntervals.entries()) {
      clearInterval(interval);
      heartbeatIntervals.delete(sessionId);
    }
    
    logger.info('SSE server cleanup completed');
  }

  // Handle process termination
  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);

  return app;
}