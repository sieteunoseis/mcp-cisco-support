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

// Generate a secure session token for authentication
function generateAuthToken(): string {
  return randomUUID().replace(/-/g, '');
}

// Create authentication middleware
function createAuthMiddleware(authToken: string, enableAuth: boolean) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!enableAuth) {
      return next();
    }

    // Skip auth for health check and root endpoints
    if (req.path === '/health' || req.path === '/') {
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
  const authToken = generateAuthToken();
  
  // Log authentication configuration on startup
  if (enableAuth) {
    logger.info('🔐 HTTP Bearer token authentication enabled');
    logger.info(`🔑 Bearer token: ${authToken}`);
    logger.info('Use this Bearer token to authenticate requests or set DANGEROUSLY_OMIT_AUTH=true to disable auth');
    logger.info('');
    logger.info('📡 Authentication methods:');
    logger.info(`   1. Header: Authorization: Bearer ${authToken}`);
    logger.info(`   2. Query:  ?token=${authToken}`);
    logger.info('');
    logger.info('🔗 Example requests:');
    logger.info(`   curl -H "Authorization: Bearer ${authToken}" http://localhost:${process.env.PORT || 3000}/mcp`);
    logger.info(`   curl http://localhost:${process.env.PORT || 3000}/mcp?token=${authToken}`);
    logger.info('');
  } else {
    logger.warn('⚠️  HTTP authentication DISABLED (DANGEROUSLY_OMIT_AUTH=true)');
    logger.warn('   This is not recommended for production use');
  }

  // Security middleware
  app.use(helmet());
  app.use(cors());
  app.use(morgan('combined'));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  
  // Apply authentication middleware
  app.use(createAuthMiddleware(authToken, enableAuth));

  const transportMap = new Map<string, SSEServerTransport>();
  const streamableTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  // SSE endpoint - establishes SSE connection and connects to MCP server
  app.get("/sse", async (req, res) => {
    try {
      logger.info('SSE connection request received');
      
      // Create SSE transport with proper endpoint - it will set the headers
      const transport = new SSEServerTransport("/messages", res);
      
      // Store transport for message handling
      transportMap.set(transport.sessionId, transport);
      
      logger.info('SSE transport created', { sessionId: transport.sessionId });
      
      // Connect MCP server to transport
      await mcpServer.connect(transport);
      
      logger.info('MCP server connected to SSE transport', { 
        sessionId: transport.sessionId,
        totalTransports: transportMap.size
      });
      
      // Set up cleanup handlers before connecting
      transport.onclose = () => {
        logger.info('SSE connection closed', { sessionId: transport.sessionId });
        transportMap.delete(transport.sessionId);
      };

      transport.onerror = (error) => {
        logger.error('SSE transport error', { 
          sessionId: transport.sessionId,
          error: error.message 
        });
      };

      // Handle cleanup when connection closes
      req.on('close', () => {
        transportMap.delete(transport.sessionId);
        logger.info('SSE request closed', { 
          sessionId: transport.sessionId,
          totalTransports: transportMap.size
        });
      });
      
      // Handle errors on response stream
      res.on('error', (error) => {
        logger.error('SSE response stream error', { 
          sessionId: transport.sessionId,
          error: error.message 
        });
        transportMap.delete(transport.sessionId);
      });
      
    } catch (error) {
      logger.error('Failed to establish SSE connection', { error });
      if (!res.headersSent) {
        res.status(500).json({ 
          error: 'Failed to establish SSE connection',
          message: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  });

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

  // Server info endpoint
  app.get('/', (_req, res) => {
    const port = process.env.PORT || 3000;
    res.json({
      name: 'Cisco Support MCP SSE Server',
      description: 'MCP Server-Sent Events transport for Cisco Support APIs',
      authentication: {
        enabled: enableAuth,
        type: 'Bearer Token',
        token: enableAuth ? authToken : null,
        header: enableAuth ? `Authorization: Bearer ${authToken}` : null,
        query: enableAuth ? `?token=${authToken}` : null,
        note: enableAuth ? 'Use Authorization: Bearer <token> header (recommended) or ?token=<token> query parameter' : 'Authentication disabled via DANGEROUSLY_OMIT_AUTH=true'
      },
      endpoints: {
        mcp: '/mcp (POST/GET/DELETE) - MCP StreamableHTTP endpoint',
        sse: '/sse (GET) - Legacy SSE connection',
        messages: '/messages (POST) - Legacy SSE messages',
        health: '/health (GET) - Health check (no auth required)'
      },
      examples: enableAuth ? {
        curl: `curl -H "Authorization: Bearer ${authToken}" http://localhost:${port}/mcp`,
        curlQuery: `curl http://localhost:${port}/mcp?token=${authToken}`,
        javascript: `fetch('http://localhost:${port}/mcp', { headers: { 'Authorization': 'Bearer ${authToken}' } })`
      } : undefined,
      activeTransports: transportMap.size + Object.keys(streamableTransports).length,
      timestamp: new Date().toISOString()
    });
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

  return app;
}