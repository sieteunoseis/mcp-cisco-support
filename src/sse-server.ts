import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { logger } from './mcp-server.js';

export function createSSEServer(mcpServer: Server) {
  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(cors());
  app.use(morgan('combined'));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  const transportMap = new Map<string, SSEServerTransport>();

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
      
      // Handle transport cleanup when connection closes
      req.on('close', () => {
        transportMap.delete(transport.sessionId);
        logger.info('SSE transport cleaned up', { 
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

  // Messages endpoint - handles MCP JSON-RPC messages
  app.post("/messages", (req, res) => {
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
        // Let the transport handle the message
        transport.handlePostMessage(req, res);
      } catch (error) {
        logger.error('Failed to handle message', { 
          sessionId, 
          error: error instanceof Error ? error.message : error 
        });
        res.status(500).json({ 
          error: 'Failed to handle message',
          message: error instanceof Error ? error.message : 'Unknown error'
        });
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
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      activeTransports: transportMap.size,
      server: 'mcp-cisco-support-sse'
    });
  });

  // Server info endpoint
  app.get('/', (req, res) => {
    res.json({
      name: 'Cisco Support MCP SSE Server',
      description: 'MCP Server-Sent Events transport for Cisco Support APIs',
      endpoints: {
        sse: '/sse (GET) - Establish SSE connection',
        messages: '/messages (POST) - Send MCP messages',
        health: '/health (GET) - Health check'
      },
      activeTransports: transportMap.size,
      timestamp: new Date().toISOString()
    });
  });

  // Error handling middleware
  app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
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
      availableEndpoints: ['/sse', '/messages', '/health', '/'],
      timestamp: new Date().toISOString()
    });
  });

  return app;
}