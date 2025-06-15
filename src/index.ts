#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { mcpServer, setLogging, logger } from './mcp-server.js';
import { createSSEServer } from './sse-server.js';
import { readFileSync } from 'fs';
import { join } from 'path';

// Get version from package.json
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const VERSION = packageJson.version;

// Determine mode from command line arguments
const isStdioMode = !process.argv.includes('--http');

// Configure logging based on mode
setLogging(!isStdioMode);




// Main function
async function main() {
  const args = process.argv.slice(2);
  const isHTTP = args.includes('--http');
  
  if (isHTTP) {
    // Run as SSE HTTP server
    const PORT = process.env.PORT || 3000;
    const sseServer = createSSEServer(mcpServer);
    
    // Graceful shutdown handling
    const cleanup = () => {
      logger.info('Shutting down gracefully');
      process.exit(0);
    };

    process.on('SIGTERM', cleanup);
    process.on('SIGINT', cleanup);
    
    sseServer.listen(PORT, () => {
      logger.info(`Cisco Support MCP SSE Server started on port ${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        version: VERSION,
        mode: 'sse-http'
      });
    });
  } else {
    // Run as MCP server over stdio (default)
    logger.info('Starting Cisco Support MCP Server in stdio mode');
    
    const transport = new StdioServerTransport();
    await mcpServer.connect(transport);
    
    logger.info('Cisco Support MCP Server connected via stdio');
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Failed to start server', error);
    process.exit(1);
  });
}