#!/usr/bin/env node

import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { createMCPServer, setLogging, logger } from './mcp-server.js';
import { createHttpServer } from './http-server.js';
import { VERSION } from './utils/version.js';
import { randomUUID } from 'node:crypto';

// CLI token generation functions
function generateToken(): string {
  return randomUUID().replace(/-/g, '');
}

function showTokenCommands() {
  console.log('🔑 Bearer Token Management');
  console.log('');
  console.log('Generate a new Bearer token:');
  console.log('  npx mcp-cisco-support --generate-token');
  console.log('');
  console.log('Use token via environment variable:');
  console.log('  export MCP_BEARER_TOKEN=your_custom_token_here');
  console.log('  npx mcp-cisco-support --http');
  console.log('');
  console.log('Disable authentication (not recommended):');
  console.log('  export DANGEROUSLY_OMIT_AUTH=true');
  console.log('  npx mcp-cisco-support --http');
  console.log('');
}

// Handle CLI commands
const args = process.argv.slice(2);

// Token generation command
if (args.includes('--generate-token')) {
  const newToken = generateToken();
  console.log('🔑 Generated Bearer Token:');
  console.log('');
  console.log(`   ${newToken}`);
  console.log('');
  console.log('💡 Usage Options:');
  console.log('');
  console.log('1. Set as environment variable:');
  console.log(`   export MCP_BEARER_TOKEN=${newToken}`);
  console.log('   npx mcp-cisco-support --http');
  console.log('');
  console.log('2. Use in HTTP requests:');
  console.log(`   curl -H "Authorization: Bearer ${newToken}" http://localhost:3000/mcp`);
  console.log('');
  console.log('3. Add to .env file:');
  console.log(`   echo "MCP_BEARER_TOKEN=${newToken}" >> .env`);
  console.log('');
  process.exit(0);
}

// Help command
if (args.includes('--help') || args.includes('-h')) {
  console.log(`MCP Cisco Support Server v${VERSION}`);
  console.log('');
  console.log('Usage:');
  console.log('  npx mcp-cisco-support [options]');
  console.log('');
  console.log('Options:');
  console.log('  --http               Start Streamable HTTP server mode (default: stdio)');
  console.log('  --generate-token     Generate a new Bearer token');
  console.log('  --token-help         Show token management commands');
  console.log('  --help, -h           Show this help message');
  console.log('  --version, -v        Show version number');
  console.log('');
  console.log('Environment Variables:');
  console.log('  CISCO_CLIENT_ID           Cisco API client ID (required)');
  console.log('  CISCO_CLIENT_SECRET       Cisco API client secret (required)');
  console.log('  MCP_BEARER_TOKEN          Bearer token for HTTP mode (random if unset)');
  console.log('  PORT / HOST               HTTP listen port and address (default: 3000 / 127.0.0.1)');
  console.log('  MCP_ALLOWED_ORIGINS       Extra browser origins allowed to call /mcp (comma-separated)');
  console.log('  DANGEROUSLY_OMIT_AUTH     Set to "true" to disable HTTP auth');
  console.log('');
  console.log('Examples:');
  console.log('  npx mcp-cisco-support                    # Start in stdio mode');
  console.log('  npx mcp-cisco-support --http             # Start HTTP server');
  console.log('  npx mcp-cisco-support --generate-token   # Generate Bearer token');
  console.log('');
  process.exit(0);
}

// Token help command
if (args.includes('--token-help')) {
  showTokenCommands();
  process.exit(0);
}

// Version command
if (args.includes('--version') || args.includes('-v')) {
  console.log(VERSION);
  process.exit(0);
}

// Determine mode from command line arguments
const isHttpMode = args.includes('--http') || args.includes('--sse'); // --sse kept as an alias
const isStdioMode = !isHttpMode;

// Configure logging based on mode
setLogging(!isStdioMode);




// Main function
async function main() {
  if (isHttpMode) {
    const PORT = process.env.PORT || 3000;
    const HOST = process.env.HOST || '127.0.0.1';
    const httpServer = createHttpServer(createMCPServer);
    const listener = httpServer.listen(Number(PORT), HOST, () => {
      logger.info(`Cisco Support MCP server (Streamable HTTP) started on ${HOST}:${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        version: VERSION,
      });
    });
    const shutdown = () => {
      logger.info('Shutting down');
      listener.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 5000).unref();
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } else {
    // One server instance per stdio connection; serves 2026-07-28 and 2025-era clients
    serveStdio(createMCPServer);
    logger.info('Cisco Support MCP Server connected via stdio');
  }
}

main().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
