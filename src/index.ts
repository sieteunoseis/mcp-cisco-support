#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { mcpServer, setLogging, logger } from './mcp-server.js';
import { createSSEServer } from './sse-server.js';
import { readFileSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'node:crypto';

// Get version from package.json (handle different working directories)
function findPackageJson() {
  const possiblePaths = [
    join(__dirname, '../../package.json'), // When compiled to dist/src/
    join(__dirname, '../package.json'),    // When running from src/
    join(process.cwd(), 'package.json'),   // When running from project root
  ];
  
  for (const path of possiblePaths) {
    try {
      return readFileSync(path, 'utf8');
    } catch (error) {
      // Continue to next path
    }
  }
  
  // Fallback version
  return JSON.stringify({ version: '1.7.0' });
}

const packageJson = JSON.parse(findPackageJson());
const VERSION = packageJson.version;

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
  console.log('  --http, --sse        Start HTTP server mode (default: stdio)');
  console.log('  --generate-token     Generate a new Bearer token');
  console.log('  --token-help         Show token management commands');
  console.log('  --help, -h           Show this help message');
  console.log('  --version, -v        Show version number');
  console.log('');
  console.log('Environment Variables:');
  console.log('  CISCO_CLIENT_ID           Cisco API client ID (required)');
  console.log('  CISCO_CLIENT_SECRET       Cisco API client secret (required)');
  console.log('  SUPPORT_API               Enabled APIs: bug,case,eox or all (default: bug)');
  console.log('  MCP_BEARER_TOKEN          Custom Bearer token for HTTP auth');
  console.log('  DANGEROUSLY_OMIT_AUTH     Set to "true" to disable HTTP auth');
  console.log('  PORT                      HTTP server port (default: 3000)');
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
const isHttpMode = args.includes('--http') || args.includes('--sse');
const isStdioMode = !isHttpMode;

// Configure logging based on mode
setLogging(!isStdioMode);




// Main function
async function main() {
  const args = process.argv.slice(2);
  const isHTTP = args.includes('--http') || args.includes('--sse');
  
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