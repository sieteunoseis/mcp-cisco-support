#!/usr/bin/env node

/**
 * Test runner for individual MCP tools
 * Usage: 
 *   node test-tool.js <tool_name> [real|mock]
 *   npm run test:tool <tool_name> [real|mock]
 * 
 * Examples:
 *   node test-tool.js search_bugs_by_keyword
 *   node test-tool.js get_bug_details real
 *   npm run test:tool search_bugs_by_product_id mock
 */

// Mock fetch for mock mode
function setupMockMode() {
  const mockOAuthResponse = {
    access_token: 'mock_access_token_12345',
    token_type: 'Bearer',
    expires_in: 43200,
  };

  const mockBugResponse = {
    bugs: [
      {
        bug_id: 'CSCvi12345',
        headline: 'Test bug for CallManager 12.5 memory leak',
        status: 'O',
        severity: '3',
        last_modified_date: '2024-01-15T10:30:00.000Z',
        product: 'Cisco Unified Communications Manager',
        affected_releases: ['12.5(1)SU1', '12.5(1)SU2'],
        fixed_releases: ['12.5(1)SU3'],
        description: 'Memory leak observed in CallManager 12.5 when handling large call volumes'
      },
      {
        bug_id: 'CSCvi67890',
        headline: 'CallManager 12.5 crashes during backup operation',
        status: 'F',
        severity: '2',
        last_modified_date: '2024-01-10T14:22:00.000Z',
        product: 'Cisco Unified Communications Manager',
        affected_releases: ['12.5(1)SU1'],
        fixed_releases: ['12.5(1)SU2'],
        description: 'System crashes when performing scheduled backup operations'
      }
    ],
    total_results: 2
  };

  // Mock fetch globally
  global.fetch = async (url, options) => {
    if (url.includes('oauth2')) {
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockOAuthResponse),
        text: () => Promise.resolve(JSON.stringify(mockOAuthResponse))
      };
    }
    
    return {
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockBugResponse),
      text: () => Promise.resolve(JSON.stringify(mockBugResponse))
    };
  };

  // Mock AbortController
  global.AbortController = class {
    signal = { aborted: false };
    abort() {}
  };
}

const { executeTool, getAvailableTools } = require('./dist/mcp-server.js');

// Available tools
const availableTools = [
  'get_bug_details',
  'search_bugs_by_keyword', 
  'search_bugs_by_product_id',
  'search_bugs_by_product_and_release',
  'search_bugs_by_product_series_affected',
  'search_bugs_by_product_series_fixed',
  'search_bugs_by_product_name_affected',
  'search_bugs_by_product_name_fixed'
];

// Test cases for each tool
const testCases = {
  get_bug_details: {
    tool: 'get_bug_details',
    args: { bug_ids: 'CSCvi12345' },
    description: 'Get details for a specific bug ID'
  },
  search_bugs_by_keyword: {
    tool: 'search_bugs_by_keyword',
    args: { keyword: 'CallManager', severity: '3', status: 'O' },
    description: 'Search bugs by keyword with filters'
  },
  search_bugs_by_product_id: {
    tool: 'search_bugs_by_product_id',
    args: { base_pid: 'C9200-24P', severity: '2' },
    description: 'Search bugs by product ID'
  },
  search_bugs_by_product_and_release: {
    tool: 'search_bugs_by_product_and_release',
    args: { base_pid: 'C9200-24P', software_releases: '17.5.1' },
    description: 'Search bugs by product ID and software release'
  },
  search_bugs_by_product_series_affected: {
    tool: 'search_bugs_by_product_series_affected',
    args: { product_series: 'Cisco Catalyst 9200 Series', affected_releases: '17.5.1' },
    description: 'Search bugs by product series and affected releases'
  },
  search_bugs_by_product_series_fixed: {
    tool: 'search_bugs_by_product_series_fixed',
    args: { product_series: 'Cisco Catalyst 9200 Series', fixed_releases: '17.5.2' },
    description: 'Search bugs by product series and fixed releases'
  },
  search_bugs_by_product_name_affected: {
    tool: 'search_bugs_by_product_name_affected',
    args: { product_name: 'Cisco Unified Communications Manager (CallManager)', affected_releases: '12.5(1)SU1' },
    description: 'Search bugs by exact product name and affected releases'
  },
  search_bugs_by_product_name_fixed: {
    tool: 'search_bugs_by_product_name_fixed',
    args: { product_name: 'Cisco Unified Communications Manager (CallManager)', fixed_releases: '12.5(1)SU3' },
    description: 'Search bugs by exact product name and fixed releases'
  }
};

function showUsage() {
  console.log(`
🧪 MCP Tool Test Runner

Usage: node test-tool.js <tool_name> [real|mock]

Available Tools:
${availableTools.map(tool => `  • ${tool}`).join('\n')}

Test Modes:
  • mock (default) - Use test credentials and mock responses
  • real           - Use real Cisco API credentials (requires CISCO_CLIENT_ID and CISCO_CLIENT_SECRET)

Examples:
  node test-tool.js search_bugs_by_keyword
  node test-tool.js get_bug_details real
  npm run test:tool search_bugs_by_product_id mock

Environment Variables (for real mode):
  CISCO_CLIENT_ID     - Your Cisco API Client ID
  CISCO_CLIENT_SECRET - Your Cisco API Client Secret
`);
}

async function runToolTest(toolName, mode = 'mock') {
  const testCase = testCases[toolName];
  if (!testCase) {
    console.error(`❌ Unknown tool: ${toolName}`);
    console.error(`Available tools: ${availableTools.join(', ')}`);
    process.exit(1);
  }

  // Check credentials for real mode
  if (mode === 'real') {
    if (!process.env.CISCO_CLIENT_ID || !process.env.CISCO_CLIENT_SECRET) {
      console.error(`❌ Real mode requires CISCO_CLIENT_ID and CISCO_CLIENT_SECRET environment variables`);
      console.error(`Example: CISCO_CLIENT_ID=your_id CISCO_CLIENT_SECRET=your_secret node test-tool.js ${toolName} real`);
      process.exit(1);
    }
  } else {
    // Set mock credentials and setup mock fetch
    process.env.CISCO_CLIENT_ID = 'test_client_id';
    process.env.CISCO_CLIENT_SECRET = 'test_client_secret';
    setupMockMode();
  }

  console.log(`🔧 Testing Tool: ${toolName}`);
  console.log(`📝 Description: ${testCase.description}`);
  console.log(`🎯 Mode: ${mode === 'real' ? '🌐 Real API' : '🧪 Mock Mode'}`);
  console.log(`📋 Arguments:`, JSON.stringify(testCase.args, null, 2));
  console.log(`\n⏳ Executing tool...`);

  const startTime = Date.now();

  try {
    const result = await executeTool(testCase.tool, testCase.args);
    const duration = Date.now() - startTime;
    
    console.log(`\n✅ Success! (${duration}ms)`);
    console.log(`📊 Result:`, JSON.stringify(result, null, 2));
    
    if (result.bugs) {
      console.log(`\n📈 Summary:`);
      console.log(`  • Found ${result.bugs.length} bugs`);
      if (result.bugs.length > 0) {
        console.log(`  • First bug: ${result.bugs[0].bug_id} - ${result.bugs[0].headline?.substring(0, 60)}...`);
      }
    }

  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`\n❌ Error! (${duration}ms)`);
    console.error(`💥 ${error.message}`);
    
    if (mode === 'real') {
      console.log(`\n🔍 Common real API issues:`);
      console.log(`  • 403 Forbidden: Rate limiting or access restrictions`);
      console.log(`  • 404 Not Found: Endpoint or data doesn't exist`);
      console.log(`  • 408 Not Entitled: Specific bug access requires permissions`);
      console.log(`  • Rate limiting: "Developer Over Qps" - too many requests`);
    }
    
    process.exit(1);
  }
}

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
  showUsage();
  process.exit(0);
}

const toolName = args[0];
const mode = args[1] || 'mock';

if (!['mock', 'real'].includes(mode)) {
  console.error(`❌ Invalid mode: ${mode}. Use 'mock' or 'real'`);
  process.exit(1);
}

// Run the test
runToolTest(toolName, mode).catch(console.error);