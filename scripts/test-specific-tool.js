#!/usr/bin/env node

/**
 * Jest test runner for specific tools
 * Usage: node scripts/test-specific-tool.js <tool_name>
 */

const { spawn } = require('child_process');

const toolName = process.argv[2];

if (!toolName) {
  console.log(`
🧪 Jest Tool Test Runner

Usage: node scripts/test-specific-tool.js <tool_name>

Available Tools:
  • get_bug_details
  • search_bugs_by_keyword
  • search_bugs_by_product_id
  • search_bugs_by_product_and_release
  • search_bugs_by_product_series_affected
  • search_bugs_by_product_series_fixed
  • search_bugs_by_product_name_affected
  • search_bugs_by_product_name_fixed

Examples:
  node scripts/test-specific-tool.js search_bugs_by_keyword
  npm run test:jest-tool search_bugs_by_keyword
`);
  process.exit(1);
}

// Convert tool name to test pattern
const testPattern = toolName.replace(/_/g, '.*');

console.log(`🧪 Running Jest tests for: ${toolName}`);
console.log(`📋 Test pattern: ${testPattern}`);

// Run Jest with the specific test pattern
const jest = spawn('npx', ['jest', '--testNamePattern', testPattern], {
  stdio: 'inherit',
  shell: true
});

jest.on('close', (code) => {
  process.exit(code);
});