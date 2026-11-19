import { getAvailableTools } from '../src/mcp-server';

describe('Simple Tests', () => {
  beforeAll(() => {
    // Disable logging during tests
    const { setLogging } = require('../src/mcp-server');
    setLogging(false);
  });

  test('should be able to import and call getAvailableTools', () => {
    const tools = getAvailableTools();
    expect(tools).toBeDefined();
    expect(Array.isArray(tools)).toBe(true);
    expect(tools.length).toBeGreaterThan(0);
  });

  test('should always expose all 12 tools', () => {
    const names = getAvailableTools().map(tool => tool.name).sort();
    expect(names).toEqual(['assess_upgrade', 'bug_get', 'bug_search', 'case_get', 'case_search', 'device_lookup', 'eox_get', 'product_get', 'psirt_get', 'psirt_search', 'rma_get', 'software_get']);
  });

  test('should have tool descriptions', () => {
    const tools = getAvailableTools();
    tools.forEach(tool => {
      expect(tool.name).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(tool.inputSchema).toBeDefined();
    });
  });
});