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

  test('should have bug API tools', () => {
    const names = getAvailableTools().map(tool => tool.name).sort();
    // SUPPORT_API=bug exposes the bug tools plus the upgrade assessment
    expect(names).toEqual(['assess_upgrade', 'bug_get', 'bug_search']);
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