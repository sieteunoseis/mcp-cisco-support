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
    const tools = getAvailableTools();
    const bugTools = tools.filter(tool => tool.name.includes('bug'));
    expect(bugTools.length).toBe(8); // 8 bug API tools
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