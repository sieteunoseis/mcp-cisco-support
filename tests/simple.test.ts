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
    const names = tools.map(tool => tool.name);
    // SUPPORT_API=bug exposes the 8 core bug search tools plus the enhanced analysis tools
    for (const name of ['get_bug_details', 'search_bugs_by_keyword', 'search_bugs_by_product_id', 'search_bugs_by_product_and_release',
      'search_bugs_by_product_series_affected', 'search_bugs_by_product_series_fixed',
      'search_bugs_by_product_name_affected', 'search_bugs_by_product_name_fixed']) {
      expect(names).toContain(name);
    }
    expect(tools.length).toBe(14);
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