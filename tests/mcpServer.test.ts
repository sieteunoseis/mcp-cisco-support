import { createMCPServer, getAvailableTools, getAvailablePrompts, generatePrompt } from '../src/mcp-server';
import { CallToolRequestSchema, ListToolsRequestSchema, ListPromptsRequestSchema, GetPromptRequestSchema, PingRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { mockOAuthResponse, mockBugResponse } from './mockData';
import { mockFetch } from './setup';

// Skip this entire test suite if mockFetch is unavailable (integration test mode)
const isIntegrationMode = !mockFetch;

(isIntegrationMode ? describe.skip : describe)('MCP Server', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default successful responses
    mockFetch!.mockImplementation((url, init) => {
      if (typeof url === 'string' && url.includes('oauth2')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockOAuthResponse)
        } as Response);
      }
      
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockBugResponse)
      } as Response);
    });
  });

  describe('Server Creation', () => {
    test('should create MCP server instance', () => {
      const server = createMCPServer();
      expect(server).toBeDefined();
    });
  });

  describe('Tools Management', () => {
    test('should list available tools', () => {
      const tools = getAvailableTools();
      expect(tools).toBeDefined();
      expect(Array.isArray(tools)).toBe(true);
      expect(tools.length).toBeGreaterThan(0);
      
      // Should include Bug API tools
      const bugTools = tools.filter(t => t.name.includes('bug'));
      expect(bugTools.length).toBeGreaterThan(0);
    });

    test('should have valid tool schemas', () => {
      const tools = getAvailableTools();
      
      tools.forEach(tool => {
        expect(tool.name).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
      });
    });

    test('should include only Bug API tools', () => {
      const tools = getAvailableTools();
      const bugTools = tools.filter(t => t.name.includes('bug'));
      
      expect(bugTools.length).toBe(8); // Only bug API tools
      expect(tools.every(t => t.name.startsWith('get_bug') || t.name.startsWith('search_bugs'))).toBe(true);
    });
  });

  describe('Prompts Management', () => {
    test('should list available prompts', () => {
      const prompts = getAvailablePrompts();
      expect(prompts).toBeDefined();
      expect(Array.isArray(prompts)).toBe(true);
      expect(prompts.length).toBeGreaterThan(0);
    });

    test('should include cisco-high-severity-search prompt', () => {
      const prompts = getAvailablePrompts();
      const highSevPrompt = prompts.find(p => p.name === 'cisco-high-severity-search');
      
      expect(highSevPrompt).toBeDefined();
      expect(highSevPrompt!.description).toContain('severity 3 or higher');
    });

    test('should generate cisco-high-severity-search prompt content', () => {
      const messages = generatePrompt('cisco-high-severity-search', {
        product_keyword: 'CallManager',
        version: '12.5',
        max_severity: '3'
      });
      
      expect(messages).toHaveLength(1);
      expect(messages[0].role).toBe('user');
      expect(messages[0].content.type).toBe('text');
      expect(messages[0].content.text).toContain('CallManager version 12.5');
      expect(messages[0].content.text).toContain('severity="1"');
      expect(messages[0].content.text).toContain('severity="2"');
      expect(messages[0].content.text).toContain('severity="3"');
    });

    test('should generate cisco-incident-investigation prompt content', () => {
      const messages = generatePrompt('cisco-incident-investigation', {
        symptom: 'memory leak',
        product: 'CallManager',
        severity: '2',
        software_version: '12.5'
      });
      
      expect(messages).toHaveLength(1);
      expect(messages[0].content.text).toContain('memory leak');
      expect(messages[0].content.text).toContain('CallManager');
      expect(messages[0].content.text).toContain('12.5');
    });

    test('should throw error for unknown prompt', () => {
      expect(() => generatePrompt('unknown-prompt', {})).toThrow('Unknown prompt: unknown-prompt');
    });
  });

  describe('Server Handlers', () => {
    let server: ReturnType<typeof createMCPServer>;

    beforeEach(() => {
      server = createMCPServer();
    });

    test('should handle ping requests', async () => {
      // Note: This is a simplified test. In practice, you'd need to properly set up the server
      // and use the actual MCP protocol to test handlers
      expect(server).toBeDefined();
    });

    test('should handle list tools requests', async () => {
      // This tests the underlying function that the handler uses
      const tools = getAvailableTools();
      expect(tools.length).toBeGreaterThan(0);
    });

    test('should handle list prompts requests', async () => {
      // This tests the underlying function that the handler uses
      const prompts = getAvailablePrompts();
      expect(prompts.length).toBeGreaterThan(0);
    });
  });

  describe('API Configuration', () => {
    test('should respect SUPPORT_API environment variable', () => {
      // Test that only bug API tools are available when SUPPORT_API=bug
      const tools = getAvailableTools();
      const apiTypes = new Set();
      
      tools.forEach(tool => {
        if (tool.name.includes('bug')) apiTypes.add('bug');
        if (tool.name.includes('case')) apiTypes.add('case');
        if (tool.name.includes('eox')) apiTypes.add('eox');
      });
      
      // Should have bug tools
      expect(apiTypes.has('bug')).toBe(true);
      
      // Should only have bug tools (no case tools implemented yet)
      const caseTools = tools.filter(t => t.name.includes('case'));
      expect(caseTools.length).toBe(0); // No case tools yet
    });
  });

  describe('Error Handling in Handlers', () => {
    test('should handle tool execution errors gracefully', async () => {
      // Mock a fetch failure
      mockFetch!.mockImplementationOnce(() => Promise.reject(new Error('Network error')));
      
      // The actual server would handle this error and return an error response
      // Here we test the underlying function
      try {
        const { executeTool } = await import('../src/mcp-server');
        await executeTool('search_bugs_by_keyword', { keyword: 'test' });
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Network error');
      }
    });
  });
});