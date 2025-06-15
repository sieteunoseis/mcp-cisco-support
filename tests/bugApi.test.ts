import { executeTool, getAvailableTools } from '../src/mcp-server';
import { 
  mockOAuthResponse, 
  mockBugResponse, 
  mockSingleBugResponse,
  mockEmptyResponse,
  mockErrorResponse,
  mockTimeoutError,
  mockAbortError,
  testCases 
} from './mockData';

// Mock fetch globally
const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe('Cisco Bug API Tools', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default successful OAuth response
    mockFetch.mockImplementation((url, init) => {
      if (typeof url === 'string' && url.includes('oauth2')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockOAuthResponse),
          text: () => Promise.resolve(JSON.stringify(mockOAuthResponse))
        } as Response);
      }
      
      // Default API response
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockBugResponse),
        text: () => Promise.resolve(JSON.stringify(mockBugResponse))
      } as Response);
    });
  });

  describe('Tool Discovery', () => {
    test('should list all available Bug API tools', () => {
      const tools = getAvailableTools();
      const bugTools = tools.filter(tool => tool.name.startsWith('get_bug_') || tool.name.startsWith('search_bugs_'));
      
      expect(bugTools).toHaveLength(8);
      expect(bugTools.map(t => t.name)).toEqual([
        'get_bug_details',
        'search_bugs_by_keyword',
        'search_bugs_by_product_id',
        'search_bugs_by_product_and_release',
        'search_bugs_by_product_series_affected',
        'search_bugs_by_product_series_fixed',
        'search_bugs_by_product_name_affected',
        'search_bugs_by_product_name_fixed'
      ]);
    });

    test('should have proper input schemas for all tools', () => {
      const tools = getAvailableTools();
      const bugTools = tools.filter(tool => tool.name.startsWith('get_bug_') || tool.name.startsWith('search_bugs_'));
      
      bugTools.forEach(tool => {
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
        expect(tool.inputSchema.required).toBeDefined();
      });
    });
  });

  describe('get_bug_details', () => {
    test('should fetch details for specific bug IDs', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/bug_ids/CSCvi12345%2CCSCvi67890');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockSingleBugResponse)
        } as Response);
      });

      const result = await executeTool('get_bug_details', testCases.get_bug_details.valid);
      
      expect(result.bugs).toHaveLength(1);
      expect(result.bugs![0].bug_id).toBe('CSCvi12345');
    });

    test('should handle missing required bug_ids parameter', async () => {
      await expect(executeTool('get_bug_details', {})).rejects.toThrow('Missing required field: bug_ids');
    });

    test('should handle empty bug_ids parameter', async () => {
      await expect(executeTool('get_bug_details', { bug_ids: '' })).rejects.toThrow('Missing required field: bug_ids');
    });
  });

  describe('search_bugs_by_keyword', () => {
    test('should search bugs by keyword with all parameters', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/keyword/CallManager%2012.5');
        expect(url).toContain('severity=3');
        expect(url).toContain('status=O');
        expect(url).toContain('modified_date=2');
        expect(url).toContain('page_index=1');
        
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_keyword', testCases.search_bugs_by_keyword.valid);
      
      expect(result.bugs).toHaveLength(2);
      expect(result.total_results).toBe(2);
    });

    test('should handle missing required keyword parameter', async () => {
      await expect(executeTool('search_bugs_by_keyword', {})).rejects.toThrow('Missing required field: keyword');
    });

    test('should search with keyword only (no optional parameters)', async () => {
      const result = await executeTool('search_bugs_by_keyword', { keyword: 'CallManager' });
      expect(result.bugs).toBeDefined();
    });
  });

  describe('search_bugs_by_product_id', () => {
    test('should search bugs by product ID', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/products/product_id/WS-C3560-48PS-S');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_id', testCases.search_bugs_by_product_id.valid);
      expect(result.bugs).toHaveLength(2);
    });

    test('should handle missing required base_pid parameter', async () => {
      await expect(executeTool('search_bugs_by_product_id', {})).rejects.toThrow('Missing required field: base_pid');
    });
  });

  describe('search_bugs_by_product_and_release', () => {
    test('should search bugs by product ID and software releases', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/products/product_id/WS-C3560-48PS-S/software_releases/12.2%2825%29SE%2C15.0%282%29SE');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_and_release', testCases.search_bugs_by_product_and_release.valid);
      expect(result.bugs).toHaveLength(2);
    });

    test('should handle missing required parameters', async () => {
      await expect(executeTool('search_bugs_by_product_and_release', { base_pid: 'test' })).rejects.toThrow('Missing required field: software_releases');
      await expect(executeTool('search_bugs_by_product_and_release', { software_releases: 'test' })).rejects.toThrow('Missing required field: base_pid');
    });
  });

  describe('search_bugs_by_product_series_affected', () => {
    test('should search bugs by product series and affected releases', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/product_series/Cisco%205500%20Series%20Wireless%20Controllers/affected_releases/7.4%28100.0%29%2C7.5%28100.0%29');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_series_affected', testCases.search_bugs_by_product_series_affected.valid);
      expect(result.bugs).toHaveLength(2);
    });

    test('should handle missing required parameters', async () => {
      await expect(executeTool('search_bugs_by_product_series_affected', { product_series: 'test' })).rejects.toThrow('Missing required field: affected_releases');
      await expect(executeTool('search_bugs_by_product_series_affected', { affected_releases: 'test' })).rejects.toThrow('Missing required field: product_series');
    });
  });

  describe('search_bugs_by_product_series_fixed', () => {
    test('should search bugs by product series and fixed releases', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/product_series/Cisco%205500%20Series%20Wireless%20Controllers/fixed_releases/7.6%28100.6%29%2C7.7%28100.0%29');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_series_fixed', testCases.search_bugs_by_product_series_fixed.valid);
      expect(result.bugs).toHaveLength(2);
    });
  });

  describe('search_bugs_by_product_name_affected', () => {
    test('should search bugs by product name and affected releases', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/products/product_name/Cisco%20Unified%20Communications%20Manager%20%28CallManager%29/affected_releases/12.5%281%29SU1%2C12.5%281%29SU2');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_name_affected', testCases.search_bugs_by_product_name_affected.valid);
      expect(result.bugs).toHaveLength(2);
    });
  });

  describe('search_bugs_by_product_name_fixed', () => {
    test('should search bugs by product name and fixed releases', async () => {
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        expect(url).toContain('/bugs/products/product_name/Cisco%20Unified%20Communications%20Manager%20%28CallManager%29/fixed_releases/12.5%281%29SU3%2C12.5%281%29SU4');
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockBugResponse)
        } as Response);
      });

      const result = await executeTool('search_bugs_by_product_name_fixed', testCases.search_bugs_by_product_name_fixed.valid);
      expect(result.bugs).toHaveLength(2);
    });
  });
});