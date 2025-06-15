import { executeTool } from '../src/mcp-server';
import { 
  mockOAuthResponse, 
  mockErrorResponse,
  mockTimeoutError,
  mockAbortError 
} from './mockData';

const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe('Error Handling and Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Parameter Validation', () => {
    test('should reject unknown tools', async () => {
      await expect(executeTool('unknown_tool', {})).rejects.toThrow('Unknown tool: unknown_tool');
    });

    test('should validate severity parameter enum values', async () => {
      // Mock successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        // Should not reach this point due to validation
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      // This should pass with valid severity
      const result = await executeTool('search_bugs_by_keyword', { 
        keyword: 'test', 
        severity: '3' 
      });
      expect(result).toBeDefined();
    });

    test('should validate status parameter enum values', async () => {
      // Mock successful OAuth  
      mockFetch.mockImplementationOnce((url, init) => {
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      // This should pass with valid status
      const result = await executeTool('search_bugs_by_keyword', { 
        keyword: 'test', 
        status: 'O' 
      });
      expect(result).toBeDefined();
    });

    test('should validate modified_date parameter enum values', async () => {
      // Mock successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      // This should pass with valid modified_date
      const result = await executeTool('search_bugs_by_keyword', { 
        keyword: 'test', 
        modified_date: '3' 
      });
      expect(result).toBeDefined();
    });
  });

  describe('OAuth2 Error Handling', () => {
    test('should handle OAuth2 authentication failures', async () => {
      mockFetch.mockImplementationOnce(() => 
        Promise.resolve({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: () => Promise.resolve('Invalid credentials')
        } as Response)
      );

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication failed: 401 Unauthorized - Invalid credentials');
    });

    test('should handle OAuth2 timeout errors', async () => {
      mockFetch.mockImplementationOnce(() => Promise.reject(mockTimeoutError));

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication connection timed out');
    });

    test('should handle OAuth2 abort errors', async () => {
      mockFetch.mockImplementationOnce(() => Promise.reject(mockAbortError));

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication timed out after 30 seconds');
    });
  });

  describe('API Error Handling', () => {
    test('should handle 500 Internal Server Error from Cisco API', async () => {
      // Successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        // API error
        return Promise.resolve({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          text: () => Promise.resolve(JSON.stringify(mockErrorResponse))
        } as Response);
      });

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('Cisco API call failed: 500 Internal Server Error');
    });

    test('should handle API timeout errors', async () => {
      // Successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        // Timeout error
        return Promise.reject(mockTimeoutError);
      });

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('Cisco API connection timed out while waiting for response headers');
    });

    test('should handle API abort errors', async () => {
      // Successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        // Abort error
        return Promise.reject(mockAbortError);
      });

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('Cisco API call timed out after 60 seconds');
    });

    test('should handle 401 errors and retry with new token', async () => {
      let callCount = 0;
      mockFetch.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        callCount++;
        if (callCount === 1) {
          // First call returns 401
          return Promise.resolve({
            ok: false,
            status: 401,
            statusText: 'Unauthorized',
            text: () => Promise.resolve('Token expired')
          } as Response);
        } else {
          // Second call (after token refresh) succeeds
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ bugs: [], total_results: 0 })
          } as Response);
        }
      });

      const result = await executeTool('search_bugs_by_keyword', { keyword: 'test' });
      expect(result.bugs).toEqual([]);
      expect(mockFetch).toHaveBeenCalledTimes(4); // 2 OAuth + 1 failed API + 1 successful API
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty API responses', async () => {
      // Successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      const result = await executeTool('search_bugs_by_keyword', { keyword: 'nonexistent' });
      expect(result.bugs).toEqual([]);
      expect(result.total_results).toBe(0);
    });

    test('should handle malformed JSON responses', async () => {
      // Successful OAuth
      mockFetch.mockImplementationOnce((url, init) => {
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
          json: () => Promise.reject(new Error('Unexpected end of JSON input'))
        } as Response);
      });

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('Unexpected end of JSON input');
    });

    test('should handle network connectivity issues', async () => {
      mockFetch.mockImplementationOnce(() => 
        Promise.reject(new Error('fetch failed'))
      );

      await expect(executeTool('search_bugs_by_keyword', { keyword: 'test' }))
        .rejects.toThrow('fetch failed');
    });
  });

  describe('Case API Placeholder', () => {
    test('should return helpful error for case API placeholder', async () => {
      const result = await executeTool('search_case_placeholder', {});
      
      expect(result).toEqual({
        error: 'Case API Not Implemented',
        message: 'The Cisco Case Management API is not yet implemented in this MCP server. Currently, only the Bug Search API is available.',
        alternatives: [
          'Use search_bugs_by_keyword to find bugs related to your case topic',
          'Use search_bugs_by_product_id if you have a specific product ID',
          'Use search_bugs_by_product_series_affected for product series searches'
        ],
        example: 'Try: "Search for bugs related to \'Unified Communications Manager\' with keyword search"',
        available_apis: ['bug'],
        planned_apis: ['case', 'eox', 'product', 'serial', 'rma', 'software', 'asd']
      });
    });
  });
});