import { executeTool } from '../src/mcp-server';
import { 
  mockOAuthResponse, 
  mockErrorResponse,
  mockTimeoutError,
  mockAbortError 
} from './mockData';
import { mockFetch } from './setup';

// Skip this entire test suite if mockFetch is unavailable (integration test mode)
const isIntegrationMode = !mockFetch;

(isIntegrationMode ? describe.skip : describe)('Error Handling and Validation', () => {
  beforeEach(() => {
    // Reset implementations too, so one test's mock can't leak into the next
    mockFetch!.mockReset();
  });

  describe('Parameter Validation', () => {
    test('should reject unknown tools', async () => {
      await expect(executeTool('unknown_tool', {})).rejects.toThrow('Unknown tool: unknown_tool');
    });

    test('should point 2.x tool names at their replacement', async () => {
      await expect(executeTool('search_bugs_by_keyword', { keyword: 'x' }))
        .rejects.toThrow('replaced by "bug_search" in v3.0.0');
    });

    test('should validate severity parameter enum values', async () => {
      // Mock successful OAuth
      mockFetch!.mockImplementation((url, init) => {
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
      const result = await executeTool('bug_search', { 
        keyword: 'test', 
        severity: '3' 
      });
      expect(result).toBeDefined();
    });

    test('should validate status parameter enum values', async () => {
      // Mock successful OAuth  
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      // This should pass with valid status
      const result = await executeTool('bug_search', { 
        keyword: 'test', 
        status: 'O' 
      });
      expect(result).toBeDefined();
    });

    test('should validate modified_date parameter enum values', async () => {
      // Mock successful OAuth
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      // This should pass with valid modified_date
      const result = await executeTool('bug_search', { 
        keyword: 'test', 
        modified_date: '3' 
      });
      expect(result).toBeDefined();
    });
  });

  describe('OAuth2 Error Handling', () => {
    test('should handle OAuth2 authentication failures', async () => {
      mockFetch!.mockImplementationOnce(() => 
        Promise.resolve({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: () => Promise.resolve('Invalid credentials')
        } as Response)
      );

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication failed: 401 Unauthorized - Invalid credentials');
    });

    test('should handle OAuth2 timeout errors', async () => {
      mockFetch!.mockImplementationOnce(() => Promise.reject(mockTimeoutError));

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication connection timed out');
    });

    test('should handle OAuth2 abort errors', async () => {
      mockFetch!.mockImplementationOnce(() => Promise.reject(mockAbortError));

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('OAuth2 authentication timed out after 30 seconds');
    });
  });

  describe('API Error Handling', () => {
    test('should handle 500 Internal Server Error from Cisco API', async () => {
      // Successful OAuth
      mockFetch!.mockImplementation((url, init) => {
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

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('Bug API call failed: 500 Internal Server Error');
    });

    test('should handle API timeout errors', async () => {
      // Successful OAuth
      mockFetch!.mockImplementation((url, init) => {
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

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('Bug API connection timed out while waiting for response headers');
    });

    test('should handle API abort errors', async () => {
      // Successful OAuth
      mockFetch!.mockImplementation((url, init) => {
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

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('Bug API call timed out after 60 seconds');
    });

    test('should handle 401 errors and retry with new token', async () => {
      let callCount = 0;
      mockFetch!.mockImplementation((url, init) => {
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

      const result: any = await executeTool('bug_search', { keyword: 'test' });
      expect(result.count).toBe(0);
      expect(mockFetch).toHaveBeenCalledTimes(4); // 2 OAuth + 1 failed API + 1 successful API
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty API responses', async () => {
      // Successful OAuth
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
          json: () => Promise.resolve({ bugs: [], total_results: 0 })
        } as Response);
      });

      const result: any = await executeTool('bug_search', { keyword: 'nonexistent' });
      expect(result.count).toBe(0);
      expect(result.hint).toMatch(/No bugs matched/);
    });

    test('should handle malformed JSON responses', async () => {
      // Successful OAuth
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
          json: () => Promise.reject(new Error('Unexpected end of JSON input'))
        } as Response);
      });

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('Unexpected end of JSON input');
    });

    test('should handle network connectivity issues', async () => {
      mockFetch!.mockImplementationOnce(() => 
        Promise.reject(new Error('fetch failed'))
      );

      await expect(executeTool('bug_search', { keyword: 'test' }))
        .rejects.toThrow('fetch failed');
    });
  });
});