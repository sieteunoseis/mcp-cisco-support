// Set environment before imports to ensure proper API initialization
process.env.SUPPORT_API = 'case';

import { executeTool, getAvailableTools } from '../src/mcp-server';
import { createApiRegistry } from '../src/apis/index.js';
import { 
  mockOAuthResponse, 
  mockEmptyResponse,
  mockErrorResponse,
  mockTimeoutError,
  mockAbortError
} from './mockData';
import { mockFetch } from './setup';

// Mock Case API responses
const mockCaseSummaryResponse = {
  cases: [
    {
      case_id: '12345678',
      title: 'Network connectivity issue',
      status: 'O',
      severity: '2',
      created_date: '2024-01-15T10:30:00Z',
      last_modified_date: '2024-01-16T14:20:00Z',
      contract_id: 'CON123456',
      owner: 'john.doe@company.com'
    },
    {
      case_id: '87654321',
      title: 'Router configuration problem',
      status: 'C',
      severity: '3',
      created_date: '2024-01-10T09:15:00Z',
      last_modified_date: '2024-01-12T16:45:00Z',
      contract_id: 'CON789012',
      owner: 'jane.smith@company.com'
    }
  ],
  total_results: 2
};

const mockCaseDetailsResponse = {
  case_id: '12345678',
  title: 'Network connectivity issue with Cisco ASR router',
  description: 'Customer experiencing intermittent connectivity issues with ASR 9000 series router',
  status: 'O',
  severity: '2',
  priority: 'High',
  created_date: '2024-01-15T10:30:00Z',
  last_modified_date: '2024-01-16T14:20:00Z',
  contract_id: 'CON123456',
  owner: 'john.doe@company.com',
  product: 'Cisco ASR 9000 Series',
  software_version: '7.5.2',
  case_notes: [
    {
      date: '2024-01-15T10:30:00Z',
      author: 'TAC Engineer',
      note: 'Initial case opened. Investigating connectivity issues.'
    }
  ]
};

const mockCasesByContractResponse = {
  cases: [
    {
      case_id: '11111111',
      title: 'Contract-related case 1',
      status: 'O',
      severity: '3',
      contract_id: 'CON123456'
    },
    {
      case_id: '22222222',
      title: 'Contract-related case 2',
      status: 'W',
      severity: '2',
      contract_id: 'CON123456'
    }
  ],
  total_results: 2
};

const mockCasesByUserResponse = {
  cases: [
    {
      case_id: '33333333',
      title: 'User case 1',
      status: 'O',
      severity: '1',
      owner: 'user123@company.com'
    },
    {
      case_id: '44444444',
      title: 'User case 2',
      status: 'C',
      severity: '4',
      owner: 'user123@company.com'
    }
  ],
  total_results: 2
};

// Skip this entire test suite if mockFetch is unavailable (integration test mode)
const isIntegrationMode = !mockFetch;

(isIntegrationMode ? describe.skip : describe)('Cisco Case API Tools', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Set environment to enable Case API
    process.env.SUPPORT_API = 'case';
    
    // Default successful OAuth response
    mockFetch!.mockImplementation((url, init) => {
      if (typeof url === 'string' && url.includes('oauth2')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockOAuthResponse),
          text: () => Promise.resolve(JSON.stringify(mockOAuthResponse))
        } as Response);
      }
      
      // Default Case API response
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockCaseSummaryResponse),
        text: () => Promise.resolve(JSON.stringify(mockCaseSummaryResponse))
      } as Response);
    });
  });

  describe('Case API Tool Discovery', () => {
    test('should discover case API tools when case API is enabled', async () => {
      const tools = await getAvailableTools();
      const caseTools = tools.filter(tool => tool.name.includes('case'));
      
      expect(caseTools.length).toBeGreaterThan(0);
      expect(caseTools.map(t => t.name)).toEqual(
        expect.arrayContaining([
          'get_case_summary',
          'get_case_details', 
          'search_cases_by_contract',
          'search_cases_by_user'
        ])
      );
    });

    test('should not discover case tools when only bug API is enabled', async () => {
      process.env.SUPPORT_API = 'bug';
      const tools = await getAvailableTools();
      const caseTools = tools.filter(tool => tool.name.includes('case'));
      
      expect(caseTools.length).toBe(0);
    });
  });

  describe('get_case_summary', () => {
    test('should get case summary for multiple case IDs', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        if (typeof url === 'string' && url.includes('case_ids')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockCaseSummaryResponse)
          } as Response);
        }
        
        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('get_case_summary', {
        case_ids: '12345678,87654321'
      });

      expect(result).toHaveProperty('cases');
      expect(result.cases).toHaveLength(2);
      expect(result.cases[0]).toHaveProperty('case_id', '12345678');
      expect(result.cases[1]).toHaveProperty('case_id', '87654321');
    });

    test('should validate case_ids parameter format', async () => {
      // This should pass validation at the schema level, but let's test with clearly invalid format
      await expect(executeTool('get_case_summary', {
        case_ids: 'abc-def-ghi'
      })).rejects.toThrow();
    });

    test('should handle API errors gracefully', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
          text: () => Promise.resolve('Case not found')
        } as Response);
      });

      await expect(executeTool('get_case_summary', {
        case_ids: '99999999'
      })).rejects.toThrow('Case API call failed: 404 Not Found');
    });
  });

  describe('get_case_details', () => {
    test('should get detailed information for a single case', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        if (typeof url === 'string' && url.includes('details/case_id')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockCaseDetailsResponse)
          } as Response);
        }
        
        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('get_case_details', {
        case_id: '12345678'
      });

      expect(result).toHaveProperty('case_id', '12345678');
      expect(result).toHaveProperty('title');
      expect(result).toHaveProperty('description');
      expect(result).toHaveProperty('case_notes');
    });

    test('should validate single case_id format', async () => {
      await expect(executeTool('get_case_details', {
        case_id: '12345,67890'
      })).rejects.toThrow();
    });
  });

  describe('search_cases_by_contract', () => {
    test('should search cases by contract ID', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        if (typeof url === 'string' && url.includes('contracts/contract_ids')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockCasesByContractResponse)
          } as Response);
        }
        
        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('search_cases_by_contract', {
        contract_ids: 'CON123456'
      });

      expect(result).toHaveProperty('cases');
      expect(result.cases).toHaveLength(2);
      expect(result.cases[0]).toHaveProperty('contract_id', 'CON123456');
    });

    test('should support status filtering with single values only', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        if (typeof url === 'string' && url.includes('contracts/contract_ids') && url.includes('status=O')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({
              cases: [mockCasesByContractResponse.cases[0]],
              total_results: 1
            })
          } as Response);
        }
        
        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('search_cases_by_contract', {
        contract_ids: 'CON123456',
        status: 'O'
      });

      expect(result).toHaveProperty('cases');
      expect(result.cases).toHaveLength(1);
      expect(result.cases[0]).toHaveProperty('status', 'O');
    });

    test('should support status_flag filtering', async () => {
      const result = await executeTool('search_cases_by_contract', {
        contract_ids: 'CON123456',
        status_flag: 'Active'
      });

      expect(result).toHaveProperty('cases');
    });
  });

  describe('search_cases_by_user', () => {
    test('should search cases by user ID', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        if (typeof url === 'string' && url.includes('users/user_ids')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockCasesByUserResponse)
          } as Response);
        }
        
        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('search_cases_by_user', {
        user_ids: 'user123@company.com'
      });

      expect(result).toHaveProperty('cases');
      expect(result.cases).toHaveLength(2);
      expect(result.cases[0]).toHaveProperty('owner', 'user123@company.com');
    });

    test('should handle multiple user IDs', async () => {
      const result = await executeTool('search_cases_by_user', {
        user_ids: 'user1@company.com,user2@company.com'
      });

      expect(result).toHaveProperty('cases');
    });

    test('should support status filtering', async () => {
      const result = await executeTool('search_cases_by_user', {
        user_ids: 'user123@company.com',
        status: 'O',
        status_flag: 'Active'
      });

      expect(result).toHaveProperty('cases');
    });
  });

  describe('Case API Error Handling', () => {
    test('should handle authentication errors', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        return Promise.resolve({
          ok: false,
          status: 401,
          statusText: 'Unauthorized',
          text: () => Promise.resolve('Unauthorized')
        } as Response);
      });

      await expect(executeTool('get_case_details', {
        case_id: '12345678'
      })).rejects.toThrow('Case API call failed after token refresh: 401 Unauthorized');
    });

    test('should handle access denied errors', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        return Promise.resolve({
          ok: false,
          status: 403,
          statusText: 'Forbidden',
          text: () => Promise.resolve('Forbidden')
        } as Response);
      });

      await expect(executeTool('get_case_details', {
        case_id: '12345678'
      })).rejects.toThrow('Case API call failed: 403 Forbidden');
    });

    test('should handle timeout errors', async () => {
      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }
        
        return Promise.reject(mockAbortError);
      });

      await expect(executeTool('get_case_details', {
        case_id: '12345678'
      })).rejects.toThrow('Case API call timed out after 60 seconds');
    });
  });

  describe('Case API Parameter Validation', () => {
    test('should validate case_ids pattern (numbers and commas only)', async () => {
      await expect(executeTool('get_case_summary', {
        case_ids: 'CSC12345,67890'
      })).rejects.toThrow();
    });

    test('should validate contract_ids pattern', async () => {
      // Valid patterns should work
      await expect(executeTool('search_cases_by_contract', {
        contract_ids: 'CON123-456,CON789-012'
      })).resolves.toBeDefined();
    });

    test('should validate user_ids pattern (allows email format)', async () => {
      // Valid email patterns should work
      await expect(executeTool('search_cases_by_user', {
        user_ids: 'user@company.com,user.name@company.co.uk'
      })).resolves.toBeDefined();
    });

    test('should validate single status values only', async () => {
      // Single status should work
      await expect(executeTool('search_cases_by_contract', {
        contract_ids: 'CON123456',
        status: 'O'
      })).resolves.toBeDefined();
      
      // Multiple statuses should not be allowed by schema
      const tool = (await getAvailableTools()).find(t => t.name === 'search_cases_by_contract');
      expect(tool?.inputSchema?.properties).toBeDefined();
      if (tool?.inputSchema?.properties) {
        const statusProperty = tool.inputSchema.properties.status as any;
        expect(statusProperty?.enum).not.toContain('O,C');
      }
    });
  });
});