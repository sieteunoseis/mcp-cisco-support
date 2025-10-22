import { executeTool, getAvailableTools } from '../src/mcp-server';
import { mockOAuthResponse } from './mockData';
import { mockFetch } from './setup';

// Mock Serial API responses
const mockSerialCoverageStatusResponse = {
  serial_numbers: [
    {
      sr_no: 'SAL09232Q0Z',
      is_valid: 'Y',
      base_pid: 'WS-C2960-24TT-L',
      orderable_pid: 'WS-C2960-24TT-L',
      item_description: 'Catalyst 2960 24 10/100 + 2 T/SFP LAN Base Image',
      warranty_type: 'SMARTnet',
      warranty_end_date: '2025-12-31',
      is_covered: 'Y',
      service_contract_number: 'SC12345'
    }
  ],
  pagination_response_record: {
    page_index: 1,
    total_records: 1
  }
};

const mockRmaDetailsResponse = {
  returns: [
    {
      rma_number: '84894022',
      status: 'Open',
      return_reason: 'Defective hardware',
      created_date: '2025-01-15T10:00:00Z',
      serial_number: 'SAL09232Q0Z',
      product_id: 'WS-C2960-24TT-L',
      tracking_number: '1Z999AA10123456784'
    }
  ]
};

// Skip this entire test suite if mockFetch is unavailable (integration test mode)
const isIntegrationMode = !mockFetch;

(isIntegrationMode ? describe.skip : describe)('Serial and RMA API Tools', () => {
  beforeEach(() => {
    jest.clearAllMocks();

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

      // Serial API endpoints
      if (typeof url === 'string' && url.includes('sn2info')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockSerialCoverageStatusResponse),
          text: () => Promise.resolve(JSON.stringify(mockSerialCoverageStatusResponse))
        } as Response);
      }

      // RMA API endpoints
      if (typeof url === 'string' && url.includes('return')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(mockRmaDetailsResponse),
          text: () => Promise.resolve(JSON.stringify(mockRmaDetailsResponse))
        } as Response);
      }

      // Default response
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve('{}')
      } as Response);
    });
  });

  describe('Serial API - Tool Discovery', () => {
    test('should list all Serial API tools when enabled', () => {
      process.env.SUPPORT_API = 'serial';

      const tools = getAvailableTools();
      const serialTools = tools.filter(tool =>
        tool.name.includes('coverage') || tool.name.includes('serial') || tool.name.includes('instance')
      );

      expect(serialTools.length).toBeGreaterThanOrEqual(3);

      const toolNames = serialTools.map(t => t.name);
      expect(toolNames).toEqual(expect.arrayContaining([
        'get_coverage_status_by_serial',
        'get_coverage_summary_by_serial',
        'get_coverage_summary_by_instance'
      ]));
    });

    test('should have proper input schemas for Serial tools', () => {
      process.env.SUPPORT_API = 'serial';
      const tools = getAvailableTools();
      const serialTools = tools.filter(tool => tool.name.startsWith('get_coverage'));

      serialTools.forEach(tool => {
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
      });
    });
  });

  describe('get_coverage_status_by_serial', () => {
    test('should fetch coverage status for serial numbers', async () => {
      process.env.SUPPORT_API = 'serial';

      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }

        if (typeof url === 'string' && url.includes('coverage/status/serial_numbers')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockSerialCoverageStatusResponse)
          } as Response);
        }

        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('get_coverage_status_by_serial', {
        serial_numbers: 'SAL09232Q0Z'
      });

      expect(result).toHaveProperty('serial_numbers');
      expect(Array.isArray(result.serial_numbers)).toBe(true);
      expect(result.serial_numbers![0]).toHaveProperty('sr_no', 'SAL09232Q0Z');
      expect(result.serial_numbers![0]).toHaveProperty('is_covered', 'Y');
    });

    test('should handle multiple serial numbers', async () => {
      process.env.SUPPORT_API = 'serial';

      const result = await executeTool('get_coverage_status_by_serial', {
        serial_numbers: 'SAL09232Q0Z,FOC0903N5J9'
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('SAL09232Q0Z,FOC0903N5J9'),
        expect.any(Object)
      );
    });
  });

  describe('RMA API - Tool Discovery', () => {
    test('should list all RMA API tools when enabled', () => {
      process.env.SUPPORT_API = 'rma';

      const tools = getAvailableTools();
      const rmaTools = tools.filter(tool => tool.name.includes('rma'));

      expect(rmaTools.length).toBeGreaterThanOrEqual(3);

      const toolNames = rmaTools.map(t => t.name);
      expect(toolNames).toEqual(expect.arrayContaining([
        'get_rma_details',
        'get_rmas_by_user',
        'search_rmas_by_serial'
      ]));
    });

    test('should have proper input schemas for RMA tools', () => {
      process.env.SUPPORT_API = 'rma';
      const tools = getAvailableTools();
      const rmaTools = tools.filter(tool => tool.name.includes('rma'));

      rmaTools.forEach(tool => {
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema.properties).toBeDefined();
      });
    });
  });

  describe('get_rma_details', () => {
    test('should fetch RMA details by RMA number', async () => {
      process.env.SUPPORT_API = 'rma';

      mockFetch!.mockImplementation((url, init) => {
        if (typeof url === 'string' && url.includes('oauth2')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockOAuthResponse)
          } as Response);
        }

        if (typeof url === 'string' && url.includes('returns/rma_numbers')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockRmaDetailsResponse)
          } as Response);
        }

        return Promise.reject(new Error('Unexpected URL'));
      });

      const result = await executeTool('get_rma_details', {
        rma_number: '84894022'
      });

      expect(result).toHaveProperty('returns');
      expect(Array.isArray(result.returns)).toBe(true);
      expect(result.returns![0]).toHaveProperty('rma_number', '84894022');
      expect(result.returns![0]).toHaveProperty('status', 'Open');
    });
  });

  describe('Integration - Serial and RMA APIs', () => {
    test('should work with both APIs enabled', () => {
      process.env.SUPPORT_API = 'serial,rma';

      const tools = getAvailableTools();
      const serialTools = tools.filter(tool => tool.name.includes('coverage'));
      const rmaTools = tools.filter(tool => tool.name.includes('rma'));

      expect(serialTools.length).toBeGreaterThanOrEqual(3);
      expect(rmaTools.length).toBeGreaterThanOrEqual(3);
    });
  });
});
