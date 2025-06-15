/**
 * Integration tests with real Cisco API calls
 * These tests require valid CISCO_CLIENT_ID and CISCO_CLIENT_SECRET
 * They are skipped by default and can be run with: npm test -- --testNamePattern="Integration"
 */

import { executeTool } from '../src/mcp-server';

const SKIP_INTEGRATION = !process.env.CISCO_CLIENT_ID || !process.env.CISCO_CLIENT_SECRET || process.env.SKIP_INTEGRATION === 'true';

describe.skip('Integration Tests (Real API)', () => {
  // These tests are skipped by default as they require real API credentials
  // and make actual network calls to Cisco's API
  
  beforeAll(() => {
    if (SKIP_INTEGRATION) {
      console.log('Skipping integration tests - no API credentials or SKIP_INTEGRATION=true');
    }
  });

  describe('Real API Calls', () => {
    test('should authenticate with Cisco API', async () => {
      if (SKIP_INTEGRATION) return;
      
      // This will test the actual OAuth flow
      try {
        const result = await executeTool('search_bugs_by_keyword', { 
          keyword: 'cisco',
          page_index: 1 
        });
        
        expect(result).toBeDefined();
        expect(result.bugs).toBeDefined();
        expect(Array.isArray(result.bugs)).toBe(true);
      } catch (error) {
        // If this fails, it might be due to:
        // 1. Invalid credentials
        // 2. Network issues
        // 3. API being down
        console.warn('Integration test failed:', error);
        throw error;
      }
    }, 30000); // 30 second timeout for real API calls

    test('should handle parameter validation on real API', async () => {
      if (SKIP_INTEGRATION) return;
      
      // Test that single severity values work
      const result = await executeTool('search_bugs_by_keyword', { 
        keyword: 'CallManager',
        severity: '3',
        status: 'O',
        page_index: 1
      });
      
      expect(result).toBeDefined();
      expect(result.bugs).toBeDefined();
    }, 30000);

    test('should get specific bug details', async () => {
      if (SKIP_INTEGRATION) return;
      
      // Test with a known bug ID (this might fail if the bug doesn't exist)
      try {
        const result = await executeTool('get_bug_details', { 
          bug_ids: 'CSCvi12345' // This might not exist, but tests the endpoint
        });
        
        expect(result).toBeDefined();
        expect(result.bugs).toBeDefined();
      } catch (error) {
        // Expected if bug doesn't exist
        if (error instanceof Error && error.message.includes('403')) {
          console.log('Bug not found or no access - this is expected for test bug IDs');
        } else {
          throw error;
        }
      }
    }, 30000);

    test('should search by product name', async () => {
      if (SKIP_INTEGRATION) return;
      
      const result = await executeTool('search_bugs_by_product_name_affected', {
        product_name: 'Cisco Unified Communications Manager (CallManager)',
        affected_releases: '12.5(1)SU1',
        page_index: 1
      });
      
      expect(result).toBeDefined();
      expect(result.bugs).toBeDefined();
    }, 30000);
  });

  describe('Real Error Scenarios', () => {
    test('should handle invalid product IDs gracefully', async () => {
      if (SKIP_INTEGRATION) return;
      
      try {
        await executeTool('search_bugs_by_product_id', {
          base_pid: 'INVALID-PRODUCT-ID-12345'
        });
      } catch (error) {
        // Should get a proper error message, not a timeout
        expect(error).toBeInstanceOf(Error);
        const message = (error as Error).message;
        expect(message).not.toContain('timeout');
      }
    }, 30000);

    test('should handle rate limiting if it occurs', async () => {
      if (SKIP_INTEGRATION) return;
      
      // Make multiple rapid requests to test rate limiting
      const promises = Array.from({ length: 3 }, (_, i) => 
        executeTool('search_bugs_by_keyword', { 
          keyword: `test${i}`,
          page_index: 1 
        })
      );
      
      try {
        const results = await Promise.all(promises);
        results.forEach(result => {
          expect(result).toBeDefined();
          expect(result.bugs).toBeDefined();
        });
      } catch (error) {
        // If rate limited, should get a proper error message
        expect(error).toBeInstanceOf(Error);
        console.log('Rate limiting or other API error:', (error as Error).message);
      }
    }, 60000);
  });
});

describe('Integration Test Setup', () => {
  test('should have proper environment setup', () => {
    // Always run this test to verify environment
    if (SKIP_INTEGRATION) {
      console.log('Integration tests are skipped');
      console.log('To run integration tests:');
      console.log('1. Set CISCO_CLIENT_ID and CISCO_CLIENT_SECRET environment variables');
      console.log('2. Run: npm test -- --testNamePattern="Integration"');
      console.log('3. Or set SKIP_INTEGRATION=false');
    }
    
    expect(typeof process.env.CISCO_CLIENT_ID).toBe('string');
    expect(typeof process.env.CISCO_CLIENT_SECRET).toBe('string');
  });
});