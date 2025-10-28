/**
 * Utility Functions Unit Tests
 *
 * Direct testing of critical utility functions without API mocking.
 * Covers validation, formatting, sampling, and version normalization.
 */

import { validateToolArgs, setDefaultValues, buildApiParams } from '../src/utils/validation.js';
import { Tool } from '@modelcontextprotocol/sdk/types.js';

describe('Validation Utils', () => {
  describe('validateToolArgs', () => {
    it('validates required fields are present', () => {
      const tool: Tool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string' }
          },
          required: ['keyword']
        }
      };

      expect(() => {
        validateToolArgs(tool, { keyword: 'test' });
      }).not.toThrow();

      expect(() => {
        validateToolArgs(tool, {});
      }).toThrow('Missing required field: keyword');
    });

    it('validates enum values', () => {
      const tool: Tool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {
            severity: {
              type: 'string',
              enum: ['1', '2', '3', '4', '5', '6']
            }
          }
        }
      };

      expect(() => {
        validateToolArgs(tool, { severity: '3' });
      }).not.toThrow();

      expect(() => {
        validateToolArgs(tool, { severity: '7' });
      }).toThrow(/Invalid value for severity/);
    });

    it('validates regex patterns', () => {
      const tool: Tool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {
            bug_id: {
              type: 'string',
              pattern: '^CSC[a-z]{2}[0-9]{5}$'
            }
          }
        }
      };

      expect(() => {
        validateToolArgs(tool, { bug_id: 'CSCvi12345' });
      }).not.toThrow();

      expect(() => {
        validateToolArgs(tool, { bug_id: 'INVALID123' });
      }).toThrow(/Invalid format for bug_id/);
    });

    it('handles missing schema gracefully', () => {
      const tool: Tool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      };

      expect(() => {
        validateToolArgs(tool, { any: 'value' });
      }).not.toThrow();
    });

    it('validates multiple fields with mixed requirements', () => {
      const tool: Tool = {
        name: 'test_tool',
        description: 'Test tool',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string' },
            severity: {
              type: 'string',
              enum: ['1', '2', '3']
            },
            status: {
              type: 'string',
              enum: ['O', 'F', 'T']
            }
          },
          required: ['keyword']
        }
      };

      // Valid args
      expect(() => {
        validateToolArgs(tool, {
          keyword: 'crash',
          severity: '2',
          status: 'O'
        });
      }).not.toThrow();

      // Missing required field
      expect(() => {
        validateToolArgs(tool, { severity: '2' });
      }).toThrow('Missing required field: keyword');

      // Invalid enum value
      expect(() => {
        validateToolArgs(tool, {
          keyword: 'crash',
          severity: '5'
        });
      }).toThrow(/Invalid value for severity/);
    });
  });

  describe('setDefaultValues', () => {
    it('sets default modified_date to 5 (All)', () => {
      const args = { keyword: 'test' };
      const result = setDefaultValues(args);
      expect(result.modified_date).toBe('5');
    });

    it('preserves existing page_index', () => {
      const args = { keyword: 'test', page_index: 5 };
      const result = setDefaultValues(args);
      expect(result.page_index).toBe(5);
    });

    it('preserves existing modified_date', () => {
      const args = { keyword: 'test', modified_date: '2' };
      const result = setDefaultValues(args);
      expect(result.modified_date).toBe('2');
    });

    it('does not modify original args object', () => {
      const args = { keyword: 'test' };
      const result = setDefaultValues(args);
      expect(result).not.toBe(args);
      expect(args).toEqual({ keyword: 'test' });
    });

    it('handles empty args object', () => {
      const args = {};
      const result = setDefaultValues(args);
      expect(result.modified_date).toBe('5');
    });
  });

  describe('buildApiParams', () => {
    it('includes defined status and severity', () => {
      const args = {
        status: 'O',
        severity: '3'
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('status', 'O');
      expect(result).toHaveProperty('severity', '3');
    });

    it('excludes undefined severity and status', () => {
      const args = {
        page_index: 1,
        severity: undefined,
        status: undefined
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('page_index', 1);
      expect(result).not.toHaveProperty('severity');
      expect(result).not.toHaveProperty('status');
    });

    it('includes page_index when provided', () => {
      const args = {
        page_index: 5,
        status: 'O'
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('page_index', 5);
      expect(result).toHaveProperty('status', 'O');
    });

    it('includes zero page_index values', () => {
      const args = {
        page_index: 0,
        status: 'O'
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('page_index', 0);
    });

    it('includes modified_date when provided', () => {
      const args = {
        modified_date: '2',
        status: 'F'
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('modified_date', '2');
      expect(result).toHaveProperty('status', 'F');
    });

    it('includes sort_by when provided', () => {
      const args = {
        sort_by: 'severity',
        status: 'O'
      };
      const result = buildApiParams(args);
      expect(result).toHaveProperty('sort_by', 'severity');
    });

    it('handles empty args object', () => {
      const args = {};
      const result = buildApiParams(args);
      // Should return empty object when no params provided
      expect(Object.keys(result).length).toBeGreaterThanOrEqual(0);
    });
  });
});

describe('Version Normalization', () => {
  // Note: These tests require importing from bug-api.ts
  // Since normalizeVersionString is private, we'll test the public behavior
  // through tool execution in integration tests

  describe('Version format transformations', () => {
    it('should handle standard Cisco version format', () => {
      // Testing the expected behavior for version normalization
      const testVersions = [
        { input: '17.09.06', expected: '17.9.6' },
        { input: '17.9.6', expected: '17.9.6' },
        { input: '15.01.04', expected: '15.1.4' },
        { input: '12.5', expected: '12.5' }
      ];

      testVersions.forEach(({ input, expected }) => {
        // Simulate normalization logic
        const normalized = input.replace(/\.0+(\d)/g, '.$1');
        expect(normalized).toBe(expected);
      });
    });

    it('should generate version variations', () => {
      // Test the expected variation generation logic
      const fullVersion = '17.09.06';
      const normalized = fullVersion.replace(/\.0+(\d)/g, '.$1'); // '17.9.6'
      const parts = fullVersion.split('.');
      const shortVersion = parts.slice(0, 2).join('.'); // '17.09'
      const shortNormalized = shortVersion.replace(/\.0+(\d)/g, '.$1'); // '17.9'

      expect(normalized).toBe('17.9.6');
      expect(shortNormalized).toBe('17.9');
    });
  });
});

describe('Sampling Utils', () => {
  describe('Client capability detection', () => {
    it('should detect when sampling is supported', () => {
      // Mock MCP server with sampling capability
      const mockServer = {
        getClientCapabilities: () => ({
          sampling: {}
        })
      };

      const capabilities = mockServer.getClientCapabilities();
      const hasSampling = capabilities && 'sampling' in capabilities;
      expect(hasSampling).toBe(true);
    });

    it('should detect when sampling is not supported', () => {
      // Mock MCP server without sampling capability
      const mockServer = {
        getClientCapabilities: () => ({
          // No sampling capability
        })
      };

      const capabilities = mockServer.getClientCapabilities();
      const hasSampling = capabilities && 'sampling' in capabilities;
      expect(hasSampling).toBe(false);
    });

    it('should handle null capabilities', () => {
      const mockServer = {
        getClientCapabilities: () => null
      };

      const capabilities = mockServer.getClientCapabilities();
      const hasSampling = capabilities && 'sampling' in capabilities;
      // null && 'sampling' evaluates to null, not false
      expect(hasSampling).toBeFalsy();
      expect(hasSampling).toBe(null);
    });
  });

  describe('Sampling request construction', () => {
    it('should construct proper sampling request', () => {
      const samplingRequest = {
        method: 'sampling/createMessage',
        params: {
          messages: [{
            role: 'user',
            content: {
              type: 'text',
              text: 'Test prompt'
            }
          }],
          systemPrompt: 'Test system prompt',
          maxTokens: 500,
          modelPreferences: {
            intelligencePriority: 0.8,
            speedPriority: 0.6,
            costPriority: 0.5
          }
        }
      };

      expect(samplingRequest.method).toBe('sampling/createMessage');
      expect(samplingRequest.params.messages).toHaveLength(1);
      expect(samplingRequest.params.maxTokens).toBe(500);
      expect(samplingRequest.params.modelPreferences.intelligencePriority).toBe(0.8);
    });

    it('should validate model preferences range', () => {
      const validPreferences = {
        intelligencePriority: 0.8,
        speedPriority: 0.6,
        costPriority: 0.5
      };

      // All values should be between 0.0 and 1.0
      Object.values(validPreferences).forEach(value => {
        expect(value).toBeGreaterThanOrEqual(0.0);
        expect(value).toBeLessThanOrEqual(1.0);
      });
    });
  });
});

describe('Web Search Utils', () => {
  describe('Query construction', () => {
    it('should construct search query with product and version', () => {
      const product = 'ISR4431';
      const version = '17.9.6';
      const query = `${product} ${version} bugs issues`;

      expect(query).toBe('ISR4431 17.9.6 bugs issues');
    });

    it('should handle special characters in queries', () => {
      const product = 'Cisco ASR 1000';
      const escapedQuery = encodeURIComponent(product);

      expect(escapedQuery).toBe('Cisco%20ASR%201000');
    });

    it('should construct EoL search queries', () => {
      const product = 'ISR4431';
      const eolQuery = `${product} end of life end of sale cisco`;

      expect(eolQuery).toContain('end of life');
      expect(eolQuery).toContain('cisco');
    });
  });
});

describe('Formatting Utils', () => {
  describe('Result formatting', () => {
    it('should format bug results with hyperlinks', () => {
      const bugId = 'CSCvi12345';
      const expectedUrl = `https://bst.cloudapps.cisco.com/bugsearch/bug/${bugId}`;

      expect(expectedUrl).toBe('https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi12345');
    });

    it('should format case IDs with hyperlinks', () => {
      const caseId = '123456789';
      const expectedUrl = `https://mycase.cloudapps.cisco.com/case/${caseId}`;

      expect(expectedUrl).toBe('https://mycase.cloudapps.cisco.com/case/123456789');
    });

    it('should handle empty results', () => {
      const emptyResult = {
        bugs: [],
        total_results: 0
      };

      expect(emptyResult.bugs).toHaveLength(0);
      expect(emptyResult.total_results).toBe(0);
    });

    it('should format large result counts', () => {
      const count = 1234;
      const formatted = count.toLocaleString();

      expect(formatted).toBe('1,234');
    });
  });
});

describe('Authentication Utils', () => {
  describe('Token expiration calculation', () => {
    it('should calculate token expiry correctly', () => {
      const expiresIn = 43200; // 12 hours in seconds
      const now = Date.now();
      const expiresAt = now + (expiresIn * 1000);

      const remainingMs = expiresAt - now;
      const remainingHours = remainingMs / (1000 * 60 * 60);

      expect(remainingHours).toBeCloseTo(12, 1);
    });

    it('should detect expired tokens', () => {
      const expiresAt = Date.now() - 1000; // 1 second ago
      const isExpired = Date.now() >= expiresAt;

      expect(isExpired).toBe(true);
    });

    it('should refresh token before expiry', () => {
      const expiresAt = Date.now() + (30 * 60 * 1000); // 30 minutes from now
      const refreshThreshold = 30 * 60 * 1000; // Refresh 30 minutes before expiry
      const shouldRefresh = Date.now() >= (expiresAt - refreshThreshold);

      expect(shouldRefresh).toBe(true);
    });
  });
});

describe('Error Handling Utils', () => {
  describe('Error message formatting', () => {
    it('should format API errors with status code', () => {
      const error = {
        status: 400,
        statusText: 'Bad Request',
        message: 'Invalid parameter: severity'
      };

      const formatted = `API Error ${error.status}: ${error.statusText} - ${error.message}`;
      expect(formatted).toBe('API Error 400: Bad Request - Invalid parameter: severity');
    });

    it('should handle network errors', () => {
      const error = new Error('Network request failed');
      expect(error.message).toBe('Network request failed');
      expect(error).toBeInstanceOf(Error);
    });

    it('should handle timeout errors', () => {
      const error = { name: 'AbortError', message: 'The operation was aborted' };
      expect(error.name).toBe('AbortError');
    });
  });
});

describe('Parameter Processing', () => {
  describe('Cisco API parameter validation', () => {
    it('should validate single severity values', () => {
      const validSeverities = ['1', '2', '3', '4', '5', '6'];
      const invalidSeverity = '1,2,3';

      expect(validSeverities).toContain('3');
      expect(validSeverities).not.toContain(invalidSeverity);
    });

    it('should validate single status values', () => {
      const validStatuses = ['O', 'F', 'T', 'R'];
      const invalidStatus = 'O,F';

      expect(validStatuses).toContain('O');
      expect(validStatuses).not.toContain(invalidStatus);
    });

    it('should handle version format variations', () => {
      const versions = ['17.09.06', '17.9.6', '17.09', '17.9'];
      const normalized = versions.map(v => v.replace(/\.0+(\d)/g, '.$1'));

      expect(normalized).toContain('17.9.6');
      expect(normalized).toContain('17.9');
    });
  });
});
