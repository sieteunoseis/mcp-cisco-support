// Mock data for Cisco API responses

export const mockOAuthResponse = {
  access_token: 'mock_access_token_12345',
  token_type: 'Bearer',
  expires_in: 43200, // 12 hours
};

export const mockBugResponse = {
  bugs: [
    {
      bug_id: 'CSCvi12345',
      headline: 'Test bug for CallManager 12.5 memory leak',
      status: 'O',
      severity: '3',
      last_modified_date: '2024-01-15T10:30:00.000Z',
      product: 'Cisco Unified Communications Manager',
      affected_releases: ['12.5(1)SU1', '12.5(1)SU2'],
      fixed_releases: ['12.5(1)SU3'],
      description: 'Memory leak observed in CallManager 12.5 when handling large call volumes'
    },
    {
      bug_id: 'CSCvi67890',
      headline: 'CallManager 12.5 crashes during backup operation',
      status: 'F',
      severity: '2',
      last_modified_date: '2024-01-10T14:22:00.000Z',
      product: 'Cisco Unified Communications Manager',
      affected_releases: ['12.5(1)SU1'],
      fixed_releases: ['12.5(1)SU2'],
      description: 'System crashes when performing scheduled backup operations'
    }
  ],
  total_results: 2
};

export const mockSingleBugResponse = {
  bugs: [
    {
      bug_id: 'CSCvi12345',
      headline: 'Test bug for CallManager 12.5 memory leak',
      status: 'O',
      severity: '3',
      last_modified_date: '2024-01-15T10:30:00.000Z',
      product: 'Cisco Unified Communications Manager',
      affected_releases: ['12.5(1)SU1', '12.5(1)SU2'],
      fixed_releases: [],
      description: 'Memory leak observed in CallManager 12.5 when handling large call volumes',
      known_affected_releases: ['12.5(1)SU1', '12.5(1)SU2'],
      known_fixed_releases: [],
      support_case_count: 15,
      duplicate_of: '',
      conditions: 'High call volume environments',
      workaround: 'Restart service daily until patch is available'
    }
  ],
  total_results: 1
};

export const mockEmptyResponse = {
  bugs: [],
  total_results: 0
};

export const mockErrorResponse = {
  ErrorResponse: {
    APIError: [{
      ErrorCode: 'API_ERROR_01',
      ErrorDescription: 'Internal error occurred',
      SuggestedAction: 'Please contact API support team at supportapis-help@cisco.com'
    }]
  }
};

export const mockTimeoutError = new Error('Headers Timeout Error');
(mockTimeoutError as any).cause = {
  code: 'UND_ERR_HEADERS_TIMEOUT'
};

export const mockAbortError = new Error('AbortError');
(mockAbortError as any).name = 'AbortError';

// Test cases for each tool
export const testCases = {
  get_bug_details: {
    valid: {
      bug_ids: 'CSCvi12345,CSCvi67890'
    },
    invalid: {
      bug_ids: '', // Empty bug IDs
      too_many: 'CSCvi1,CSCvi2,CSCvi3,CSCvi4,CSCvi5,CSCvi6' // More than 5
    }
  },
  search_bugs_by_keyword: {
    valid: {
      keyword: 'CallManager 12.5',
      severity: '3',
      status: 'O',
      modified_date: '2',
      page_index: 1
    },
    invalid: {
      keyword: '', // Empty keyword
      severity: '7', // Invalid severity
      status: 'X', // Invalid status
      modified_date: '6' // Invalid date range
    }
  },
  search_bugs_by_product_id: {
    valid: {
      base_pid: 'WS-C3560-48PS-S',
      severity: '2',
      status: 'F'
    },
    invalid: {
      base_pid: '', // Empty product ID
      severity: '1,2,3' // Comma-separated (invalid)
    }
  },
  search_bugs_by_product_and_release: {
    valid: {
      base_pid: 'WS-C3560-48PS-S',
      software_releases: '12.2(25)SE,15.0(2)SE'
    },
    invalid: {
      base_pid: '',
      software_releases: ''
    }
  },
  search_bugs_by_product_series_affected: {
    valid: {
      product_series: 'Cisco 5500 Series Wireless Controllers',
      affected_releases: '7.4(100.0),7.5(100.0)'
    },
    invalid: {
      product_series: '',
      affected_releases: ''
    }
  },
  search_bugs_by_product_series_fixed: {
    valid: {
      product_series: 'Cisco 5500 Series Wireless Controllers',
      fixed_releases: '7.6(100.6),7.7(100.0)'
    },
    invalid: {
      product_series: '',
      fixed_releases: ''
    }
  },
  search_bugs_by_product_name_affected: {
    valid: {
      product_name: 'Cisco Unified Communications Manager (CallManager)',
      affected_releases: '12.5(1)SU1,12.5(1)SU2'
    },
    invalid: {
      product_name: '',
      affected_releases: ''
    }
  },
  search_bugs_by_product_name_fixed: {
    valid: {
      product_name: 'Cisco Unified Communications Manager (CallManager)',
      fixed_releases: '12.5(1)SU3,12.5(1)SU4'
    },
    invalid: {
      product_name: '',
      fixed_releases: ''
    }
  }
};