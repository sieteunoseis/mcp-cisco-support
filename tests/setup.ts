// Set default test environment variables if not provided
if (!process.env.CISCO_CLIENT_ID || process.env.CISCO_CLIENT_ID === 'test_client_id') {
  process.env.CISCO_CLIENT_ID = 'test_client_id';
}
if (!process.env.CISCO_CLIENT_SECRET || process.env.CISCO_CLIENT_SECRET === 'test_client_secret') {
  process.env.CISCO_CLIENT_SECRET = 'test_client_secret';
}
if (!process.env.SUPPORT_API) {
  process.env.SUPPORT_API = 'bug';
}

// Check if we have real credentials for integration tests
const hasRealCredentials = process.env.CISCO_CLIENT_ID && 
  process.env.CISCO_CLIENT_SECRET &&
  process.env.CISCO_CLIENT_ID !== 'test_client_id' &&
  process.env.CISCO_CLIENT_SECRET !== 'test_client_secret';

let mockFetch: jest.MockedFunction<typeof fetch> | undefined;

// If we have real credentials, use real fetch (for integration tests)
// Otherwise, mock fetch (for unit tests)
if (hasRealCredentials) {
  // For integration tests with real credentials, use real fetch
  console.log('🔗 Integration test mode: Using real fetch and AbortController');
  // Keep the real global.fetch and AbortController - don't mock them
  mockFetch = undefined;
} else {
  // For unit tests with fake credentials, mock fetch
  console.log('🧪 Unit test mode: Using mocked fetch and AbortController');
  mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;
  global.fetch = mockFetch;
  
  // Mock AbortController for unit tests
  global.AbortController = jest.fn().mockImplementation(() => ({
    signal: { aborted: false },
    abort: jest.fn(),
  })) as any;
}

// Export the mock for use in unit tests (undefined for integration tests)
export { mockFetch };