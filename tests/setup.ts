// Mock environment variables for tests  
process.env.CISCO_CLIENT_ID = 'test_client_id';
process.env.CISCO_CLIENT_SECRET = 'test_client_secret';
process.env.SUPPORT_API = 'bug';

// Create a proper Jest mock for fetch
const mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;

// Mock the global fetch for unit tests
global.fetch = mockFetch;

// Mock AbortController
global.AbortController = jest.fn().mockImplementation(() => ({
  signal: { aborted: false },
  abort: jest.fn(),
})) as any;

// Export the mock for use in tests
export { mockFetch };