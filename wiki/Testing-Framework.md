# Testing Framework

The Cisco Support MCP Server includes a comprehensive Jest-based testing framework that validates all functionality without requiring live API calls during development.

## Test Coverage Overview

✅ **Simple Tests**: 3/3 passing - Basic functionality validation  
✅ **Bug API Tests**: 17/17 passing - All 8 Bug API tools fully tested  
✅ **MCP Server Tests**: 11/11 passing - Server functionality and configuration  
✅ **Integration Tests**: 7/7 passing - Real API validation with live credentials  
✅ **Error Handling Tests**: Timeout, authentication, and parameter validation

## Running Tests

### Basic Test Commands

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test suite
npm test -- --testNamePattern="Bug API"
npm test -- --testNamePattern="Simple" 
npm test -- --testNamePattern="MCP Server"
```

### Integration Tests with Real API

```bash
# Run integration tests with real Cisco API (requires credentials)
CISCO_CLIENT_ID=your_id CISCO_CLIENT_SECRET=your_secret npm test -- --testNamePattern="Integration"

# Run all tests including integration
CISCO_CLIENT_ID=your_id CISCO_CLIENT_SECRET=your_secret npm test
```

### Type Checking

```bash
# TypeScript type checking
npx tsc --noEmit
```

## Individual Tool Testing

The project includes multiple ways to test individual MCP tools for development and debugging:

### 1. Standalone Tool Test Runner

Test any tool with both mock and real API modes:

```bash
# Test with mock data (default)
npm run test:tool search_bugs_by_keyword
node test-tool.js search_bugs_by_keyword mock

# Test with real Cisco API
CISCO_CLIENT_ID=your_id CISCO_CLIENT_SECRET=your_secret node test-tool.js search_bugs_by_keyword real

# Test other tools
node test-tool.js get_bug_details
node test-tool.js search_bugs_by_product_id real
```

**Available Tools for Testing:**
- `get_bug_details`
- `search_bugs_by_keyword`
- `search_bugs_by_product_id`
- `search_bugs_by_product_and_release`
- `search_bugs_by_product_series_affected`
- `search_bugs_by_product_series_fixed`
- `search_bugs_by_product_name_affected`
- `search_bugs_by_product_name_fixed`

### 2. Jest-based Tool Testing

Run Jest tests for specific tools:

```bash
# Test a specific tool with Jest
npm run test:jest-tool search_bugs_by_keyword
node scripts/test-specific-tool.js get_bug_details

# This converts tool names to Jest test patterns
# search_bugs_by_keyword becomes "search.*bugs.*by.*keyword"
```

### 3. Tool Test Output Example

The standalone tool tester provides detailed output:

```bash
🔧 Testing Tool: search_bugs_by_keyword
📝 Description: Search bugs by keyword with filters
🎯 Mode: 🧪 Mock Mode
📋 Arguments: {
  "keyword": "CallManager",
  "severity": "3",
  "status": "O"
}

⏳ Executing tool...

✅ Success! (15ms)
📊 Result: {
  "bugs": [
    {
      "bug_id": "CSCvi12345",
      "headline": "Test bug for CallManager 12.5 memory leak",
      "status": "O",
      "severity": "3"
    }
  ],
  "total_results": 1
}

📈 Summary:
  • Found 1 bugs
  • First bug: CSCvi12345 - Test bug for CallManager 12.5 memory leak...
```

### 4. Tool Testing npm Scripts

```bash
# Available npm scripts for tool testing
npm run test:tool              # Build and run tool tester
npm run test:jest-tool         # Jest-based tool testing
npm run test:integration       # Real API integration tests
npm run test:coverage          # Test coverage report
```

## Test Structure

### Test Files

- **`tests/simple.test.ts`** - Basic functionality and tool discovery
- **`tests/bugApi.test.ts`** - Comprehensive Bug API tool testing with mocks
- **`tests/mcpServer.test.ts`** - MCP server functionality and prompt testing
- **`tests/integration.test.ts`** - Real API integration tests (skipped by default)
- **`tests/errorHandling.test.ts`** - Error scenarios and edge cases
- **`tests/mockData.ts`** - Mock Cisco API responses for unit tests
- **`tests/setup.ts`** - Jest configuration and global mocks

### Test Categories

#### Unit Tests (Mock Mode)
- Use comprehensive mock data that simulates real API responses
- Test all tool parameters and validation
- Fast execution without network calls
- Validate JSON Schema compliance

#### Integration Tests (Real API Mode)
- Validate OAuth2 authentication flow
- Test parameter validation with live API
- Verify error handling with actual API responses
- Check rate limiting and network error scenarios

#### Error Handling Tests
- Network timeouts and connection failures
- Invalid authentication credentials
- Parameter validation errors
- API rate limiting responses

## Mock Data Framework

### Example Mock Response

```typescript
// Mock bug response structure
{
  bugs: [
    {
      bug_id: 'CSCvi12345',
      headline: 'Test bug for CallManager 12.5 memory leak',
      status: 'O',
      severity: '3',
      product: 'Cisco Unified Communications Manager',
      affected_releases: ['12.5(1)SU1', '12.5(1)SU2'],
      fixed_releases: ['12.5(1)SU3']
    }
  ],
  total_results: 1
}
```

### Mock Configuration

The testing framework uses realistic mock data that:
- Matches actual Cisco API response formats
- Includes all required fields and data types
- Provides comprehensive test coverage
- Supports both successful and error scenarios

## Test Configuration

### Jest Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.ts'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
  ],
  coverageReporters: ['text', 'html', 'lcov'],
  forceExit: true
};
```

### Environment Setup

```typescript
// tests/setup.ts
beforeEach(() => {
  // Reset mocks and server state
  jest.clearAllMocks();
  resetServerState();
});

afterEach(() => {
  // Clean up any pending operations
  jest.restoreAllMocks();
});
```

## Testing Best Practices

### When Developing New Features

1. **Write Unit Tests First**: Create mocked tests for new tools
2. **Add Integration Tests**: Test with real API when possible
3. **Mock Properly**: Use realistic mock data that matches API responses
4. **Test Error Cases**: Include timeout, auth failures, and invalid parameters
5. **Validate Schemas**: Ensure all tools have proper JSON Schema validation

### Test Isolation

- **State Reset**: Each test gets a fresh server instance with clean state
- **Mock Management**: Proper fetch mocking with correct sequence handling
- **Module Cache**: Clearing prevents state leakage between tests
- **True Isolation**: Tests can run in any order without dependencies

## Key Test Features

### Comprehensive Coverage
- **Fetch Mocking**: Proper Jest mocking for all HTTP requests
- **Parameter Validation**: Tests for all required and optional parameters
- **Error Scenarios**: Comprehensive error handling validation
- **Schema Validation**: JSON Schema compliance for all tools
- **Real vs Mock**: Separate unit tests (mocked) and integration tests (real API)

### State Management
- **Server Reset**: `resetServerState()` function for clean test runs
- **Token Management**: OAuth2 token testing without real API calls
- **Session Isolation**: Each test runs in isolated environment
- **Memory Management**: No test state persistence between runs

## Continuous Integration

### GitHub Actions
Tests run automatically on:
- Pull requests
- Push to main branch
- Manual workflow dispatch

### Test Matrix
- Node.js versions: 18, 20
- Operating systems: Ubuntu, macOS, Windows
- Both unit tests (mocked) and integration tests (with secrets)

## Performance Testing

### Load Testing
```bash
# Test server performance under load
npm run test:load

# Memory usage monitoring
npm run test:memory
```

### Benchmark Testing
```bash
# Benchmark individual tools
npm run test:benchmark search_bugs_by_keyword

# Compare performance across versions
npm run test:benchmark:compare
```

## Debugging Tests

### Debug Mode
```bash
# Run tests with debug output
DEBUG=cisco-support:* npm test

# Run specific test with debugging
npm test -- --testNamePattern="search_bugs_by_keyword" --verbose
```

### Test Inspection
```bash
# Inspect test results
npm test -- --verbose --no-coverage

# Run single test file
npx jest tests/bugApi.test.ts

# Watch mode for development
npm run test:watch -- tests/bugApi.test.ts
```