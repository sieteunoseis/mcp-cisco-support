# Available Tools

This page documents all the MCP tools available in the Cisco Support MCP Server, organized by API.

## Bug API Tools (8 tools)

### 1. get_bug_details
Get details for up to 5 specific bug IDs.

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "tools/call",
  "params": {
    "name": "get_bug_details",
    "arguments": {
      "bug_ids": "CSCab12345,CSCcd67890"
    }
  }
}
```

### 2. search_bugs_by_keyword
Search bugs by keywords in descriptions and headlines.

```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_keyword",
    "arguments": {
      "keyword": "memory leak",
      "page_index": 1,
      "status": "open",
      "severity": "2"
    }
  }
}
```

### 3. search_bugs_by_product_id
Search bugs by base product ID.

```json
{
  "jsonrpc": "2.0",
  "id": "3",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_id",
    "arguments": {
      "base_pid": "C9200-24P"
    }
  }
}
```

### 4. search_bugs_by_product_and_release
Search bugs by product ID and software releases.

```json
{
  "jsonrpc": "2.0",
  "id": "4",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_and_release",
    "arguments": {
      "base_pid": "C9200-24P",
      "software_releases": "17.5.1,17.5.2"
    }
  }
}
```

### 5. search_bugs_by_product_series_affected
Search bugs by product series and affected releases.

```json
{
  "jsonrpc": "2.0",
  "id": "5",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_series_affected",
    "arguments": {
      "product_series": "Cisco Catalyst 9200 Series Switches",
      "affected_releases": "17.5.1"
    }
  }
}
```

### 6. search_bugs_by_product_series_fixed
Search bugs by product series and fixed releases.

```json
{
  "jsonrpc": "2.0",
  "id": "6",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_series_fixed",
    "arguments": {
      "product_series": "Cisco Catalyst 9200 Series Switches",
      "fixed_releases": "17.5.2"
    }
  }
}
```

### 7. search_bugs_by_product_name_affected
Search bugs by exact product name and affected releases.

```json
{
  "jsonrpc": "2.0",
  "id": "7",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_name_affected",
    "arguments": {
      "product_name": "Cisco Catalyst 3560-48PS Switch",
      "affected_releases": "17.5.1"
    }
  }
}
```

### 8. search_bugs_by_product_name_fixed
Search bugs by exact product name and fixed releases.

```json
{
  "jsonrpc": "2.0",
  "id": "8",
  "method": "tools/call",
  "params": {
    "name": "search_bugs_by_product_name_fixed",
    "arguments": {
      "product_name": "Cisco Catalyst 3560-48PS Switch",
      "fixed_releases": "17.5.2"
    }
  }
}
```

## Common Parameters

All search tools support these optional parameters:

- `page_index`: Page number (10 results per page, default: 1)
- `status`: Bug status filter (`open`, `resolved`, `closed`)
- `severity`: Bug severity filter (`1`, `2`, `3`, `4`, `5`, `6`)
- `modified_date`: Date filter (`2023-01-01` or range `2023-01-01..2023-12-31`)
- `sort_by`: Sort order (`modified_date`, `bug_id`, `severity`)

## Case API Tools (4 tools)

*Documentation for Case API tools will be added when available.*

## EoX API Tools (4 tools)

*Documentation for EoX API tools will be added when available.*

## PSIRT API Tools (8 tools)

*Documentation for PSIRT API tools will be added when available.*

## Product API Tools (3 tools)

*Documentation for Product API tools will be added when available.*

## Software API Tools (6 tools)

*Documentation for Software API tools will be added when available.*

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

**Available Tools:**
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

### 3. Tool Test Output

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