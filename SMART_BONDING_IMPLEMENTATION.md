# Smart Bonding Customer API Implementation Plan

**Branch**: `feature/smart-bonding-api`
**Status**: Planning Phase
**Created**: 2025-10-23

## Executive Summary

This document outlines the implementation plan for integrating Cisco's Smart Bonding Customer API into the existing MCP Cisco Support Server. The Smart Bonding API differs from existing Support APIs in authentication method and requires careful architectural consideration.

## API Overview

### Smart Bonding Customer API
- **Purpose**: Support case management and ticket synchronization
- **Base URLs**:
  - Test/Staging: `https://stage.sbnprd.xylem.cisco.com/sb-partner-oauth-proxy-api/rest/v1`
  - Production: `https://sb.xylem.cisco.com/sb-partner-oauth-proxy-api/rest/v1`
- **Authentication**: OAuth2 Client Credentials (different endpoint from other APIs)
- **Token Endpoint**: `https://cloudsso.cisco.com/as/token.oauth2`
- **Token Validity**: 1 hour (vs 12 hours for other Support APIs)

### Available Endpoints
1. **GET `/pull/call`** - Retrieve ticket updates from Cisco (not yet pulled)
2. **POST `/push/call`** - Create or update support tickets

## Key Differences from Existing APIs

### 1. Authentication Endpoint
| API Type | OAuth2 Endpoint | Token Validity |
|----------|----------------|----------------|
| **Existing Support APIs** | `https://id.cisco.com/oauth2/default/v1/token` | 12 hours |
| **Smart Bonding API** | `https://cloudsso.cisco.com/as/token.oauth2` | 1 hour |

### 2. Authentication Method
Both use OAuth2 Client Credentials flow, but require separate credentials:
- **Existing APIs**: `CISCO_CLIENT_ID` + `CISCO_CLIENT_SECRET`
- **Smart Bonding API**: `SMART_BONDING_CLIENT_ID` + `SMART_BONDING_CLIENT_SECRET`

### 3. Credential Acquisition
- **Existing APIs**: Self-service through Cisco Developer Portal
- **Smart Bonding API**: Requires engagement with Cisco Account Manager and Smart Bonding team

## Architecture Design

### Option 1: Dual Authentication System (Recommended)

**Rationale**: Clean separation of concerns, independent token management, easier debugging

**Structure**:
```
src/utils/
├── auth.ts              # Existing Support API auth (unchanged)
└── smart-bonding-auth.ts  # New Smart Bonding auth system
```

**Benefits**:
- No impact on existing authentication
- Independent token lifecycle management
- Clear separation for different OAuth2 endpoints
- Easier to troubleshoot authentication issues

**Implementation**:
```typescript
// smart-bonding-auth.ts
let sbAccessToken: string | null = null;
let sbTokenExpiry: number | null = null;
const SB_TOKEN_REFRESH_MARGIN = 5 * 60 * 1000; // 5 minutes (1 hour token)

export async function authenticateWithSmartBonding(): Promise<string> {
  const { SMART_BONDING_CLIENT_ID, SMART_BONDING_CLIENT_SECRET } = process.env;

  const tokenUrl = 'https://cloudsso.cisco.com/as/token.oauth2';
  // ... OAuth2 flow implementation
}

export async function getValidSmartBondingToken(): Promise<string> {
  // Similar to existing getValidToken() but with shorter refresh margin
}
```

### Option 2: Unified Authentication Factory (Alternative)

**Rationale**: Single authentication interface, extensible for future API types

**Structure**:
```
src/utils/auth/
├── index.ts             # Auth factory and interfaces
├── support-auth.ts      # Support API implementation
└── smart-bonding-auth.ts # Smart Bonding implementation
```

**Trade-offs**:
- More complex initial implementation
- Higher risk of breaking existing functionality
- Better long-term extensibility

**Recommendation**: Use Option 1 initially, refactor to Option 2 if more auth types are added.

### API Module Structure

Following existing pattern in `src/apis/`:

```
src/apis/
├── index.ts                    # Updated to include smart-bonding
├── base-api.ts                 # Existing base class
├── smart-bonding-base-api.ts   # New base for Smart Bonding tools
├── smart-bonding-api.ts        # Smart Bonding implementation
└── ... (other existing APIs)
```

**smart-bonding-base-api.ts**:
```typescript
import { BaseApi } from './base-api.js';
import { getValidSmartBondingToken } from '../utils/smart-bonding-auth.js';

export abstract class SmartBondingBaseApi extends BaseApi {
  protected baseUrl = 'https://sb.xylem.cisco.com/sb-partner-oauth-api/rest/v1';
  protected apiName = 'Smart Bonding';

  // Override makeApiCall to use Smart Bonding auth
  protected async makeApiCall(endpoint: string, params: Record<string, any> = {}): Promise<ApiResponse> {
    const token = await getValidSmartBondingToken();

    // ... similar implementation with Smart Bonding token
  }
}
```

## Implementation Tasks

### Phase 1: Authentication Foundation
- [ ] Create `src/utils/smart-bonding-auth.ts`
- [ ] Implement OAuth2 flow for Smart Bonding endpoint
- [ ] Add environment variables (`SMART_BONDING_CLIENT_ID`, `SMART_BONDING_CLIENT_SECRET`)
- [ ] Implement 1-hour token lifecycle with 5-minute refresh margin
- [ ] Add unit tests for authentication module
- [ ] Update `.env.example` with Smart Bonding credentials

### Phase 2: Base API Infrastructure
- [ ] Create `src/apis/smart-bonding-base-api.ts`
- [ ] Extend base API with Smart Bonding authentication
- [ ] Add environment detection (test vs production)
- [ ] Implement POST method support (existing APIs only use GET)
- [ ] Add support for `x-correlation-id` header

### Phase 3: API Tools Implementation
- [ ] Create `src/apis/smart-bonding-api.ts`
- [ ] Implement `pull_smart_bonding_tickets` tool (GET /pull/call)
- [ ] Implement `push_smart_bonding_ticket` tool (POST /push/call)
- [ ] Add JSON schema validation for ticket payloads
- [ ] Format responses with hyperlinks (case IDs, etc.)

### Phase 4: Registry Integration
- [ ] Add `smart_bonding` to `SupportedAPI` type in `src/apis/index.ts`
- [ ] Update API registry initialization
- [ ] Add to `SUPPORTED_APIS` array
- [ ] Test with `SUPPORT_API=smart_bonding` environment variable
- [ ] Test with `SUPPORT_API=all` to ensure it's included

### Phase 5: Documentation & Testing
- [ ] Update README.md with Smart Bonding API section
- [ ] Document credential acquisition process
- [ ] Create test suite for Smart Bonding tools
- [ ] Add integration tests (requires real credentials)
- [ ] Update CLAUDE.md project instructions
- [ ] Create GitHub Wiki page for Smart Bonding integration

### Phase 6: Error Handling & Edge Cases
- [ ] Handle missing credentials gracefully
- [ ] Implement rate limiting awareness
- [ ] Add timeout handling (60s for API calls)
- [ ] Test with invalid credentials
- [ ] Test token expiration and refresh
- [ ] Handle network failures

## Environment Variables

### New Variables Required

```bash
# Smart Bonding API Configuration
SMART_BONDING_CLIENT_ID=your_smart_bonding_client_id
SMART_BONDING_CLIENT_SECRET=your_smart_bonding_client_secret
SMART_BONDING_ENV=production  # or 'staging' for test environment

# Enable Smart Bonding API (add to existing SUPPORT_API)
SUPPORT_API=bug,case,smart_bonding  # or 'all'
```

### Configuration Examples

```bash
# Smart Bonding only
SUPPORT_API=smart_bonding

# Combined with other APIs
SUPPORT_API=bug,case,smart_bonding

# All APIs including Smart Bonding
SUPPORT_API=all
```

## MCP Tools Schema

### Tool 1: pull_smart_bonding_tickets

**Purpose**: Retrieve ticket updates from Cisco that haven't been pulled yet

```typescript
{
  name: 'pull_smart_bonding_tickets',
  description: 'Retrieve ticket updates from Cisco Smart Bonding that have not yet been pulled',
  inputSchema: {
    type: 'object',
    properties: {
      correlation_id: {
        type: 'string',
        description: 'Optional tracking identifier for end-to-end traceability'
      }
    },
    required: []
  }
}
```

**Response Format**:
```typescript
{
  tickets: [
    {
      SDCallID: string,        // Cisco-generated ticket ID
      CustCallID: string,      // Customer ticket ID
      ShortDescription: string,
      CallerInfo: {...},
      ComponentInfo: {...},
      Status: string,
      Priority: string,
      Severity: string,
      CreatedDate: string,
      ModifiedDate: string
    }
  ],
  total_results: number,
  correlation_id: string     // Echo back for tracking
}
```

### Tool 2: push_smart_bonding_ticket

**Purpose**: Create or update support tickets in Cisco Smart Bonding

```typescript
{
  name: 'push_smart_bonding_ticket',
  description: 'Create or update a support ticket in Cisco Smart Bonding system',
  inputSchema: {
    type: 'object',
    properties: {
      ticket_data: {
        type: 'object',
        description: 'Complete ticket information',
        properties: {
          CustCallID: { type: 'string', description: 'Customer ticket ID' },
          ShortDescription: { type: 'string', description: 'Brief description of issue' },
          DetailedDescription: { type: 'string', description: 'Full description' },
          Caller: {
            type: 'object',
            properties: {
              Name: { type: 'string' },
              Email: { type: 'string' },
              Phone: { type: 'string' }
            },
            required: ['Name', 'Email']
          },
          Priority: { type: 'string', enum: ['Low', 'Medium', 'High', 'Critical'] },
          Severity: { type: 'string', enum: ['1', '2', '3', '4'] },
          // ... additional fields per API spec
        },
        required: ['CustCallID', 'ShortDescription', 'Caller']
      },
      correlation_id: {
        type: 'string',
        description: 'Optional tracking identifier'
      }
    },
    required: ['ticket_data']
  }
}
```

**Response Format**:
```typescript
{
  status: 'success' | 'error',
  message: string,
  SDCallID: string,          // Cisco-generated ID for created/updated ticket
  CustCallID: string,        // Echo customer ID
  correlation_id: string
}
```

## Response Formatting

Following existing patterns in `src/utils/formatting.ts`:

```typescript
export interface SmartBondingTicket {
  SDCallID: string;
  CustCallID: string;
  ShortDescription: string;
  CallerInfo: CallerDetails;
  ComponentInfo: ComponentDetails;
  Status: string;
  Priority: string;
  Severity: string;
  CreatedDate: string;
  ModifiedDate: string;
}

export interface SmartBondingApiResponse extends ApiResponse {
  tickets?: SmartBondingTicket[];
  total_results?: number;
  status?: string;
  message?: string;
  SDCallID?: string;
  correlation_id?: string;
}

export function formatSmartBondingResults(data: SmartBondingApiResponse): string {
  // Format tickets with hyperlinks to Cisco ticket system
  // Include correlation IDs for tracking
  // Format dates in user-friendly format
  // Highlight priority/severity
}
```

## Testing Strategy

### Unit Tests
```typescript
// tests/smartBondingAuth.test.ts
describe('Smart Bonding Authentication', () => {
  test('should authenticate with Smart Bonding OAuth2 endpoint');
  test('should refresh token before 1-hour expiry');
  test('should handle authentication failures');
  test('should use separate credentials from Support API');
});

// tests/smartBondingApi.test.ts
describe('Smart Bonding API Tools', () => {
  test('should pull tickets successfully');
  test('should push ticket with valid data');
  test('should validate ticket schema');
  test('should handle correlation IDs');
});
```

### Integration Tests
```typescript
// tests/smartBondingIntegration.test.ts
describe('Smart Bonding Integration', () => {
  test('should authenticate and retrieve tickets', { skip: !hasCredentials });
  test('should create ticket end-to-end', { skip: !hasCredentials });
  test('should work with staging environment');
});
```

### Manual Testing Checklist
- [ ] Test with valid Smart Bonding credentials
- [ ] Test with invalid credentials
- [ ] Test token expiration and refresh (wait 55+ minutes)
- [ ] Test both staging and production environments
- [ ] Test with missing credentials (graceful failure)
- [ ] Test correlation ID tracking
- [ ] Test with Claude Desktop integration
- [ ] Test alongside existing Support API tools
- [ ] Test `SUPPORT_API=all` configuration

## Security Considerations

### Credential Isolation
- Smart Bonding credentials are separate from Support API credentials
- No shared secrets between authentication systems
- Different OAuth2 endpoints prevent credential confusion

### Token Management
- Shorter token lifetime (1 hour vs 12 hours) reduces exposure window
- 5-minute refresh margin ensures minimal use of expiring tokens
- Token stored in memory only (not persisted)

### Environment Detection
- Support for separate staging/production environments
- `SMART_BONDING_ENV` variable controls base URL
- Default to production for safety

### Input Validation
- JSON schema validation for all ticket data
- Sanitize user inputs before API calls
- Validate correlation IDs format

## Migration Path

### Backward Compatibility
- Existing APIs continue to work unchanged
- Smart Bonding is opt-in via `SUPPORT_API` configuration
- No breaking changes to current functionality

### Rollout Strategy
1. **Development**: Implement on feature branch
2. **Testing**: Comprehensive unit and integration tests
3. **Documentation**: Update all docs before merge
4. **Staging**: Test with staging environment credentials
5. **Production**: Enable for users with production credentials
6. **Monitoring**: Track authentication success rates

## Open Questions

1. **Rate Limiting**: What are the rate limits for Smart Bonding API?
   - Action: Test and document observed limits

2. **Pagination**: Does `/pull/call` support pagination for large result sets?
   - Action: Test with large ticket volumes

3. **Ticket Schema**: What are all the optional fields in ticket payloads?
   - Action: Obtain complete OpenAPI spec from Cisco

4. **Error Codes**: What specific error codes does the API return?
   - Action: Document during testing phase

5. **Webhook Support**: Does Smart Bonding support webhooks for real-time updates?
   - Action: Research and potentially implement in future phase

## Success Criteria

- [ ] Authentication works with both staging and production endpoints
- [ ] Both pull and push tools function correctly
- [ ] All tests pass (unit + integration)
- [ ] Documentation is complete and accurate
- [ ] No breaking changes to existing functionality
- [ ] Works in both stdio and HTTP modes
- [ ] Claude Desktop integration successful
- [ ] Token refresh works reliably for 1-hour lifecycle

## Timeline Estimate

- **Phase 1 (Auth)**: 2-3 hours
- **Phase 2 (Base API)**: 1-2 hours
- **Phase 3 (Tools)**: 3-4 hours
- **Phase 4 (Registry)**: 1 hour
- **Phase 5 (Docs)**: 2-3 hours
- **Phase 6 (Error Handling)**: 2-3 hours

**Total**: 11-16 hours of development time

## Related Resources

- [Smart Bonding API Docs](https://developer.cisco.com/docs/smart-bonding-customer-api/)
- [OpenAPI Spec](https://pubhub.devnetcloud.com/media/smart-bonding-customer-api/docs/2a97df78-0fc9-3e60-87f0-8e47d2e0bd16/smart_bonding_case_api_v_1.json)
- [Authentication Guide](https://developer.cisco.com/docs/smart-bonding-customer-api/authentication/)
- Existing Project Docs: [CLAUDE.md](./CLAUDE.md)

## Notes

- Consider adding elicitation support for interactive ticket creation
- Potential future enhancement: Ticket status polling/monitoring
- Investigate Smart Bonding webhooks for event-driven architecture
- Consider batch ticket operations if API supports them
