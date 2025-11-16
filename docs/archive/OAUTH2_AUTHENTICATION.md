# OAuth 2.1 Authentication Guide

This guide explains the OAuth 2.1 authorization implementation for the MCP Cisco Support server, including architecture, flows, and usage examples.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Authentication Modes](#authentication-modes)
- [OAuth 2.1 Flow](#oauth-21-flow)
- [PKCE Explained](#pkce-explained)
- [Implementation Details](#implementation-details)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [When to Use Each Mode](#when-to-use-each-mode)
- [Production Considerations](#production-considerations)

## Overview

The MCP Cisco Support server implements **two authentication modes** for HTTP transport:

1. **Bearer Token (Default)** - Simple, fast authentication using static tokens
2. **OAuth 2.1** - Full OAuth 2.1 authorization server with PKCE

The implementation follows the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) and is fully backward compatible with existing deployments.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Server (HTTP)                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐            ┌──────────────────┐      │
│  │   Bearer     │            │   OAuth 2.1      │      │
│  │   Token      │  OR        │   Authorization  │      │
│  │   Middleware │            │   Server         │      │
│  └──────────────┘            └──────────────────┘      │
│         │                              │                │
│         │                              │                │
│         └──────────┬───────────────────┘                │
│                    │                                    │
│              ┌─────▼──────┐                             │
│              │    MCP     │                             │
│              │  Endpoints │                             │
│              └────────────┘                             │
└─────────────────────────────────────────────────────────┘
```

### Component Structure

```
src/
├── oauth2.ts           # OAuth 2.1 authorization server implementation
├── sse-server.ts       # HTTP server with auth middleware selection
├── index.ts            # Main entry point
└── mcp-server.ts       # MCP server implementation
```

## Authentication Modes

### Mode 1: Bearer Token (Default)

**Description:** Simple bearer token authentication using static tokens.

**Workflow:**
```
Client Request → Bearer Token Check → MCP Handler
                      ↓ (if valid)
                 Attach user info
```

**Configuration:**
```bash
# Use default bearer authentication
AUTH_TYPE=bearer  # or omit this line

# Auto-generate random token on startup
npx mcp-cisco-support --http
# Output: 🔑 Bearer token: abc123...

# Use custom token from environment
export MCP_BEARER_TOKEN=your_custom_token_here
npx mcp-cisco-support --http
```

**Client Usage:**
```bash
# Include token in Authorization header (recommended)
curl -H "Authorization: Bearer <token>" http://localhost:3000/mcp

# Or use query parameter (less secure)
curl http://localhost:3000/mcp?token=<token>
```

### Mode 2: OAuth 2.1 Authorization

**Description:** Full OAuth 2.1 authorization server with PKCE, client registration, and token management.

**Workflow:**
```
Client Registration → Authorization Request → User Consent
                                                    ↓
Token Validation ← Token Exchange ← Authorization Code
        ↓
   MCP Handler
```

**Configuration:**
```bash
# Enable OAuth 2.1 authentication
AUTH_TYPE=oauth2.1

# Optional: Configure issuer URL (defaults to http://localhost:PORT)
OAUTH2_ISSUER_URL=https://your-server.com

# Optional: Disable dynamic client registration (enabled by default)
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=false

# Start server
npx mcp-cisco-support --http
```

**Server Output:**
```
🔐 Authentication Type: OAUTH2.1

📋 OAuth 2.1 Authorization Server Configuration:
   Issuer: http://localhost:3000
   Authorization Endpoint: http://localhost:3000/authorize
   Token Endpoint: http://localhost:3000/token
   Registration Endpoint: http://localhost:3000/register
   Metadata: http://localhost:3000/.well-known/oauth-authorization-server
```

## OAuth 2.1 Flow

### Complete Flow Diagram

```
┌─────────┐                                  ┌──────────┐                                ┌─────────┐
│  Client │                                  │ MCP      │                                │  User   │
│         │                                  │ Server   │                                │         │
└────┬────┘                                  └────┬─────┘                                └────┬────┘
     │                                            │                                           │
     │ 1. Register Client (POST /register)        │                                           │
     ├───────────────────────────────────────────>│                                           │
     │                                            │                                           │
     │ 2. Client ID & Secret                      │                                           │
     │<───────────────────────────────────────────┤                                           │
     │                                            │                                           │
     │ 3. Generate PKCE (code_verifier/challenge) │                                           │
     │                                            │                                           │
     │ 4. Authorization Request                   │                                           │
     │    GET /authorize?code_challenge=...       │                                           │
     ├───────────────────────────────────────────>│                                           │
     │                                            │                                           │
     │ 5. Show Authorization Page                 │                                           │
     │<───────────────────────────────────────────┤                                           │
     │                                            │                                           │
     │ 6. User Approves                           │                                           │
     ├────────────────────────────────────────────┼──────────────────────────────────────────>│
     │                                            │                                           │
     │ 7. Redirect with Authorization Code        │                                           │
     │    ?code=abc123&state=...                  │<──────────────────────────────────────────┤
     │<───────────────────────────────────────────┤                                           │
     │                                            │                                           │
     │ 8. Token Request                           │                                           │
     │    POST /token (code + code_verifier)      │                                           │
     ├───────────────────────────────────────────>│                                           │
     │                                            │                                           │
     │ 9. Validate PKCE & Issue Access Token      │                                           │
     │    (access_token + refresh_token)          │                                           │
     │<───────────────────────────────────────────┤                                           │
     │                                            │                                           │
     │ 10. MCP Request with Access Token          │                                           │
     │     Authorization: Bearer <token>          │                                           │
     ├───────────────────────────────────────────>│                                           │
     │                                            │                                           │
     │ 11. MCP Response                           │                                           │
     │<───────────────────────────────────────────┤                                           │
```

### Step-by-Step Flow

#### Step 1: Discover Server Metadata (RFC 8414)

**Request:**
```bash
curl http://localhost:3000/.well-known/oauth-authorization-server
```

**Response:**
```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/authorize",
  "token_endpoint": "http://localhost:3000/token",
  "registration_endpoint": "http://localhost:3000/register",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials"
  ],
  "code_challenge_methods_supported": ["S256", "plain"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "scopes_supported": ["mcp"],
  "mcp-protocol-version": "2025-06-18"
}
```

#### Step 2: Register Client (RFC 7591)

**Request:**
```bash
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3001/callback"],
    "client_name": "My MCP Client",
    "grant_types": ["authorization_code"]
  }'
```

**Response:**
```json
{
  "client_id": "mcp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "client_secret": "q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
  "redirect_uris": ["http://localhost:3001/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "client_name": "My MCP Client",
  "client_id_issued_at": 1698765432,
  "client_secret_expires_at": 0
}
```

**What the server does:**
- Generates unique `client_id` and `client_secret`
- Validates redirect URIs are secure (HTTPS or localhost)
- Stores client information in memory

#### Step 3: Generate PKCE Parameters

**Client-Side Code:**
```bash
# Generate code_verifier (random string, 43-128 characters)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
# Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

# Generate code_challenge (SHA256 hash of verifier, base64url encoded)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | \
  openssl dgst -binary -sha256 | \
  openssl base64 | tr -d '=' | tr '+/' '-_')
# Example: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

**JavaScript Example:**
```javascript
// Generate code_verifier
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

// Generate code_challenge from verifier
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(array) {
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

#### Step 4: Request Authorization Code

**Browser URL:**
```
http://localhost:3000/authorize?response_type=code&client_id=mcp_a1b2c3d4...&redirect_uri=http://localhost:3001/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=random_state_value
```

**Query Parameters:**
- `response_type=code` - Request authorization code
- `client_id` - Your registered client ID
- `redirect_uri` - Where to send the user after authorization
- `code_challenge` - PKCE challenge derived from code_verifier
- `code_challenge_method=S256` - SHA256 hashing method
- `state` - Random value to prevent CSRF attacks

**Server Response:** HTML authorization page

```html
<!DOCTYPE html>
<html>
<head>
  <title>MCP Authorization</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      max-width: 600px;
      margin: 50px auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h1 { color: #333; }
    .client-info {
      background: #f9f9f9;
      padding: 15px;
      border-radius: 4px;
      margin: 20px 0;
    }
    .button {
      background: #007bff;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
      margin-right: 10px;
    }
    .button:hover { background: #0056b3; }
    .button.deny {
      background: #6c757d;
    }
    .button.deny:hover { background: #545b62; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔐 MCP Authorization Request</h1>

    <div class="client-info">
      <p><strong>Client:</strong> My MCP Client</p>
      <p><strong>Requested Scope:</strong> mcp (default)</p>
    </div>

    <p>This application is requesting access to your MCP server.</p>

    <form method="POST" action="/authorize/approve">
      <input type="hidden" name="client_id" value="...">
      <input type="hidden" name="redirect_uri" value="...">
      <input type="hidden" name="code_challenge" value="...">
      <input type="hidden" name="code_challenge_method" value="S256">
      <input type="hidden" name="scope" value="">
      <input type="hidden" name="state" value="...">

      <button type="submit" class="button">Authorize</button>
      <button type="button" class="button deny" onclick="...">Deny</button>
    </form>
  </div>
</body>
</html>
```

#### Step 5: User Authorization Approval

**When user clicks "Authorize":**

**Server Actions:**
1. Generates authorization code: `auth_xyz789...`
2. Stores authorization code with PKCE challenge:
```javascript
{
  code: "auth_xyz789...",
  client_id: "mcp_a1b2c3d4...",
  redirect_uri: "http://localhost:3001/callback",
  code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  code_challenge_method: "S256",
  scope: "mcp",
  user_id: "default_user",
  expires_at: Date.now() + 600000,  // 10 minutes
  used: false
}
```
3. Redirects user back to client:
```
Location: http://localhost:3001/callback?code=auth_xyz789...&state=random_state_value
```

#### Step 6: Exchange Code for Access Token

**Request:**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth_xyz789..." \
  -d "redirect_uri=http://localhost:3001/callback" \
  -d "client_id=mcp_a1b2c3d4..." \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

**Server Validation:**
1. Retrieves authorization code
2. Validates code exists and not expired
3. Validates code not already used
4. Validates client_id matches
5. Validates redirect_uri matches
6. **Validates PKCE:** `SHA256(code_verifier) == stored code_challenge`
7. Marks code as used (prevents reuse)

**Response:**
```json
{
  "access_token": "token_abc123def456ghi789jkl012mno345pqr678",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_stu901vwx234yz567abc890def123ghi456",
  "scope": "mcp"
}
```

#### Step 7: Use Access Token for MCP Requests

**Request:**
```bash
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer token_abc123def456ghi789jkl012mno345pqr678" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }'
```

**Server Validation:**
1. Extracts token from Authorization header
2. Looks up token in storage
3. Checks token exists
4. Checks token not expired
5. Attaches user info to request
6. Processes MCP request

#### Step 8: Refresh Token (When Access Token Expires)

**Request:**
```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh_stu901vwx234yz567abc890def123ghi456"
```

**Server Actions:**
1. Validates refresh token exists
2. Generates new access token and refresh token
3. Deletes old tokens (token rotation)
4. Stores new tokens

**Response:**
```json
{
  "access_token": "token_jkl345mno678pqr901stu234vwx567yz890",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_abc123def456ghi789jkl012mno345pqr678",
  "scope": "mcp"
}
```

## PKCE Explained

### What is PKCE?

**PKCE** (Proof Key for Code Exchange, RFC 7636) prevents authorization code interception attacks.

### The Problem Without PKCE

```
1. User authorizes application
2. Server redirects: http://client.com/callback?code=AUTH_CODE
3. ❌ Attacker intercepts redirect and steals AUTH_CODE
4. ❌ Attacker exchanges AUTH_CODE for access token
5. ❌ Attacker gains access to user's data
```

### How PKCE Solves This

```
1. Client generates random code_verifier (kept secret)
2. Client derives code_challenge = SHA256(code_verifier)
3. Client sends code_challenge in authorization request
4. Server stores code_challenge with authorization code
5. Server redirects with authorization code
6. Attacker may intercept code, but doesn't have code_verifier
7. Client sends code + code_verifier to token endpoint
8. Server validates: SHA256(code_verifier) == stored code_challenge
9. ✅ Only original client can exchange code for token
```

### PKCE Implementation

**Code Verifier Generation:**
```javascript
// Must be 43-128 characters, [A-Z][a-z][0-9]-._~
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array); // Results in 43 characters
}
```

**Code Challenge Generation (S256 Method):**
```javascript
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}
```

**Server-Side Validation:**
```typescript
function validatePKCE(
  codeVerifier: string,
  codeChallenge: string,
  codeChallengeMethod: string
): boolean {
  if (codeChallengeMethod === 'S256') {
    const hash = createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    return hash === codeChallenge;
  }

  if (codeChallengeMethod === 'plain') {
    return codeVerifier === codeChallenge;
  }

  return false;
}
```

## Implementation Details

### File Structure

#### `src/oauth2.ts`

**Core Components:**

1. **Type Definitions**
```typescript
interface OAuth2Client {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  client_name?: string;
  client_uri?: string;
  created_at: number;
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  user_id: string;
  expires_at: number;
  used: boolean;
}

interface AccessToken {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  created_at: number;
  user_id: string;
  client_id: string;
}
```

2. **Storage (In-Memory)**
```typescript
const clients = new Map<string, OAuth2Client>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();
const refreshTokens = new Map<string, string>();
```

3. **Configuration**
```typescript
const TOKEN_EXPIRY = 3600;        // 1 hour
const CODE_EXPIRY = 600;          // 10 minutes
const REFRESH_TOKEN_EXPIRY = 86400; // 24 hours
```

4. **Key Functions**

| Function | Purpose | RFC |
|----------|---------|-----|
| `generateAuthorizationServerMetadata()` | Server metadata endpoint | RFC 8414 |
| `registerClient()` | Dynamic client registration | RFC 7591 |
| `handleAuthorizeRequest()` | Authorization endpoint | RFC 6749 |
| `handleAuthorizeApproval()` | Process user approval | - |
| `handleTokenRequest()` | Token endpoint | RFC 6749 |
| `createOAuth2Middleware()` | Token validation middleware | - |
| `validatePKCE()` | PKCE validation | RFC 7636 |
| `cleanupExpiredTokens()` | Automatic token cleanup | - |

#### `src/sse-server.ts`

**Integration Points:**

```typescript
// Detect authentication type
const authType = (process.env.AUTH_TYPE || 'bearer').toLowerCase();

// OAuth 2.1 configuration
const oauth2Config: OAuth2Config = {
  issuerUrl: process.env.OAUTH2_ISSUER_URL || `http://localhost:${port}`,
  allowDynamicRegistration: process.env.OAUTH2_ALLOW_DYNAMIC_REGISTRATION !== 'false',
  requirePKCE: true
};

// Register OAuth 2.1 endpoints
if (enableAuth && authType === 'oauth2.1') {
  app.get('/.well-known/oauth-authorization-server', ...);
  app.post('/register', ...);
  app.get('/authorize', ...);
  app.post('/authorize/approve', ...);
  app.post('/token', ...);
}

// Apply appropriate middleware
if (authType === 'oauth2.1') {
  app.use(createOAuth2Middleware());
} else {
  app.use(createAuthMiddleware(authToken, enableAuth));
}
```

### OAuth 2.1 Endpoints

| Endpoint | Method | Purpose | Public |
|----------|--------|---------|--------|
| `/.well-known/oauth-authorization-server` | GET | Server metadata (RFC 8414) | ✅ Yes |
| `/register` | POST | Client registration (RFC 7591) | ✅ Yes |
| `/authorize` | GET | Authorization request | ✅ Yes |
| `/authorize/approve` | POST | User approval | ✅ Yes |
| `/token` | POST | Token exchange/refresh | ✅ Yes |
| `/mcp` | POST/GET/DELETE | MCP endpoints | ❌ No (requires auth) |
| `/sse` | GET | Legacy SSE | ❌ No (requires auth) |
| `/messages` | POST | Legacy messages | ❌ No (requires auth) |
| `/health` | GET | Health check | ✅ Yes |
| `/` | GET | Server info | ✅ Yes |

## Configuration

### Environment Variables

```bash
# ============================================
# Authentication Type (NEW)
# ============================================
AUTH_TYPE=bearer           # Default: Simple bearer token
AUTH_TYPE=oauth2.1         # Full OAuth 2.1 authorization server

# ============================================
# Bearer Token Configuration (Existing)
# ============================================
MCP_BEARER_TOKEN=custom_token_here    # Use specific bearer token
                                       # If not set, random token is generated

# ============================================
# OAuth 2.1 Configuration (NEW)
# ============================================

# Issuer URL (defaults to http://localhost:PORT)
OAUTH2_ISSUER_URL=https://api.example.com

# Allow dynamic client registration (defaults to true)
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=true   # Enable registration endpoint
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=false  # Disable registration endpoint

# ============================================
# Disable Authentication (Existing)
# ============================================
DANGEROUSLY_OMIT_AUTH=true    # ⚠️ Disables all HTTP authentication
                               # Only for development/testing

# ============================================
# Cisco API Configuration (Existing)
# ============================================
CISCO_CLIENT_ID=your_cisco_client_id
CISCO_CLIENT_SECRET=your_cisco_client_secret
SUPPORT_API=enhanced_analysis

# ============================================
# Server Configuration (Existing)
# ============================================
PORT=3000
NODE_ENV=development
```

### Example Configurations

#### Development (Bearer Token)
```bash
# .env
AUTH_TYPE=bearer
MCP_BEARER_TOKEN=dev_token_12345
PORT=3000
CISCO_CLIENT_ID=your_id
CISCO_CLIENT_SECRET=your_secret
```

#### Production (OAuth 2.1)
```bash
# .env
AUTH_TYPE=oauth2.1
OAUTH2_ISSUER_URL=https://api.mycompany.com
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=true
PORT=443
NODE_ENV=production
CISCO_CLIENT_ID=your_id
CISCO_CLIENT_SECRET=your_secret
```

#### Testing (No Auth)
```bash
# .env
DANGEROUSLY_OMIT_AUTH=true
PORT=3000
CISCO_CLIENT_ID=your_id
CISCO_CLIENT_SECRET=your_secret
```

## Security Features

### 1. PKCE Mandatory

**Protection:** Prevents authorization code interception attacks

**Implementation:**
```typescript
// Authorization request MUST include code_challenge
if (!code_challenge) {
  return res.status(400).json({
    error: 'invalid_request',
    error_description: 'PKCE code_challenge is required'
  });
}

// Token request MUST include code_verifier
if (!code_verifier) {
  return res.status(400).json({
    error: 'invalid_request',
    error_description: 'PKCE code_verifier is required'
  });
}

// Server validates PKCE
if (!validatePKCE(code_verifier, authCode.code_challenge, authCode.code_challenge_method)) {
  return res.status(400).json({
    error: 'invalid_grant',
    error_description: 'PKCE validation failed'
  });
}
```

### 2. Secure Redirect URI Validation

**Protection:** Prevents open redirect attacks

**Implementation:**
```typescript
function isSecureRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    // Allow localhost for development, require HTTPS otherwise
    return parsed.protocol === 'https:' ||
           parsed.hostname === 'localhost' ||
           parsed.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

// Exact match required
function validateRedirectUri(uri: string, registeredUris: string[]): boolean {
  return registeredUris.includes(uri);
}
```

### 3. Short-Lived Tokens

**Protection:** Limits damage if tokens are compromised

**Token Lifespans:**
- Authorization codes: 10 minutes (single-use)
- Access tokens: 1 hour
- Refresh tokens: 24 hours

**Implementation:**
```typescript
const TOKEN_EXPIRY = 3600;        // 1 hour
const CODE_EXPIRY = 600;          // 10 minutes
const REFRESH_TOKEN_EXPIRY = 86400; // 24 hours

// Check if token is expired
const expiresAt = accessToken.created_at + (accessToken.expires_in * 1000);
if (Date.now() > expiresAt) {
  accessTokens.delete(token);
  return res.status(401).json({
    error: 'invalid_token',
    error_description: 'Access token expired'
  });
}
```

### 4. Token Rotation

**Protection:** Prevents refresh token reuse attacks

**Implementation:**
```typescript
// Refresh token flow
const oldAccessToken = refreshTokens.get(refresh_token);
const oldToken = accessTokens.get(oldAccessToken);

// Generate new tokens
const new_access_token = randomUUID().replace(/-/g, '');
const new_refresh_token = randomUUID().replace(/-/g, '');

// Remove old tokens (rotation)
accessTokens.delete(oldAccessToken);
refreshTokens.delete(refresh_token);

// Store new tokens
accessTokens.set(new_access_token, newToken);
refreshTokens.set(new_refresh_token, new_access_token);
```

### 5. One-Time Authorization Codes

**Protection:** Prevents authorization code reuse

**Implementation:**
```typescript
// Check if code was already used
if (authCode.used) {
  authorizationCodes.delete(code);
  return res.status(400).json({
    error: 'invalid_grant',
    error_description: 'Authorization code already used'
  });
}

// Mark code as used after successful token exchange
authCode.used = true;
```

### 6. Automatic Token Cleanup

**Protection:** Removes expired tokens from memory

**Implementation:**
```typescript
export function cleanupExpiredTokens(): void {
  const now = Date.now();

  // Clean up expired authorization codes
  for (const [code, authCode] of authorizationCodes.entries()) {
    if (now > authCode.expires_at || authCode.used) {
      authorizationCodes.delete(code);
    }
  }

  // Clean up expired access tokens
  for (const [token, accessToken] of accessTokens.entries()) {
    const expiresAt = accessToken.created_at + (accessToken.expires_in * 1000);
    if (now > expiresAt) {
      accessTokens.delete(token);
      if (accessToken.refresh_token) {
        refreshTokens.delete(accessToken.refresh_token);
      }
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredTokens, 5 * 60 * 1000);
```

### 7. State Parameter Support

**Protection:** Prevents CSRF attacks

**Implementation:**
```typescript
// Authorization request includes state
const { state } = req.query;

// Redirect includes state
const redirectUrl = new URL(redirect_uri);
redirectUrl.searchParams.set('code', code);
if (state) {
  redirectUrl.searchParams.set('state', state);
}

// Client validates state matches original request
```

## Usage Examples

### Example 1: Simple CLI Tool (Bearer Token)

**Server Setup:**
```bash
# Start server with bearer token auth
export MCP_BEARER_TOKEN=my_cli_token_123
export CISCO_CLIENT_ID=your_cisco_id
export CISCO_CLIENT_SECRET=your_cisco_secret
npx mcp-cisco-support --http
```

**Client Code (Python):**
```python
import requests

MCP_SERVER = "http://localhost:3000"
BEARER_TOKEN = "my_cli_token_123"

def call_mcp_tool(tool_name, arguments):
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        },
        "id": 1
    }

    response = requests.post(f"{MCP_SERVER}/mcp",
                            json=payload,
                            headers=headers)
    return response.json()

# Example: Search for bugs
result = call_mcp_tool("search_bugs_by_keyword", {
    "keyword": "memory leak",
    "severity": "3",
    "page_index": 1
})

print(result)
```

### Example 2: Web Application (OAuth 2.1)

**Server Setup:**
```bash
# Start server with OAuth 2.1 auth
export AUTH_TYPE=oauth2.1
export OAUTH2_ISSUER_URL=https://api.myapp.com
export CISCO_CLIENT_ID=your_cisco_id
export CISCO_CLIENT_SECRET=your_cisco_secret
npx mcp-cisco-support --http
```

**Client Code (JavaScript/Express):**
```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const MCP_SERVER = 'https://api.myapp.com';

app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: true
}));

// Home page - start OAuth flow
app.get('/', (req, res) => {
  if (req.session.accessToken) {
    res.send(`
      <h1>Connected to MCP Server</h1>
      <p>Access Token: ${req.session.accessToken.substring(0, 20)}...</p>
      <a href="/search">Search Bugs</a> | <a href="/logout">Logout</a>
    `);
  } else {
    res.send(`
      <h1>MCP Client Example</h1>
      <a href="/login">Connect to MCP Server</a>
    `);
  }
});

// Step 1: Register client (do this once, store credentials)
let CLIENT_ID = process.env.MCP_CLIENT_ID;
let CLIENT_SECRET = process.env.MCP_CLIENT_SECRET;

if (!CLIENT_ID) {
  // Register client
  fetch(`${MCP_SERVER}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: ['http://localhost:3001/callback'],
      client_name: 'My Web App',
      grant_types: ['authorization_code', 'refresh_token']
    })
  })
  .then(res => res.json())
  .then(data => {
    CLIENT_ID = data.client_id;
    CLIENT_SECRET = data.client_secret;
    console.log('Client registered:', CLIENT_ID);
  });
}

// Step 2 & 3: Generate PKCE and redirect to authorization
app.get('/login', (req, res) => {
  // Generate PKCE parameters
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Generate state for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');

  // Store in session
  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  // Redirect to authorization endpoint
  const authUrl = new URL(`${MCP_SERVER}/authorize`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', 'http://localhost:3001/callback');
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('scope', 'mcp');

  res.redirect(authUrl.toString());
});

// Step 5 & 6: Handle callback and exchange code for token
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Validate state
  if (state !== req.session.state) {
    return res.status(400).send('Invalid state parameter');
  }

  // Exchange code for access token
  const tokenResponse = await fetch(`${MCP_SERVER}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'http://localhost:3001/callback',
      client_id: CLIENT_ID,
      code_verifier: req.session.codeVerifier
    })
  });

  const tokens = await tokenResponse.json();

  // Store tokens in session
  req.session.accessToken = tokens.access_token;
  req.session.refreshToken = tokens.refresh_token;
  req.session.tokenExpiry = Date.now() + (tokens.expires_in * 1000);

  // Clear PKCE parameters
  delete req.session.codeVerifier;
  delete req.session.state;

  res.redirect('/');
});

// Step 7: Use access token for MCP requests
app.get('/search', async (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect('/login');
  }

  // Check if token expired, refresh if needed
  if (Date.now() > req.session.tokenExpiry) {
    const refreshResponse = await fetch(`${MCP_SERVER}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: req.session.refreshToken
      })
    });

    const tokens = await refreshResponse.json();
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;
    req.session.tokenExpiry = Date.now() + (tokens.expires_in * 1000);
  }

  // Make MCP request
  const mcpResponse = await fetch(`${MCP_SERVER}/mcp`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${req.session.accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'search_bugs_by_keyword',
        arguments: {
          keyword: 'memory leak',
          severity: '3',
          page_index: 1
        }
      },
      id: 1
    })
  });

  const result = await mcpResponse.json();
  res.json(result);
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(3001, () => {
  console.log('Client app running on http://localhost:3001');
});
```

### Example 3: Service Account (Client Credentials)

**Server Setup:**
```bash
export AUTH_TYPE=oauth2.1
npx mcp-cisco-support --http
```

**Register Service Account:**
```bash
# Register service account client
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Monitoring Service",
    "grant_types": ["client_credentials"]
  }'

# Response:
# {
#   "client_id": "mcp_service123...",
#   "client_secret": "secret456...",
#   ...
# }
```

**Client Code (Bash):**
```bash
#!/bin/bash

CLIENT_ID="mcp_service123..."
CLIENT_SECRET="secret456..."
MCP_SERVER="http://localhost:3000"

# Get access token using client credentials
TOKEN_RESPONSE=$(curl -s -X POST "$MCP_SERVER/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# Use access token for MCP requests
curl -X POST "$MCP_SERVER/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }'
```

## When to Use Each Mode

### Decision Matrix

| Scenario | Bearer Token | OAuth 2.1 | Rationale |
|----------|--------------|-----------|-----------|
| **Single user/application** | ✅ Recommended | ❌ Overkill | Simple auth sufficient |
| **Development & testing** | ✅ Recommended | ⚠️ Optional | Quick setup, easy debugging |
| **CLI tools** | ✅ Recommended | ❌ Not suitable | No user interaction |
| **Internal services** | ✅ Recommended | ⚠️ Optional | Simple, fast, no user consent needed |
| **Multi-user web app** | ❌ Limited | ✅ Recommended | Need user consent, token refresh |
| **Third-party integrations** | ❌ Insecure | ✅ Recommended | OAuth standard for delegated access |
| **Enterprise deployment** | ⚠️ Acceptable | ✅ Recommended | OAuth 2.1 compliance often required |
| **Mobile app** | ❌ Not ideal | ✅ Recommended | PKCE prevents token interception |
| **Public API** | ❌ Not suitable | ✅ Recommended | Need granular access control |
| **Service-to-service** | ✅ Recommended | ⚠️ Optional | Client credentials flow works for both |

### Use Bearer Token When:

✅ **Single Application/User**
- You control both client and server
- No need for user consent
- Simple deployment requirements

✅ **Development & Testing**
- Quick setup needed
- Iterating rapidly
- Debugging authentication issues

✅ **CLI Tools**
- No user browser interaction
- Token stored in config file or environment

✅ **Internal Services**
- Running within secure network
- Service-to-service communication
- No external access

✅ **Simple Deployments**
- Minimal infrastructure
- No need for token refresh
- Static authentication sufficient

### Use OAuth 2.1 When:

✅ **Multi-User Applications**
- Multiple users need access
- Each user has own credentials
- User consent required

✅ **Third-Party Integrations**
- External applications need access
- Delegated authorization needed
- Standard OAuth flow expected

✅ **Web Applications**
- Browser-based clients
- Need token refresh capability
- Session management required

✅ **Mobile Applications**
- PKCE prevents code interception
- Token refresh for long sessions
- Standard mobile auth pattern

✅ **Enterprise Deployments**
- OAuth 2.1 compliance mandated
- Integration with corporate SSO
- Audit trail requirements

✅ **Public APIs**
- Open to external developers
- Need rate limiting per client
- Granular access control

### Comparison Table

| Feature | Bearer Token | OAuth 2.1 |
|---------|-------------|-----------|
| **Setup Complexity** | ⭐ Simple | ⭐⭐⭐ Complex |
| **User Interaction** | None | Required (authorization flow) |
| **Token Management** | Manual rotation | Automatic refresh |
| **Multi-User Support** | ⭐ Limited | ⭐⭐⭐ Full |
| **Security Level** | ⭐⭐ Good | ⭐⭐⭐ Excellent |
| **Client Types** | Trusted clients | Public & confidential clients |
| **User Consent** | ❌ No | ✅ Yes |
| **Token Expiry** | Static | Dynamic (with refresh) |
| **Standards Compliance** | Basic auth | Full OAuth 2.1 |
| **Audit Trail** | Basic | Comprehensive |
| **Revocation** | Manual | Per-user/per-client |
| **Best For** | Simple, trusted environments | Multi-user, public APIs |
| **Default** | ✅ Yes | ❌ No |

## Production Considerations

### Current Implementation Limitations

The current implementation uses **in-memory storage** which has these limitations:

❌ **Data Loss on Restart**
- All clients, tokens, and codes lost when server restarts
- Users must re-authorize after deployment

❌ **No Horizontal Scaling**
- Cannot run multiple server instances
- Each instance has separate storage

❌ **Memory Leaks**
- Without external persistence, old tokens accumulate
- Automatic cleanup helps but not perfect

### Production Recommendations

#### 1. Use Persistent Storage

**Replace in-memory Maps with Redis or Database:**

```typescript
// Instead of:
const clients = new Map<string, OAuth2Client>();
const accessTokens = new Map<string, AccessToken>();

// Use Redis:
import Redis from 'ioredis';
const redis = new Redis();

// Store client
await redis.set(`client:${client_id}`, JSON.stringify(client));
await redis.expire(`client:${client_id}`, 86400 * 365); // 1 year

// Store access token with auto-expiry
await redis.set(`token:${access_token}`, JSON.stringify(tokenData));
await redis.expire(`token:${access_token}`, TOKEN_EXPIRY);

// Retrieve token
const tokenJson = await redis.get(`token:${access_token}`);
const token = tokenJson ? JSON.parse(tokenJson) : null;
```

#### 2. Implement Rate Limiting

**Protect endpoints from abuse:**

```typescript
import rateLimit from 'express-rate-limit';

// Rate limit token endpoint
const tokenLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window
  message: 'Too many token requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/token', tokenLimiter, (req, res) => {
  handleTokenRequest(req, res);
});
```

#### 3. Add Proper User Management

**Implement real user authentication:**

```typescript
// Instead of hardcoded user
user_id: 'default_user'

// Use actual user authentication
import passport from 'passport';

app.get('/authorize',
  passport.authenticate('local', { session: true }),
  (req, res) => {
    // req.user contains authenticated user
    handleAuthorizeRequest(req, res, req.user);
  }
);
```

#### 4. Implement Audit Logging

**Track all OAuth operations:**

```typescript
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'oauth-audit.log' })
  ]
});

// Log all OAuth events
logger.info('Client registered', {
  client_id,
  client_name,
  redirect_uris,
  timestamp: new Date().toISOString(),
  ip: req.ip
});

logger.info('Authorization granted', {
  client_id,
  user_id,
  scope,
  timestamp: new Date().toISOString()
});

logger.info('Access token issued', {
  client_id,
  user_id,
  token_id: access_token.substring(0, 10),
  expires_in: TOKEN_EXPIRY,
  timestamp: new Date().toISOString()
});
```

#### 5. Use HTTPS in Production

**Enforce TLS for all communications:**

```typescript
import https from 'https';
import fs from 'fs';

const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem')
};

https.createServer(options, app).listen(443);

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.protocol !== 'https') {
    return res.redirect(`https://${req.hostname}${req.url}`);
  }
  next();
});
```

#### 6. Implement Token Revocation

**Allow users to revoke tokens:**

```typescript
// Revocation endpoint (RFC 7009)
app.post('/revoke', async (req, res) => {
  const { token, token_type_hint } = req.body;

  // Remove from storage
  if (token_type_hint === 'access_token') {
    await redis.del(`token:${token}`);
  } else if (token_type_hint === 'refresh_token') {
    const access_token = await redis.get(`refresh:${token}`);
    await redis.del(`token:${access_token}`);
    await redis.del(`refresh:${token}`);
  }

  logger.info('Token revoked', { token_type_hint });
  res.status(200).json({ success: true });
});
```

#### 7. Add Scope Support

**Implement granular permissions:**

```typescript
// Define scopes
const SCOPES = {
  'mcp:read': 'Read MCP tools and resources',
  'mcp:write': 'Execute MCP tools',
  'mcp:admin': 'Administer MCP server'
};

// Check scopes in middleware
function requireScope(...requiredScopes: string[]) {
  return (req, res, next) => {
    const userScopes = req.oauth2.scope?.split(' ') || [];
    const hasRequired = requiredScopes.every(s => userScopes.includes(s));

    if (!hasRequired) {
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'Required scopes not granted'
      });
    }

    next();
  };
}

// Protect endpoints
app.post('/mcp', requireScope('mcp:write'), ...);
```

#### 8. Monitor and Alert

**Set up monitoring for OAuth operations:**

```typescript
import prometheus from 'prom-client';

// Metrics
const tokenIssued = new prometheus.Counter({
  name: 'oauth_tokens_issued_total',
  help: 'Total number of access tokens issued'
});

const tokenValidation = new prometheus.Counter({
  name: 'oauth_token_validations_total',
  help: 'Total number of token validations',
  labelNames: ['result'] // 'success' or 'failure'
});

// Instrument code
tokenIssued.inc();
tokenValidation.labels('success').inc();

// Expose metrics
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});
```

### Production Deployment Checklist

- [ ] **Replace in-memory storage with Redis/Database**
- [ ] **Implement proper user authentication**
- [ ] **Enable HTTPS/TLS**
- [ ] **Add rate limiting on all OAuth endpoints**
- [ ] **Implement comprehensive audit logging**
- [ ] **Set up monitoring and alerting**
- [ ] **Add token revocation endpoint**
- [ ] **Implement scope-based access control**
- [ ] **Configure CORS properly**
- [ ] **Set secure cookie flags**
- [ ] **Implement CSRF protection**
- [ ] **Add security headers (already done via Helmet)**
- [ ] **Regular security audits**
- [ ] **Backup and recovery procedures**
- [ ] **Load balancing strategy**
- [ ] **Disaster recovery plan**

## Troubleshooting

### Common Issues

#### Issue 1: "PKCE validation failed"

**Cause:** code_verifier doesn't match code_challenge

**Solution:**
```bash
# Ensure code_verifier is stored correctly
# Verify code_challenge generation:

CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | \
  openssl dgst -binary -sha256 | \
  openssl base64 | tr -d '=' | tr '+/' '-_')

echo "Verifier: $CODE_VERIFIER"
echo "Challenge: $CODE_CHALLENGE"
```

#### Issue 2: "Invalid redirect_uri"

**Cause:** Redirect URI doesn't match registered URIs

**Solution:**
- Ensure exact match (including trailing slash)
- Use same protocol (http/https)
- Use same port number

```bash
# Registered: http://localhost:3001/callback
# Request:    http://localhost:3001/callback  ✅
# Request:    http://localhost:3001/callback/ ❌ (trailing slash)
# Request:    https://localhost:3001/callback ❌ (different protocol)
```

#### Issue 3: "Authorization code expired"

**Cause:** More than 10 minutes elapsed

**Solution:**
- Complete token exchange within 10 minutes
- Restart authorization flow if expired

#### Issue 4: "Access token expired"

**Cause:** Token older than 1 hour

**Solution:**
- Use refresh token to get new access token

```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

#### Issue 5: "Invalid client"

**Cause:** Client not registered or wrong credentials

**Solution:**
- Register client first
- Verify client_id and client_secret
- Check client exists in storage

### Debug Mode

**Enable detailed logging:**

```bash
# Set environment variable
DEBUG=oauth:* npx mcp-cisco-support --http

# Or modify code temporarily
logger.level = 'debug';
```

**Check server logs:**
```bash
# Look for OAuth events
grep "OAuth" /var/log/mcp-server.log

# Check token validation
grep "token validation" /var/log/mcp-server.log
```

## References

### RFCs and Standards

- **[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)** - The OAuth 2.0 Authorization Framework
- **[RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)** - Proof Key for Code Exchange (PKCE)
- **[RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)** - OAuth 2.0 Authorization Server Metadata
- **[RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)** - OAuth 2.0 Dynamic Client Registration
- **[RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)** - OAuth 2.0 Token Revocation
- **[OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09)** - OAuth 2.1 Authorization Framework

### MCP Specifications

- **[MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)** - MCP OAuth 2.1 Authorization
- **[MCP Protocol](https://modelcontextprotocol.io/)** - Model Context Protocol Documentation

### Additional Resources

- **[OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)** - Security recommendations
- **[OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)** - Mobile and desktop apps
- **[PKCE Explained](https://www.oauth.com/oauth2-servers/pkce/)** - Visual guide to PKCE

---

**Document Version:** 1.0
**Last Updated:** 2025-01-30
**MCP Server Version:** 1.17.0+
**Author:** Claude (Anthropic)
