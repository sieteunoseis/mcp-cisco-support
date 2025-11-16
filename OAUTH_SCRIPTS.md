# OAuth 2.1 Development Scripts

Quick reference for OAuth 2.1 development npm scripts.

## Development Mode (with auto-reload)

### Start OAuth server in development mode:
```bash
npm run dev:http:oauth
# or
npm run oauth:dev
```

Both commands:
- Use `tsx watch` for automatic TypeScript reload
- Set `AUTH_TYPE=oauth2.1`
- Start HTTP server on port 3000

## Production Mode

### Build and start OAuth server:
```bash
npm run start:oauth
# or
npm run oauth:start
```

Both commands:
- Build TypeScript to JavaScript
- Set `AUTH_TYPE=oauth2.1`
- Start production HTTP server

## Testing OAuth Configuration

### Test OAuth server metadata:
```bash
npm run oauth:test
```

This fetches and pretty-prints the OAuth authorization server metadata.

Expected output:
```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/authorize",
  "token_endpoint": "http://localhost:3000/token",
  "registration_endpoint": "http://localhost:3000/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256", "plain"],
  ...
}
```

## Manual Testing

### 1. Start the server
```bash
npm run oauth:dev
```

### 2. Test public endpoints
```bash
# OAuth server metadata
curl http://localhost:3000/.well-known/oauth-authorization-server | jq

# Protected resource metadata
curl http://localhost:3000/.well-known/oauth-protected-resource/mcp | jq

# Register a client
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:3001/callback"],"client_name":"Test Client"}' | jq
```

### 3. Complete OAuth flow
See the [OAuth 2.1 Authentication Wiki](https://github.com/sieteunoseis/mcp-cisco-support/wiki/OAuth-2.1-Authentication) for complete flow examples and configuration guide.

## Comparison with Bearer Token Mode

| Script | Auth Type | Auto-reload | Build Required |
|--------|-----------|-------------|----------------|
| `npm run dev` | Bearer | Yes | No |
| `npm run dev:http` | Bearer | Yes | No |
| `npm run dev:http:oauth` | **OAuth 2.1** | Yes | No |
| `npm run oauth:dev` | **OAuth 2.1** | Yes | No |
| `npm start -- --http` | Bearer | No | Yes |
| `npm run start:oauth` | **OAuth 2.1** | No | Yes |
| `npm run oauth:start` | **OAuth 2.1** | No | Yes |

## Environment Variables

You can override OAuth settings via environment variables:

```bash
# Custom issuer URL
OAUTH2_ISSUER_URL=https://your-server.com npm run oauth:dev

# Disable dynamic client registration
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=false npm run oauth:dev

# Combine multiple settings
OAUTH2_ISSUER_URL=https://example.com \
OAUTH2_ALLOW_DYNAMIC_REGISTRATION=false \
npm run oauth:dev
```

## Troubleshooting

### Server shows "Authentication Type: BEARER" instead of "OAUTH2.1"
- Make sure you're using one of the OAuth scripts above
- Check that `AUTH_TYPE=oauth2.1` is set
- Try: `AUTH_TYPE=oauth2.1 npm run dev:http` instead of `npm run dev:http`

### 401 Unauthorized on `.well-known` endpoints
- Rebuild the project: `npm run build`
- These endpoints should be publicly accessible
- Check server logs for authentication middleware blocking requests

### MCP Jam can't discover OAuth server
- Ensure server is running with OAuth mode
- Test metadata endpoint: `npm run oauth:test`
- Check that port 3000 is accessible
