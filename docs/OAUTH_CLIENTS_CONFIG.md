# OAuth 2.1 Clients Configuration

This document explains how to configure pre-authorized OAuth 2.1 clients using JSON configuration files.

## Overview

Instead of using dynamic client registration where any client can register at runtime, you can pre-configure specific OAuth clients that are allowed to authenticate with your MCP server.

**Benefits:**
- **Security**: Control exactly which applications can access your server
- **Version Control**: Track authorized clients in git (without secrets)
- **Hot Reload**: Update client configuration without restarting the server
- **Flexible Secrets**: Separate client secrets from main config for better security

## Configuration Files

### Primary Config: `config/oauth-clients.json`

Contains client metadata (can be committed to git):
- Client IDs
- Redirect URIs
- Scopes
- Grant types
- Client descriptions
- Enable/disable flags

### Secrets Config: `config/oauth-secrets.json` (Optional)

Contains client secrets (should be gitignored):
- Client secret mappings
- Separated for security
- Only needed for confidential clients

## File Structure

### oauth-clients.json

```json
{
  "clients": [
    {
      "client_id": "mcp_inspector_prod",
      "client_uri": "https://modelcontextprotocol.io",
      "redirect_uris": [
        "https://inspector.example.com/oauth/callback"
      ],
      "scopes": ["mcp"],
      "grant_types": ["authorization_code", "refresh_token"],
      "description": "MCP Inspector - Production",
      "enabled": true
    },
    {
      "client_id": "mcp_inspector_dev",
      "client_uri": "http://localhost:6274",
      "redirect_uris": [
        "http://localhost:6274/oauth/callback"
      ],
      "scopes": ["mcp"],
      "grant_types": ["authorization_code"],
      "description": "MCP Inspector - Local Development",
      "enabled": true
    }
  ],
  "settings": {
    "allow_dynamic_registration": false,
    "require_client_secret": false,
    "token_expiry_seconds": 3600,
    "refresh_token_expiry_seconds": 86400
  }
}
```

### oauth-secrets.json (gitignored)

```json
{
  "secrets": {
    "mcp_inspector_prod": "your_production_secret_here_change_me"
  }
}
```

## OAuth Scopes

The server supports fine-grained access control through OAuth scopes. Each scope maps to a specific Cisco Support API:

| Scope | API Access | Description |
|-------|-----------|-------------|
| `mcp` | **All APIs** | Full access to all MCP tools and APIs (default) |
| `mcp:bug` | Bug Search API | Bug search, details, and product-specific queries |
| `mcp:case` | Case Management API | Support case operations and management |
| `mcp:eox` | End-of-Life API | Product lifecycle and EoL information |
| `mcp:psirt` | Security Advisory API | Security vulnerabilities and advisories |
| `mcp:product` | Product Information API | Product details and specifications |
| `mcp:software` | Software Suggestions API | Software recommendations and upgrades |
| `mcp:serial` | Serial Number API | Serial number lookup and warranty info |
| `mcp:rma` | RMA API | Return authorization tracking |
| `mcp:smart_bonding` | Smart Bonding API | Ticket management (experimental) |

### Scope Configuration Examples

**Full access (default)**:
```json
{
  "scopes": ["mcp"]
}
```

**Specific API access**:
```json
{
  "scopes": ["mcp:bug", "mcp:psirt"]  // Only Bug and Security APIs
}
```

**Multiple APIs**:
```json
{
  "scopes": ["mcp:case", "mcp:rma", "mcp:eox"]  // Support operations focus
}
```

**Security Best Practice**: Only grant scopes that the application actually needs. This follows the principle of least privilege.

### How Scopes Work

**In OAuth 2.1 Mode (`AUTH_TYPE=oauth2.1`)**:
1. The server enables ALL APIs at startup (ignores `SUPPORT_API` env var)
2. Clients request specific scopes during authorization (e.g., `mcp:bug mcp:psirt`)
3. The authorization server validates and stores scopes in the access token
4. Each API request validates the token and attaches scopes to the request context

**Token Scope Validation**:
```typescript
// OAuth middleware attaches scopes to each request:
req.oauth_scopes = ['mcp:bug', 'mcp:psirt']  // From access token
req.oauth_client_id = 'bug_search_app'
```

**Future Enhancement**: Per-request tool filtering based on token scopes (currently all registered tools are available to authenticated clients).

**In Bearer Token or stdio Mode**:
- Scopes are not used
- API access is controlled by the `SUPPORT_API` environment variable
- All clients with a valid token have the same API access

## Client Types

### Public Clients (PKCE-only)

For clients that cannot securely store secrets (desktop apps, mobile apps, web apps):

```json
{
  "client_id": "mcp_inspector_dev",
  "client_uri": "http://localhost:6274",
  "redirect_uris": ["http://localhost:6274/oauth/callback"],
  "scopes": ["mcp"],
  "grant_types": ["authorization_code"],
  "description": "Public client - no secret needed, PKCE required"
}
```

**No secret needed** - PKCE provides security.

### Confidential Clients (with secret)

For clients that can securely store secrets (backend services):

```json
// In oauth-clients.json
{
  "client_id": "backend_service",
  "client_uri": "https://api.company.com",
  "redirect_uris": ["https://api.company.com/oauth/callback"],
  "scopes": ["mcp"],
  "grant_types": ["authorization_code", "client_credentials"],
  "description": "Backend service with secret"
}

// In oauth-secrets.json
{
  "secrets": {
    "backend_service": "super_secret_value_keep_this_safe"
  }
}
```

## Configuration Settings

### allow_dynamic_registration

- **Type**: boolean
- **Default**: true
- **Description**: Allow clients to register at runtime via `/register` endpoint
- **Recommended**: Set to `false` in production if you only want pre-configured clients

```json
{
  "settings": {
    "allow_dynamic_registration": false
  }
}
```

### require_client_secret

- **Type**: boolean
- **Default**: false
- **Description**: Require all clients to have a secret (disables public clients)
- **Recommended**: Keep as `false` to support both public and confidential clients

### token_expiry_seconds

- **Type**: integer
- **Default**: 3600 (1 hour)
- **Description**: How long access tokens remain valid

### refresh_token_expiry_seconds

- **Type**: integer
- **Default**: 86400 (24 hours)
- **Description**: How long refresh tokens remain valid

## Setup Instructions

### Step 1: Copy Example Files

```bash
cp config/oauth-clients.example.json config/oauth-clients.json
cp config/oauth-secrets.example.json config/oauth-secrets.json
```

### Step 2: Configure Clients

Edit `config/oauth-clients.json`:

```json
{
  "clients": [
    {
      "client_id": "your_app_prod",
      "client_uri": "https://your-app.com",
      "redirect_uris": ["https://your-app.com/oauth/callback"],
      "scopes": ["mcp"],
      "grant_types": ["authorization_code"],
      "description": "Your production application",
      "enabled": true
    }
  ],
  "settings": {
    "allow_dynamic_registration": false
  }
}
```

### Step 3: Add Secrets (if needed)

Edit `config/oauth-secrets.json`:

```json
{
  "secrets": {
    "your_app_prod": "generate_a_secure_random_secret_here"
  }
}
```

### Step 4: Configure Environment

In `.env`:

```bash
# OAuth 2.1 mode
AUTH_TYPE=oauth2.1

# Optional: Custom paths
OAUTH_CLIENTS_CONFIG=config/oauth-clients.json
OAUTH_SECRETS_CONFIG=config/oauth-secrets.json
```

### Step 5: Start Server

```bash
npm run oauth:dev
```

Server will log loaded clients:

```
[INFO] OAuth client secrets loaded
       secretsPath: config/oauth-secrets.json
       client_count: 1

[INFO] Loaded pre-configured OAuth client
       client_id: your_app_prod
       client_uri: https://your-app.com
       has_secret: true
       secret_source: secrets_file
       description: Your production application

[INFO] OAuth clients configuration loaded
       total_clients: 1
       allow_dynamic_registration: false
```

## Hot Reload

The server automatically watches both config files and reloads when they change:

```bash
# Edit config files
vim config/oauth-clients.json

# Server automatically reloads
[INFO] OAuth clients config file changed, reloading...
[INFO] OAuth clients configuration loaded
```

No server restart needed!

## Security Best Practices

1. **Never commit secrets**
   - Add `config/oauth-secrets.json` to `.gitignore`
   - Use `.example.json` files for templates

2. **Use separate secrets file**
   - Keep main config in version control
   - Keep secrets file out of version control

3. **Disable dynamic registration in production**
   ```json
   {
     "settings": {
       "allow_dynamic_registration": false
     }
   }
   ```

4. **Use HTTPS in production**
   - All `redirect_uris` should use `https://`
   - Only allow `http://localhost` for development

5. **Rotate secrets periodically**
   - Update `oauth-secrets.json`
   - Server hot-reloads automatically

## Troubleshooting

### Client Not Found

If you see "Client not found" errors:

1. Check client_id matches exactly:
   ```json
   {
     "client_id": "mcp_inspector_dev"  // Must match exactly
   }
   ```

2. Check client is enabled:
   ```json
   {
     "client_id": "...",
     "enabled": true  // Not false
   }
   ```

3. Check server logs for loading errors:
   ```
   [ERROR] Failed to load OAuth clients config
   ```

### Dynamic Registration Disabled

If dynamic registration fails with "access_denied":

This is expected if you have:
```json
{
  "settings": {
    "allow_dynamic_registration": false
  }
}
```

Solution: Add the client to `oauth-clients.json` instead.

### Redirect URI Mismatch

If authorization fails with redirect URI errors:

1. Ensure exact match:
   ```json
   {
     "redirect_uris": [
       "http://localhost:6274/oauth/callback"  // Must match exactly
     ]
   }
   ```

2. For localhost with varying ports, use wildcard:
   ```json
   {
     "redirect_uris": [
       "http://localhost:*/oauth/callback"  // Allows any port
     ]
   }
   ```

### Secret Not Loading

If confidential client behaves like public client:

1. Check secret file exists:
   ```bash
   ls config/oauth-secrets.json
   ```

2. Check JSON syntax is valid:
   ```bash
   cat config/oauth-secrets.json | jq
   ```

3. Check client_id matches:
   ```json
   {
     "secrets": {
       "exact_client_id_here": "secret_value"
     }
   }
   ```

4. Check server logs:
   ```
   [INFO] Loaded pre-configured OAuth client
          secret_source: secrets_file  // Should say this
   ```

## Migration from Dynamic Registration

If you've been using dynamic registration and want to switch to pre-configured clients:

1. Note the client_id and redirect_uris from existing registrations
2. Add them to `oauth-clients.json`
3. If needed, generate and add secrets to `oauth-secrets.json`
4. Set `allow_dynamic_registration: false`
5. Restart server

Existing clients will need to re-authenticate, but configuration will persist across restarts.

## Example Configurations

### Development Setup (Mixed)

```json
{
  "clients": [
    {
      "client_id": "mcp_inspector_dev",
      "client_uri": "http://localhost:6274",
      "redirect_uris": ["http://localhost:6274/oauth/callback"],
      "scopes": ["mcp"],
      "grant_types": ["authorization_code"],
      "description": "Local development",
      "enabled": true
    }
  ],
  "settings": {
    "allow_dynamic_registration": true,  // Allow others to register
    "require_client_secret": false
  }
}
```

### Production Setup (Locked Down)

```json
{
  "clients": [
    {
      "client_id": "production_web_app",
      "client_uri": "https://app.company.com",
      "redirect_uris": ["https://app.company.com/oauth/callback"],
      "scopes": ["mcp"],
      "grant_types": ["authorization_code", "refresh_token"],
      "description": "Production web application - Full API access",
      "enabled": true
    },
    {
      "client_id": "mobile_app",
      "client_uri": "https://company.com",
      "redirect_uris": ["com.company.app://oauth/callback"],
      "scopes": ["mcp:bug", "mcp:psirt", "mcp:case"],
      "grant_types": ["authorization_code"],
      "description": "Mobile app - Limited to bug search, security, and case management",
      "enabled": true
    },
    {
      "client_id": "security_scanner",
      "client_uri": "https://security.company.com",
      "redirect_uris": ["https://security.company.com/oauth/callback"],
      "scopes": ["mcp:psirt", "mcp:eox"],
      "grant_types": ["authorization_code", "refresh_token"],
      "description": "Security scanning tool - Only security and lifecycle data",
      "enabled": true
    }
  ],
  "settings": {
    "allow_dynamic_registration": false,  // Only pre-configured clients
    "require_client_secret": false,  // Allow public clients (mobile)
    "token_expiry_seconds": 1800,  // 30 minutes
    "refresh_token_expiry_seconds": 604800  // 7 days
  }
}
```

With `oauth-secrets.json`:
```json
{
  "secrets": {
    "production_web_app": "highly_secure_random_string_here"
  }
}
```

Note: `mobile_app` has no secret (public client with PKCE).
