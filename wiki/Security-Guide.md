# Security Guide

The Cisco Support MCP Server implements comprehensive security measures for both local and remote access patterns.

## Transport Security Modes

### stdio Mode (Default)
- **No authentication required** - Direct MCP client connection
- **Use case**: Claude Desktop, local MCP clients
- **Security**: Inherits security from the host MCP client

### HTTP Mode (--http)
- **Bearer Token Authentication** - Required for all HTTP endpoints
- **Use case**: Remote access, web applications, API integration
- **Security**: Token-based authentication with secure headers

## Bearer Token Management

### Generate a New Token

```bash
npx mcp-cisco-support --generate-token
```

This will output a cryptographically secure random token that you can use for authentication.

### Use a Custom Token

```bash
export MCP_BEARER_TOKEN=your_custom_token_here
npx mcp-cisco-support --http
```

### Add to .env File

```bash
# Custom Bearer token for HTTP authentication
MCP_BEARER_TOKEN=your_custom_secure_token_here
```

### Disable Authentication (⚠️ NOT RECOMMENDED)

**Only for development/testing environments:**

```bash
export DANGEROUSLY_OMIT_AUTH=true
npx mcp-cisco-support --http
```

## Authentication Methods

### Bearer Header (Recommended)

```bash
curl -H "Authorization: Bearer your_token_here" \
     -X POST http://localhost:3000/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
```

### Query Parameter (Fallback)

```bash
curl -X POST "http://localhost:3000/mcp?token=your_token_here" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"ping","id":1}'
```

## Security Best Practices

### 1. Strong Token Generation
- Always use the `--generate-token` command for production tokens
- Tokens are 32-character cryptographically secure random strings
- Never use predictable or simple tokens

### 2. Secure Token Storage
- Store tokens in environment variables or `.env` files
- Never commit tokens to version control
- Use different tokens for different environments

### 3. Network Security
- Use HTTPS in production deployments
- Consider network-level restrictions (VPN, firewall rules)
- Monitor access logs for suspicious activity

### 4. Token Rotation
- Regularly generate new tokens
- Implement token rotation policies for production systems
- Revoke old tokens when rotating

### 5. Access Control
- Only expose HTTP mode to trusted networks
- Use stdio mode for local-only access
- Implement proper network segmentation

## Cisco API Security

### OAuth2 Credentials
- Store `CISCO_CLIENT_ID` and `CISCO_CLIENT_SECRET` securely
- Use environment variables, never hardcode credentials
- Rotate credentials according to Cisco's recommendations

### Token Management
- OAuth2 tokens are automatically managed by the server
- Tokens are cached in memory only (not persisted)
- Automatic refresh 30 minutes before expiry

## Docker Security

### Secure Deployment

```bash
docker run -p 3000:3000 \
  -e CISCO_CLIENT_ID=your_client_id \
  -e CISCO_CLIENT_SECRET=your_client_secret \
  -e SUPPORT_API=bug,case,eox \
  -e MCP_BEARER_TOKEN=your_secure_token \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest --http
```

### Security Features
- **Non-root execution**: Container runs as non-root user
- **Minimal base image**: Alpine Linux for reduced attack surface
- **Health checks**: Built-in health monitoring
- **Security headers**: Helmet middleware for HTTP security

## Security Headers

The server automatically applies these security headers:

- **Content Security Policy**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Restricts browser features

## CORS Configuration

Cross-Origin Resource Sharing is configured to:
- Allow all origins in development
- Require explicit configuration in production
- Support preflight requests
- Include credentials when needed

## Input Validation

All MCP tools implement:
- **JSON Schema validation**: Strict parameter validation
- **Type checking**: TypeScript type safety
- **Sanitization**: Input cleaning and validation
- **Rate limiting**: Protection against abuse

## Monitoring and Logging

### Security Event Logging
- Authentication failures
- Invalid token attempts
- Unusual request patterns
- API errors and timeouts

### Log Format
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "warn",
  "message": "Authentication failed",
  "ip": "192.168.1.100",
  "userAgent": "curl/7.64.1",
  "endpoint": "/mcp"
}
```

## Environment Variables Security

### Required Variables
```bash
# Cisco API credentials (REQUIRED)
CISCO_CLIENT_ID=your_client_id_here
CISCO_CLIENT_SECRET=your_client_secret_here

# Bearer token for HTTP mode (OPTIONAL - auto-generated if not set)
MCP_BEARER_TOKEN=your_secure_token
```

### Optional Security Variables
```bash
# Server configuration
PORT=3000
NODE_ENV=production

# API configuration
SUPPORT_API=bug,case,eox

# Development/testing only (NEVER use in production)
DANGEROUSLY_OMIT_AUTH=false
```

## Security Checklist

### Before Deployment
- [ ] Generate secure bearer token
- [ ] Set strong Cisco API credentials
- [ ] Configure environment variables properly
- [ ] Enable HTTPS in production
- [ ] Set up proper network security
- [ ] Configure log monitoring

### Regular Maintenance
- [ ] Rotate bearer tokens
- [ ] Monitor access logs
- [ ] Update dependencies
- [ ] Review security configurations
- [ ] Check for security updates

### Emergency Response
- [ ] Revoke compromised tokens immediately
- [ ] Review access logs for suspicious activity
- [ ] Update all affected credentials
- [ ] Implement additional security measures
- [ ] Document incident and lessons learned