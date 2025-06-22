# Troubleshooting Guide

Comprehensive troubleshooting guide for common issues with the Cisco Support MCP Server.

## Common Issues

### 1. Authentication Errors

#### Symptoms
- "OAuth2 Authentication Failed" messages
- 401 Unauthorized responses
- Health endpoint shows authentication issues

#### Solutions

**Verify Cisco API Credentials:**
```bash
# Check environment variables are set
echo $CISCO_CLIENT_ID
echo $CISCO_CLIENT_SECRET

# Test credentials manually
curl -X POST https://id.cisco.com/oauth2/default/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_ID&client_secret=YOUR_SECRET"
```

**Common Credential Issues:**
- Incorrect Client ID or Secret
- Expired or revoked credentials
- Missing Bug API access permissions
- Network connectivity issues to `https://id.cisco.com`

**Check Application Permissions:**
1. Visit [Cisco API Console](https://apiconsole.cisco.com/)
2. Verify your application has Bug API access
3. Ensure application status is "Active"
4. Check API usage quotas

### 2. Network Timeouts

#### Symptoms
- Requests timing out after 30 seconds
- Intermittent connection failures
- "Network request failed" errors

#### Solutions

**Check Network Connectivity:**
```bash
# Test Cisco API connectivity
curl -I https://apix.cisco.com/bug/v2.0/bugs/bug_ids/CSCab12345

# Test OAuth endpoint
curl -I https://id.cisco.com/oauth2/default/v1/token

# Check DNS resolution
nslookup apix.cisco.com
```

**Firewall Configuration:**
- Allow outbound HTTPS (443) to `*.cisco.com`
- Allow outbound HTTPS to `apix.cisco.com`
- Allow outbound HTTPS to `id.cisco.com`

**Proxy Configuration:**
```bash
# Set proxy if required
export HTTPS_PROXY=http://proxy.company.com:8080
export HTTP_PROXY=http://proxy.company.com:8080
```

### 3. MCP Server Connection Issues

#### Symptoms
- "Command not found" errors in Claude Desktop
- MCP server not loading
- Connection refused errors

#### Solutions

**NPX Installation Issues:**
```bash
# Clear NPX cache
npx --clear

# Install globally instead
npm install -g mcp-cisco-support

# Verify installation
which mcp-cisco-support
```

**Node.js Version:**
```bash
# Check Node.js version (requires 18+)
node --version

# Update Node.js if needed
npm install -g n
sudo n stable
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id_here",
        "CISCO_CLIENT_SECRET": "your_client_secret_here"
      }
    }
  }
}
```

### 4. HTTP Mode Authentication

#### Symptoms
- 401/403 responses in HTTP mode
- "Authentication required" errors
- Bearer token not working

#### Solutions

**Generate New Token:**
```bash
# Generate secure token
npx mcp-cisco-support --generate-token

# Use generated token
export MCP_BEARER_TOKEN=generated_token_here
```

**Test Authentication:**
```bash
# Test with Bearer header
curl -H "Authorization: Bearer your_token" http://localhost:3000/ping

# Test with query parameter
curl "http://localhost:3000/ping?token=your_token"
```

**Disable Authentication (Development Only):**
```bash
export DANGEROUSLY_OMIT_AUTH=true
npx mcp-cisco-support --http
```

### 5. Test Failures

#### Symptoms
- Jest tests failing
- Mock data issues
- Integration test failures

#### Solutions

**Run Tests Individually:**
```bash
# Test specific suite
npm test -- --testNamePattern="Bug API"

# Run with verbose output
npm test -- --verbose

# Check for state leakage
npm test -- --runInBand
```

**Environment Variables for Tests:**
```bash
# Set test credentials
export CISCO_CLIENT_ID=test_id
export CISCO_CLIENT_SECRET=test_secret

# Run integration tests
npm test -- --testNamePattern="Integration"
```

**Clear Test Cache:**
```bash
# Clear Jest cache
npx jest --clearCache

# Reset node_modules
rm -rf node_modules package-lock.json
npm install
```

### 6. Docker Issues

#### Symptoms
- Container won't start
- Environment variables not working
- Health check failures

#### Solutions

**Check Docker Logs:**
```bash
# View container logs
docker logs container_name

# Follow logs in real-time
docker logs -f container_name

# Check container status
docker ps -a
```

**Environment Variable Issues:**
```bash
# Test environment variables
docker run --rm -e CISCO_CLIENT_ID=test \
  ghcr.io/sieteunoseis/mcp-cisco-support:latest \
  sh -c 'echo $CISCO_CLIENT_ID'
```

**Port Binding:**
```bash
# Check port conflicts
netstat -tulpn | grep 3000

# Use different port
docker run -p 8080:3000 ...
```

## Debugging Commands

### Server Health Check

```bash
# Basic health check
curl http://localhost:3000/health

# Detailed health with authentication
curl -H "Authorization: Bearer your_token" http://localhost:3000/health
```

### Enable Debug Logging

```bash
# Development mode with debug output
NODE_ENV=development npm run dev

# Specific debug categories
DEBUG=cisco-support:* npm run dev

# Debug with timestamps
DEBUG=cisco-support:* npm run dev 2>&1 | ts '[%Y-%m-%d %H:%M:%S]'
```

### Test Individual Components

```bash
# Test MCP protocol
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"test","method":"ping"}'

# Test specific tool
node test-tool.js search_bugs_by_keyword mock

# Test OAuth flow
curl -X POST https://id.cisco.com/oauth2/default/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CISCO_CLIENT_ID&client_secret=$CISCO_CLIENT_SECRET"
```

### Monitor Real-time Logs

**macOS - Claude Desktop Logs:**
```bash
# Follow MCP logs
tail -n 20 -F ~/Library/Logs/Claude/mcp*.log

# Search for errors
grep -i error ~/Library/Logs/Claude/mcp*.log

# Search for cisco-support
grep -i "cisco-support" ~/Library/Logs/Claude/mcp*.log
```

**Windows - Claude Desktop Logs:**
```cmd
# Check logs directory
%APPDATA%\Claude\logs\

# Use PowerShell to monitor
Get-Content -Path "$env:APPDATA\Claude\logs\mcp*.log" -Wait
```

**Docker Logs:**
```bash
# Follow container logs
docker logs -f cisco-support-container

# View last 100 lines
docker logs --tail 100 cisco-support-container
```

## Configuration Validation

### Check Configuration Files

```bash
# Validate JSON configuration
python -m json.tool claude_desktop_config.json

# Check environment variables
env | grep CISCO

# Validate .env file
cat .env | grep -v '^#' | grep -v '^$'
```

### Test Configuration

```bash
# Test stdio mode
npx mcp-cisco-support --validate-config

# Test HTTP mode
npx mcp-cisco-support --http --validate-config

# Test with specific API configuration
SUPPORT_API=bug,case npx mcp-cisco-support --validate-config
```

## Performance Issues

### Memory Usage

```bash
# Monitor memory usage
ps aux | grep mcp-cisco-support

# Node.js memory debugging
node --inspect --max-old-space-size=4096 dist/index.js

# Docker memory limits
docker stats cisco-support-container
```

### Network Performance

```bash
# Test API response times
time curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list"}'

# Monitor network connections
netstat -an | grep 3000

# Check DNS resolution time
time nslookup apix.cisco.com
```

## Error Code Reference

### HTTP Status Codes

- **200**: Success
- **400**: Bad Request - Invalid parameters
- **401**: Unauthorized - Authentication required
- **403**: Forbidden - Invalid or expired token
- **404**: Not Found - Invalid endpoint
- **429**: Too Many Requests - Rate limited
- **500**: Internal Server Error - Server issue
- **503**: Service Unavailable - Cisco API down

### Cisco API Error Codes

- **400**: Invalid request parameters
- **401**: Invalid or expired OAuth token
- **403**: Insufficient permissions
- **404**: Bug/resource not found
- **429**: Rate limit exceeded
- **500**: Cisco API internal error
- **502/503**: Cisco API temporarily unavailable

## Getting Help

### Log Collection

When reporting issues, collect these logs:

```bash
# Server logs
npm run dev > debug.log 2>&1

# Health status
curl http://localhost:3000/health > health.json

# Configuration (remove secrets)
env | grep -E '^(NODE_|CISCO_|SUPPORT_|MCP_)' | sed 's/SECRET=.*/SECRET=***/' > env.txt

# System information
node --version > system.txt
npm --version >> system.txt
uname -a >> system.txt
```

### Support Resources

- **GitHub Issues**: [Project Issues](https://github.com/sieteunoseis/mcp-cisco-support/issues)
- **Cisco Developer**: [Support APIs Documentation](https://developer.cisco.com/docs/support-apis/)
- **MCP Protocol**: [Model Context Protocol](https://modelcontextprotocol.io/)

### Before Reporting Issues

1. **Check existing issues** on GitHub
2. **Verify configuration** with validation commands
3. **Test with minimal setup** (single API, no custom config)
4. **Collect relevant logs** and error messages
5. **Include environment details** (OS, Node.js version, etc.)

## Quick Fixes Checklist

- [ ] Verify Node.js 18+ is installed
- [ ] Check Cisco API credentials are correct
- [ ] Ensure network connectivity to Cisco APIs
- [ ] Restart Claude Desktop completely
- [ ] Clear NPX cache: `npx --clear`
- [ ] Test with minimal configuration
- [ ] Check for typos in config files
- [ ] Verify JSON syntax in Claude Desktop config
- [ ] Test authentication manually
- [ ] Check firewall/proxy settings