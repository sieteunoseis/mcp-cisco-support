# Cisco Support MCP Server Wiki

**Welcome to the comprehensive documentation for the Cisco Support MCP Server!**

[![npm version](https://img.shields.io/npm/v/mcp-cisco-support.svg)](https://www.npmjs.com/package/mcp-cisco-support)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.13.0-green.svg)](https://modelcontextprotocol.io/)

---

## Quick Links

- 🏠 [GitHub Repository](https://github.com/sieteunoseis/mcp-cisco-support)
- 📦 [NPM Package](https://www.npmjs.com/package/mcp-cisco-support)
- 🐛 [Issue Tracker](https://github.com/sieteunoseis/mcp-cisco-support/issues)
- 📚 [MCP Specification](https://modelcontextprotocol.io/specification)

---

## Project Status

**Current Version:** 1.12.0 (October 2025)

**Status:** ✅ Production Ready

### API Implementation Progress

| API | Status | Tools | Description |
|-----|--------|-------|-------------|
| **Bug** | ✅ Complete | 14 | Bug search, details, product-specific queries, smart analysis |
| **Case** | ✅ Complete | 4 | Support case management and operations |
| **EoX** | ✅ Complete | 4 | End-of-Life/Sale information and lifecycle tracking |
| **PSIRT** | ✅ Complete | 8 | Security vulnerability data and advisories |
| **Product** | ✅ Complete | 6 | Product details, specifications, and MDF information |
| **Software** | ✅ Complete | 6 | Software suggestions and upgrade recommendations |
| **Serial** | ✅ Complete | 3 | Serial number mapping, coverage, and warranty info |
| **RMA** | ✅ Complete | 3 | Return Merchandise Authorization tracking |
| **Smart Bonding** | ⚠️ Experimental | 8 | Smart Bonding ticket lifecycle management (UNTESTED) |

**Total:** 56 MCP tools across 9 Cisco Support APIs

### MCP Features Implemented

| Feature | Status | Description |
|---------|--------|-------------|
| **Tools** | ✅ Implemented | 56 tools across all Cisco Support APIs |
| **Prompts** | ✅ Implemented | 11 pre-built workflow templates |
| **Resources** | ✅ Implemented ✨ NEW | Structured data access via URIs |
| **Ping** | ✅ Implemented | Connectivity and health checks |
| **ElicitationRequest** | ✅ Experimental | Dynamic user interaction (limited client support) |
| **Progress Notifications** | 🔄 Planned | Real-time operation updates |
| **Sampling** | 🔄 Planned | Server-initiated LLM requests |
| **Logging** | 🔄 Planned | MCP-compliant structured logging |

---

## What's New in v1.12.0

### MCP Resources ✨ NEW
- **Static Resources:** Pre-defined datasets (recent bugs, advisories, etc.)
- **Resource Templates:** Dynamic URI patterns for any bug/product/CVE
- **50% Fewer API Calls:** Client-side caching and proactive fetching
- **URI Scheme:** `cisco://bugs/{id}`, `cisco://products/{id}`, `cisco://security/cve/{id}`

[Learn more about MCP Resources →](MCP-Resources)

### Smart Bonding API ⚠️ EXPERIMENTAL
- **8 New Tools:** Complete ticket lifecycle management
- **Separate Authentication:** Different OAuth2 endpoint from standard APIs
- **File Upload Support:** HTTPS PUT mechanism with temporary credentials
- **Status:** UNTESTED - Requires Cisco Account Manager credentials

### All Cisco Support APIs Complete
- ✅ Bug, Case, EoX, PSIRT, Product, Software, Serial, RMA all implemented
- ✅ 56 total MCP tools available
- ✅ 11 workflow prompts for common scenarios
- ✅ Comprehensive test coverage (40+ tests)

---

## Documentation

### Getting Started

- [Advanced Configuration](Advanced-Configuration) - Environment variables, Claude Desktop setup, API configuration
- [Available Tools](Available-Tools) - Complete reference for all 56 MCP tools with examples
- [MCP Prompts](MCP-Prompts) - Pre-built workflow templates for common scenarios

### Core Features

- [MCP Resources](MCP-Resources) ✨ NEW - Resource URIs, templates, and usage guide
- [Suggested Search Strategies](Suggested-Search-Strategies) - Best practices for bug searches
- [Security Guide](Security-Guide) - Authentication, Bearer tokens, security best practices

### Development & Integration

- [Development Guide](Development-Guide) - Architecture, contributions, adding new APIs
- [Testing Framework](Testing-Framework) - Jest-based testing with mocks and integration tests
- [N8n Personal Assistant Integration](N8n-Personal-Assistant-Integration) - N8N platform integration
- [SSE Integration](SSE-Integration) - Server-Sent Events and real-time communication

### Deployment & Troubleshooting

- [Docker Deployment](Docker-Deployment) - Containerized deployment instructions
- [Troubleshooting Guide](Troubleshooting-Guide) - Common issues, debugging, and solutions

---

## Key Features

### 🔐 Secure Authentication
- OAuth2 client credentials flow
- Automatic token refresh
- Bearer token support for HTTP mode
- Dual authentication systems (Standard + Smart Bonding)

### ⚡ Real-time Updates
- Server-Sent Events (SSE) support
- Live tool execution monitoring
- Heartbeat messages for connection health
- Real-time resource access

### 🔍 Comprehensive Search
- 14 bug search tools with smart analysis
- Multi-severity searches
- Product-specific queries
- Version comparison tools
- Progressive search strategies

### 🛡️ Security Monitoring
- PSIRT security advisories
- CVE tracking
- Severity-based filtering
- Real-time advisory resources

### 📊 Resource Access ✨ NEW
- Static resources for common datasets
- Resource templates for dynamic URIs
- 50% reduction in duplicate API calls
- Proactive data fetching and caching

### 🧪 Comprehensive Testing
- 40+ Jest-based tests
- Mock Cisco API responses
- Integration test support
- Type-safe TypeScript implementation

---

## Supported Platforms

### MCP Clients

✅ **Claude Desktop** - Full support with stdio transport
✅ **VS Code** - MCP extension compatibility
✅ **MCP Inspector** - Complete testing and debugging
✅ **Custom Clients** - Any MCP-compliant client

### Deployment Options

✅ **NPX** - `npx mcp-cisco-support`
✅ **Docker** - Multi-platform containers (amd64, arm64)
✅ **Node.js** - Direct installation via npm
✅ **GitHub Actions** - Automated CI/CD workflows

---

## Quick Start

### Installation

```bash
# Via NPX (recommended)
npx mcp-cisco-support

# Via NPM
npm install -g mcp-cisco-support
mcp-cisco-support
```

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cisco-support": {
      "command": "npx",
      "args": ["mcp-cisco-support"],
      "env": {
        "CISCO_CLIENT_ID": "your_client_id",
        "CISCO_CLIENT_SECRET": "your_secret",
        "SUPPORT_API": "all"
      }
    }
  }
}
```

**Configuration Files:**
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

### API Configuration Options

```bash
# All APIs and tools (56 tools)
SUPPORT_API=all

# Enhanced analysis only (6 smart tools)
SUPPORT_API=enhanced_analysis

# Specific APIs
SUPPORT_API=bug,psirt,product

# Experimental Smart Bonding
SUPPORT_API=smart_bonding
```

---

## Example Queries

### Bug Searches
- "Search for recent bugs related to 'crash' in Cisco products"
- "Find bugs for product ID C9300-24P affecting version 17.5.1"
- "Show me severity 1 or higher bugs modified in the last week"

### Software Comparison
- "Compare software versions 17.9.1 and 17.12.3 for Cisco C9300-24P"
- "Should I upgrade from 15.1(4)M to 15.2(4)M on my ASR 1000?"

### Security Monitoring
- "Get the latest critical security advisories"
- "Find CVE-2018-0101 security advisory details"
- "Show me all security issues for Cisco ASR 9000"

### Resource Access ✨ NEW
- "Get cisco://bugs/recent/critical"
- "Fetch cisco://products/C9300-24P"
- "Read cisco://security/cve/CVE-2018-0101"

---

## Statistics

**API Coverage:** 9/9 Cisco Support APIs (100%)
**Total Tools:** 56 MCP tools
**Workflow Prompts:** 11 pre-built templates
**Resource URIs:** 5 static + 4 template patterns
**Test Coverage:** 40+ comprehensive tests
**Active Development:** Since 2024
**Latest Release:** v1.12.0 (October 2025)

---

## Support & Contributions

### Getting Help

- 📖 Check the [Troubleshooting Guide](Troubleshooting-Guide)
- 🐛 [Report Issues](https://github.com/sieteunoseis/mcp-cisco-support/issues)
- 💬 [Discuss on GitHub](https://github.com/sieteunoseis/mcp-cisco-support/discussions)

### Contributing

We welcome contributions! See the [Development Guide](Development-Guide) for:
- Architecture overview
- Code structure
- Adding new APIs
- Testing requirements
- Pull request process

---

## License

MIT License - see [LICENSE](https://github.com/sieteunoseis/mcp-cisco-support/blob/main/LICENSE) for details.

---

## Acknowledgments

Built with:
- [Model Context Protocol SDK](https://github.com/modelcontextprotocol/sdk) by Anthropic
- [Cisco Support APIs](https://developer.cisco.com/docs/support-apis/)
- TypeScript, Express, and the open-source community

---

**Last Updated:** October 23, 2025 | **Version:** 1.12.0 | **Maintained by:** [sieteunoseis](https://github.com/sieteunoseis)
