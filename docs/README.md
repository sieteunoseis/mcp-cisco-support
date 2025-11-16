# Documentation

**For comprehensive user documentation, visit the [GitHub Wiki](https://github.com/sieteunoseis/mcp-cisco-support/wiki).**

---

## 📚 User Documentation (Wiki)

All user-facing documentation has been moved to the GitHub Wiki for better organization and discoverability:

### Getting Started
- [Home](https://github.com/sieteunoseis/mcp-cisco-support/wiki) - Project overview and quick links
- [Advanced Configuration](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Advanced-Configuration) - Environment variables and setup
- [Available Tools](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Available-Tools) - Complete tool reference

### Core Features
- [OAuth 2.1 Authentication](https://github.com/sieteunoseis/mcp-cisco-support/wiki/OAuth-2.1-Authentication) 🔒 - Production OAuth server with scope-based access control
- [TOON Format](https://github.com/sieteunoseis/mcp-cisco-support/wiki/TOON-Format) 📝 - Enhanced response formatting
- [MCP Sampling](https://github.com/sieteunoseis/mcp-cisco-support/wiki/MCP-Sampling) - AI-powered tools
- [MCP Resources](https://github.com/sieteunoseis/mcp-cisco-support/wiki/MCP-Resources) - Resource URIs and templates
- [Progress Notifications](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Progress-Notifications) - Real-time operation updates
- [Security Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Security-Guide) - Authentication and best practices

### Development & Deployment
- [Development Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Development-Guide) - Architecture and contributions
- [Docker Deployment](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Docker-Deployment) - Container deployment
- [Testing Framework](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Testing-Framework) - Testing methodology
- [Troubleshooting Guide](https://github.com/sieteunoseis/mcp-cisco-support/wiki/Troubleshooting-Guide) - Common issues

---

## 🛠️ Technical Reference (This Directory)

This directory contains technical implementation documentation and reference materials:

### Active Documentation

1. **[OAUTH_CLIENTS_CONFIG.md](./OAUTH_CLIENTS_CONFIG.md)** - OAuth 2.1 Configuration Reference
   - Detailed OAuth client configuration guide
   - Configuration file schemas and examples
   - Hot-reload configuration
   - Security best practices
   - **When to use:** Setting up OAuth 2.1 clients and troubleshooting config issues

2. **[tool-examples.md](./tool-examples.md)** - MCP Tool Usage Examples
   - Comprehensive examples for all 60+ MCP tools
   - Usage patterns and best practices
   - API parameter documentation
   - **When to use:** Understanding tool parameters and building integrations

### Implementation Analysis

3. **[PRODUCT_AUTOCOMPLETE_IMPLEMENTATION.md](./PRODUCT_AUTOCOMPLETE_IMPLEMENTATION.md)** - Product Autocomplete Guide
   - MCP product autocomplete resources implementation
   - User-provided cookie authentication setup
   - Cookie lifecycle management
   - **When to use:** Understanding product autocomplete feature

4. **[PRODUCT_AUTOCOMPLETE_SOLUTIONS.md](./PRODUCT_AUTOCOMPLETE_SOLUTIONS.md)** - Design Analysis
   - Analysis of 5 different solution approaches
   - Design decision rationale
   - Future enhancement possibilities
   - **When to use:** Understanding architecture decisions

### Research Documents

5. **[CISCO_COOKIE_ANALYSIS.md](./CISCO_COOKIE_ANALYSIS.md)** - Cookie Lifecycle Research
   - Cookie authentication patterns
   - 24-hour validity analysis
   - Refresh strategies
   - **When to use:** Understanding Cisco API authentication behavior

6. **[ISR4431_SEARCH_ANALYSIS.md](./ISR4431_SEARCH_ANALYSIS.md)** - Bug Fix Analysis
   - Root cause analysis of search failures
   - Enhanced fallback logic
   - Multi-severity search improvements
   - **When to use:** Understanding bug search enhancements

---

## 📦 Archive

Historical documentation and implementation summaries have been moved to [archive/](./archive/):

- OAuth 2.1 implementation history
- MCP enhancement proposals
- Feature implementation summaries
- Wiki drafts (now published to GitHub Wiki)
- API roadmaps and planning docs

**Note:** Archive documents are kept for historical reference but may be outdated. Always refer to the GitHub Wiki for current documentation.

---

## 📝 Documentation Structure

```
docs/
├── README.md (this file)                          # Documentation index
├── OAUTH_CLIENTS_CONFIG.md                        # OAuth config reference
├── tool-examples.md                               # Tool usage examples
├── PRODUCT_AUTOCOMPLETE_IMPLEMENTATION.md         # Autocomplete guide
├── PRODUCT_AUTOCOMPLETE_SOLUTIONS.md              # Design analysis
├── CISCO_COOKIE_ANALYSIS.md                       # Cookie research
├── ISR4431_SEARCH_ANALYSIS.md                     # Search bug fix
└── archive/                                       # Historical docs
    ├── OAUTH2_AUTHENTICATION.md                   # Original OAuth guide (see wiki)
    ├── wiki-drafts/                               # Old wiki drafts (published)
    └── [other historical documents]
```

---

## 🔗 Quick Links

- **Main Repository:** https://github.com/sieteunoseis/mcp-cisco-support
- **GitHub Wiki:** https://github.com/sieteunoseis/mcp-cisco-support/wiki
- **NPM Package:** https://www.npmjs.com/package/mcp-cisco-support
- **Issue Tracker:** https://github.com/sieteunoseis/mcp-cisco-support/issues
- **Glama.ai Listing:** https://glama.ai/mcp/servers/@sieteunoseis/mcp-cisco-support
- **Cisco Code Exchange:** https://developer.cisco.com/codeexchange/github/repo/sieteunoseis/mcp-cisco-support

---

**Last Updated:** November 15, 2025 | **Version:** 1.18.0
