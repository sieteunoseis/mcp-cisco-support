# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.18.0] - 2025-11-15

### Added
- **TOON Format Output**: Added Text-Object-Oriented Notation (TOON) format for API responses
  - Provides structured, human-readable output by default instead of raw JSON
  - Clean hierarchical data representation with clear nesting
  - Easy navigation and consistent styling across all responses
  - New dependency: `@toon-format/toon` package for JSON-to-TOON conversion
  - Enabled by default for better readability

### Changed
- **Response Format Default**: All API responses now use TOON format by default
  - Native JSON responses still available via `DISABLE_TOON_FORMAT=true` environment variable
  - Configurable in Claude Desktop and Docker deployments
  - Better user experience with cleaner, more readable output

### Documentation
- Added comprehensive TOON format documentation to README.md:
  - "📋 TOON Format Output" section explaining benefits and usage
  - Configuration examples for enabling/disabling TOON format
  - Side-by-side comparison of TOON vs JSON output
  - Claude Desktop configuration examples with TOON settings
- Updated environment variable documentation in `.env.example`
- Added TOON format examples to usage documentation

## [1.17.0] - 2025-10-28

### Added
- **Serial Number Support in MCP Prompts**: All product-focused prompts now accept serial numbers as an alternative to product names
  - Updated 6 prompts to support `serial_number` parameter: cisco-high-severity-search, cisco-incident-investigation, cisco-upgrade-planning, cisco-maintenance-prep, cisco-security-advisory, cisco-known-issues
  - When serial number is provided, server automatically looks up product details via Serial Number API
  - Makes investigation easier when you have device serial but don't know exact product model
  - Prompts now accept either `product` OR `serial_number` (not both required)

### Changed
- **Prompt Parameter Flexibility**: Product-related parameters are now optional when serial_number is provided
  - `product_keyword` in cisco-high-severity-search is now optional (either product_keyword OR serial_number)
  - `product` parameter in 5 prompts is now optional (either product OR serial_number)
  - Updated prompt descriptions to explain either/or requirement
  - Added 'serial' API requirement to prompt API mapping

### Documentation
- Updated README MCP Prompts section with serial number support information
- Added explanation of automatic product lookup from serial numbers
- Updated prompt count from 6 to 10+ prompts
- Added prompt descriptions with emojis for better visual organization

## [1.16.0] - 2025-10-28

### Added
- **Product Autocomplete MCP Resources**: New MCP resources for searching Cisco's internal product catalog
  - `cisco://products/autocomplete/{search_term}` - Dynamic resource template for product searches
  - `cisco://products/autocomplete-help` - Static resource with comprehensive setup instructions
  - User-provided cookie authentication via `CISCO_WEB_COOKIE` environment variable
  - Cookie lifecycle management (24-hour typical validity with automatic expiration detection)
  - Graceful error handling for missing/expired cookies with helpful setup instructions
  - Security best practices documentation and warnings

### Changed
- **Enhanced Bug API Fallback Logic**: Improved `multi_severity_search` tool behavior
  - Product ID searches now fallback to keyword search when no results found (regardless of version parameter)
  - Added severity breakdown counts to all multi-severity search results
  - Better handling of product searches that return no results
- **EnhancedAnalysisApi Internal Tool Access**: Fixed internal tool execution
  - Implemented method swapping to allow EnhancedAnalysisApi to call internal Bug API tools
  - Added fallback loop in ApiRegistry for tools not in advertised list
  - Resolved issue where enhanced_analysis mode returned zero results

### Documentation
- Added new README section: "🔍 MCP Resources - Product Autocomplete"
  - Setup instructions with 4 steps
  - Cookie lifecycle and refresh guidance
  - Security best practices
  - Usage examples for Claude Desktop
- Updated Claude Desktop configuration examples to include `CISCO_WEB_COOKIE`
- Added `CISCO_WEB_COOKIE` documentation to `.env.example`
- Created comprehensive implementation documentation:
  - `docs/PRODUCT_AUTOCOMPLETE_IMPLEMENTATION.md` - Complete implementation guide
  - `docs/PRODUCT_AUTOCOMPLETE_SOLUTIONS.md` - Analysis of 5 solution approaches
  - `docs/CISCO_COOKIE_ANALYSIS.md` - Cookie lifecycle research
  - `docs/ISR4431_SEARCH_ANALYSIS.md` - Root cause analysis of search issues

### Fixed
- Fixed product ID searches returning no results when product doesn't exist in Bug API database
- Fixed severity breakdown not being included in multi-severity search responses
- Fixed EnhancedAnalysisApi unable to execute internal Bug API tools

### Security
- Cookie-based authentication requires user to extract their own session cookie
- No server-side cookie storage or persistence
- Clear warnings about cookie security in all documentation
- Recommendation to use dedicated Cisco account for API access

## [1.14.1] - 2025-10-27

### Fixed
- **Critical**: Added `-y` flag to all `npx mcp-cisco-support` commands in documentation to prevent Claude Desktop from hanging on installation prompts
- Fixed all Claude Desktop configuration examples in README.md and CLAUDE.md to use `"args": ["-y", "mcp-cisco-support"]`
- Added explanatory note about the `-y` flag requirement for background operation

### Changed
- Reorganized project documentation: moved feature documentation files to `docs/` folder
  - Moved `MCP_ENHANCEMENTS_SUMMARY.md` to `docs/`
  - Moved `RESOURCES_FIX_SUMMARY.md` to `docs/`
  - Moved `SAMPLING_IMPLEMENTATION_SUMMARY.md` to `docs/`
  - Moved `SMART_BONDING_IMPLEMENTATION.md` to `docs/`
  - Moved `tool-examples.md` to `docs/`
- Updated GitHub Wiki to reflect v1.14.0 features
  - Added comprehensive MCP Sampling documentation page
  - Updated Home page with sampling features and AI-powered tools
  - Updated tool count to 61 (56 standard + 5 AI-powered)

### Documentation
- Created `SKILL_IMPLEMENTATION_PLAN.md` - comprehensive plan for Claude Desktop skill development
- Updated wiki with latest sampling implementation details

## [1.14.0] - 2025-10-24

### Added
- **ElicitationRequest Support**: Implemented MCP elicitation requests for dynamic user interaction
  - Added `ElicitRequestSchema` handler to MCP server
  - Added `elicitation` capability to server configuration
  - Created `createElicitationRequest` helper function
  - Added predefined elicitation schemas for common scenarios:
    - `apiCredentials`: Request API credentials with user confirmation
    - `searchRefinement`: Request search parameter refinement (severity, status, date range)
    - `userConfirmation`: Request user confirmation for actions
    - `productSelection`: Request product selection from multiple options
  - Added comprehensive test coverage for elicitation features
  - Updated documentation with usage examples and best practices

### Changed
- Enhanced MCP server capabilities to support interactive user workflows
- Updated TypeScript imports to include elicitation-related types

### Technical Details
- Follows MCP specification 2025-06-18 for elicitation requests
- Implements security-first design (never requests sensitive information)
- Supports three response actions: accept, decline, cancel
- Includes proper error handling and logging for elicitation requests

## [1.10.0] - Previous Release
- Existing features and bug fixes...