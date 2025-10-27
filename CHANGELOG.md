# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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