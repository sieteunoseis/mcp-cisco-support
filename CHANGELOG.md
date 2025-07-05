# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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