# ElicitationRequest Example Usage

This document demonstrates how to use the new elicitationRequest feature in the Cisco Support MCP server.

## Overview

The elicitationRequest feature allows the server to dynamically request additional information from users during tool execution. This makes interactions more natural and helps gather missing parameters without requiring users to restart their requests.

## Example Scenarios

### 1. Interactive Bug Search

**User Request:** "Find bugs for CallManager"

**Server Response with Elicitation:**
```
I found your request for CallManager bugs. To provide better results, I'd like to gather some additional search parameters.

[Elicitation Request with searchRefinement schema]
- Severity: Which severity level are you interested in? (1=Critical, 2=High, 3=Medium, etc.)
- Status: Are you looking for Open bugs, Fixed bugs, or both?
- Date Range: How recent should the bugs be? (Last 7 days, 30 days, etc.)
```

**User Response:**
```json
{
  "action": "accept",
  "content": {
    "severity": "2",
    "status": "O",
    "dateRange": "2"
  }
}
```

**Server Follow-up:**
```
Perfect! I'll search for high-severity (level 2) open bugs in CallManager from the last 30 days.
[Executes refined search with specific parameters]
```

### 2. Product Selection

**User Request:** "Show me bugs for ASR routers"

**Server Response with Elicitation:**
```
I found multiple ASR router products. Please select which specific product you're interested in:

[Elicitation Request with productSelection schema]
- Cisco ASR 1000 Series
- Cisco ASR 9000 Series  
- Cisco ASR 920 Series
- Cisco ASR 1001-X
```

**User Response:**
```json
{
  "action": "accept",
  "content": {
    "selectedProduct": "Cisco ASR 1000 Series",
    "version": "17.06.05"
  }
}
```

### 3. Confirmation for Broad Searches

**User Request:** "Find all bugs modified today"

**Server Response with Elicitation:**
```
This search could return a large number of results and may take some time. Would you like to proceed?

[Elicitation Request with userConfirmation schema]
```

**User Response:**
```json
{
  "action": "accept",
  "content": {
    "confirmed": true,
    "reason": "I need to review all recent changes for my report"
  }
}
```

## Testing the Feature

### Using the Interactive Search Prompt

Try the new `cisco-interactive-search` prompt:

```
Please use the "cisco-interactive-search" prompt with these parameters:
- initial_query: "memory leak"
- use_elicitation: true
```

This will demonstrate:
1. Basic search execution
2. Elicitation requests for search refinement
3. Interactive parameter gathering
4. Enhanced results with context

### Manual Testing

You can also manually test elicitation by:

1. **Starting a broad search** that would benefit from refinement
2. **Using ambiguous terms** that match multiple products
3. **Requesting actions** that might need confirmation
4. **Providing incomplete information** that requires additional details

## Available Elicitation Schemas

### searchRefinement
Request search parameter refinement:
- **severity**: Bug severity level (1-6)
- **status**: Bug status (O=Open, F=Fixed, etc.)
- **dateRange**: Modified date range (1-5)

### userConfirmation  
Request user confirmation for actions:
- **confirmed**: Boolean confirmation
- **reason**: Optional reason for confirmation

### productSelection
Request specific product selection:
- **selectedProduct**: Selected product name
- **version**: Optional product version

### apiCredentials
Request API credentials (demonstration only):
- **clientId**: Cisco API Client ID
- **confirm**: Confirmation of credential sharing

## Implementation Notes

### Security Considerations
- Never requests sensitive information like passwords or keys
- Always respects user decline/cancel actions
- Provides clear explanations for why information is needed

### User Experience
- Clear, concise messages explaining what's needed
- Logical flow from broad to specific requests
- Graceful handling of user decline/cancel actions

### Error Handling
- Validates user responses against schemas
- Provides helpful error messages for invalid inputs
- Falls back to default behavior when elicitation fails

## Best Practices

1. **Use Sparingly**: Only request information that significantly improves results
2. **Be Clear**: Explain why additional information is needed
3. **Respect Choices**: Handle decline/cancel gracefully
4. **Validate Input**: Always validate user responses
5. **Provide Context**: Show how the information will be used

## Future Enhancements

Potential improvements for the elicitation feature:
- Dynamic schema generation based on API responses
- Multi-step elicitation workflows
- Context-aware parameter suggestions
- Integration with user preferences/history
- Advanced validation and error recovery