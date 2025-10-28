/**
 * Elicitation Request Schemas
 *
 * ⚠️ EXPERIMENTAL FEATURE - Limited Client Support
 *
 * ElicitationRequest is an MCP specification feature for requesting user input
 * at runtime using structured schemas. However, as of January 2025, few MCP clients
 * (including Claude Desktop) have confirmed full implementation.
 *
 * ## Status
 * - ✅ Spec Compliant: Code follows MCP specification (2025-06-18)
 * - ❌ Limited Client Support: Not widely implemented yet
 * - ✅ Alternative Available: Claude Desktop handles this via conversational follow-ups
 *
 * ## Why Keep It?
 * - Future client support (when available)
 * - Custom MCP client implementations
 * - HTTP mode with custom UI
 * - Reference implementation
 *
 * ## For Claude Desktop Users
 * Claude handles missing parameters naturally through conversation instead of
 * using structured elicitation requests.
 */

/**
 * Common elicitation schemas for Cisco Support scenarios
 * All schemas use flat object structure with primitive types only (per MCP spec)
 */
export const ElicitationSchemas = {
  /**
   * Request missing API credentials
   * Security Note: Never used for actual credential storage - only for user confirmation
   */
  apiCredentials: {
    type: 'object',
    properties: {
      clientId: {
        type: 'string',
        description: 'Cisco API Client ID'
      },
      confirm: {
        type: 'boolean',
        description: 'Confirm you want to provide credentials'
      }
    },
    required: ['clientId', 'confirm']
  },

  /**
   * Request search refinement parameters
   * Used when initial search is too broad or needs filtering
   */
  searchRefinement: {
    type: 'object',
    properties: {
      severity: {
        type: 'string',
        enum: ['1', '2', '3', '4', '5', '6'],
        description: 'Bug severity level (1=highest, 6=lowest)'
      },
      status: {
        type: 'string',
        enum: ['O', 'F', 'T', 'R'],
        description: 'Bug status (O=Open, F=Fixed, T=Terminated, R=Resolved)'
      },
      dateRange: {
        type: 'string',
        enum: ['1', '2', '3', '4', '5'],
        description: 'Modified date range (1=last 7 days, 2=last 30 days, etc.)'
      }
    },
    required: []
  },

  /**
   * Request user confirmation for potentially destructive actions
   * Used before executing operations that modify state or have significant impact
   */
  userConfirmation: {
    type: 'object',
    properties: {
      confirmed: {
        type: 'boolean',
        description: 'Confirm you want to proceed'
      },
      reason: {
        type: 'string',
        description: 'Optional reason for confirmation'
      }
    },
    required: ['confirmed']
  },

  /**
   * Request product selection when multiple matches found
   * Used when search returns ambiguous results
   */
  productSelection: {
    type: 'object',
    properties: {
      selectedProduct: {
        type: 'string',
        description: 'Select the specific product'
      },
      version: {
        type: 'string',
        description: 'Product version (if applicable)'
      }
    },
    required: ['selectedProduct']
  }
};

/**
 * Create an elicitation request (for future client support)
 *
 * @param message - Human-readable message explaining what input is needed
 * @param schema - JSON Schema for the requested input (must be flat object with primitives)
 * @returns Elicitation request object
 *
 * @example
 * ```typescript
 * const request = createElicitationRequest(
 *   'Please refine your search parameters',
 *   ElicitationSchemas.searchRefinement
 * );
 * ```
 */
export function createElicitationRequest(message: string, schema: any) {
  return {
    method: 'elicitation/create',
    params: {
      message,
      requestedSchema: schema
    }
  };
}
