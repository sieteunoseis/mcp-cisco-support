import { Tool } from '@modelcontextprotocol/sdk/types.js';

export interface ToolArgs {
  [key: string]: any;
}

// Validate tool arguments against schema
export function validateToolArgs(tool: Tool, args: ToolArgs): void {
  const schema = tool.inputSchema;
  
  if (!schema || typeof schema !== 'object') {
    return; // No schema to validate against
  }
  
  // Check required fields
  if (schema.required && Array.isArray(schema.required)) {
    for (const field of schema.required) {
      if (!args[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
  }
  
  // Check enum values and patterns if specified
  if (schema.properties && typeof schema.properties === 'object') {
    Object.entries(schema.properties).forEach(([key, property]) => {
      if (args[key] !== undefined && typeof property === 'object' && property !== null) {
        const prop = property as any;
        
        // Validate enum values
        if (prop.enum && Array.isArray(prop.enum)) {
          if (!prop.enum.includes(args[key])) {
            throw new Error(`Invalid value for ${key}: ${args[key]}. Must be one of: ${prop.enum.join(', ')}`);
          }
        }
        
        // Validate regex patterns
        if (prop.pattern && typeof prop.pattern === 'string') {
          const regex = new RegExp(prop.pattern);
          if (!regex.test(args[key])) {
            throw new Error(`Invalid format for ${key}: ${args[key]}. Must match pattern: ${prop.pattern}`);
          }
        }
      }
    });
  }
}

// Set default values for optional parameters
export function setDefaultValues(args: ToolArgs): ToolArgs {
  const processedArgs = { ...args };
  
  // Common defaults
  if (!processedArgs.page_index) processedArgs.page_index = 1;
  if (!processedArgs.modified_date) processedArgs.modified_date = '5';
  
  return processedArgs;
}

// Build API parameters from tool arguments
export function buildApiParams(args: ToolArgs): Record<string, any> {
  const apiParams: Record<string, any> = {
    page_index: args.page_index || 1
  };
  
  // Add optional filters - only if explicitly provided
  if (args.status) apiParams.status = args.status;
  if (args.severity) apiParams.severity = args.severity;
  if (args.modified_date) apiParams.modified_date = args.modified_date;
  if (args.sort_by) apiParams.sort_by = args.sort_by;
  
  return apiParams;
}