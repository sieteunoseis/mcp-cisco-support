import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BugApi } from './bug-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

/**
 * Enhanced Analysis API - provides only the advanced analysis tools from Bug API
 * This is a filtered view of Bug API tools focused on comprehensive analysis
 */
export class EnhancedAnalysisApi extends BugApi {
  protected apiName = 'Enhanced Analysis';

  getTools(): Tool[] {
    // Get all tools from BugApi and filter to only enhanced analysis tools
    const allBugTools = super.getTools();
    
    const enhancedAnalysisToolNames = [
      'smart_search_strategy',
      'progressive_bug_search', 
      'multi_severity_search',
      'comprehensive_analysis',
      'compare_software_versions',
      'product_name_resolver'
    ];
    
    return allBugTools.filter(tool => enhancedAnalysisToolNames.includes(tool.name));
  }

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<ApiResponse> {
    // Validate that the tool is allowed in enhanced analysis mode
    const allowedTools = this.getTools().map(tool => tool.name);
    
    if (!allowedTools.includes(name)) {
      throw new Error(`Tool ${name} is not available in Enhanced Analysis mode. Available tools: ${allowedTools.join(', ')}`);
    }
    
    // Delegate to parent BugApi implementation
    return await super.executeTool(name, args, meta);
  }
}