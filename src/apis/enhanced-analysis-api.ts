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
    // Get list of tools exposed to external callers
    const exposedTools = this.getTools().map(tool => tool.name);

    // List of internal tools that enhanced analysis tools can use internally
    // but aren't exposed to external callers
    const internalTools = [
      'get_bug_details',
      'search_bugs_by_keyword',
      'search_bugs_by_product_id',
      'search_bugs_by_product_and_release',
      'search_bugs_by_product_series_affected',
      'search_bugs_by_product_series_fixed',
      'search_bugs_by_product_name_affected',
      'search_bugs_by_product_name_fixed'
    ];

    // Allow both exposed and internal tools
    if (!exposedTools.includes(name) && !internalTools.includes(name)) {
      throw new Error(`Tool ${name} is not available in Enhanced Analysis mode. Available tools: ${exposedTools.join(', ')}`);
    }

    // For internal tools, we need to temporarily use BugApi's getTools() to pass validation
    // Save the original getTools method, replace it, then restore it
    if (internalTools.includes(name)) {
      const originalGetTools = this.getTools.bind(this);
      try {
        // Temporarily use parent's getTools which includes all tools
        this.getTools = () => super.getTools();
        return await super.executeTool(name, args, meta);
      } finally {
        // Restore the enhanced analysis getTools
        this.getTools = originalGetTools;
      }
    }

    // For exposed tools, just delegate normally
    return await super.executeTool(name, args, meta);
  }
}