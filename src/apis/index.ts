import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { BugApi } from './bug-api.js';
import { CaseApi } from './case-api.js';
import { EoxApi } from './eox-api.js';
import { PsirtApi } from './psirt-api.js';
import { ProductApi } from './product-api.js';
import { SoftwareApi } from './software-api.js';
import { EnhancedAnalysisApi } from './enhanced-analysis-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

// Supported API types
export type SupportedAPI = 'psirt' | 'bug' | 'case' | 'eox' | 'product' | 'serial' | 'rma' | 'software' | 'enhanced_analysis';

export const SUPPORTED_APIS: SupportedAPI[] = ['psirt', 'bug', 'case', 'eox', 'product', 'serial', 'rma', 'software', 'enhanced_analysis'];

// Placeholder API class for unimplemented APIs
class PlaceholderApi extends BaseApi {
  protected baseUrl = '';
  protected apiName: string;

  constructor(apiName: string) {
    super();
    this.apiName = apiName;
  }

  getTools(): Tool[] {
    return [
      {
        name: `${this.apiName.toLowerCase()}_placeholder`,
        description: `⚠️ ${this.apiName} API not yet implemented. Please use Bug API tools instead for related searches.`,
        inputSchema: {
          type: 'object',
          properties: {
            message: {
              type: 'string',
              description: `This is a placeholder - ${this.apiName} API is not yet implemented`
            }
          },
          required: []
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<ApiResponse> {
    return {
      error: `${this.apiName} API Not Implemented`,
      message: `The Cisco ${this.apiName} API is not yet implemented in this MCP server. Currently, only the Bug and Case APIs are available.`,
      alternatives: [
        'Use search_bugs_by_keyword to find bugs related to your topic',
        'Use search_bugs_by_product_id if you have a specific product ID',
        'Use get_case_details if you have a case ID to investigate'
      ],
      example: `Try: "Search for bugs related to your ${this.apiName.toLowerCase()} topic with keyword search"`,
      available_apis: ['bug', 'case'],
      planned_apis: ['eox', 'product', 'serial', 'rma', 'software', 'asd']
    } as any;
  }
}

// API registry
export class ApiRegistry {
  private apis: Map<SupportedAPI, BaseApi> = new Map();
  private enabledApis: SupportedAPI[] = [];

  constructor(enabledApis: SupportedAPI[]) {
    this.enabledApis = enabledApis;
    this.initializeApis();
  }

  private initializeApis(): void {
    // Initialize implemented APIs
    this.apis.set('bug', new BugApi());
    this.apis.set('case', new CaseApi());
    this.apis.set('eox', new EoxApi());
    this.apis.set('psirt', new PsirtApi());
    this.apis.set('product', new ProductApi());
    this.apis.set('software', new SoftwareApi());
    this.apis.set('enhanced_analysis', new EnhancedAnalysisApi());
    
    // Initialize placeholder APIs for unimplemented ones only
    this.apis.set('serial', new PlaceholderApi('Serial'));
    this.apis.set('rma', new PlaceholderApi('RMA'));
  }

  // Get all tools from enabled APIs
  getAvailableTools(): Tool[] {
    const availableTools: Tool[] = [];
    
    for (const apiName of this.enabledApis) {
      const api = this.apis.get(apiName);
      if (api) {
        const apiTools = api.getTools();
        availableTools.push(...apiTools);
      }
    }
    
    return availableTools;
  }

  // Execute a tool call
  async executeTool(name: string, args: ToolArgs): Promise<{ result: ApiResponse; apiName: string }> {
    // Find which API owns this tool
    for (const apiName of this.enabledApis) {
      const api = this.apis.get(apiName);
      if (api) {
        const tools = api.getTools();
        const tool = tools.find(t => t.name === name);
        if (tool) {
          const result = await api.executeTool(name, args);
          return { result, apiName };
        }
      }
    }
    
    throw new Error(`Unknown tool: ${name}`);
  }

  // Get enabled API names
  getEnabledApis(): SupportedAPI[] {
    return [...this.enabledApis];
  }

  // Check if an API is enabled
  isApiEnabled(apiName: SupportedAPI): boolean {
    return this.enabledApis.includes(apiName);
  }
}

// Get enabled APIs from environment
export function getEnabledAPIs(): SupportedAPI[] {
  const supportApiEnv = process.env.SUPPORT_API || 'bug';
  
  if (supportApiEnv.toLowerCase() === 'all') {
    return SUPPORTED_APIS.filter(api => api !== 'enhanced_analysis'); // Exclude enhanced_analysis from 'all'
  }
  
  if (supportApiEnv.toLowerCase() === 'enhanced_analysis') {
    return ['enhanced_analysis']; // Only return enhanced analysis tools
  }
  
  const requestedAPIs = supportApiEnv.toLowerCase().split(',').map(api => api.trim()) as SupportedAPI[];
  return requestedAPIs.filter(api => SUPPORTED_APIS.includes(api));
}

// Create API registry instance
export function createApiRegistry(): ApiRegistry {
  const enabledApis = getEnabledAPIs();
  return new ApiRegistry(enabledApis);
}