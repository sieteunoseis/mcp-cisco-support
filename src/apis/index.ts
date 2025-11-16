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
import { SerialApi } from './serial-api.js';
import { RmaApi } from './rma-api.js';
import { SmartBondingApi } from './smart-bonding-api.js';
import { samplingTools, handleSamplingTool } from './sampling-tools.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { scopesToEnabledAPIs } from '../oauth2.js';

// Supported API types
export type SupportedAPI = 'psirt' | 'bug' | 'case' | 'eox' | 'product' | 'serial' | 'rma' | 'software' | 'enhanced_analysis' | 'smart_bonding' | 'sampling';

export const SUPPORTED_APIS: SupportedAPI[] = ['psirt', 'bug', 'case', 'eox', 'product', 'serial', 'rma', 'software', 'enhanced_analysis', 'smart_bonding', 'sampling'];

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

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<ApiResponse> {
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

// Module-level variable to store current request's OAuth scopes
// This is set by the SSE/HTTP transport layer before handling MCP requests
let currentRequestScopes: string[] | undefined;

/**
 * Set the OAuth scopes for the current request
 * Called by HTTP transport before handling MCP requests
 */
export function setCurrentRequestScopes(scopes: string[] | undefined): void {
  currentRequestScopes = scopes;
}

/**
 * Get the OAuth scopes for the current request
 */
export function getCurrentRequestScopes(): string[] | undefined {
  return currentRequestScopes;
}

// API registry
export class ApiRegistry {
  private apis: Map<SupportedAPI, BaseApi> = new Map();
  private enabledApis: SupportedAPI[] = [];
  private mcpServer?: Server;

  constructor(enabledApis: SupportedAPI[], mcpServer?: Server) {
    this.enabledApis = enabledApis;
    this.mcpServer = mcpServer;
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
    this.apis.set('serial', new SerialApi());
    this.apis.set('rma', new RmaApi());
    this.apis.set('enhanced_analysis', new EnhancedAnalysisApi());
    this.apis.set('smart_bonding', new SmartBondingApi() as any); // Cast needed due to different base class
  }

  // Get all tools from enabled APIs
  // In OAuth mode, filters based on current request scopes
  getAvailableTools(): Tool[] {
    // In OAuth 2.1 mode, filter tools based on current request scopes
    let apisToUse = this.enabledApis;

    if (process.env.AUTH_TYPE === 'oauth2.1' && currentRequestScopes) {
      apisToUse = getEnabledAPIs(currentRequestScopes);
    }

    const availableTools: Tool[] = [];

    for (const apiName of apisToUse) {
      // Handle sampling tools specially (they're not in the apis map)
      if (apiName === 'sampling') {
        availableTools.push(...samplingTools);
        continue;
      }

      const api = this.apis.get(apiName);
      if (api) {
        const apiTools = api.getTools();
        availableTools.push(...apiTools);
      }
    }

    return availableTools;
  }

  // Execute a tool call
  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<{ result: ApiResponse; apiName: string }> {
    // Check if this is a sampling tool
    if (this.enabledApis.includes('sampling')) {
      const samplingTool = samplingTools.find(t => t.name === name);
      if (samplingTool && this.mcpServer) {
        // Get cisco auth from bug API for any tools that need it
        const bugApi = this.apis.get('bug');
        const ciscoAuth = bugApi ? (bugApi as any).ciscoAuth : null;

        const result = await handleSamplingTool(this.mcpServer, name, args, ciscoAuth);
        return { result, apiName: 'sampling' };
      }
    }

    // Find which API owns this tool
    for (const apiName of this.enabledApis) {
      const api = this.apis.get(apiName);
      if (api) {
        const tools = api.getTools();
        const tool = tools.find(t => t.name === name);
        if (tool) {
          const result = await api.executeTool(name, args, meta);
          return { result, apiName };
        }
      }
    }

    // If tool not found in advertised tools, try calling it anyway
    // This allows APIs with internal tools (like enhanced_analysis) to handle them
    for (const apiName of this.enabledApis) {
      const api = this.apis.get(apiName);
      if (api) {
        try {
          const result = await api.executeTool(name, args, meta);
          return { result, apiName };
        } catch (error) {
          // If this API doesn't have the tool, try the next one
          if (error instanceof Error && (
            error.message.includes('not available') ||
            error.message.includes('Tool implementation not found') ||
            error.message.includes('Unknown tool')
          )) {
            continue;
          }
          // If it's a different error, re-throw it
          throw error;
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

// Get enabled APIs from environment or OAuth scopes
export function getEnabledAPIs(oauthScopes?: string[]): SupportedAPI[] {
  // In OAuth 2.1 mode, enable ALL APIs at startup
  // Per-request filtering will be done based on OAuth token scopes
  if (process.env.AUTH_TYPE === 'oauth2.1' && !oauthScopes) {
    // Enable all APIs so the registry has all tools available
    // The tools/list handler will filter based on actual OAuth scopes
    return SUPPORTED_APIS;
  }

  // If oauthScopes provided, convert scopes to APIs (per-request filtering)
  if (oauthScopes && process.env.AUTH_TYPE === 'oauth2.1') {
    const enabledApis = scopesToEnabledAPIs(oauthScopes);
    return enabledApis as SupportedAPI[];
  }

  // Fallback to environment variable for non-OAuth modes
  const supportApiEnv = process.env.SUPPORT_API || 'bug';
  const lowerEnv = supportApiEnv.toLowerCase();

  // Handle 'all' or 'all,something' patterns
  if (lowerEnv === 'all' || lowerEnv.startsWith('all,')) {
    const baseApis = SUPPORTED_APIS.filter(api => api !== 'enhanced_analysis' && api !== 'smart_bonding' && api !== 'sampling');

    // If it's "all,sampling" or "all,xyz", add the additional APIs
    if (lowerEnv.includes(',')) {
      const additionalApis = lowerEnv.split(',')
        .slice(1) // Skip 'all'
        .map(api => api.trim())
        .filter(api => SUPPORTED_APIS.includes(api as SupportedAPI)) as SupportedAPI[];

      return [...baseApis, ...additionalApis];
    }

    return baseApis;
  }

  if (lowerEnv === 'enhanced_analysis') {
    return ['enhanced_analysis']; // Only return enhanced analysis tools
  }

  const requestedAPIs = lowerEnv.split(',').map(api => api.trim()) as SupportedAPI[];
  return requestedAPIs.filter(api => SUPPORTED_APIS.includes(api));
}

// Create API registry instance
export function createApiRegistry(mcpServer?: Server, oauthScopes?: string[]): ApiRegistry {
  const enabledApis = getEnabledAPIs(oauthScopes);
  return new ApiRegistry(enabledApis, mcpServer);
}