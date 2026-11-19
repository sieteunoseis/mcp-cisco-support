import { Tool } from '@modelcontextprotocol/server';
import { Server } from '@modelcontextprotocol/server';
import { BaseApi } from './base-api.js';
import { BugApi } from './bug-api.js';
import { CaseApi } from './case-api.js';
import { EoxApi } from './eox-api.js';
import { PsirtApi } from './psirt-api.js';
import { ProductApi } from './product-api.js';
import { SoftwareApi } from './software-api.js';
import { SerialApi } from './serial-api.js';
import { RmaApi } from './rma-api.js';
type ToolArgs = Record<string, any>;
import { ApiResponse } from './base-api.js';
import { TOOL_SPECS, RENAMED_TOOLS, ApiName, ApiClient } from '../tools/index.js';
import { validateArgs } from '../tools/validate.js';

// Cisco Support APIs the server talks to
export type SupportedAPI = ApiName;

export const SUPPORTED_APIS: SupportedAPI[] = ['bug', 'psirt', 'eox', 'product', 'serial', 'software', 'case', 'rma'];

let warnedSupportApi = false;

/** SUPPORT_API was removed in 3.0.0: every tool is always available. */
function warnIfSupportApiSet(): void {
  if (process.env.SUPPORT_API && !warnedSupportApi) {
    warnedSupportApi = true;
    // stderr, so it is safe in stdio mode
    console.error('SUPPORT_API is no longer used (3.0.0 always exposes all 12 tools); you can remove it.');
  }
}

// API registry
export class ApiRegistry {
  private apis: Record<SupportedAPI, BaseApi>;

  // The server argument is kept for call-site compatibility
  constructor(_mcpServer?: Server) {
    warnIfSupportApiSet();
    this.apis = {
      bug: new BugApi(),
      psirt: new PsirtApi(),
      eox: new EoxApi(),
      product: new ProductApi(),
      serial: new SerialApi(),
      software: new SoftwareApi(),
      case: new CaseApi(),
      rma: new RmaApi(),
    };
  }

  // All tools, always
  getAvailableTools(): Tool[] {
    return TOOL_SPECS.map(s => s.tool);
  }

  // Execute a tool call
  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string; signal?: AbortSignal }): Promise<{ result: ApiResponse; apiName: string }> {
    const spec = TOOL_SPECS.find(s => s.tool.name === name);
    if (!spec) {
      const renamed = RENAMED_TOOLS[name];
      if (renamed) {
        throw new Error(`Unknown tool: ${name}. It was replaced by "${renamed}" in v3.0.0.`);
      }
      throw new Error(`Unknown tool: ${name}`);
    }
    validateArgs(spec.tool.inputSchema as any, (args ?? {}) as Record<string, unknown>);

    // Bind the caller's cancellation signal to every upstream request
    const signal = meta?.signal;
    const apis = Object.fromEntries(
      (Object.entries(this.apis) as [SupportedAPI, BaseApi][]).map(([apiName, api]) => [
        apiName,
        { request: (endpoint: string, params: Record<string, any> = {}) => api.request(endpoint, params, signal) },
      ]),
    ) as Record<SupportedAPI, ApiClient>;
    const result = await spec.handler(args as Record<string, any>, { apis, progressToken: meta?.progressToken });
    return { result, apiName: spec.requires[0] };
  }
}

// Create API registry instance
export function createApiRegistry(mcpServer?: Server): ApiRegistry {
  return new ApiRegistry(mcpServer);
}
