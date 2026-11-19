import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
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
import { TOOL_SPECS, RENAMED_TOOLS, ApiName, ApiClient, ToolContext } from '../tools/index.js';
import { validateArgs } from '../tools/validate.js';

// Supported API types (values for SUPPORT_API)
export type SupportedAPI = ApiName;

export const SUPPORTED_APIS: SupportedAPI[] = ['bug', 'psirt', 'eox', 'product', 'serial', 'software', 'case', 'rma'];

// API registry
export class ApiRegistry {
  private apis: Record<SupportedAPI, BaseApi>;
  private enabledApis: SupportedAPI[];

  // The server argument is kept for call-site compatibility (sampling was removed in 3.0)
  constructor(enabledApis: SupportedAPI[], _mcpServer?: Server) {
    this.enabledApis = enabledApis;
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

  private specsFor() {
    const enabled = new Set(this.enabledApis);
    return TOOL_SPECS.filter(s => s.requires.some(api => enabled.has(api)));
  }

  // Tools advertised to clients for the enabled APIs
  getAvailableTools(): Tool[] {
    return this.specsFor().map(s => s.tool);
  }

  // Execute a tool call
  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string; signal?: AbortSignal }): Promise<{ result: ApiResponse; apiName: string }> {
    const spec = this.specsFor().find(s => s.tool.name === name);
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
    const ctx: ToolContext = {
      apis,
      enabled: new Set(this.enabledApis),
      progressToken: meta?.progressToken,
    };
    const result = await spec.handler(args as Record<string, any>, ctx);
    return { result, apiName: spec.requires[0] };
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

let warnedSupportApi = false;

// Get enabled APIs from the SUPPORT_API environment variable
export function getEnabledAPIs(): SupportedAPI[] {
  const requested = (process.env.SUPPORT_API || 'bug')
    .toLowerCase()
    .split(',')
    .map(api => api.trim())
    .filter(Boolean);

  // Warn (stderr, safe in stdio mode) about values that do nothing in 3.x
  const REMOVED = ['sampling', 'smart_bonding', 'enhanced_analysis'];
  const unknown = requested.filter(v => v !== 'all' && !SUPPORTED_APIS.includes(v as SupportedAPI));
  if (unknown.length && !warnedSupportApi) {
    warnedSupportApi = true;
    const removed = unknown.filter(v => REMOVED.includes(v));
    const other = unknown.filter(v => !REMOVED.includes(v));
    console.error(`SUPPORT_API: ignoring ${[
      removed.length ? `${removed.join(', ')} (removed in 3.0.0)` : '',
      other.length ? `${other.join(', ')} (unknown)` : '',
    ].filter(Boolean).join('; ')}. Valid values: ${SUPPORTED_APIS.join(', ')}, all`);
  }

  if (requested.includes('all')) {
    return [...SUPPORTED_APIS];
  }
  // 2.x values: enhanced_analysis was a subset of the bug tools; sampling and
  // smart_bonding were removed in 3.0
  if (requested.includes('enhanced_analysis') && !requested.includes('bug')) {
    requested.push('bug');
  }
  const enabled = SUPPORTED_APIS.filter(api => requested.includes(api));
  if (enabled.length === 0) {
    // Never start with zero tools because of an outdated or misspelled value
    console.error(`SUPPORT_API="${process.env.SUPPORT_API}" enables no APIs; falling back to "bug". Valid values: ${SUPPORTED_APIS.join(', ')}, all`);
    return ['bug'];
  }
  return enabled;
}

// Create API registry instance
export function createApiRegistry(mcpServer?: Server): ApiRegistry {
  return new ApiRegistry(getEnabledAPIs(), mcpServer);
}
