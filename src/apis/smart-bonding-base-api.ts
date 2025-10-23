import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getValidSmartBondingToken } from '../utils/smart-bonding-auth.js';
import { logger } from '../utils/logger.js';
import { validateToolArgs, setDefaultValues, ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

/**
 * ⚠️ EXPERIMENTAL: Smart Bonding Base API
 *
 * Base class for Smart Bonding API tools with separate authentication system.
 * Uses different OAuth2 endpoint (cloudsso.cisco.com) than standard Support APIs.
 *
 * Status: UNTESTED - Requires Smart Bonding credentials from Cisco Account Manager
 */
export abstract class SmartBondingBaseApi {
  protected baseUrl: string;
  protected apiName = 'Smart Bonding';

  constructor() {
    // Environment-based URL (staging vs production)
    const env = process.env.SMART_BONDING_ENV || 'production';
    this.baseUrl = env === 'staging'
      ? 'https://stage.sbnprd.xylem.cisco.com/sb-partner-oauth-proxy-api/rest/v1'
      : 'https://sb.xylem.cisco.com/sb-partner-oauth-proxy-api/rest/v1';

    logger.info(`Smart Bonding API initialized`, {
      environment: env,
      baseUrl: this.baseUrl,
      status: 'EXPERIMENTAL/UNTESTED'
    });
  }

  // Get tools provided by this API
  abstract getTools(): Tool[];

  // Execute a tool call for this API
  abstract executeTool(name: string, args: ToolArgs): Promise<ApiResponse>;

  /**
   * Make authenticated API call to Smart Bonding endpoint
   * Supports both GET and POST methods (unlike standard Support APIs)
   */
  protected async makeApiCall(
    endpoint: string,
    method: 'GET' | 'POST' = 'GET',
    body?: any,
    params: Record<string, any> = {},
    correlationId?: string
  ): Promise<ApiResponse> {
    const token = await getValidSmartBondingToken();

    // Build query string for GET requests
    const queryParams = new URLSearchParams();
    if (method === 'GET') {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          queryParams.append(key, String(value));
        }
      });
    }

    const queryString = queryParams.toString();
    const url = `${this.baseUrl}${endpoint}${queryString ? '?' + queryString : ''}`;

    try {
      logger.info(`Making Smart Bonding API call [EXPERIMENTAL]`, {
        method,
        endpoint,
        params,
        fullUrl: url,
        hasBody: !!body,
        correlationId: correlationId || '(none)'
      });

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 second timeout

      const headers: Record<string, string> = {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'mcp-cisco-support/1.0-smart-bonding-experimental'
      };

      // Add correlation ID header if provided
      if (correlationId) {
        headers['x-correlation-id'] = correlationId;
      }

      // Add Content-Type for POST requests
      if (method === 'POST' && body) {
        headers['Content-Type'] = 'application/json';
      }

      const fetchOptions: RequestInit = {
        method,
        headers,
        signal: controller.signal
      };

      // Add body for POST requests
      if (method === 'POST' && body) {
        fetchOptions.body = JSON.stringify(body);
      }

      const response = await fetch(url, fetchOptions);

      clearTimeout(timeoutId);

      if (response.status === 401) {
        logger.warn('Smart Bonding API returned 401, token may be expired, refreshing...');
        // Token expired, refresh and retry once
        const newToken = await getValidSmartBondingToken();
        const retryController = new AbortController();
        const retryTimeoutId = setTimeout(() => retryController.abort(), 60000);

        const retryHeaders = { ...headers, 'Authorization': `Bearer ${newToken}` };
        const retryOptions = { ...fetchOptions, signal: retryController.signal, headers: retryHeaders };

        const retryResponse = await fetch(url, retryOptions);

        clearTimeout(retryTimeoutId);

        if (!retryResponse.ok) {
          const errorText = await retryResponse.text();
          logger.error('Smart Bonding API call failed after token refresh', {
            status: retryResponse.status,
            errorText: errorText.substring(0, 500)
          });
          throw new Error(`Smart Bonding API call failed after token refresh: ${retryResponse.status} ${retryResponse.statusText} - ${errorText}`);
        }

        const retryData = await retryResponse.json() as ApiResponse;
        return retryData;
      }

      if (!response.ok) {
        const errorText = await response.text();
        logger.error(`Smart Bonding API call failed`, {
          status: response.status,
          statusText: response.statusText,
          url: url,
          method,
          errorText: errorText.substring(0, 500)
        });
        throw new Error(`Smart Bonding API call failed: ${response.status} ${response.statusText} - URL: ${url} - ${errorText}`);
      }

      const data = await response.json() as ApiResponse;
      logger.info(`Smart Bonding API call successful`, {
        endpoint,
        method,
        resultCount: this.getResultCount(data)
      });

      return data;
    } catch (error) {
      // Handle specific timeout errors
      if (error instanceof Error) {
        if (error.name === 'AbortError' || error.message.includes('timeout')) {
          logger.error(`Smart Bonding API call timed out`, { endpoint, method, timeout: '60s' });
          throw new Error(`Smart Bonding API call timed out after 60 seconds. The API may be experiencing high load. Please try again later.`);
        } else if (error.message.includes('Headers Timeout') || error.message.includes('UND_ERR_HEADERS_TIMEOUT')) {
          logger.error(`Smart Bonding API headers timeout`, { endpoint, method });
          throw new Error(`Smart Bonding API connection timed out while waiting for response headers. The service may be temporarily unavailable.`);
        }
      }

      logger.error(`Smart Bonding API call failed`, { endpoint, method, error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  // Validate tool arguments
  protected validateTool(name: string, args: ToolArgs): { tool: Tool; processedArgs: ToolArgs } {
    const tools = this.getTools();
    const tool = tools.find(t => t.name === name);

    if (!tool) {
      throw new Error(`Unknown Smart Bonding tool: ${name}`);
    }

    validateToolArgs(tool, args);
    const processedArgs = setDefaultValues(args);

    return { tool, processedArgs };
  }

  // Get result count from API response
  protected getResultCount(data: ApiResponse): number {
    if ('tickets' in data && Array.isArray(data.tickets)) {
      return data.tickets.length;
    }
    if ('status' in data && data.status === 'success') {
      return 1; // Single operation success
    }
    return 0;
  }
}
