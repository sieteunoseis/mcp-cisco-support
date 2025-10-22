import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getValidToken } from '../utils/auth.js';
import { logger } from '../utils/logger.js';
import { validateToolArgs, setDefaultValues, buildApiParams, ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

// Base API class providing common functionality
export abstract class BaseApi {
  protected abstract baseUrl: string;
  protected abstract apiName: string;

  // Get tools provided by this API
  abstract getTools(): Tool[];

  // Execute a tool call for this API
  abstract executeTool(name: string, args: ToolArgs): Promise<ApiResponse>;

  // Make authenticated API call
  protected async makeApiCall(endpoint: string, params: Record<string, any> = {}): Promise<ApiResponse> {
    const token = await getValidToken();
    
    // Build query string
    const queryParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        queryParams.append(key, String(value));
      }
    });
    
    const queryString = queryParams.toString();
    const url = `${this.baseUrl}${endpoint}${queryString ? '?' + queryString : ''}`;
    
    try {
      logger.info(`Making ${this.apiName} API call`, {
        endpoint,
        params,
        fullUrl: url,
        queryString: queryString || '(none)'
      });
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 60000); // 60 second timeout
      
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': 'mcp-cisco-support/1.0'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      if (response.status === 401) {
        logger.warn('Received 401, token may be expired, refreshing...');
        // Token expired, refresh and retry once
        const newToken = await getValidToken();
        const retryController = new AbortController();
        const retryTimeoutId = setTimeout(() => retryController.abort(), 60000); // 60 second timeout
        
        const retryResponse = await fetch(url, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${newToken}`,
            'Accept': 'application/json',
            'User-Agent': 'mcp-cisco-support/1.0'
          },
          signal: retryController.signal
        });
        
        clearTimeout(retryTimeoutId);
        
        if (!retryResponse.ok) {
          const errorText = await retryResponse.text();
          throw new Error(`${this.apiName} API call failed after token refresh: ${retryResponse.status} ${retryResponse.statusText} - ${errorText}`);
        }
        
        const retryData = await retryResponse.json() as ApiResponse;
        return retryData;
      }

      if (!response.ok) {
        const errorText = await response.text();
        logger.error(`${this.apiName} API call failed`, {
          status: response.status,
          statusText: response.statusText,
          url: url,
          params: params,
          errorText: errorText.substring(0, 500)
        });
        throw new Error(`${this.apiName} API call failed: ${response.status} ${response.statusText} - URL: ${url} - ${errorText}`);
      }

      const data = await response.json() as ApiResponse;
      logger.info(`${this.apiName} API call successful`, { 
        endpoint, 
        resultCount: this.getResultCount(data)
      });
      
      return data;
    } catch (error) {
      // Handle specific timeout errors
      if (error instanceof Error) {
        if (error.name === 'AbortError' || error.message.includes('timeout')) {
          logger.error(`${this.apiName} API call timed out`, { endpoint, params, timeout: '60s' });
          throw new Error(`${this.apiName} API call timed out after 60 seconds. The API may be experiencing high load. Please try again later.`);
        } else if (error.message.includes('Headers Timeout') || error.message.includes('UND_ERR_HEADERS_TIMEOUT')) {
          logger.error(`${this.apiName} API headers timeout`, { endpoint, params });
          throw new Error(`${this.apiName} API connection timed out while waiting for response headers. The service may be temporarily unavailable.`);
        }
      }
      
      logger.error(`${this.apiName} API call failed`, { endpoint, error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  // Validate tool arguments
  protected validateTool(name: string, args: ToolArgs): { tool: Tool; processedArgs: ToolArgs } {
    const tools = this.getTools();
    const tool = tools.find(t => t.name === name);
    
    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    validateToolArgs(tool, args);
    const processedArgs = setDefaultValues(args);
    
    return { tool, processedArgs };
  }

  // Get result count from API response (to be overridden by subclasses if needed)
  protected getResultCount(data: ApiResponse): number {
    if ('bugs' in data && Array.isArray(data.bugs)) {
      return data.bugs.length;
    }
    if ('cases' in data && Array.isArray(data.cases)) {
      return data.cases.length;
    }
    return 0;
  }

  // Build standard API parameters
  protected buildStandardParams(args: ToolArgs): Record<string, any> {
    return buildApiParams(args);
  }
}