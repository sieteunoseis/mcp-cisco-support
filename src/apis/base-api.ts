import { getValidToken, resetToken } from '../utils/auth.js';
import { logger } from '../utils/logger.js';

/** Raw JSON body returned by a Cisco API */
export type ApiResponse = Record<string, any>;

// Base API class providing common functionality
export abstract class BaseApi {
  protected abstract baseUrl: string;
  protected abstract apiName: string;

  /** Raw GET against this API's base URL (used by the v3 tool layer) */
  async request(endpoint: string, params: Record<string, any> = {}, signal?: AbortSignal): Promise<any> {
    return this.makeApiCall(endpoint, params, signal);
  }

  /**
   * Encode a value for an apix.cisco.com path. Cisco's gateway rejects %2F,
   * and product IDs like "ISR4431/K9" are sent with a literal slash, so '/'
   * is kept, but '..' segments are refused so input can't climb to another API.
   */
  static encodePathValue(value: string): string {
    if (value.split('/').some(part => part === '..' || part === '.')) {
      throw new Error(`Invalid identifier: "${value}"`);
    }
    return encodeURIComponent(value).replace(/%2F/gi, '/');
  }

  /**
   * Cisco's gateway rate-limits per second and answers with
   * 403 "Developer Over Qps" (or 429). Back off and retry those.
   */
  protected async makeApiCall(endpoint: string, params: Record<string, any> = {}, signal?: AbortSignal): Promise<ApiResponse> {
    const delays = [1000, 2000, 4000];
    for (let attempt = 0; ; attempt++) {
      if (signal?.aborted) throw new Error(`${this.apiName} API call cancelled by the client`);
      try {
        return await this.makeApiCallOnce(endpoint, params, signal);
      } catch (error) {
        const message = error instanceof Error ? error.message : '';
        const rateLimited = /Over Qps|Over Rate|\b429\b/i.test(message);
        if (!rateLimited || attempt >= delays.length || signal?.aborted) throw error;
        logger.warn(`${this.apiName} API rate limited, retrying`, { endpoint, attempt: attempt + 1, delayMs: delays[attempt] });
        await new Promise<void>(resolve => {
          const timer = setTimeout(resolve, delays[attempt]);
          signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
        });
      }
    }
  }

  private async makeApiCallOnce(endpoint: string, params: Record<string, any> = {}, signal?: AbortSignal): Promise<ApiResponse> {
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
      // Abort the upstream request when the MCP client cancels the tool call
      const onCancel = () => controller.abort();
      signal?.addEventListener('abort', onCancel, { once: true });
      
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': 'mcp-cisco-support/1.0'
        },
        signal: controller.signal
      }).finally(() => {
        clearTimeout(timeoutId);
        signal?.removeEventListener('abort', onCancel);
      });

      if (response.status === 401) {
        logger.warn('Received 401, token may be expired, refreshing...');
        // Token rejected: drop the cached token so a new one is fetched, then retry once
        resetToken();
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
        }).finally(() => clearTimeout(retryTimeoutId));
        
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
        // 403 that is not rate limiting = the API key isn't entitled to this API
        if (response.status === 403 && !/Over Qps|Over Rate/i.test(errorText)) {
          const reason = errorText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
          throw new Error(`${this.apiName} API: access denied (403${reason ? `: ${reason}` : ''}). ` +
            `The Cisco API credentials (CISCO_CLIENT_ID) are probably not entitled to the ${this.apiName} API; ` +
            `request access for it on the Cisco API Console (https://apiconsole.cisco.com).`);
        }
        throw new Error(`${this.apiName} API call failed: ${response.status} ${response.statusText} - URL: ${url} - ${errorText.substring(0, 500)}`);
      }

      const data = await response.json() as ApiResponse;
      logger.info(`${this.apiName} API call successful`, { 
        endpoint, 
      });
      
      return data;
    } catch (error) {
      // Handle specific timeout errors
      if (error instanceof Error) {
        if (signal?.aborted) {
          throw new Error(`${this.apiName} API call cancelled by the client`);
        }
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
}
