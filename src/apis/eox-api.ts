import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

/**
 * Cisco End-of-Life (EoX) API v5.0 Implementation
 * 
 * Based on WADL specification and API documentation
 * Base URL: https://apix.cisco.com/supporttools/eox/rest/5
 */
export class EoxApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/supporttools/eox/rest/5';
  protected apiName = 'EoX';

  /**
   * Get all available EoX API tools
   */
  getTools(): Tool[] {
    return [
      {
        name: 'get_eox_by_date',
        description: 'Get end-of-life information for products within a specific date range based on EoX attributes (sales date, support date, etc.)',
        inputSchema: {
          type: 'object',
          properties: {
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format (e.g., 2024-01-01)',
              pattern: '^\\d{4}-\\d{2}-\\d{2}$'
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format (e.g., 2024-12-31)',
              pattern: '^\\d{4}-\\d{2}-\\d{2}$'
            },
            eox_attrib: {
              type: 'string',
              description: 'EoX attribute to filter by (default: UPDATED_TIMESTAMP)',
              enum: [
                'EO_EXT_ANNOUNCE_DATE',
                'EO_SALES_DATE', 
                'EO_FAIL_ANALYSIS_DATE',
                'EO_SW_MAINTENANCE_DATE',
                'EO_CONTRACT_RENEW_DATE',
                'EO_SECURITY_VUL_SUPPORT_DATE',
                'UPDATED_TIMESTAMP'
              ],
              default: 'UPDATED_TIMESTAMP'
            },
            page_index: {
              type: 'integer',
              description: 'Page number to retrieve (default: 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['start_date', 'end_date']
        }
      },
      {
        name: 'get_eox_by_product_id',
        description: 'Get end-of-life information for specific product IDs (up to 20 product IDs per call)',
        inputSchema: {
          type: 'object',
          properties: {
            product_ids: {
              type: 'string',
              description: 'Product IDs separated by commas (up to 20 IDs, e.g., "WS-C3560-48PS-S,WS-C2960-24TC-L")'
            },
            page_index: {
              type: 'integer',
              description: 'Page number to retrieve (default: 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['product_ids']
        }
      },
      {
        name: 'get_eox_by_serial_number',
        description: 'Get end-of-life information for specific serial numbers (up to 20 serial numbers per call)',
        inputSchema: {
          type: 'object',
          properties: {
            serial_numbers: {
              type: 'string',
              description: 'Serial numbers separated by commas (up to 20 numbers, e.g., "FCW2218E0TG,JAE11108ESH")'
            },
            page_index: {
              type: 'integer',
              description: 'Page number to retrieve (default: 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['serial_numbers']
        }
      },
      {
        name: 'get_eox_by_software_release',
        description: 'Get end-of-life information for software releases (up to 20 software version/OS combinations)',
        inputSchema: {
          type: 'object',
          properties: {
            input1: {
              type: 'string',
              description: 'Software version and OS type as comma-separated tuple (e.g., "12.4(15),IOS")'
            },
            input2: {
              type: 'string',
              description: 'Additional software version and OS type tuple (optional)'
            },
            input3: {
              type: 'string', 
              description: 'Additional software version and OS type tuple (optional)'
            },
            input4: {
              type: 'string',
              description: 'Additional software version and OS type tuple (optional)'
            },
            input5: {
              type: 'string',
              description: 'Additional software version and OS type tuple (optional)'
            },
            page_index: {
              type: 'integer',
              description: 'Page number to retrieve (default: 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['input1']
        }
      }
    ];
  }

  /**
   * Execute EoX API tool calls
   */
  async executeTool(name: string, args: ToolArgs): Promise<ApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);

    switch (name) {
      case 'get_eox_by_date':
        return this.getEoxByDate(processedArgs);
      case 'get_eox_by_product_id':
        return this.getEoxByProductId(processedArgs);
      case 'get_eox_by_serial_number':
        return this.getEoxBySerialNumber(processedArgs);
      case 'get_eox_by_software_release':
        return this.getEoxBySoftwareRelease(processedArgs);
      default:
        throw new Error(`Unknown EoX tool: ${name}`);
    }
  }

  /**
   * Get EoX information by date range
   */
  private async getEoxByDate(args: ToolArgs): Promise<ApiResponse> {
    const { start_date, end_date, eox_attrib = 'UPDATED_TIMESTAMP', page_index = 1 } = args;
    
    const endpoint = `/EOXByDates/${page_index}/${start_date}/${end_date}`;
    const params: Record<string, any> = {};
    
    if (eox_attrib && eox_attrib !== 'UPDATED_TIMESTAMP') {
      params.eoxAttrib = eox_attrib;
    }
    
    return this.makeApiCall(endpoint, params);
  }

  /**
   * Get EoX information by product IDs
   */
  private async getEoxByProductId(args: ToolArgs): Promise<ApiResponse> {
    const { product_ids, page_index = 1 } = args;
    
    const endpoint = `/EOXByProductID/${page_index}/${product_ids}`;
    
    return this.makeApiCall(endpoint);
  }

  /**
   * Get EoX information by serial numbers
   */
  private async getEoxBySerialNumber(args: ToolArgs): Promise<ApiResponse> {
    const { serial_numbers, page_index = 1 } = args;
    
    const endpoint = `/EOXBySerialNumber/${page_index}/${serial_numbers}`;
    
    return this.makeApiCall(endpoint);
  }

  /**
   * Get EoX information by software release strings
   */
  private async getEoxBySoftwareRelease(args: ToolArgs): Promise<ApiResponse> {
    const { page_index = 1, ...inputs } = args;
    
    const endpoint = `/EOXBySWReleaseString/${page_index}`;
    const params: Record<string, any> = {};
    
    // Add software release inputs (input1-input5)
    ['input1', 'input2', 'input3', 'input4', 'input5'].forEach(inputKey => {
      if (inputs[inputKey]) {
        params[inputKey] = inputs[inputKey];
      }
    });
    
    return this.makeApiCall(endpoint, params);
  }

  /**
   * Override to get result count from EoX API response
   */
  protected getResultCount(data: ApiResponse): number {
    if ('EOXRecord' in data && Array.isArray(data.EOXRecord)) {
      return data.EOXRecord.length;
    }
    return 0;
  }
}