import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

export interface SerialApiResponse extends ApiResponse {
  serial_numbers?: Array<{
    sr_no?: string;
    sr_no_list?: string[];
    is_valid?: string;
    base_pid?: string;
    orderable_pid?: string;
    item_description?: string;
    item_type?: string;
    instance_id?: number;
    warranty_type?: string;
    warranty_end_date?: string;
    covered_product_line_end_date?: string;
    is_covered?: string;
    service_contract_number?: string;
    service_line_descr?: string;
    parent_sr_no?: string;
  }>;
  pagination_response_record?: {
    page_index?: number;
    page_records?: number;
    total_records?: number;
    last_index?: number;
  };
}

export class SerialApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/sn2info/v2';
  protected apiName = 'Serial';

  getTools(): Tool[] {
    return [
      {
        name: 'get_coverage_status_by_serial',
        description: 'Get detailed coverage status, warranty, and product information for up to 75 serial numbers. Returns comprehensive coverage details including warranty dates, contract information, and product identifiers.',
        inputSchema: {
          type: 'object',
          properties: {
            serial_numbers: {
              type: 'string',
              description: 'Comma-separated list of serial numbers (max 75, e.g., "SAL09232Q0Z,FOC0903N5J9"). Supported formats include 11-character serial numbers and other Cisco serial number formats.',
              pattern: '^[A-Za-z0-9,\\s]+$'
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (starts at 1). Each page returns up to 75 results.',
              minimum: 1,
              default: 1
            }
          },
          required: ['serial_numbers']
        }
      },
      {
        name: 'get_coverage_summary_by_serial',
        description: 'Get summary coverage information for up to 75 serial numbers. Returns brief coverage status and key dates. Use this for quick coverage lookups without full details.',
        inputSchema: {
          type: 'object',
          properties: {
            serial_numbers: {
              type: 'string',
              description: 'Comma-separated list of serial numbers (max 75, e.g., "SAL09232Q0Z,FOC0903N5J9,INM07501EC3")',
              pattern: '^[A-Za-z0-9,\\s]+$'
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (starts at 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['serial_numbers']
        }
      },
      {
        name: 'get_coverage_summary_by_instance',
        description: 'Get coverage summary by instance numbers. Instance numbers are unique identifiers for devices in Cisco systems. Returns coverage information for specified instances.',
        inputSchema: {
          type: 'object',
          properties: {
            instance_numbers: {
              type: 'string',
              description: 'Comma-separated list of instance numbers (e.g., "12345,67890"). Instance numbers are numeric identifiers.',
              pattern: '^[0-9,\\s]+$'
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (starts at 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['instance_numbers']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<SerialApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);

    switch (name) {
      case 'get_coverage_status_by_serial': {
        const serialNumbers = (processedArgs.serial_numbers as string)
          .split(',')
          .map(s => s.trim())
          .join(',');
        const endpoint = `/coverage/status/serial_numbers/${serialNumbers}`;
        const params = { page_index: processedArgs.page_index };
        return await this.makeApiCall(endpoint, params) as SerialApiResponse;
      }

      case 'get_coverage_summary_by_serial': {
        const serialNumbers = (processedArgs.serial_numbers as string)
          .split(',')
          .map(s => s.trim())
          .join(',');
        const endpoint = `/coverage/summary/serial_numbers/${serialNumbers}`;
        const params = { page_index: processedArgs.page_index };
        return await this.makeApiCall(endpoint, params) as SerialApiResponse;
      }

      case 'get_coverage_summary_by_instance': {
        const instanceNumbers = (processedArgs.instance_numbers as string)
          .split(',')
          .map(s => s.trim())
          .join(',');
        const endpoint = `/coverage/summary/instance_numbers/${instanceNumbers}`;
        const params = { page_index: processedArgs.page_index };
        return await this.makeApiCall(endpoint, params) as SerialApiResponse;
      }

      default:
        throw new Error(`Unknown Serial API tool: ${name}`);
    }
  }

  protected getResultCount(data: ApiResponse): number {
    const serialData = data as SerialApiResponse;
    if (serialData.serial_numbers && Array.isArray(serialData.serial_numbers)) {
      return serialData.serial_numbers.length;
    }
    return 0;
  }
}
