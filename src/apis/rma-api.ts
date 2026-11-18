import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

export interface RmaApiResponse extends ApiResponse {
  returns?: Array<{
    rma_number?: string;
    user_id?: string;
    status?: string;
    return_reason?: string;
    created_date?: string;
    last_modified_date?: string;
    serial_number?: string;
    product_id?: string;
    product_description?: string;
    quantity?: number;
    tracking_number?: string;
    ship_date?: string;
    delivery_date?: string;
    case_number?: string;
  }>;
  pagination_response_record?: {
    page_index?: number;
    page_records?: number;
    total_records?: number;
    last_index?: number;
  };
}

export class RmaApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/return/v1.0';
  protected apiName = 'RMA';

  getTools(): Tool[] {
    return [
      {
        name: 'get_rma_details',
        description: 'Get detailed information for a specific RMA (Return Material Authorization) number. Returns comprehensive RMA details including status, return reason, product information, tracking, and associated case number.',
        inputSchema: {
          type: 'object',
          properties: {
            rma_number: {
              type: 'string',
              description: 'RMA number to look up (e.g., "84894022"). RMA numbers are typically 8-digit numeric values.',
              pattern: '^[0-9A-Z\\-]+$'
            }
          },
          required: ['rma_number']
        }
      },
      {
        name: 'get_rmas_by_user',
        description: 'Get list of RMAs associated with a specific user ID. Returns RMAs for the specified user, by default from the last 30 days. Maximum date range is 90 days.',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: {
              type: 'string',
              description: 'Cisco user ID (email or user identifier)',
              pattern: '^[A-Za-z0-9@.\\-_]+$'
            },
            from_date: {
              type: 'string',
              description: 'Start date (GMT) in YYYY-MM-DD format, e.g. "2023-01-01". Maximum 90 days range.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}$'
            },
            to_date: {
              type: 'string',
              description: 'End date (GMT) in YYYY-MM-DD format, e.g. "2023-03-31". Maximum 90 days from from_date.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}$'
            },
            status: {
              type: 'string',
              description: 'Filter by a single RMA status',
              enum: ['open', 'booked', 'hold', 'closed', 'cancelled']
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (starts at 1)',
              minimum: 1,
              default: 1
            }
          },
          required: ['user_id']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<RmaApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);

    switch (name) {
      case 'get_rma_details': {
        const rmaNumber = processedArgs.rma_number as string;
        const endpoint = `/returns/rma_numbers/${encodeURIComponent(rmaNumber)}`;
        return await this.makeApiCall(endpoint) as RmaApiResponse;
      }

      case 'get_rmas_by_user': {
        const userId = processedArgs.user_id as string;
        // Path and camelCase query params per Cisco-Return-API-v1_0 WADL
        const endpoint = `/returns/users/user_ids/${encodeURIComponent(userId)}`;
        const params: Record<string, any> = {
          pageIndex: processedArgs.page_index
        };

        if (processedArgs.from_date) {
          params.fromDate = processedArgs.from_date;
        }
        if (processedArgs.to_date) {
          params.toDate = processedArgs.to_date;
        }
        if (processedArgs.status) {
          params.status = processedArgs.status;
        }

        return await this.makeApiCall(endpoint, params) as RmaApiResponse;
      }

      default:
        throw new Error(`Unknown RMA API tool: ${name}`);
    }
  }

  protected getResultCount(data: ApiResponse): number {
    const rmaData = data as RmaApiResponse;
    if (rmaData.returns && Array.isArray(rmaData.returns)) {
      return rmaData.returns.length;
    }
    return 0;
  }
}
