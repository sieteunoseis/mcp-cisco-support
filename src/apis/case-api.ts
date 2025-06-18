import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { CaseApiResponse } from '../utils/formatting.js';

export class CaseApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/case/v3';
  protected apiName = 'Case';

  getTools(): Tool[] {
    return [
      {
        name: 'get_case_summary',
        description: 'Get case summary information for up to 30 specific case IDs. Returns brief information for multiple cases.',
        inputSchema: {
          type: 'object',
          properties: {
            case_ids: {
              type: 'string',
              description: 'Comma-separated list of case IDs (max 30, e.g., "123456789,987654321")',
              pattern: '^[0-9,\\s]+$'
            },
            sort_by: {
              type: 'string',
              description: 'Sort results by field. UPDATED_DATE: Sort by last modification time (ascending). Default. STATUS: Sort by status (ascending)',
              enum: ['STATUS', 'SEVERITY', 'CREATED_DATE', 'MODIFIED_DATE', 'UPDATED_DATE'],
              default: 'UPDATED_DATE'
            }
          },
          required: ['case_ids']
        }
      },
      {
        name: 'get_case_details',
        description: 'Get detailed information for a single case ID. Returns comprehensive case information including status, severity, description, and all case attributes.',
        inputSchema: {
          type: 'object',
          properties: {
            case_id: {
              type: 'string',
              description: 'Single case ID to get details for (e.g., "123456789")',
              pattern: '^[0-9]+$'
            }
          },
          required: ['case_id']
        }
      },
      {
        name: 'search_cases_by_contract',
        description: 'Search for cases associated with specific contract IDs (max 10). Returns cases linked to the specified contracts.',
        inputSchema: {
          type: 'object',
          properties: {
            contract_ids: {
              type: 'string',
              description: 'Comma-separated list of contract IDs (max 10)',
              pattern: '^[A-Za-z0-9,\\s\\-]+$'
            },
            status_flag: {
              type: 'string',
              description: 'Return only cases associated with the specified status; O = open, C = closed. If status_flag is O (open), all open cases within the specified date range are returned; if a date range is not specified, all open cases associated with the other search parameters are returned. The maximum range returned is 90 days. The default behavior for this parameter is to return cases of both open and closed status.',
              enum: ['O', 'C']
            },
            date_created_from: {
              type: 'string',
              description: 'Beginning date (in UTC) of the range in which to search. For example: 2013-04-23T11:00:14Z Note: The maximum date range currently supported is 90 days.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$'
            },
            date_created_to: {
              type: 'string',
              description: 'End date (in UTC) of the range in which to search. For example: 2013-04-23T11:00:00Z Note: The maximum date range currently supported is 90 days.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$'
            },
            sort_by: {
              type: 'string',
              description: 'Sort results by field. UPDATED_DATE: Sort by last modification time (ascending). Default. STATUS: Sort by status (ascending)',
              enum: ['STATUS', 'SEVERITY', 'CREATED_DATE', 'MODIFIED_DATE', 'UPDATED_DATE'],
              default: 'UPDATED_DATE'
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (default: 5)',
              minimum: 1,
              default: 5
            }
          },
          required: ['contract_ids']
        }
      },
      {
        name: 'search_cases_by_user',
        description: 'Search for cases associated with specific user IDs (max 10). Returns cases owned by or involving the specified users.',
        inputSchema: {
          type: 'object',
          properties: {
            user_ids: {
              type: 'string',
              description: 'Comma-separated list of user IDs (max 10)',
              pattern: '^[A-Za-z0-9@.,\\s\\-]+$'
            },
            status_flag: {
              type: 'string',
              description: 'Return only cases associated with the specified status; O = open, C = closed. If status_flag is O (open), all open cases within the specified date range are returned; if a date range is not specified, all open cases associated with the other search parameters are returned. The maximum range returned is 90 days. The default behavior for this parameter is to return cases of both open and closed status.',
              enum: ['O', 'C']
            },
            date_created_from: {
              type: 'string',
              description: 'Beginning date (in UTC) of the range in which to search. For example: 2013-04-23T11:00:14Z Note: The maximum date range currently supported is 90 days.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$'
            },
            date_created_to: {
              type: 'string',
              description: 'End date (in UTC) of the range in which to search. For example: 2013-04-23T11:00:00Z Note: The maximum date range currently supported is 90 days.',
              pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$'
            },
            sort_by: {
              type: 'string',
              description: 'Sort results by field. UPDATED_DATE: Sort by last modification time (ascending). Default. STATUS: Sort by status (ascending)',
              enum: ['STATUS', 'SEVERITY', 'CREATED_DATE', 'MODIFIED_DATE', 'UPDATED_DATE'],
              default: 'UPDATED_DATE'
            },
            page_index: {
              type: 'integer',
              description: 'Page number for pagination (default: 5)',
              minimum: 1,
              default: 5
            }
          },
          required: ['user_ids']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<CaseApiResponse> {
    const { processedArgs } = this.validateTool(name, args);
    
    let endpoint: string;
    let apiParams: Record<string, any> = {};
    
    switch (name) {
      case 'get_case_summary':
        endpoint = `/cases/case_ids/${encodeURIComponent(processedArgs.case_ids)}`;
        apiParams.sort_by = processedArgs.sort_by || 'UPDATED_DATE';
        break;
        
      case 'get_case_details':
        endpoint = `/cases/details/case_id/${encodeURIComponent(processedArgs.case_id)}`;
        break;
        
      case 'search_cases_by_contract':
        endpoint = `/cases/contracts/contract_ids/${encodeURIComponent(processedArgs.contract_ids)}`;
        // Add all optional parameters with defaults
        if (processedArgs.status_flag) apiParams.status_flag = processedArgs.status_flag;
        if (processedArgs.date_created_from) apiParams.date_created_from = processedArgs.date_created_from;
        if (processedArgs.date_created_to) apiParams.date_created_to = processedArgs.date_created_to;
        apiParams.sort_by = processedArgs.sort_by || 'UPDATED_DATE';
        apiParams.page_index = processedArgs.page_index || 5;
        break;
        
      case 'search_cases_by_user':
        endpoint = `/cases/users/user_ids/${encodeURIComponent(processedArgs.user_ids)}`;
        // Add all optional parameters with defaults
        if (processedArgs.status_flag) apiParams.status_flag = processedArgs.status_flag;
        if (processedArgs.date_created_from) apiParams.date_created_from = processedArgs.date_created_from;
        if (processedArgs.date_created_to) apiParams.date_created_to = processedArgs.date_created_to;
        apiParams.sort_by = processedArgs.sort_by || 'UPDATED_DATE';
        apiParams.page_index = processedArgs.page_index || 5;
        break;
        
      default:
        throw new Error(`Tool implementation not found: ${name}`);
    }
    
    return await this.makeApiCall(endpoint, apiParams) as CaseApiResponse;
  }

  // Override result count for Case API responses
  protected getResultCount(data: CaseApiResponse): number {
    if ('cases' in data && Array.isArray(data.cases)) {
      return data.cases.length;
    }
    // Some Case API endpoints might return a single case object
    if ('case_id' in data) {
      return 1;
    }
    return 0;
  }
}