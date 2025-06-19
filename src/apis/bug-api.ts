import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { BugApiResponse } from '../utils/formatting.js';

export class BugApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/bug/v2.0';
  protected apiName = 'Bug';

  getTools(): Tool[] {
    return [
      {
        name: 'get_bug_details',
        title: 'Get Bug Details',
        description: 'Get details for up to 5 specific bug IDs',
        inputSchema: {
          type: 'object',
          properties: {
            bug_ids: {
              type: 'string',
              description: 'Comma-separated list of bug IDs (max 5)'
            }
          },
          required: ['bug_ids']
        }
      },
      {
        name: 'search_bugs_by_keyword',
        title: 'Search Bugs by Keyword',
        description: 'Search for bugs using keywords in descriptions and headlines. Use this when searching by general terms, symptoms, or when product-specific tools are not applicable. IMPORTANT: Cisco API only accepts ONE severity and ONE status value per search - for "severity 3 or higher" you must make separate searches for each severity level (1, 2, 3).',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Keywords to search for'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['keyword']
        }
      },
      {
        name: 'search_bugs_by_product_id',
        description: 'Search bugs by specific base product ID (e.g., C9200-24P). Use when you have an exact Cisco product ID. For general product searches by name, consider using keyword search instead.',
        inputSchema: {
          type: 'object',
          properties: {
            base_pid: {
              type: 'string',
              description: 'Base product ID'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['base_pid']
        }
      },
      {
        name: 'search_bugs_by_product_and_release',
        description: 'Search bugs by product ID and software releases',
        inputSchema: {
          type: 'object',
          properties: {
            base_pid: {
              type: 'string',
              description: 'Base product ID'
            },
            software_releases: {
              type: 'string',
              description: 'Comma-separated software release versions'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['base_pid', 'software_releases']
        }
      },
      {
        name: 'search_bugs_by_product_series_affected',
        description: 'Search bugs by product series and affected releases',
        inputSchema: {
          type: 'object',
          properties: {
            product_series: {
              type: 'string',
              description: 'Product series name'
            },
            affected_releases: {
              type: 'string',
              description: 'Comma-separated affected release versions'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['product_series', 'affected_releases']
        }
      },
      {
        name: 'search_bugs_by_product_series_fixed',
        description: 'Search bugs by product series and fixed releases',
        inputSchema: {
          type: 'object',
          properties: {
            product_series: {
              type: 'string',
              description: 'Product series name'
            },
            fixed_releases: {
              type: 'string',
              description: 'Comma-separated fixed release versions'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['product_series', 'fixed_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_affected',
        description: 'Search bugs by exact product name and affected releases',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Exact product name'
            },
            affected_releases: {
              type: 'string',
              description: 'Comma-separated affected release versions'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['product_name', 'affected_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_fixed',
        description: 'Search bugs by exact product name and fixed releases',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Exact product name'
            },
            fixed_releases: {
              type: 'string',
              description: 'Comma-separated fixed release versions'
            },
            page_index: {
              type: 'integer',
              default: 1,
              description: 'Page number (10 results per page)'
            },
            status: {
              type: 'string',
              description: 'Bug status filter. IMPORTANT: Only ONE status allowed per search. Values: O=Open, F=Fixed, T=Terminated. Do NOT use comma-separated values like "O,F".',
              enum: ['O', 'F', 'T']
            },
            severity: {
              type: 'string',
              description: 'Bug severity filter. IMPORTANT: Only ONE severity level allowed per search. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). To find "severity 3 or higher", make separate searches for severity 1, then severity 2, then severity 3. Do NOT use comma-separated values.',
              enum: ['1', '2', '3', '4', '5', '6']
            },
            modified_date: {
              type: 'string',
              description: 'Last modified date filter. Values: 1=Last Week, 2=Last 30 Days, 3=Last 6 Months, 4=Last Year, 5=All. Default: 5 (All)',
              enum: ['1', '2', '3', '4', '5'],
              default: '5'
            },
            sort_by: {
              type: 'string',
              description: 'Sort order'
            }
          },
          required: ['product_name', 'fixed_releases']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs): Promise<BugApiResponse> {
    const { processedArgs } = this.validateTool(name, args);
    
    // Build API parameters
    const apiParams = this.buildStandardParams(processedArgs);
    
    let endpoint: string;
    
    switch (name) {
      case 'get_bug_details':
        endpoint = `/bugs/bug_ids/${encodeURIComponent(processedArgs.bug_ids)}`;
        break;
        
      case 'search_bugs_by_keyword':
        endpoint = `/bugs/keyword/${encodeURIComponent(processedArgs.keyword)}`;
        break;
        
      case 'search_bugs_by_product_id':
        endpoint = `/bugs/products/product_id/${encodeURIComponent(processedArgs.base_pid)}`;
        break;
        
      case 'search_bugs_by_product_and_release':
        endpoint = `/bugs/products/product_id/${encodeURIComponent(processedArgs.base_pid)}/software_releases/${encodeURIComponent(processedArgs.software_releases)}`;
        break;
        
      case 'search_bugs_by_product_series_affected':
        endpoint = `/bugs/product_series/${encodeURIComponent(processedArgs.product_series)}/affected_releases/${encodeURIComponent(processedArgs.affected_releases)}`;
        break;
        
      case 'search_bugs_by_product_series_fixed':
        endpoint = `/bugs/product_series/${encodeURIComponent(processedArgs.product_series)}/fixed_releases/${encodeURIComponent(processedArgs.fixed_releases)}`;
        break;
        
      case 'search_bugs_by_product_name_affected':
        endpoint = `/bugs/products/product_name/${encodeURIComponent(processedArgs.product_name)}/affected_releases/${encodeURIComponent(processedArgs.affected_releases)}`;
        break;
        
      case 'search_bugs_by_product_name_fixed':
        endpoint = `/bugs/products/product_name/${encodeURIComponent(processedArgs.product_name)}/fixed_releases/${encodeURIComponent(processedArgs.fixed_releases)}`;
        break;
        
      default:
        throw new Error(`Tool implementation not found: ${name}`);
    }
    
    return await this.makeApiCall(endpoint, apiParams) as BugApiResponse;
  }
}