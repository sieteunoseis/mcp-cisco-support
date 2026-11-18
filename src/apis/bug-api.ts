import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { BugApiResponse } from '../utils/formatting.js';
import { logger } from '../utils/logger.js';

export class BugApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/bug/v2.0';
  protected apiName = 'Bug';

  // Utility functions for enhanced search capabilities

  /**
   * Normalize a single version string to Cisco API format
   * Converts "17.09.06" to "17.9.6" by removing leading zeros
   */
  private normalizeVersionString(version: string): string {
    if (!version) return version;
    // Remove leading zeros from each version segment: 17.09.06 -> 17.9.6
    return version.replace(/\.0+(\d)/g, '.$1');
  }


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
        description: 'Search for bugs using keywords in descriptions and headlines. Use this when searching by general terms, symptoms, or when product-specific tools are not applicable. IMPORTANT: severity parameter returns ONLY that specific level. For "severity 3 or higher" searches, use multi_severity_search tool instead. NOTE: Do NOT use product IDs (like ISR4431/K9) as keywords - use search_bugs_by_product_id instead.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Keywords to search for (general terms, symptoms, error messages - NOT product IDs)'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['base_pid']
        }
      },
      {
        name: 'search_bugs_by_product_and_release',
        description: 'Search bugs by specific product ID and software releases. CRITICAL: Use "software_releases" parameter with comma-separated values like "17.9.1,17.12.3" to search up to 75 versions in ONE API call. NEVER make multiple separate calls for different versions - the API supports multiple versions in a single request. Use this when you have an exact product ID and want to filter by specific software versions. For product series searches, use search_bugs_by_product_series_affected instead.',
        inputSchema: {
          type: 'object',
          properties: {
            base_pid: {
              type: 'string',
              description: 'Specific product ID (e.g., "C9300-24P", "ISR4431", "ASA5516-X") - NOT product series names'
            },
            software_releases: {
              type: 'string',
              description: 'Comma-separated software release versions (e.g., "17.9.1,17.12.3") - can search up to 75 versions in one call. Do NOT make separate API calls for each version.'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['base_pid', 'software_releases']
        }
      },
      {
        name: 'search_bugs_by_product_series_affected',
        description: 'Search bugs by product series and affected releases. This endpoint accepts full product series names like "Cisco 4000 Series Integrated Services Routers". IMPORTANT: Use Cisco API version format without leading zeros (17.9.6 not 17.09.06).',
        inputSchema: {
          type: 'object',
          properties: {
            product_series: {
              type: 'string',
              description: 'Product series name (accepts full names like "Cisco 4000 Series Integrated Services Routers", "Cisco Catalyst 9200 Series", etc.)'
            },
            affected_releases: {
              type: 'string',
              description: 'Comma-separated affected release versions in Cisco API format (e.g., "17.9.6,17.12.3" not "17.09.06" - no leading zeros). Can search up to 75 versions in one call.'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_series', 'affected_releases']
        }
      },
      {
        name: 'search_bugs_by_product_series_fixed',
        description: 'Search bugs by product series and fixed releases. This endpoint accepts full product series names like "Cisco 4000 Series Integrated Services Routers". IMPORTANT: Use Cisco API version format without leading zeros (17.9.6 not 17.09.06).',
        inputSchema: {
          type: 'object',
          properties: {
            product_series: {
              type: 'string',
              description: 'Product series name (accepts full names like "Cisco 4000 Series Integrated Services Routers", "Cisco Catalyst 9200 Series", etc.)'
            },
            fixed_releases: {
              type: 'string',
              description: 'Comma-separated fixed release versions in Cisco API format (e.g., "17.9.6,17.12.3" not "17.09.06" - no leading zeros). Can search up to 75 versions in one call.'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_series', 'fixed_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_affected',
        description: 'Search bugs by full product name and affected releases. NOTE: Requires FULL descriptive product names (like "Cisco 4431 Integrated Services Router") not product IDs. Use search_bugs_by_product_id for product IDs like ISR4431.',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Full descriptive product name (e.g., "Cisco 4431 Integrated Services Router", "Cisco 2504 Wireless Controller") - NOT product IDs like ISR4431'
            },
            affected_releases: {
              type: 'string',
              description: 'Comma-separated affected release versions (e.g., "12.5(1)SU5,14.0(1)SU2"). Can search up to 75 versions in one call.'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_name', 'affected_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_fixed',
        description: 'Search bugs by full product name and fixed releases. NOTE: Requires FULL descriptive product names (like "Cisco 4431 Integrated Services Router") not product IDs. Use search_bugs_by_product_id for product IDs like ISR4431.',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Full descriptive product name (e.g., "Cisco 4431 Integrated Services Router", "Cisco 2504 Wireless Controller") - NOT product IDs like ISR4431'
            },
            fixed_releases: {
              type: 'string',
              description: 'Comma-separated fixed release versions (e.g., "12.5(1)SU6,14.0(1)SU3"). Can search up to 75 versions in one call.'
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
              description: 'Bug severity filter. Returns bugs with ONLY the specified severity level. Values: 1=Severity 1 (highest), 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6 (lowest). For "severity 3 or higher" bugs, use multi_severity_search tool which handles multiple separate API calls.',
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_name', 'fixed_releases']
        }
      },
      // Enhanced search tools based on user analysis
    ];
  }

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<BugApiResponse> {
    const { processedArgs } = this.validateTool(name, args);

    // Normalize version strings to remove leading zeros (17.09.06 -> 17.9.6)
    // This ensures Cisco API compatibility across all tools
    if (processedArgs.software_releases) {
      processedArgs.software_releases = this.normalizeVersionString(processedArgs.software_releases as string);
    }
    if (processedArgs.affected_releases) {
      processedArgs.affected_releases = this.normalizeVersionString(processedArgs.affected_releases as string);
    }
    if (processedArgs.fixed_releases) {
      processedArgs.fixed_releases = this.normalizeVersionString(processedArgs.fixed_releases as string);
    }
    if (processedArgs.version) {
      processedArgs.version = this.normalizeVersionString(processedArgs.version as string);
    }

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
        // Ensure forward slashes are properly encoded for product IDs like ISR4431-V/K9
        const encodedBasePid = encodeURIComponent(processedArgs.base_pid).replace(/\//g, '%2F');
        endpoint = `/bugs/products/product_id/${encodedBasePid}`;
        break;
        
      case 'search_bugs_by_product_and_release':
        // Ensure forward slashes are properly encoded for product IDs like ISR4431-V/K9
        const encodedBasePidForRelease = encodeURIComponent(processedArgs.base_pid).replace(/\//g, '%2F');
        endpoint = `/bugs/products/product_id/${encodedBasePidForRelease}/software_releases/${encodeURIComponent(processedArgs.software_releases)}`;
        break;
        
      case 'search_bugs_by_product_series_affected':
        endpoint = `/bugs/product_series/${encodeURIComponent(processedArgs.product_series)}/affected_releases/${encodeURIComponent(processedArgs.affected_releases)}`;
        break;
        
      case 'search_bugs_by_product_series_fixed':
        endpoint = `/bugs/product_series/${encodeURIComponent(processedArgs.product_series)}/fixed_in_releases/${encodeURIComponent(processedArgs.fixed_releases)}`;
        logger.info('Product series fixed endpoint', { 
          product_series: processedArgs.product_series,
          fixed_releases: processedArgs.fixed_releases,
          endpoint,
          fullUrl: `${this.baseUrl}${endpoint}`
        });
        break;
        
      case 'search_bugs_by_product_name_affected':
        endpoint = `/bugs/product_name/${encodeURIComponent(processedArgs.product_name)}/affected_releases/${encodeURIComponent(processedArgs.affected_releases)}`;
        break;
        
      case 'search_bugs_by_product_name_fixed':
        endpoint = `/bugs/product_name/${encodeURIComponent(processedArgs.product_name)}/fixed_in_releases/${encodeURIComponent(processedArgs.fixed_releases)}`;
        break;
        
      default:
        throw new Error(`Tool implementation not found: ${name}`);
    }
    
    return await this.makeApiCall(endpoint, apiParams) as BugApiResponse;
  }
}
