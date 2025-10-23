import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

export class PsirtApi extends BaseApi {
  protected baseUrl = 'https://apix.cisco.com/security/advisories/v2';
  protected apiName = 'PSIRT';

  getTools(): Tool[] {
    return [
      {
        name: 'get_all_security_advisories',
        title: 'Get All Security Advisories',
        description: 'Get all published security advisories with optional pagination and filtering. NOTE: PSIRT API does not support searching by product series or product name directly - use severity, year, or date range filters instead.',
        inputSchema: {
          type: 'object',
          properties: {
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              maximum: 100,
              description: 'Page number (1-100)'
            },
            page_size: {
              type: 'integer',
              default: 20,
              minimum: 1,
              maximum: 100,
              description: 'Number of advisories per page (1-100)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: []
        }
      },
      {
        name: 'get_security_advisory_by_id',
        title: 'Get Security Advisory by ID',
        description: 'Get a specific security advisory by its advisory ID (e.g., cisco-sa-20180221-ucdm)',
        inputSchema: {
          type: 'object',
          properties: {
            advisory_id: {
              type: 'string',
              description: 'Advisory ID in format cisco-sa-YYYYMMDD-xxxx (e.g., cisco-sa-20180221-ucdm)',
              pattern: '^cisco-sa-'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['advisory_id']
        }
      },
      {
        name: 'get_security_advisory_by_cve',
        title: 'Get Security Advisory by CVE',
        description: 'Get security advisory by CVE identifier (e.g., CVE-2018-0101)',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: {
              type: 'string',
              description: 'CVE identifier in format CVE-YYYY-NNNN (e.g., CVE-2018-0101)',
              pattern: '^CVE-[0-9]{4}-[0-9]+$'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['cve_id']
        }
      },
      {
        name: 'get_security_advisories_by_severity',
        title: 'Get Security Advisories by Severity',
        description: 'Get all security advisories for a specific severity level. Severity levels: critical, high, medium, low, informational (NOT numeric like Bug API)',
        inputSchema: {
          type: 'object',
          properties: {
            severity: {
              type: 'string',
              description: 'Security impact rating. Valid options: critical, high, medium, low, informational',
              enum: ['critical', 'high', 'medium', 'low', 'informational']
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              maximum: 100,
              description: 'Page number (1-100)'
            },
            page_size: {
              type: 'integer',
              default: 20,
              minimum: 1,
              maximum: 100,
              description: 'Number of advisories per page (1-100)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['severity']
        }
      },
      {
        name: 'get_security_advisory_by_bug_id',
        title: 'Get Security Advisory by Bug ID',
        description: 'Get security advisory by Cisco bug ID',
        inputSchema: {
          type: 'object',
          properties: {
            bug_id: {
              type: 'string',
              description: 'Cisco bug ID (e.g., CSCvi12345)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['bug_id']
        }
      },
      {
        name: 'get_latest_security_advisories',
        title: 'Get Latest Security Advisories',
        description: 'Get the latest N security advisories',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              default: 10,
              description: 'Number of latest advisories to retrieve (1-100)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: []
        }
      },
      {
        name: 'get_security_advisories_by_year',
        title: 'Get Security Advisories by Year',
        description: 'Get all security advisories published in a specific year',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'integer',
              minimum: 2000,
              maximum: 2025,
              description: 'Year to filter advisories (e.g., 2023)'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              maximum: 100,
              description: 'Page number (1-100)'
            },
            page_size: {
              type: 'integer',
              default: 20,
              minimum: 1,
              maximum: 100,
              description: 'Number of advisories per page (1-100)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['year']
        }
      },
      {
        name: 'get_security_advisories_by_first_published',
        title: 'Get Security Advisories by Date Range',
        description: 'Get security advisories by first published date range',
        inputSchema: {
          type: 'object',
          properties: {
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
              pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
              pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
            },
            page_index: {
              type: 'integer',
              default: 1,
              minimum: 1,
              maximum: 100,
              description: 'Page number (1-100)'
            },
            page_size: {
              type: 'integer',
              default: 20,
              minimum: 1,
              maximum: 100,
              description: 'Number of advisories per page (1-100)'
            },
            summary_details: {
              type: 'boolean',
              default: false,
              description: 'Include advisory summary description'
            },
            product_names: {
              type: 'boolean',
              default: false,
              description: 'Include product names in response'
            }
          },
          required: ['start_date', 'end_date']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<ApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);
    
    switch (name) {
      case 'get_all_security_advisories':
        return await this.getAllSecurityAdvisories(processedArgs);
      case 'get_security_advisory_by_id':
        return await this.getSecurityAdvisoryById(processedArgs);
      case 'get_security_advisory_by_cve':
        return await this.getSecurityAdvisoryByCve(processedArgs);
      case 'get_security_advisories_by_severity':
        return await this.getSecurityAdvisoriesBySeverity(processedArgs);
      case 'get_security_advisory_by_bug_id':
        return await this.getSecurityAdvisoryByBugId(processedArgs);
      case 'get_latest_security_advisories':
        return await this.getLatestSecurityAdvisories(processedArgs);
      case 'get_security_advisories_by_year':
        return await this.getSecurityAdvisoriesByYear(processedArgs);
      case 'get_security_advisories_by_first_published':
        return await this.getSecurityAdvisoriesByFirstPublished(processedArgs);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async getAllSecurityAdvisories(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index !== undefined) params.pageIndex = args.page_index;
    if (args.page_size !== undefined) params.pageSize = args.page_size;
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall('/all', params);
    
    return this.formatSecurityAdvisoryResponse(response, 'All Security Advisories');
  }

  private async getSecurityAdvisoryById(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/advisory/${args.advisory_id}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `Security Advisory ${args.advisory_id}`);
  }

  private async getSecurityAdvisoryByCve(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/cve/${args.cve_id}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `Security Advisory for CVE ${args.cve_id}`);
  }

  private async getSecurityAdvisoriesBySeverity(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index !== undefined) params.pageIndex = args.page_index;
    if (args.page_size !== undefined) params.pageSize = args.page_size;
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/severity/${args.severity}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `${args.severity.toUpperCase()} Severity Security Advisories`);
  }

  private async getSecurityAdvisoryByBugId(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/bugid/${args.bug_id}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `Security Advisory for Bug ${args.bug_id}`);
  }

  private async getLatestSecurityAdvisories(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/latest/${args.number || 10}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `Latest ${args.number || 10} Security Advisories`);
  }

  private async getSecurityAdvisoriesByYear(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};
    if (args.page_index !== undefined) params.pageIndex = args.page_index;
    if (args.page_size !== undefined) params.pageSize = args.page_size;
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall(`/year/${args.year}`, params);
    
    return this.formatSecurityAdvisoryResponse(response, `Security Advisories for ${args.year}`);
  }

  private async getSecurityAdvisoriesByFirstPublished(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {
      startDate: args.start_date,
      endDate: args.end_date
    };
    if (args.page_index !== undefined) params.pageIndex = args.page_index;
    if (args.page_size !== undefined) params.pageSize = args.page_size;
    if (args.summary_details) params.summaryDetails = args.summary_details;
    if (args.product_names) params.productNames = args.product_names;

    const response = await this.makeApiCall('/all/firstpublished', params);
    
    return this.formatSecurityAdvisoryResponse(response, `Security Advisories Published ${args.start_date} to ${args.end_date}`);
  }

  private formatSecurityAdvisoryResponse(data: any, title: string): ApiResponse {
    if (!data || (!data.advisories && !data.advisory)) {
      return {
        error: 'No Data Found',
        message: 'No security advisories found matching the specified criteria.',
        data: null
      };
    }

    // Handle single advisory response
    if (data.advisory) {
      const advisory = data.advisory;
      return {
        data: {
          title,
          count: 1,
          advisories: [this.formatAdvisory(advisory)]
        }
      };
    }

    // Handle multiple advisories response
    const advisories = data.advisories || [];
    const formattedAdvisories = advisories.map((advisory: any) => this.formatAdvisory(advisory));

    return {
      data: {
        title,
        count: advisories.length,
        total_results: data.total_results || advisories.length,
        advisories: formattedAdvisories,
        pagination: data.pagination_info || null
      }
    };
  }

  private formatAdvisory(advisory: any): any {
    return {
      advisory_id: advisory.advisoryId || advisory.advisory_id,
      advisory_title: advisory.advisoryTitle || advisory.title,
      severity: advisory.severity,
      first_published: advisory.firstPublished || advisory.first_published,
      last_updated: advisory.lastUpdated || advisory.last_updated,
      status: advisory.status,
      cves: advisory.cves || [],
      bug_ids: advisory.bugIDs || advisory.bug_ids || [],
      products: advisory.productNames || advisory.products || [],
      summary: advisory.summary || null,
      cisco_url: `https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/${advisory.advisoryId || advisory.advisory_id}`
    };
  }
}