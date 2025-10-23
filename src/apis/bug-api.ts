import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from './base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { BugApiResponse } from '../utils/formatting.js';
import { logger } from '../utils/logger.js';
import { WebSearchHelper } from '../utils/web-search.js';

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

  /**
   * Generate multiple version variations for progressive search
   * Returns array of normalized versions for fallback attempts
   */
  private normalizeVersion(version: string): string[] {
    const versions = [];

    // Convert to Cisco API format first: 17.09.06 -> 17.9.6 (remove leading zeros)
    const ciscoFormat = this.normalizeVersionString(version);
    versions.push(ciscoFormat);

    // Also keep original version in case it's already in correct format
    if (ciscoFormat !== version) {
      versions.push(version);
    }

    // Create abbreviated versions: 17.09.06 -> 17.09 -> 17.9
    if (version.includes('.')) {
      const parts = version.split('.');
      if (parts.length >= 3) {
        const shortVersion = parts.slice(0, 2).join('.');
        const shortCiscoFormat = this.normalizeVersionString(shortVersion);
        versions.push(shortCiscoFormat);
        if (shortCiscoFormat !== shortVersion) {
          versions.push(shortVersion);
        }
      }
      if (parts.length >= 2) {
        versions.push(parts[0]);
      }
    }

    // Remove duplicates and return
    return [...new Set(versions)];
  }

  private normalizeProductId(productId: string): string[] {
    const products = [];
    products.push(productId);
    
    // Remove suffixes like /K9
    if (productId.includes('/')) {
      products.push(productId.split('/')[0]);
    }
    
    // Handle series mappings
    if (productId.startsWith('ISR44')) {
      products.push('ISR4400');
      products.push('ISR');
    } else if (productId.startsWith('C92')) {
      products.push('C9200');
    } else if (productId.startsWith('ASR9')) {
      products.push('ASR9000');
    }
    
    return [...new Set(products)];
  }

  private async searchMultipleSeverities(searchFunc: (severity: string) => Promise<BugApiResponse>, maxSeverity: number = 3, meta?: { progressToken?: string }): Promise<BugApiResponse> {
    const allBugs: any[] = [];
    let totalResults = 0;

    logger.info('Starting multi-severity search', { maxSeverity });

    for (let severity = 1; severity <= maxSeverity; severity++) {
      try {
        // Send progress notification before searching this severity
        const { sendProgress } = await import('../mcp-server.js');
        sendProgress(meta?.progressToken, severity - 1, maxSeverity);

        logger.info(`Searching severity ${severity}`);
        const result = await searchFunc(severity.toString());
        
        if (result.bugs && Array.isArray(result.bugs)) {
          allBugs.push(...result.bugs);
          totalResults += result.total_results || result.bugs.length;
          logger.info(`Found ${result.bugs.length} bugs at severity ${severity}`);
        }
      } catch (error) {
        logger.warn(`Search failed for severity ${severity}`, { error: error instanceof Error ? error.message : error });
        // Continue with other severities
      }
    }
    
    // Remove duplicates by bug_id
    const uniqueBugs = allBugs.filter((bug, index, self) => 
      index === self.findIndex(b => b.bug_id === bug.bug_id)
    );
    
    logger.info('Multi-severity search completed', { 
      totalFound: uniqueBugs.length,
      searchedSeverities: maxSeverity 
    });
    
    return {
      bugs: uniqueBugs,
      total_results: uniqueBugs.length,
      page_index: 1
    };
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
      {
        name: 'smart_search_strategy',
        title: 'Smart Search Strategy Advisor',
        description: 'Analyzes search queries and suggests optimal search approaches based on input patterns. Provides strategic guidance for finding bugs effectively.',
        inputSchema: {
          type: 'object',
          properties: {
            query_description: {
              type: 'string',
              description: 'Describe what you want to search for (e.g., "ISR4431 version 17.09.06 high severity bugs")'
            },
            search_context: {
              type: 'string',
              description: 'Context for the search (incident, upgrade planning, maintenance, security review)',
              enum: ['incident', 'upgrade_planning', 'maintenance', 'security_review', 'general']
            }
          },
          required: ['query_description']
        }
      },
      {
        name: 'progressive_bug_search',
        title: 'Progressive Bug Search',
        description: 'Automatically tries multiple search strategies, starting specific and broadening scope if needed. Handles version normalization and product ID variations.',
        inputSchema: {
          type: 'object',
          properties: {
            primary_search_term: {
              type: 'string',
              description: 'Primary search term (product name, model, or keyword)'
            },
            version: {
              type: 'string',
              description: 'Software version (will try multiple formats: 17.09.06 -> 17.09 -> 17)'
            },
            severity_range: {
              type: 'string',
              description: 'Severity range to search (will search each level separately)',
              enum: ['high', 'medium', 'all'],
              default: 'high'
            },
            status: {
              type: 'string',
              description: 'Bug status filter',
              enum: ['O', 'F', 'T']
            }
          },
          required: ['primary_search_term']
        }
      },
      {
        name: 'multi_severity_search',
        title: 'Multi-Severity Search',
        description: 'RECOMMENDED for multi-severity searches: Automatically searches multiple severity levels and combines results. Use this when you need "severity 3 or higher", "high severity bugs", or any range of severities. Handles the API limitation that requires separate calls for each severity level. SMART FALLBACK: When product_id search with version returns no results, automatically falls back to keyword search for better coverage.',
        inputSchema: {
          type: 'object',
          properties: {
            search_term: {
              type: 'string',
              description: 'Search term (keyword or product identifier). For keyword searches, limited to 50 characters. Long product series names will be automatically shortened.'
            },
            search_type: {
              type: 'string',
              description: 'Type of search to perform. Use "product_series" for full product names like "Cisco 4000 Series Integrated Services Routers". For product IDs like "ISR4431", use "product_id" which will automatically fallback to keyword search if needed.',
              enum: ['keyword', 'product_id', 'product_series']
            },
            max_severity: {
              type: 'integer',
              description: 'Maximum severity level to include (1=highest, 6=lowest)',
              default: 3,
              minimum: 1,
              maximum: 6
            },
            version: {
              type: 'string',
              description: 'Software version to search for (e.g., "15.0", "14.0", "17.9.6"). Will be automatically included in search terms and used for product_series searches as affected_releases. For product_id searches, enables automatic keyword fallback if no results found.'
            }
          },
          required: ['search_term', 'search_type']
        }
      },
      {
        name: 'comprehensive_analysis',
        title: 'Comprehensive Bug and Lifecycle Analysis',
        description: 'BEST FOR DETAILED ANALYSIS: Combines bug database search with web search guidance for EoL information. Provides complete product analysis including known issues, lifecycle status, and actionable recommendations. Ideal for failover issues, configuration problems, and product reliability concerns.',
        inputSchema: {
          type: 'object',
          properties: {
            product_identifier: {
              type: 'string',
              description: 'Product name, model, or ID to analyze (e.g., ISR4431/K9, Cisco ASR 1000)'
            },
            software_version: {
              type: 'string',
              description: 'Software version to analyze (e.g., 17.09.06, 15.1(4)M)'
            },
            analysis_focus: {
              type: 'string',
              description: 'Focus of the analysis',
              enum: ['security', 'stability', 'lifecycle', 'upgrade_planning', 'incident_response', 'comprehensive'],
              default: 'comprehensive'
            },
            include_web_search_guidance: {
              type: 'boolean',
              description: 'Include web search queries and strategies for additional research',
              default: true
            }
          },
          required: ['product_identifier']
        }
      },
      {
        name: 'compare_software_versions',
        title: 'Compare Software Versions',
        description: 'Compare bugs, CVEs, and recommendations between two software versions on the same product. Analyzes differences in known issues, security vulnerabilities, and provides upgrade recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'string',
              description: 'Product ID or series name (e.g., C9300-24P, ISR4431/K9, "Cisco 4000 Series Integrated Services Routers")'
            },
            version_a: {
              type: 'string',
              description: 'First version to compare (e.g., 17.9.1, 15.1(4)M)'
            },
            version_b: {
              type: 'string',
              description: 'Second version to compare (e.g., 17.12.3, 15.2(4)M)'
            },
            include_cve_analysis: {
              type: 'boolean',
              description: 'Include CVE and security advisory analysis',
              default: true
            },
            include_eol_status: {
              type: 'boolean',
              description: 'Include end-of-life status comparison',
              default: true
            },
            include_recommendations: {
              type: 'boolean',
              description: 'Include software upgrade recommendations',
              default: true
            },
            max_severity: {
              type: 'integer',
              description: 'Maximum bug severity level to include (1=highest, 6=lowest)',
              default: 3,
              minimum: 1,
              maximum: 6
            }
          },
          required: ['product_id', 'version_a', 'version_b']
        }
      },
      {
        name: 'product_name_resolver',
        title: 'Product Name Resolver',
        description: 'Resolves product IDs to full product names and provides web search strategies. Helps convert technical product codes to searchable terms.',
        inputSchema: {
          type: 'object',
          properties: {
            product_id: {
              type: 'string',
              description: 'Product ID to resolve (e.g., ISR4431/K9, WS-C2960-24TC-L)'
            },
            include_search_strategies: {
              type: 'boolean',
              description: 'Include recommended web search strategies',
              default: true
            }
          },
          required: ['product_id']
        }
      }
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
        endpoint = `/bugs/products/product_name/${encodeURIComponent(processedArgs.product_name)}/affected_releases/${encodeURIComponent(processedArgs.affected_releases)}`;
        break;
        
      case 'search_bugs_by_product_name_fixed':
        endpoint = `/bugs/products/product_name/${encodeURIComponent(processedArgs.product_name)}/fixed_in_releases/${encodeURIComponent(processedArgs.fixed_releases)}`;
        break;
        
      // Enhanced search tools
      case 'smart_search_strategy':
        return this.generateSearchStrategy(processedArgs);
        
      case 'progressive_bug_search':
        return this.executeProgressiveSearch(processedArgs);
        
      case 'multi_severity_search':
        return this.executeMultiSeveritySearch(processedArgs, meta);
        
      case 'comprehensive_analysis':
        return this.executeComprehensiveAnalysis(processedArgs, meta);
        
      case 'compare_software_versions':
        return this.executeCompareSoftwareVersions(processedArgs, meta);
        
      case 'product_name_resolver':
        return this.executeProductNameResolver(processedArgs);
        
      default:
        throw new Error(`Tool implementation not found: ${name}`);
    }
    
    return await this.makeApiCall(endpoint, apiParams) as BugApiResponse;
  }

  // Enhanced tool implementations
  private async generateSearchStrategy(args: ToolArgs): Promise<BugApiResponse> {
    const queryDescription = args.query_description as string;
    const searchContext = (args.search_context as string) || 'general';
    
    // Analyze the query and generate strategy
    const strategy = this.analyzeSearchQuery(queryDescription, searchContext);
    
    return {
      bugs: [],
      total_results: 0,
      page_index: 1,
      search_strategy: strategy
    };
  }

  private analyzeSearchQuery(query: string, context: string): any {
    const strategy = {
      recommended_approach: [] as string[],
      search_parameters: {} as Record<string, any>,
      tips: [] as string[],
      context_specific_advice: [] as string[]
    };
    
    const lowerQuery = query.toLowerCase();
    
    // Detect product patterns
    if (lowerQuery.includes('isr44')) {
      strategy.recommended_approach.push('Use progressive_bug_search with primary_search_term="ISR4400"');
      strategy.search_parameters.product_variations = ['ISR4431/K9', 'ISR4431', 'ISR4400', 'ISR'];
      strategy.tips.push('ISR4431 variations: Try ISR4400 series search if exact model fails');
    }
    
    // Detect version patterns
    const versionMatch = query.match(/(\d+\.\d+\.\d+)/);
    if (versionMatch) {
      const fullVersion = versionMatch[1];
      const shortVersion = fullVersion.split('.').slice(0, 2).join('.');
      strategy.recommended_approach.push(`Try version variations: ${fullVersion} -> ${shortVersion}`);
      strategy.search_parameters.version_variations = [fullVersion, shortVersion];
      strategy.tips.push('Version searching: Start with full version, then try abbreviated (17.09.06 -> 17.09)');
    }
    
    // Detect severity patterns  
    if (lowerQuery.includes('high severity') || lowerQuery.includes('critical')) {
      strategy.recommended_approach.push('Use multi_severity_search with max_severity=3');
      strategy.search_parameters.severity_strategy = 'Search severities 1, 2, 3 separately and combine';
      strategy.tips.push('Severity limitation: API only accepts single values - search each severity individually');
    }
    
    // Context-specific advice
    switch (context) {
      case 'incident':
        strategy.context_specific_advice = [
          'Focus on open bugs (status=O) with high severity',
          'Search for specific error messages or symptoms',
          'Check both current and recent software versions',
          'Look for workarounds in bug descriptions'
        ];
        break;
      case 'upgrade_planning':
        strategy.context_specific_advice = [
          'Search fixed bugs in target version',
          'Check for new bugs introduced in target version',
          'Review upgrade-blocking issues',
          'Consider end-of-life status of current version'
        ];
        break;
      case 'security_review':
        strategy.context_specific_advice = [
          'Focus on security-related keywords: CVE, DoS, authentication',
          'Check recent security advisories',
          'Review high-severity security bugs',
          'Look for patches and mitigation strategies'
        ];
        break;
    }
    
    // General search effectiveness tips
    strategy.tips.push(
      'Start specific, then broaden: exact model -> series -> general',
      'Try partial version strings for better coverage',
      'Use keyword search for symptoms, product search for hardware',
      'Combine bug database with web search for complete picture'
    );
    
    return strategy;
  }

  private async executeProgressiveSearch(args: ToolArgs): Promise<BugApiResponse> {
    const primaryTerm = args.primary_search_term as string;
    const version = args.version as string;
    const severityRange = (args.severity_range as string) || 'high';
    const status = args.status as string;
    
    logger.info('Starting progressive search', { primaryTerm, version, severityRange });
    
    // Build search variations
    const searchVariations = [];
    
    // Try product ID approach first
    const productVariations = this.normalizeProductId(primaryTerm);
    for (const product of productVariations) {
      if (version) {
        const versionVariations = this.normalizeVersion(version);
        for (const v of versionVariations) {
          searchVariations.push({
            type: 'keyword',
            args: { keyword: `${product} ${v}`, status }
          });
        }
      }
      searchVariations.push({
        type: 'product_id',
        args: { base_pid: product, status }
      });
      searchVariations.push({
        type: 'keyword', 
        args: { keyword: product, status }
      });
    }
    
    // Try searches with different severity levels based on range
    const severityLevels = severityRange === 'high' ? ['1', '2', '3'] : 
                          severityRange === 'medium' ? ['3', '4'] : 
                          ['1', '2', '3', '4', '5', '6'];
    
    let bestResult: BugApiResponse = { bugs: [], total_results: 0, page_index: 1 };
    
    for (const variation of searchVariations) {
      for (const severity of severityLevels) {
        try {
          const searchArgs = { ...variation.args, severity };
          let result: BugApiResponse;
          
          if (variation.type === 'keyword') {
            result = await this.executeTool('search_bugs_by_keyword', searchArgs);
          } else {
            result = await this.executeTool('search_bugs_by_product_id', searchArgs);
          }
          
          if (result.bugs && result.bugs.length > bestResult.bugs!.length) {
            bestResult = result;
            logger.info('Found better result in progressive search', {
              variation: variation.type,
              args: searchArgs,
              resultCount: result.bugs.length
            });
          }
          
          // If we found results, we can be less aggressive about continuing
          if (result.bugs && result.bugs.length >= 5) {
            break;
          }
        } catch (error) {
          logger.warn('Progressive search variation failed', {
            variation,
            severity,
            error: error instanceof Error ? error.message : error
          });
        }
      }
      
      if (bestResult.bugs && bestResult.bugs.length >= 10) {
        break; // Good enough result found
      }
    }
    
    return bestResult;
  }

  private async executeMultiSeveritySearch(args: ToolArgs, meta?: { progressToken?: string }): Promise<BugApiResponse> {
    const searchTerm = args.search_term as string;
    const searchType = args.search_type as string;
    const maxSeverity = (args.max_severity as number) || 3;
    const version = args.version as string | undefined;
    const additionalParams = (args.additional_params as Record<string, any>) || {};

    // If version is provided, enhance search parameters
    if (version) {
      // For product_series searches, use version as affected_releases if not already specified
      if (searchType === 'product_series' && !additionalParams.affected_releases && !additionalParams.fixed_releases) {
        additionalParams.affected_releases = version;
      }
    }

    logger.info('Starting multi-severity search', { searchTerm, searchType, maxSeverity, version });

    const searchFunc = async (severity: string): Promise<BugApiResponse> => {
      const searchArgs = {
        severity,
        ...additionalParams
      };

      switch (searchType) {
        case 'keyword':
          // Handle keyword length limitation (50 characters max)
          let keywordTerm = searchTerm;

          // Include version in keyword search if provided
          if (version) {
            keywordTerm = `${searchTerm} ${version}`;
          }

          if (keywordTerm.length > 50) {
            // For long product series names, extract key terms
            if (searchTerm.toLowerCase().includes('4000 series')) {
              keywordTerm = version ? `ISR4000 ${version}` : 'ISR4000';
            } else if (searchTerm.toLowerCase().includes('catalyst 9200')) {
              keywordTerm = version ? `Catalyst 9200 ${version}` : 'Catalyst 9200';
            } else if (searchTerm.toLowerCase().includes('asr 1000')) {
              keywordTerm = version ? `ASR1000 ${version}` : 'ASR1000';
            } else if (searchTerm.toLowerCase().includes('callmanager') || searchTerm.toLowerCase().includes('unified communications manager')) {
              keywordTerm = version ? `CallManager ${version}` : 'CallManager';
            } else {
              // Generic shortening: take first 47 chars + '...'
              keywordTerm = keywordTerm.substring(0, 47) + '...';
            }
            logger.info('Shortened keyword search term', {
              original: version ? `${searchTerm} ${version}` : searchTerm,
              shortened: keywordTerm,
              reason: 'Keyword search 50-character limit'
            });
          }
          return await this.executeTool('search_bugs_by_keyword', { keyword: keywordTerm, ...searchArgs });
        case 'product_id':
          // Try product_id search first
          const productIdResult = await this.executeTool('search_bugs_by_product_id', { base_pid: searchTerm, ...searchArgs });

          // If product_id search returns no results and version is provided, fallback to keyword search
          if ((!productIdResult.bugs || productIdResult.bugs.length === 0) && version) {
            logger.info('Product ID search returned no results, falling back to keyword search', {
              searchTerm,
              version,
              severity
            });

            let keywordTerm = `${searchTerm} ${version}`;
            if (keywordTerm.length > 50) {
              keywordTerm = keywordTerm.substring(0, 47) + '...';
            }

            return await this.executeTool('search_bugs_by_keyword', { keyword: keywordTerm, ...searchArgs });
          }

          return productIdResult;
        case 'product_series':
          const affectedReleases = additionalParams.affected_releases || (version ? version : undefined);
          const fixedReleases = additionalParams.fixed_releases;

          if (!affectedReleases && !fixedReleases) {
            throw new Error('product_series search requires a version parameter or affected_releases/fixed_releases');
          }

          const toolName = fixedReleases ?
            'search_bugs_by_product_series_fixed' :
            'search_bugs_by_product_series_affected';
          const releaseParam = fixedReleases || affectedReleases;
          return await this.executeTool(toolName, {
            product_series: searchTerm,
            [fixedReleases ? 'fixed_releases' : 'affected_releases']: releaseParam,
            ...searchArgs
          });
        default:
          throw new Error(`Unsupported search type: ${searchType}`);
      }
    };

    return await this.searchMultipleSeverities(searchFunc, maxSeverity, meta);
  }

  private async executeComprehensiveAnalysis(args: ToolArgs, meta?: { progressToken?: string }): Promise<BugApiResponse> {
    const productIdentifier = args.product_identifier as string;
    const softwareVersion = args.software_version as string;
    const analysisFocus = (args.analysis_focus as string) || 'comprehensive';
    const includeWebSearchGuidance = (args.include_web_search_guidance as boolean) !== false;

    logger.info('Starting comprehensive analysis', { productIdentifier, softwareVersion, analysisFocus });
    
    // Convert full product names to searchable terms for bug database
    let searchableProductTerm = productIdentifier;
    let productSeries = null;
    
    // Check if we can get the product series for this identifier
    productSeries = WebSearchHelper.getProductSeries(productIdentifier);
    
    if (productIdentifier.toLowerCase().includes('cisco') && productIdentifier.length > 20) {
      // This looks like a full product name, try to extract the series
      if (productIdentifier.toLowerCase().includes('4000 series') || productIdentifier.toLowerCase().includes('4431') || productIdentifier.toLowerCase().includes('4451')) {
        productSeries = 'Cisco 4000 Series Integrated Services Routers';
        searchableProductTerm = 'ISR4431';
      } else if (productIdentifier.toLowerCase().includes('catalyst 9200') || productIdentifier.toLowerCase().includes('9200 series')) {
        productSeries = 'Cisco Catalyst 9200 Series';
        searchableProductTerm = 'C9200';
      } else if (productIdentifier.toLowerCase().includes('asr 1000') || productIdentifier.toLowerCase().includes('1000 series')) {
        productSeries = 'Cisco ASR 1000 Series';
        searchableProductTerm = 'ASR1000';
      } else {
        // Extract model numbers or use keyword search approach
        const modelMatch = productIdentifier.match(/(\w+\d+)/);
        if (modelMatch) {
          searchableProductTerm = modelMatch[1];
        }
      }
      logger.info('Processed product identifier', { 
        original: productIdentifier, 
        searchable: searchableProductTerm,
        productSeries: productSeries 
      });
    }
    
    const analysis = {
      product: productIdentifier,
      searchable_product_term: searchableProductTerm,
      version: softwareVersion,
      focus: analysisFocus,
      bug_analysis: null as any,
      product_resolution: null as any,
      web_search_guidance: null as any,
      recommendations: [] as string[],
      search_strategy_used: [] as string[]
    };
    
    // Step 1: Product name resolution
    const { sendProgress } = await import('../mcp-server.js');
    const totalSteps = 5;
    sendProgress(meta?.progressToken, 0, totalSteps);

    try {
      analysis.product_resolution = await WebSearchHelper.resolveProductName(productIdentifier);
      analysis.search_strategy_used.push('Product ID resolution via known mappings and patterns');
    } catch (error) {
      logger.error('Product resolution failed', { error });
    }

    // Step 2: Bug database analysis
    sendProgress(meta?.progressToken, 1, totalSteps);

    try {
      let searchQuery = searchableProductTerm;
      if (softwareVersion) {
        searchQuery += ` ${softwareVersion}`;
      }

      analysis.search_strategy_used.push('Progressive bug search with version normalization and product name conversion');
      analysis.bug_analysis = await this.executeProgressiveSearch({
        primary_search_term: searchableProductTerm,
        version: softwareVersion,
        severity_range: analysisFocus === 'security' ? 'high' : 'medium'
      });
      
      // Add product series search if we have that information and a software version
      sendProgress(meta?.progressToken, 2, totalSteps);

      if (productSeries && softwareVersion) {
        analysis.search_strategy_used.push('Product series search with full product name and Cisco API version format');
        try {
          // Convert version to Cisco API format (17.09.06 -> 17.9.6)
          const ciscoFormattedVersion = WebSearchHelper.formatVersionForCiscoAPI(softwareVersion);
          const productSeriesResult = await this.executeTool('search_bugs_by_product_series_affected', {
            product_series: productSeries,
            affected_releases: ciscoFormattedVersion
          });
          
          if (productSeriesResult.bugs && analysis.bug_analysis.bugs) {
            const combinedBugs = [...analysis.bug_analysis.bugs, ...productSeriesResult.bugs];
            const uniqueBugs = combinedBugs.filter((bug, index, self) => 
              index === self.findIndex(b => b.bug_id === bug.bug_id)
            );
            analysis.bug_analysis.bugs = uniqueBugs;
            analysis.bug_analysis.total_results = uniqueBugs.length;
            logger.info('Combined product series search results', { 
              addedBugs: productSeriesResult.bugs.length,
              totalUnique: uniqueBugs.length 
            });
          }
        } catch (error) {
          logger.warn('Product series search failed', { productSeries, softwareVersion, error });
        }
      }

      // Add multi-severity search for critical analysis
      sendProgress(meta?.progressToken, 3, totalSteps);

      if (analysisFocus === 'security' || analysisFocus === 'comprehensive') {
        analysis.search_strategy_used.push('Multi-severity search for complete coverage');
        const multiSevResult = await this.executeMultiSeveritySearch({
          search_term: searchQuery,
          search_type: 'keyword',
          max_severity: 3
        });
        
        // Combine results
        if (multiSevResult.bugs && analysis.bug_analysis.bugs) {
          const combinedBugs = [...analysis.bug_analysis.bugs, ...multiSevResult.bugs];
          const uniqueBugs = combinedBugs.filter((bug, index, self) => 
            index === self.findIndex(b => b.bug_id === bug.bug_id)
          );
          analysis.bug_analysis.bugs = uniqueBugs;
          analysis.bug_analysis.total_results = uniqueBugs.length;
        }
      }
    } catch (error) {
      logger.error('Bug analysis failed in comprehensive analysis', { error });
      analysis.bug_analysis = { error: error instanceof Error ? error.message : 'Unknown error' };
    }

    // Step 3: Generate web search guidance
    sendProgress(meta?.progressToken, 4, totalSteps);

    if (includeWebSearchGuidance) {
      try {
        analysis.web_search_guidance = {
          lifecycle_queries: WebSearchHelper.generateLifecycleSearchQueries(productIdentifier, softwareVersion),
          product_info: analysis.product_resolution,
          recommended_searches: []
        };

        // Add context-specific web search guidance
        if (analysisFocus === 'incident_response') {
          const incidentStrategy = WebSearchHelper.generateIncidentSearchStrategy(
            productIdentifier, 
            softwareVersion
          );
          analysis.web_search_guidance.incident_strategy = incidentStrategy;
        }

        // Add general research recommendations
        analysis.web_search_guidance.recommended_searches = [
          `"${productIdentifier}" release notes site:cisco.com`,
          `"${productIdentifier}" field notices site:cisco.com`,
          `"${productIdentifier}" security advisories site:cisco.com`
        ];

        if (softwareVersion) {
          analysis.web_search_guidance.recommended_searches.push(
            `"${softwareVersion}" bugs fixes site:cisco.com`,
            `"${softwareVersion}" known issues site:cisco.com`
          );
        }

        analysis.search_strategy_used.push('Web search guidance generation for external research');
      } catch (error) {
        logger.error('Web search guidance generation failed', { error });
      }
    }
    
    // Step 4: Generate recommendations based on findings
    if (analysis.bug_analysis && analysis.bug_analysis.bugs) {
      const bugCount = analysis.bug_analysis.bugs.length;
      const openBugs = analysis.bug_analysis.bugs.filter((b: any) => b.status === 'O').length;
      const criticalBugs = analysis.bug_analysis.bugs.filter((b: any) => ['1', '2'].includes(b.severity)).length;
      
      if (criticalBugs > 0) {
        analysis.recommendations.push(`⚠️ Found ${criticalBugs} critical/high severity bugs - review immediately`);
      }
      
      if (openBugs > 0) {
        analysis.recommendations.push(`📋 ${openBugs} open bugs found - check for workarounds and fixes`);
      }
      
      if (bugCount === 0) {
        analysis.recommendations.push('✅ No bugs found with current search criteria - consider broader search');
      }
      
      // Product resolution recommendations
      if (analysis.product_resolution?.fullName) {
        analysis.recommendations.push(`🔗 Product resolved: ${analysis.product_resolution.fullName}`);
        if (analysis.product_resolution.modelUrl) {
          analysis.recommendations.push(`📖 Official documentation: ${analysis.product_resolution.modelUrl}`);
        }
      }
      
      // Web search recommendations
      if (includeWebSearchGuidance && analysis.web_search_guidance) {
        analysis.recommendations.push('🌐 Use provided web search queries for additional research');
        analysis.recommendations.push('🔍 Check Cisco.com for latest field notices and security advisories');
      }
      
      // Version-specific recommendations
      if (softwareVersion) {
        analysis.recommendations.push('📅 Verify end-of-life status using provided lifecycle search queries');
        analysis.recommendations.push('⬆️ Review newer software versions for bug fixes and security updates');
      }
    }
    
    // Return the analysis as a bug response with metadata
    return {
      bugs: analysis.bug_analysis?.bugs || [],
      total_results: analysis.bug_analysis?.bugs?.length || 0,
      page_index: 1,
      comprehensive_analysis: analysis
    };
  }

  private async executeCompareSoftwareVersions(args: ToolArgs, meta?: { progressToken?: string }): Promise<BugApiResponse> {
    const productId = args.product_id as string;
    const versionA = args.version_a as string;
    const versionB = args.version_b as string;
    const includeCveAnalysis = (args.include_cve_analysis as boolean) !== false;
    const includeEolStatus = (args.include_eol_status as boolean) !== false;
    const includeRecommendations = (args.include_recommendations as boolean) !== false;
    const maxSeverity = (args.max_severity as number) || 3;

    logger.info('Starting software version comparison', {
      productId, versionA, versionB, includeCveAnalysis, includeEolStatus, includeRecommendations, maxSeverity
    });
    
    const comparison: any = {
      product_id: productId,
      version_a: versionA,
      version_b: versionB,
      analysis_timestamp: new Date().toISOString(),
      bug_comparison: null,
      cve_analysis: null,
      software_recommendations: null,
      eol_status: null,
      recommendations: [],
      summary: {
        version_a_issues: 0,
        version_b_issues: 0,
        shared_issues: 0,
        fixed_in_b: 0,
        introduced_in_b: 0,
        recommendation: null
      }
    };
    
    const { sendProgress } = await import('../mcp-server.js');
    const totalSteps = 6;

    try {
      // 1. Bug Analysis - Compare bugs between versions
      sendProgress(meta?.progressToken, 0, totalSteps);
      logger.info('Analyzing bugs for both versions');
      const bugComparison = await this.compareBugsBetweenVersions(productId, versionA, versionB, maxSeverity);
      comparison.bug_comparison = bugComparison;
      
      // Update summary counts
      comparison.summary.version_a_issues = bugComparison.version_a_bugs?.length || 0;
      comparison.summary.version_b_issues = bugComparison.version_b_bugs?.length || 0;
      comparison.summary.shared_issues = bugComparison.shared_bugs?.length || 0;
      comparison.summary.fixed_in_b = bugComparison.fixed_in_version_b?.length || 0;
      comparison.summary.introduced_in_b = bugComparison.introduced_in_version_b?.length || 0;
      
      // 2. CVE Analysis (if requested)
      sendProgress(meta?.progressToken, 1, totalSteps);
      if (includeCveAnalysis) {
        logger.info('Analyzing CVEs and security advisories');
        const cveAnalysis = await this.analyzeCvesBetweenVersions(productId, versionA, versionB);
        comparison.cve_analysis = cveAnalysis;
      }
      
      // 3. Software Recommendations (if requested and Software API available)
      sendProgress(meta?.progressToken, 2, totalSteps);
      if (includeRecommendations) {
        logger.info('Getting software recommendations');
        const recommendations = await this.getSoftwareRecommendations(productId, versionA, versionB);
        comparison.software_recommendations = recommendations;
      }
      
      // 4. End-of-Life Status (if requested)
      sendProgress(meta?.progressToken, 3, totalSteps);
      if (includeEolStatus) {
        logger.info('Checking end-of-life status');
        const eolStatus = await this.checkEolStatus(versionA, versionB);
        comparison.eol_status = eolStatus;
      }
      
      // 5. Generate Recommendations
      sendProgress(meta?.progressToken, 4, totalSteps);
      comparison.recommendations = this.generateVersionComparisonRecommendations(comparison);

      // 6. Determine overall recommendation
      sendProgress(meta?.progressToken, 5, totalSteps);
      comparison.summary.recommendation = this.determineOverallRecommendation(comparison);
      
      logger.info('Software version comparison completed successfully', {
        productId,
        versionA,
        versionB,
        bugDifferences: comparison.summary.fixed_in_b - comparison.summary.introduced_in_b,
        recommendation: comparison.summary.recommendation
      });
      
    } catch (error) {
      logger.error('Error during software version comparison', { 
        productId, versionA, versionB, error: error instanceof Error ? error.message : error 
      });
      
      comparison.error = `Software version comparison failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
      comparison.recommendations.push('⚠️ Comparison failed - verify product ID and version formats');
    }
    
    return {
      bugs: [], // No direct bugs in this response
      total_results: 1,
      page_index: 1,
      version_comparison: comparison
    };
  }

  private async executeProductNameResolver(args: ToolArgs): Promise<BugApiResponse> {
    const productId = args.product_id as string;
    const includeSearchStrategies = (args.include_search_strategies as boolean) !== false;
    
    logger.info('Resolving product name', { productId });
    
    try {
      const resolution = await WebSearchHelper.resolveProductName(productId);
      
      const result = {
        product_id: productId,
        resolution: resolution,
        search_strategies: includeSearchStrategies ? {
          lifecycle_queries: WebSearchHelper.generateLifecycleSearchQueries(productId),
          general_queries: [
            `"${productId}" specifications site:cisco.com`,
            `"${productId}" datasheet site:cisco.com`,
            `"${productId}" installation guide site:cisco.com`,
            `"${productId}" configuration guide site:cisco.com`
          ]
        } : null
      };
      
      return {
        bugs: [],
        total_results: 0,
        page_index: 1,
        product_resolution: result
      };
    } catch (error) {
      logger.error('Product name resolution failed', { productId, error });
      
      return {
        bugs: [],
        total_results: 0,
        page_index: 1,
        error: `Failed to resolve product name: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  // Helper methods for version comparison
  private async compareBugsBetweenVersions(productId: string, versionA: string, versionB: string, maxSeverity: number): Promise<any> {
    try {
      // Normalize versions to Cisco API format
      const normalizedVersionA = this.normalizeVersionForComparison(versionA);
      const normalizedVersionB = this.normalizeVersionForComparison(versionB);
      
      // Search bugs for both versions
      const [bugsA, bugsB] = await Promise.all([
        this.searchBugsForVersion(productId, normalizedVersionA, maxSeverity),
        this.searchBugsForVersion(productId, normalizedVersionB, maxSeverity)
      ]);
      
      // Analyze differences
      const versionABugIds = new Set(bugsA.bugs?.map((bug: any) => bug.bug_id) || []);
      const versionBBugIds = new Set(bugsB.bugs?.map((bug: any) => bug.bug_id) || []);
      
      // Find shared bugs
      const sharedBugIds = new Set([...versionABugIds].filter(id => versionBBugIds.has(id)));
      
      // Find bugs fixed in version B (present in A but not in B)
      const fixedInBIds = new Set([...versionABugIds].filter(id => !versionBBugIds.has(id)));
      
      // Find bugs introduced in version B (present in B but not in A)
      const introducedInBIds = new Set([...versionBBugIds].filter(id => !versionABugIds.has(id)));
      
      return {
        version_a_bugs: bugsA.bugs || [],
        version_b_bugs: bugsB.bugs || [],
        shared_bugs: (bugsA.bugs || []).filter((bug: any) => sharedBugIds.has(bug.bug_id)),
        fixed_in_version_b: (bugsA.bugs || []).filter((bug: any) => fixedInBIds.has(bug.bug_id)),
        introduced_in_version_b: (bugsB.bugs || []).filter((bug: any) => introducedInBIds.has(bug.bug_id)),
        analysis: {
          total_bugs_a: versionABugIds.size,
          total_bugs_b: versionBBugIds.size,
          shared_bugs: sharedBugIds.size,
          fixed_count: fixedInBIds.size,
          introduced_count: introducedInBIds.size,
          net_improvement: fixedInBIds.size - introducedInBIds.size
        }
      };
    } catch (error) {
      logger.error('Bug comparison failed', { productId, versionA, versionB, error });
      return {
        error: `Bug comparison failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        version_a_bugs: [],
        version_b_bugs: [],
        shared_bugs: [],
        fixed_in_version_b: [],
        introduced_in_version_b: []
      };
    }
  }

  private async searchBugsForVersion(productId: string, version: string, maxSeverity: number): Promise<any> {
    // Try different search strategies based on product ID format
    if (this.isProductSeries(productId)) {
      return await this.executeMultiSeveritySearch({
        search_term: productId,
        search_type: 'product_series',
        max_severity: maxSeverity,
        additional_params: { affected_releases: version }
      });
    } else {
      return await this.executeMultiSeveritySearch({
        search_term: productId,
        search_type: 'product_id',
        max_severity: maxSeverity,
        version: version
      });
    }
  }

  private async analyzeCvesBetweenVersions(productId: string, versionA: string, versionB: string): Promise<any> {
    // This would integrate with PSIRT API if available
    // For now, return a placeholder structure
    return {
      note: 'CVE analysis requires PSIRT API integration',
      version_a_cves: [],
      version_b_cves: [],
      recommendations: [
        '🔍 Manually check Cisco Security Advisories for both versions',
        '🌐 Search: site:tools.cisco.com security advisory [product] [version]'
      ]
    };
  }

  private async getSoftwareRecommendations(productId: string, versionA: string, versionB: string): Promise<any> {
    // This would integrate with Software API if available
    // For now, return a placeholder structure
    return {
      note: 'Software recommendations require Software API integration',
      recommendations: [
        '🔍 Use dedicated Software API tools for detailed recommendations',
        '🌐 Check Cisco.com for latest recommended releases',
        `📋 Tools: get_software_suggestions_by_product_ids, get_compatible_software_by_product_id`
      ]
    };
  }

  private async checkEolStatus(versionA: string, versionB: string): Promise<any> {
    // This would integrate with EoX API if available
    // For now, return a placeholder structure
    return {
      note: 'End-of-life status requires EoX API integration',
      version_a_eol: null,
      version_b_eol: null,
      recommendations: [
        '🔍 Use EoX API tools to check end-of-life status',
        '🌐 Search: get_eox_by_software_release tool'
      ]
    };
  }

  private generateVersionComparisonRecommendations(comparison: any): string[] {
    const recommendations: string[] = [];
    const summary = comparison.summary;
    
    // Bug analysis recommendations
    if (summary.fixed_in_b > 0) {
      recommendations.push(`✅ Version B fixes ${summary.fixed_in_b} known issues from Version A`);
    }
    
    if (summary.introduced_in_b > 0) {
      recommendations.push(`⚠️ Version B introduces ${summary.introduced_in_b} new known issues`);
    }
    
    if (summary.shared_issues > 0) {
      recommendations.push(`📋 ${summary.shared_issues} issues affect both versions`);
    }
    
    // Net improvement analysis
    const netImprovement = summary.fixed_in_b - summary.introduced_in_b;
    if (netImprovement > 0) {
      recommendations.push(`📈 Net improvement: ${netImprovement} fewer known issues in Version B`);
    } else if (netImprovement < 0) {
      recommendations.push(`📉 Net regression: ${Math.abs(netImprovement)} more known issues in Version B`);
    } else {
      recommendations.push(`⚖️ Equal number of known issues in both versions`);
    }
    
    // General recommendations
    recommendations.push('🔍 Review specific bug details for impact assessment');
    recommendations.push('📅 Check end-of-life dates for both versions');
    recommendations.push('🛡️ Verify security advisory coverage for both versions');
    
    return recommendations;
  }

  private determineOverallRecommendation(comparison: any): string {
    const summary = comparison.summary;
    const netImprovement = summary.fixed_in_b - summary.introduced_in_b;
    
    if (netImprovement > 5) {
      return `Strongly recommend Version B (${comparison.version_b}) - significantly fewer known issues`;
    } else if (netImprovement > 0) {
      return `Recommend Version B (${comparison.version_b}) - fewer known issues`;
    } else if (netImprovement === 0) {
      return `No clear preference - similar issue counts. Consider other factors (features, support, EoL)`;
    } else if (netImprovement > -5) {
      return `Slight preference for Version A (${comparison.version_a}) - fewer new issues`;
    } else {
      return `Consider staying with Version A (${comparison.version_a}) - significantly fewer known issues`;
    }
  }

  private normalizeVersionForComparison(version: string): string {
    // Convert version formats for Cisco API compatibility
    // Example: 17.09.06 -> 17.9.6
    return version.replace(/\.0+(\d)/g, '.$1');
  }

  private isProductSeries(productId: string): boolean {
    // Detect if this is a product series name vs. specific product ID
    const seriesKeywords = [
      'series', 'cisco', 'catalyst', 'nexus', 'asr', 'isr', 'integrated services',
      'wireless controller', 'unified communications'
    ];
    
    const lowerId = productId.toLowerCase();
    return seriesKeywords.some(keyword => lowerId.includes(keyword)) || lowerId.includes(' ');
  }
}