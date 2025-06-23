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
  private normalizeVersion(version: string): string[] {
    const versions = [];
    
    // Convert to Cisco API format first: 17.09.06 -> 17.9.6 (remove leading zeros)
    const ciscoFormat = version.replace(/\.0+(\d)/g, '.$1');
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
        const shortCiscoFormat = shortVersion.replace(/\.0+(\d)/g, '.$1');
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

  private async searchMultipleSeverities(searchFunc: (severity: string) => Promise<BugApiResponse>, maxSeverity: number = 3): Promise<BugApiResponse> {
    const allBugs: any[] = [];
    let totalResults = 0;
    
    logger.info('Starting multi-severity search', { maxSeverity });
    
    for (let severity = 1; severity <= maxSeverity; severity++) {
      try {
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
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
              description: 'Comma-separated affected release versions in Cisco API format (e.g., "17.9.6" not "17.09.06" - no leading zeros)'
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
              description: 'Comma-separated fixed release versions in Cisco API format (e.g., "17.9.6" not "17.09.06" - no leading zeros)'
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_series', 'fixed_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_affected',
        description: 'Search bugs by product identifier and affected releases. NOTE: Use product IDs (like ISR4431, WS-C2960-24TC-L) not full marketing names. For full product names, use keyword search instead.',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Product identifier (e.g., ISR4431, WS-C2960-24TC-L) - NOT full marketing names like "Cisco 4431 Integrated Services Router"'
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
              description: 'Sort order for results. Default: modified_date (recent first)',
              enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest']
            },
          },
          required: ['product_name', 'affected_releases']
        }
      },
      {
        name: 'search_bugs_by_product_name_fixed',
        description: 'Search bugs by product identifier and fixed releases. NOTE: Use product IDs (like ISR4431, WS-C2960-24TC-L) not full marketing names. For full product names, use keyword search instead.',
        inputSchema: {
          type: 'object',
          properties: {
            product_name: {
              type: 'string',
              description: 'Product identifier (e.g., ISR4431, WS-C2960-24TC-L) - NOT full marketing names like "Cisco 4431 Integrated Services Router"'
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
        description: 'Searches multiple severity levels in parallel and combines results. Handles the API limitation of single severity values per search.',
        inputSchema: {
          type: 'object',
          properties: {
            search_term: {
              type: 'string',
              description: 'Search term (keyword or product identifier)'
            },
            search_type: {
              type: 'string',
              description: 'Type of search to perform',
              enum: ['keyword', 'product_id', 'product_series']
            },
            max_severity: {
              type: 'integer',
              description: 'Maximum severity level to include (1=highest, 6=lowest)',
              default: 3,
              minimum: 1,
              maximum: 6
            },
            additional_params: {
              type: 'object',
              description: 'Additional parameters specific to search type (e.g., affected_releases for product_series)',
              additionalProperties: true
            }
          },
          required: ['search_term', 'search_type']
        }
      },
      {
        name: 'comprehensive_analysis',
        title: 'Comprehensive Bug and Lifecycle Analysis',
        description: 'Combines bug database search with web search guidance for EoL information. Provides complete product analysis including known issues, lifecycle status, and actionable recommendations.',
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
        
      // Enhanced search tools
      case 'smart_search_strategy':
        return this.generateSearchStrategy(processedArgs);
        
      case 'progressive_bug_search':
        return this.executeProgressiveSearch(processedArgs);
        
      case 'multi_severity_search':
        return this.executeMultiSeveritySearch(processedArgs);
        
      case 'comprehensive_analysis':
        return this.executeComprehensiveAnalysis(processedArgs);
        
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

  private async executeMultiSeveritySearch(args: ToolArgs): Promise<BugApiResponse> {
    const searchTerm = args.search_term as string;
    const searchType = args.search_type as string;
    const maxSeverity = (args.max_severity as number) || 3;
    const additionalParams = (args.additional_params as Record<string, any>) || {};
    
    logger.info('Starting multi-severity search', { searchTerm, searchType, maxSeverity });
    
    const searchFunc = async (severity: string): Promise<BugApiResponse> => {
      const searchArgs = {
        severity,
        ...additionalParams
      };
      
      switch (searchType) {
        case 'keyword':
          return await this.executeTool('search_bugs_by_keyword', { keyword: searchTerm, ...searchArgs });
        case 'product_id':
          return await this.executeTool('search_bugs_by_product_id', { base_pid: searchTerm, ...searchArgs });
        case 'product_series':
          if (!additionalParams.affected_releases && !additionalParams.fixed_releases) {
            throw new Error('product_series search requires affected_releases or fixed_releases in additional_params');
          }
          const toolName = additionalParams.fixed_releases ? 
            'search_bugs_by_product_series_fixed' : 
            'search_bugs_by_product_series_affected';
          const releaseParam = additionalParams.fixed_releases || additionalParams.affected_releases;
          return await this.executeTool(toolName, {
            product_series: searchTerm,
            [additionalParams.fixed_releases ? 'fixed_releases' : 'affected_releases']: releaseParam,
            ...searchArgs
          });
        default:
          throw new Error(`Unsupported search type: ${searchType}`);
      }
    };
    
    return await this.searchMultipleSeverities(searchFunc, maxSeverity);
  }

  private async executeComprehensiveAnalysis(args: ToolArgs): Promise<BugApiResponse> {
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
    try {
      analysis.product_resolution = await WebSearchHelper.resolveProductName(productIdentifier);
      analysis.search_strategy_used.push('Product ID resolution via known mappings and patterns');
    } catch (error) {
      logger.error('Product resolution failed', { error });
    }

    // Step 2: Bug database analysis
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
}