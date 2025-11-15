import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  PingRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListResourceTemplatesRequestSchema,
  Prompt,
  PromptMessage,
  TextContent,
  ElicitRequestSchema,
  ElicitResult
} from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';
import { join } from 'path';

// Import modular API system
import { createApiRegistry, ApiRegistry, SupportedAPI, getEnabledAPIs } from './apis/index.js';
import { formatBugResults, formatCaseResults, formatEoxResults, ApiResponse, BugApiResponse, CaseApiResponse, EoxApiResponse } from './utils/formatting.js';
import { setLogging, logger } from './utils/logger.js';
import { SERVER_ICON } from './utils/icon.js';
import { initializeProgressNotifications, sendProgress, createProgressTracker } from './utils/progress.js';
import { ciscoPrompts, promptApiMapping, getFilteredPrompts } from './prompts/cisco-prompts.js';
import { ElicitationSchemas, createElicitationRequest } from './elicitation/schemas.js';
import { shouldUseToonFormat, bugResponseToToon, caseResponseToToon, eoxResponseToToon, getFormatDescription } from './utils/toon-formatter.js';

// Load environment variables
dotenv.config();

// Get version from package.json (handle different working directories)
function findPackageJson(): string {
  const possiblePaths = [
    join(__dirname, '../../package.json'),  // When compiled to dist/src/
    join(__dirname, '../package.json'),     // When running from src/
    join(process.cwd(), 'package.json'),    // When running from project root
  ];
  
  for (const path of possiblePaths) {
    try {
      return readFileSync(path, 'utf8');
    } catch (error) {
      // Continue to next path
    }
  }
  
  // Fallback version
  return JSON.stringify({ version: '1.5.0' });
}

const packageJson = JSON.parse(findPackageJson());
const VERSION = packageJson.version;

// Initialize API registry (will be created fresh each time for dynamic config)
let apiRegistry: ApiRegistry;
let ENABLED_APIS: SupportedAPI[];

// Initialize or refresh the API registry
function initializeApiRegistry() {
  ENABLED_APIS = getEnabledAPIs();
  apiRegistry = createApiRegistry();
}

// Initialize at module load
initializeApiRegistry();

// Prompts are now imported from ./prompts/cisco-prompts.js
// Elicitation schemas are now imported from ./elicitation/schemas.js

// Get available prompts (filtered by enabled APIs)
export function getAvailablePrompts(): Prompt[] {
  return getFilteredPrompts(ENABLED_APIS);
}

// Generate prompt content based on prompt name and arguments
export function generatePrompt(name: string, args: Record<string, any>): PromptMessage[] {
  switch (name) {
    case 'cisco-high-severity-search':
      const maxSev = args.max_severity ? parseInt(args.max_severity) : 3;
      const versionText = args.version ? ` version ${args.version}` : '';
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Search for high-severity bugs for ${args.product_keyword}${versionText}:

**Search Requirements:**
- Product: ${args.product_keyword}${versionText}
- Severity: ${maxSev} or higher (1 = highest severity)
- Status: Open bugs only

**Important:** The Cisco Bug API only accepts ONE severity level per search. You must search each severity individually:

1. First search: severity="1", status="O", keyword="${args.product_keyword}${versionText}"
2. Second search: severity="2", status="O", keyword="${args.product_keyword}${versionText}"
${maxSev >= 3 ? `3. Third search: severity="3", status="O", keyword="${args.product_keyword}${versionText}"` : ''}

Please execute these searches sequentially and combine the results. Do NOT use comma-separated values like "1,2,3" for severity as this will cause a 500 error.`
          }
        }
      ];

    case 'cisco-incident-investigation':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me investigate this Cisco incident:

**Incident Details:**
- Symptom/Error: ${args.symptom}
- Product: ${args.product}
${args.severity ? `- Severity: Level ${args.severity}` : ''}
${args.software_version ? `- Software Version: ${args.software_version}` : ''}

**Investigation Plan:**
1. Search for bugs matching the symptom keywords
2. Check product-specific bugs ${args.software_version ? `for version ${args.software_version}` : ''}
3. Focus on ${args.severity ? `severity ${args.severity} and higher` : 'high severity'} issues
4. Look for workarounds and fixes

Please start by searching for bugs related to "${args.symptom}" and then narrow down by product specifics.`
          }
        }
      ];

    case 'cisco-upgrade-planning':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me plan a Cisco software upgrade:

**Upgrade Details:**
- Current Version: ${args.current_version}
- Target Version: ${args.target_version}
- Product: ${args.product}
${args.environment ? `- Environment: ${args.environment}` : ''}

**Pre-Upgrade Analysis Needed:**
1. Find bugs fixed between ${args.current_version} and ${args.target_version}
2. Identify new bugs introduced in ${args.target_version}
3. Check for upgrade-blocking issues
4. Look for known upgrade procedures and considerations

Please search for bugs related to both versions and provide an upgrade risk assessment.`
          }
        }
      ];

    case 'cisco-maintenance-prep':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me prepare for Cisco maintenance:

**Maintenance Details:**
- Type: ${args.maintenance_type}
- Product: ${args.product}
${args.software_version ? `- Software Version: ${args.software_version}` : ''}
${args.timeline ? `- Timeline: ${args.timeline}` : ''}

**Pre-Maintenance Checklist:**
1. Search for bugs related to ${args.maintenance_type.toLowerCase()}
2. Check for product-specific issues ${args.software_version ? `in version ${args.software_version}` : ''}
3. Identify potential failure scenarios
4. Find recommended procedures and precautions
5. Look for rollback considerations

Please help me identify risks and create a maintenance plan with appropriate safeguards.`
          }
        }
      ];

    case 'cisco-security-advisory':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me research security issues for Cisco products:

**Security Assessment:**
- Product: ${args.product}
${args.software_version ? `- Version: ${args.software_version}` : ''}
${args.security_focus ? `- Focus Area: ${args.security_focus}` : ''}

**Security Analysis Needed:**
1. Search for security-related bugs and vulnerabilities
2. Focus on high-severity security issues
3. Check for recent security advisories
4. Look for patches and mitigation strategies
${args.security_focus ? `5. Specific research on: ${args.security_focus}` : ''}

Please search for security bugs using relevant keywords like "security", "vulnerability", "CVE", "DoS", "authentication", "authorization", etc.`
          }
        }
      ];

    case 'cisco-known-issues':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me research known issues in Cisco software:

**Research Target:**
- Product: ${args.product}
- Software Version: ${args.software_version}
${args.issue_type ? `- Issue Focus: ${args.issue_type}` : ''}

**Known Issues Analysis:**
1. Search for bugs in ${args.software_version}
2. Focus on ${args.issue_type || 'all types of'} issues
3. Check bug status (open vs. fixed)
4. Look for workarounds and solutions
5. Identify upgrade recommendations

Please search comprehensively for bugs affecting this version and provide a summary of major known issues.`
          }
        }
      ];

    case 'cisco-case-investigation':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me investigate Cisco support cases:

**Investigation Target:**
${args.case_id ? `- Case ID: ${args.case_id}` : ''}
${args.contract_id ? `- Contract ID: ${args.contract_id}` : ''}
${args.user_id ? `- User ID: ${args.user_id}` : ''}
${args.status ? `- Status Filter: ${args.status}` : ''}

**Case Investigation Plan:**
${args.case_id ? '1. Get detailed case information' : ''}
${args.contract_id ? '1. Search cases by contract ID' : ''}
${args.user_id ? '1. Search cases by user ID' : ''}
2. Analyze case status and severity
3. Look for related cases or patterns
4. Check for associated bugs or known issues

Please use the appropriate Case API tools to gather comprehensive case information.`
          }
        }
      ];

    case 'cisco-lifecycle-planning':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me plan for Cisco product lifecycle management:

**Lifecycle Planning Target:**
${args.product_ids ? `- Product IDs: ${args.product_ids}` : ''}
${args.serial_numbers ? `- Serial Numbers: ${args.serial_numbers}` : ''}
${args.date_range_start && args.date_range_end ? `- Date Range: ${args.date_range_start} to ${args.date_range_end}` : ''}

**Lifecycle Analysis Plan:**
1. Check end-of-life and end-of-sale dates for specified products
2. Identify upcoming maintenance and support end dates  
3. Analyze end-of-software maintenance dates
4. Review product bulletins and migration information
5. Plan replacement timeline and budget considerations

**Key Dates to Monitor:**
- End of Sale Date (when product stops being sold)
- End of Software Maintenance (when software updates stop)
- Last Date of Support (when all support ends)
- End of Service Contract Renewal (when new contracts stop)

Please use the EoX API tools to gather comprehensive lifecycle information for planning purposes.`
          }
        }
      ];

    case 'cisco-eox-research':
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Help me research Cisco end-of-life information:

**Research Focus:** ${args.product_focus}
**Search Values:** ${args.search_values}

**EoX Research Plan:**
${args.product_focus === 'product_ids' ? '1. Search EoX information by Product IDs' : ''}
${args.product_focus === 'serial_numbers' ? '1. Search EoX information by Serial Numbers' : ''}
${args.product_focus === 'software_releases' ? '1. Search EoX information by Software Releases' : ''}
${args.product_focus === 'date_range' ? '1. Search EoX information by Date Range' : ''}
2. Analyze end-of-life timeline and critical dates
3. Review product bulletins and migration guides
4. Identify replacement products and upgrade paths
5. Assess impact on current operations

**Important EoX Milestones:**
- **End of Life Announcement:** When Cisco announces the product's retirement
- **End of Sale:** Last date to order the product
- **End of Software Maintenance:** Last software updates and bug fixes
- **End of Support:** All technical support ends

Please use the appropriate EoX API tools based on the research focus area.`
          }
        }
      ];

    case 'cisco-smart-search':
      const includeWebGuidance = args.include_web_guidance !== 'false';
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Please perform an intelligent search analysis for: "${args.search_query}"

**Search Strategy Request:**
${args.search_context ? `- Context: ${args.search_context}` : ''}
- Query: ${args.search_query}
- Include web search guidance: ${includeWebGuidance}

**Recommended Approach:**
1. **Start with Smart Search Strategy**: Use \`smart_search_strategy\` tool to analyze the query and get optimal search recommendations
2. **Execute Comprehensive Analysis**: Use \`comprehensive_analysis\` tool with the product identifier and version detected
3. **Apply Progressive Search**: If initial results are limited, the system will automatically try broader search terms
4. **Multi-Severity Coverage**: For high-priority searches, automatically search multiple severity levels
${includeWebGuidance ? '5. **Web Search Guidance**: Get specific web search queries for additional research on Cisco.com' : ''}

**Enhanced Features Available:**
- **Product ID Resolution**: Converts technical product codes (ISR4431/K9) to full product names
- **Version Normalization**: Tries multiple version formats (17.09.06 → 17.09 → 17)
- **Automatic Refinement**: Broadens search scope when specific queries return no results
- **Parallel Severity Search**: Searches multiple severity levels simultaneously
- **Lifecycle Integration**: Includes end-of-life status and upgrade recommendations

Please execute this intelligent search strategy using the enhanced tools to provide comprehensive results.`
          }
        }
      ];

    case 'cisco-interactive-search':
      const useElicitation = args.use_elicitation !== 'false';
      return [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `Please perform an interactive search that demonstrates the elicitationRequest feature:

**Interactive Search Configuration:**
${args.initial_query ? `- Initial Query: ${args.initial_query}` : '- No initial query provided'}
- Use Elicitation: ${useElicitation}

**Demonstration Approach:**
1. **Start with Basic Search**: Use the provided initial query or ask for one
2. **Elicitation Demo**: Use elicitationRequest to gather additional search parameters:
   - Ask for search refinement (severity, status, date range)
   - Request user confirmation for search strategy
   - Collect product selection if multiple matches found
3. **Interactive Refinement**: Based on initial results, use elicitation to:
   - Refine search scope if too many results
   - Request confirmation before broad searches
   - Ask for product-specific details if needed
4. **Enhanced Results**: Provide comprehensive results with context

**Available Elicitation Schemas:**
- \`searchRefinement\`: Request severity, status, and date range parameters
- \`userConfirmation\`: Request confirmation for search strategy
- \`productSelection\`: Request specific product selection from options

**Example Elicitation Flow:**
1. If no initial query: "What would you like to search for in Cisco bugs?"
2. If broad results: "I found many results. Would you like to refine by severity level?"
3. If multiple products: "I found several products. Which specific one interests you?"
4. If potentially impactful: "This search will query multiple APIs. Proceed?"

This interactive approach showcases how elicitationRequest can make tools more user-friendly and context-aware.`
          }
        }
      ];

    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
}

// ============================================================================
// ELICITATION REQUEST SUPPORT - FUTURE/EXPERIMENTAL
// ============================================================================
// Note: ElicitationRequest is part of MCP spec (2025-06-18) but client support
// is limited as of January 2025. No major MCP clients (including Claude Desktop)
// have confirmed full implementation yet.
//
// Current Status:
// - ❌ Claude Desktop: No confirmed support
// - ❌ MCP Inspector: Unknown support
// - ✅ Spec compliant: Code follows MCP 2025-06-18 specification
//
// Alternative: Claude Desktop handles missing parameters through natural
// conversational follow-up questions, which works better than rigid schemas.
//
// This code is kept for:
// - Future client support (when available)
// - Custom MCP client implementations
// - HTTP mode with custom UI
// - Reference implementation
//
// Last Updated: January 2025 (v1.11.3)
// ============================================================================

// Elicitation request utilities are now exported from ./elicitation/schemas.js
// Re-export for backward compatibility
export { ElicitationSchemas, createElicitationRequest } from './elicitation/schemas.js';

// Format results based on API type and configuration
function formatResults(result: ApiResponse, apiName: string, toolName: string, args: Record<string, any>): string {
  // Check if TOON format should be used
  const useToon = shouldUseToonFormat();
  const formatType = getFormatDescription();

  logger.info(`Formatting results as ${formatType}`, { apiName, toolName });

  // If TOON format is enabled, use TOON formatting for JSON data
  if (useToon) {
    try {
      if (apiName === 'Bug' || toolName.includes('bug')) {
        return bugResponseToToon(result as BugApiResponse);
      } else if (apiName === 'Case' || toolName.includes('case')) {
        return caseResponseToToon(result as CaseApiResponse);
      } else if (apiName === 'EoX' || toolName.includes('eox')) {
        return eoxResponseToToon(result as EoxApiResponse);
      } else {
        // Fallback to TOON for generic API responses
        return bugResponseToToon(result as BugApiResponse);
      }
    } catch (error) {
      logger.warn('TOON formatting failed, falling back to standard format', { error });
      // Fall through to standard formatting
    }
  }

  // Standard format (human-readable markdown)
  const searchContext = { toolName, args };

  if (apiName === 'Bug' || toolName.includes('bug')) {
    return formatBugResults(result as BugApiResponse, searchContext);
  } else if (apiName === 'Case' || toolName.includes('case')) {
    return formatCaseResults(result as CaseApiResponse, searchContext);
  } else if (apiName === 'EoX' || toolName.includes('eox')) {
    return formatEoxResults(result as EoxApiResponse, searchContext);
  } else {
    // For placeholder APIs, the result already contains formatted error message
    return formatBugResults(result as BugApiResponse, searchContext);
  }
}

// Re-export progress utilities for backward compatibility
export { sendProgress, createProgressTracker } from './utils/progress.js';

// Create MCP server
export function createMCPServer(): Server {
  const server = new Server(
    {
      name: 'mcp-cisco-support',
      version: VERSION,
      icon: SERVER_ICON,
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {},
        elicitation: {},
      },
    }
  );

  // Initialize progress notification system
  initializeProgressNotifications(server);

  // Reinitialize API registry with server instance for sampling support
  ENABLED_APIS = getEnabledAPIs();  // Refresh enabled APIs list
  apiRegistry = createApiRegistry(server);

  // Ping handler
  server.setRequestHandler(PingRequestSchema, async () => {
    logger.info('Ping request received');
    return {};
  });

  // Elicitation request handler
  server.setRequestHandler(ElicitRequestSchema, async (request) => {
    const { message, requestedSchema } = request.params;
    
    try {
      logger.info('Elicitation request received', { 
        message: message?.substring(0, 100) + (message?.length > 100 ? '...' : ''),
        schemaProperties: Object.keys(requestedSchema?.properties || {})
      });
      
      // For demonstration purposes, we'll create a sample elicitation request
      // In a real implementation, this would interact with the client
      const result: ElicitResult = {
        action: 'accept',
        content: {
          // This is a placeholder - in practice, the client would provide this data
          sample: 'This is a sample elicitation response'
        }
      };
      
      logger.info('Elicitation request completed', { 
        action: result.action,
        hasContent: !!result.content
      });
      
      return result;
    } catch (error) {
      logger.error('Elicitation request failed', { 
        error: error instanceof Error ? error.message : error 
      });
      
      return {
        action: 'cancel'
      };
    }
  });

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: apiRegistry.getAvailableTools(),
    };
  });

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const meta = request.params._meta as { progressToken?: string } | undefined;

    try {
      logger.info('Tool call started', { name, args, hasProgressToken: !!meta?.progressToken });

      const { result, apiName } = await apiRegistry.executeTool(name, args || {}, meta);
      
      logger.info('Tool call completed', { 
        name, 
        apiName,
        resultCount: ('bugs' in result && Array.isArray(result.bugs)) ? result.bugs.length : 
                    ('cases' in result && Array.isArray(result.cases)) ? result.cases.length :
                    ('EOXRecord' in result && Array.isArray(result.EOXRecord)) ? result.EOXRecord.length : 0
      });
      
      const content: TextContent = {
        type: 'text',
        text: formatResults(result, apiName, name, args || {})
      };
      
      return {
        content: [content],
        isError: false,
      };
    } catch (error) {
      logger.error('Tool call failed', { 
        name, 
        error: error instanceof Error ? error.message : error 
      });
      
      // Provide helpful error messages for common issues
      let errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      if (errorMessage.includes('Unknown tool')) {
        errorMessage += '\n\nℹ️ Currently available tools:\n' + 
          apiRegistry.getAvailableTools().map(t => `• ${t.name}: ${t.description}`).join('\n');
        
        errorMessage += `\n\nℹ️ Enabled APIs: ${ENABLED_APIS.join(', ')}`;
      }
      
      if (errorMessage.includes('Tool implementation not found')) {
        errorMessage += '\n\nℹ️ This tool may require an API that is not yet implemented or enabled.';
        errorMessage += `\nCurrently enabled APIs: ${ENABLED_APIS.join(', ')}`;
        errorMessage += `\nTo enable more APIs, set SUPPORT_API environment variable (e.g., SUPPORT_API=bug,case)`;
      }
      
      const errorContent: TextContent = {
        type: 'text',
        text: `Error: ${errorMessage}`
      };
      
      return {
        content: [errorContent],
        isError: true,
      };
    }
  });

  // List prompts handler
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    logger.info('List prompts request received');
    return {
      prompts: getAvailablePrompts(),
    };
  });

  // Get prompt handler
  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      logger.info('Get prompt request', { name, args });

      const messages = generatePrompt(name, args || {});

      logger.info('Prompt generated', { name, messageCount: messages.length });

      return {
        messages,
      };
    } catch (error) {
      logger.error('Prompt generation failed', {
        name,
        error: error instanceof Error ? error.message : error
      });

      throw error;
    }
  });

  // Helper function to get resource templates
  function getResourceTemplates() {
    const resourceTemplates = [];

    // Bug resources (if bug API is enabled)
    if (ENABLED_APIS.includes('bug')) {
      resourceTemplates.push({
        uriTemplate: 'cisco://bugs/{bug_id}',
        name: 'Cisco Bug Report',
        description: 'Access any Cisco bug by its ID (e.g., CSCvi12345)',
        mimeType: 'application/json'
      });
    }

    // Product resources (if product API is enabled)
    if (ENABLED_APIS.includes('product')) {
      resourceTemplates.push(
        {
          uriTemplate: 'cisco://products/{product_id}',
          name: 'Cisco Product Information',
          description: 'Get product details by product ID (e.g., C9300-24P, ISR4431)',
          mimeType: 'application/json'
        },
        {
          uriTemplate: 'cisco://products/autocomplete/{search_term}',
          name: 'Cisco Product Autocomplete',
          description: 'Search Cisco product catalog by name or model (requires CISCO_WEB_COOKIE)',
          mimeType: 'application/json'
        }
      );
    }

    // Security resources (if PSIRT API is enabled)
    if (ENABLED_APIS.includes('psirt')) {
      resourceTemplates.push(
        {
          uriTemplate: 'cisco://security/advisories/{advisory_id}',
          name: 'Cisco Security Advisory',
          description: 'Get security advisory by ID (e.g., cisco-sa-20180221-ucdm)',
          mimeType: 'application/json'
        },
        {
          uriTemplate: 'cisco://security/cve/{cve_id}',
          name: 'Security Advisory by CVE',
          description: 'Get security advisory by CVE identifier (e.g., CVE-2018-0101)',
          mimeType: 'application/json'
        }
      );
    }

    return resourceTemplates;
  }

  // List resources handler
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    logger.info('List resources request received');

    const resources = [];

    // Bug resources (if bug API is enabled)
    if (ENABLED_APIS.includes('bug')) {
      resources.push(
        {
          uri: 'cisco://bugs/recent/critical',
          name: 'Recent Critical Bugs',
          description: 'High-severity bugs from the last 7 days',
          mimeType: 'application/json'
        },
        {
          uri: 'cisco://bugs/recent/high',
          name: 'Recent High-Severity Bugs',
          description: 'Severity 1-3 bugs from the last 30 days',
          mimeType: 'application/json'
        }
      );
    }

    // Product resources (if product API is enabled)
    if (ENABLED_APIS.includes('product')) {
      resources.push(
        {
          uri: 'cisco://products/catalog',
          name: 'Product Catalog',
          description: 'Product catalog overview',
          mimeType: 'application/json'
        },
        {
          uri: 'cisco://products/autocomplete-help',
          name: 'Product Autocomplete Setup',
          description: 'How to configure and use Cisco product autocomplete',
          mimeType: 'text/markdown'
        }
      );
    }

    // Security resources (if PSIRT API is enabled)
    if (ENABLED_APIS.includes('psirt')) {
      resources.push(
        {
          uri: 'cisco://security/advisories/recent',
          name: 'Recent Security Advisories',
          description: 'Latest 20 security advisories from Cisco PSIRT',
          mimeType: 'application/json'
        },
        {
          uri: 'cisco://security/advisories/critical',
          name: 'Critical Security Advisories',
          description: 'Critical severity security advisories',
          mimeType: 'application/json'
        }
      );
    }

    logger.info('Returning resources', { resourceCount: resources.length });

    return { resources };
  });

  // List resource templates handler (separate method per MCP spec 2025-06-18)
  server.setRequestHandler(
    ListResourceTemplatesRequestSchema,
    async () => {
      logger.info('List resource templates request received');

      const resourceTemplates = getResourceTemplates();

      logger.info('Returning resource templates', {
        templateCount: resourceTemplates.length
      });

      return { resourceTemplates };
    }
  );

  // Read resource handler
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    logger.info('Read resource request', { uri });

    try {
      let result: any;
      let description = '';

      // Bug resources
      if (uri === 'cisco://bugs/recent/critical') {
        description = 'Recent critical bugs (severity 1-2) from last 7 days';
        const bugs1 = await apiRegistry.executeTool('search_bugs_by_keyword', {
          keyword: 'cisco',
          severity: '1',
          modified_date: '1'
        });
        const bugs2 = await apiRegistry.executeTool('search_bugs_by_keyword', {
          keyword: 'cisco',
          severity: '2',
          modified_date: '1'
        });
        result = {
          description,
          severity1: bugs1.result,
          severity2: bugs2.result
        };
      } else if (uri === 'cisco://bugs/recent/high') {
        description = 'Recent high-severity bugs (severity 1-3) from last 30 days';
        const bugs1 = await apiRegistry.executeTool('search_bugs_by_keyword', {
          keyword: 'bug',
          severity: '1',
          modified_date: '2'
        });
        const bugs2 = await apiRegistry.executeTool('search_bugs_by_keyword', {
          keyword: 'bug',
          severity: '2',
          modified_date: '2'
        });
        const bugs3 = await apiRegistry.executeTool('search_bugs_by_keyword', {
          keyword: 'bug',
          severity: '3',
          modified_date: '2'
        });
        result = {
          description,
          severity1: bugs1.result,
          severity2: bugs2.result,
          severity3: bugs3.result
        };
      } else if (uri.startsWith('cisco://bugs/')) {
        // Dynamic bug lookup: cisco://bugs/{bug_id}
        const bugId = uri.replace('cisco://bugs/', '');
        description = `Bug details for ${bugId}`;
        const bugResult = await apiRegistry.executeTool('get_bug_details', {
          bug_ids: bugId
        });
        result = bugResult.result;
      } else if (uri === 'cisco://products/autocomplete-help') {
        // Help resource for product autocomplete setup
        description = 'Product Autocomplete Setup Instructions';
        const helpText = `# Using Cisco Product Autocomplete

This feature allows you to search Cisco's product catalog using their internal autocomplete API. It requires your Cisco.com session cookie.

## Setup Instructions

### Step 1: Log in to Cisco
1. Visit https://bst.cloudapps.cisco.com/
2. Log in with your Cisco account

### Step 2: Extract Your Session Cookie
1. Open browser DevTools (F12 or Right-click > Inspect)
2. Go to the **Application** tab (Chrome) or **Storage** tab (Firefox)
3. Under **Cookies**, select \`https://bst.cloudapps.cisco.com\`
4. Find these cookies and copy their values:
   - \`JSESSIONID\`
   - \`OptanonConsent\`
   - Any other cookies for bst.cloudapps.cisco.com

### Step 3: Format Your Cookie String
Combine all cookies in this format:
\`\`\`
JSESSIONID=value1; OptanonConsent=value2; other_cookie=value3
\`\`\`

### Step 4: Set Environment Variable
Add to your \`.env\` file or MCP configuration:
\`\`\`bash
CISCO_WEB_COOKIE="JSESSIONID=...; OptanonConsent=...; ..."
\`\`\`

### Step 5: Query Products
Once configured, you can query:
\`\`\`
cisco://products/autocomplete/4431
cisco://products/autocomplete/catalyst
cisco://products/autocomplete/ASA
\`\`\`

## Cookie Lifecycle

**Typical Validity**: 24 hours
**Recommended Refresh**: Daily before heavy use

### Signs Your Cookie Expired
- "Cookie expired or invalid" error messages
- 401 Unauthorized or 403 Forbidden responses
- Empty results or authentication errors

### How to Refresh
1. Visit https://bst.cloudapps.cisco.com/
2. If still logged in, just extract the cookie again
3. If logged out, log back in and extract new cookie
4. Update your \`.env\` file with the new cookie

## Security Best Practices

1. **Never commit cookies to git** - they're like passwords
2. **Use .env file** - already in .gitignore
3. **Refresh regularly** - cookies expire after ~24 hours
4. **Monitor for unusual activity** - check your Cisco account
5. **Use dedicated account** - not your primary Cisco login

## Example Response

When querying \`cisco://products/autocomplete/4431\`:
\`\`\`json
{
  "autoPopulateHMPProductDetails": [{
    "parentMdfConceptId": 286281708,
    "parentMdfConceptName": "Cisco 4000 Series Integrated Services Routers",
    "mdfConceptId": 284358776,
    "mdfConceptName": "Cisco 4431 Integrated Services Router",
    "mdfMetaclass": "Model"
  }]
}
\`\`\`

## Troubleshooting

**"CISCO_WEB_COOKIE not configured"**
- Set the environment variable in your .env file or MCP config

**"Cookie expired or invalid"**
- Extract a fresh cookie from your browser
- Ensure you're still logged in to Cisco

**"No results found"**
- Try a different search term
- Check if the product exists in Cisco's catalog
- Verify your cookie is still valid

## Need Help?

See the main documentation for more details on MCP resources and Cisco API integration.
`;

        return {
          contents: [{
            uri,
            mimeType: 'text/markdown',
            text: helpText
          }]
        };
      } else if (uri.startsWith('cisco://products/autocomplete/')) {
        // Product autocomplete lookup: cisco://products/autocomplete/{search_term}
        const searchTerm = uri.replace('cisco://products/autocomplete/', '');
        description = `Product autocomplete search for "${searchTerm}"`;

        const webCookie = process.env.CISCO_WEB_COOKIE;

        if (!webCookie) {
          result = {
            error: 'CISCO_WEB_COOKIE not configured',
            message: 'To use product autocomplete, you must provide your Cisco.com session cookie',
            help: 'See cisco://products/autocomplete-help for setup instructions',
            setup_steps: [
              '1. Log in to https://bst.cloudapps.cisco.com/',
              '2. Open browser DevTools (F12)',
              '3. Go to Application/Storage > Cookies',
              '4. Copy the entire Cookie header value',
              '5. Set environment variable: CISCO_WEB_COOKIE="your-cookie-here"'
            ]
          };
        } else {
          try {
            const response = await fetch(
              `https://bst.cloudapps.cisco.com/api/productAutocomplete?productsearchTerm=${encodeURIComponent(searchTerm)}`,
              {
                headers: {
                  'Cookie': webCookie,
                  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                  'Referer': 'https://bst.cloudapps.cisco.com/',
                  'Accept': 'application/json'
                }
              }
            );

            if (response.status === 401 || response.status === 403) {
              result = {
                error: 'Cookie expired or invalid',
                message: 'Your Cisco.com session cookie has expired or is invalid',
                help: 'See cisco://products/autocomplete-help for instructions on refreshing your cookie',
                status: response.status,
                refresh_steps: [
                  '1. Visit https://bst.cloudapps.cisco.com/',
                  '2. Log in if needed',
                  '3. Extract fresh cookie from browser DevTools',
                  '4. Update CISCO_WEB_COOKIE environment variable'
                ]
              };
            } else if (!response.ok) {
              result = {
                error: `HTTP ${response.status}`,
                message: `Cisco API returned error: ${response.statusText}`,
                help: 'See cisco://products/autocomplete-help for troubleshooting'
              };
            } else {
              const data = await response.json();
              result = data;
            }
          } catch (error) {
            result = {
              error: 'Network error',
              message: error instanceof Error ? error.message : 'Unknown error occurred',
              help: 'Check your internet connection and cookie configuration'
            };
          }
        }
      } else if (uri.startsWith('cisco://products/')) {
        // Dynamic product lookup: cisco://products/{product_id}
        const productId = uri.replace('cisco://products/', '');
        if (productId === 'catalog') {
          result = {
            description: 'Use cisco://products/{product_id} to access specific product information',
            examples: [
              'cisco://products/C9300-24P',
              'cisco://products/ISR4431',
              'cisco://products/ASA5516-X'
            ]
          };
        } else {
          description = `Product information for ${productId}`;
          const productResult = await apiRegistry.executeTool('get_product_info_by_product_ids', {
            product_ids: productId
          });
          result = productResult.result;
        }
      } else if (uri === 'cisco://security/advisories/recent') {
        description = 'Latest 20 security advisories';
        const advisories = await apiRegistry.executeTool('get_latest_security_advisories', {
          number: 20,
          summary_details: true
        });
        result = advisories.result;
      } else if (uri === 'cisco://security/advisories/critical') {
        description = 'Critical severity security advisories';
        const advisories = await apiRegistry.executeTool('get_security_advisories_by_severity', {
          severity: 'critical',
          page_size: 20,
          summary_details: true
        });
        result = advisories.result;
      } else if (uri.startsWith('cisco://security/advisories/')) {
        // Dynamic advisory lookup: cisco://security/advisories/{advisory_id}
        const advisoryId = uri.replace('cisco://security/advisories/', '');
        description = `Security advisory ${advisoryId}`;
        const advisory = await apiRegistry.executeTool('get_security_advisory_by_id', {
          advisory_id: advisoryId,
          summary_details: true
        });
        result = advisory.result;
      } else if (uri.startsWith('cisco://security/cve/')) {
        // CVE lookup: cisco://security/cve/{cve_id}
        const cveId = uri.replace('cisco://security/cve/', '');
        description = `Security advisory for ${cveId}`;
        const advisory = await apiRegistry.executeTool('get_security_advisory_by_cve', {
          cve_id: cveId,
          summary_details: true
        });
        result = advisory.result;
      } else {
        throw new Error(`Unknown resource URI: ${uri}`);
      }

      logger.info('Resource read completed', { uri });

      return {
        contents: [{
          uri,
          mimeType: 'application/json',
          text: JSON.stringify({ description, data: result }, null, 2)
        }]
      };
    } catch (error) {
      logger.error('Resource read failed', {
        uri,
        error: error instanceof Error ? error.message : error
      });

      throw error;
    }
  });

  return server;
}

// Export the main server instance and utilities
export const mcpServer = createMCPServer();
export { setLogging, logger, apiRegistry, ENABLED_APIS };

// Export functions for backward compatibility with tests
export function getAvailableTools() {
  // Reinitialize registry to pick up any environment changes
  initializeApiRegistry();
  return apiRegistry.getAvailableTools();
}

export async function executeTool(name: string, args: Record<string, any>) {
  // Reinitialize registry to pick up any environment changes
  initializeApiRegistry();
  const { result } = await apiRegistry.executeTool(name, args);
  return result;
}