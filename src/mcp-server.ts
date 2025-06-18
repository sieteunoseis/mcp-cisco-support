import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  PingRequestSchema,
  Prompt,
  PromptMessage,
  TextContent
} from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';
import { join } from 'path';

// Import modular API system
import { createApiRegistry, ApiRegistry, SupportedAPI, getEnabledAPIs } from './apis/index.js';
import { formatBugResults, formatCaseResults, formatEoxResults, ApiResponse, BugApiResponse, CaseApiResponse, EoxApiResponse } from './utils/formatting.js';
import { setLogging, logger } from './utils/logger.js';

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

// Cisco Support MCP Prompts (unchanged from original)
const ciscoPrompts: Prompt[] = [
  {
    name: 'cisco-high-severity-search',
    description: 'Search for high-severity bugs (severity 3 or higher) for specific products - handles API limitation requiring separate searches',
    arguments: [
      {
        name: 'product_keyword',
        description: 'Product name or keyword to search for (e.g., "Cisco Unified Communications Manager", "CallManager")',
        required: true
      },
      {
        name: 'version',
        description: 'Product version if applicable (e.g., "12.5", "17.5.1")',
        required: false
      },
      {
        name: 'max_severity',
        description: 'Highest severity to include (1=highest, 6=lowest). Will search from 1 down to this number.',
        required: false
      }
    ]
  },
  {
    name: 'cisco-incident-investigation',
    description: 'Investigate Cisco bugs related to specific incident symptoms and errors',
    arguments: [
      {
        name: 'symptom',
        description: 'The error message, symptom, or behavior observed during the incident',
        required: true
      },
      {
        name: 'product',
        description: 'Cisco product experiencing the issue (e.g., "Cisco ASR 1000", "Cisco Catalyst 9200")',
        required: true
      },
      {
        name: 'severity',
        description: 'Incident severity level (1=Critical, 2=High, 3=Medium)',
        required: false
      },
      {
        name: 'software_version',
        description: 'Current software version if known (e.g., "17.5.2")',
        required: false
      }
    ]
  },
  {
    name: 'cisco-upgrade-planning',
    description: 'Research known issues and bugs before upgrading Cisco software or hardware',
    arguments: [
      {
        name: 'current_version',
        description: 'Current software version (e.g., "17.5.1")',
        required: true
      },
      {
        name: 'target_version',
        description: 'Target upgrade version (e.g., "17.5.5")',
        required: true
      },
      {
        name: 'product',
        description: 'Cisco product being upgraded (e.g., "Cisco ASR 9000 Series")',
        required: true
      },
      {
        name: 'environment',
        description: 'Environment type (production, staging, lab)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-maintenance-prep',
    description: 'Prepare for maintenance windows by identifying potential issues and bugs',
    arguments: [
      {
        name: 'maintenance_type',
        description: 'Type of maintenance (software upgrade, hardware replacement, configuration change)',
        required: true
      },
      {
        name: 'product',
        description: 'Cisco product undergoing maintenance',
        required: true
      },
      {
        name: 'software_version',
        description: 'Current or target software version',
        required: false
      },
      {
        name: 'timeline',
        description: 'Maintenance window timeline (e.g., "next week", "emergency")',
        required: false
      }
    ]
  },
  {
    name: 'cisco-security-advisory',
    description: 'Research security-related bugs and vulnerabilities for Cisco products',
    arguments: [
      {
        name: 'product',
        description: 'Cisco product to check for security issues',
        required: true
      },
      {
        name: 'software_version',
        description: 'Software version to check',
        required: false
      },
      {
        name: 'security_focus',
        description: 'Specific security concern (CVE, vulnerability type, etc.)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-known-issues',
    description: 'Check for known issues in specific Cisco software releases or products',
    arguments: [
      {
        name: 'product',
        description: 'Cisco product to check',
        required: true
      },
      {
        name: 'software_version',
        description: 'Specific software version or range',
        required: true
      },
      {
        name: 'issue_type',
        description: 'Type of issues to focus on (performance, stability, features)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-case-investigation',
    description: 'Investigate support cases and related information using Case API tools',
    arguments: [
      {
        name: 'case_id',
        description: 'Specific case ID to investigate (optional)',
        required: false
      },
      {
        name: 'contract_id',
        description: 'Contract ID to search cases for (optional)',
        required: false
      },
      {
        name: 'user_id',
        description: 'User ID to search cases for (optional)',
        required: false
      },
      {
        name: 'status',
        description: 'Case status to filter by (Open, Closed, etc.)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-lifecycle-planning',
    description: 'Research end-of-life information for Cisco products to plan replacements and maintenance',
    arguments: [
      {
        name: 'product_ids',
        description: 'Product IDs to check (comma-separated, e.g., "WS-C3560-48PS-S,WS-C2960-24TC-L")',
        required: false
      },
      {
        name: 'serial_numbers',
        description: 'Serial numbers to check (comma-separated)',
        required: false
      },
      {
        name: 'date_range_start',
        description: 'Start date for lifecycle search (YYYY-MM-DD)',
        required: false
      },
      {
        name: 'date_range_end',
        description: 'End date for lifecycle search (YYYY-MM-DD)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-eox-research',
    description: 'Research end-of-life and end-of-sale information for specific Cisco products',
    arguments: [
      {
        name: 'product_focus',
        description: 'Focus area: product_ids, serial_numbers, software_releases, or date_range',
        required: true
      },
      {
        name: 'search_values',
        description: 'Values to search for (product IDs, serial numbers, or software releases)',
        required: true
      }
    ]
  }
];

// Prompt to API mapping - defines which APIs each prompt uses
const promptApiMapping: Record<string, SupportedAPI[]> = {
  'cisco-high-severity-search': ['bug'],
  'cisco-incident-investigation': ['bug'],
  'cisco-upgrade-planning': ['bug'],
  'cisco-maintenance-prep': ['bug'],
  'cisco-security-advisory': ['bug'],
  'cisco-known-issues': ['bug'],
  'cisco-case-investigation': ['case'],
  'cisco-lifecycle-planning': ['eox'],
  'cisco-eox-research': ['eox']
};

// Get available prompts (filtered by enabled APIs)
export function getAvailablePrompts(): Prompt[] {
  // Check if prompts should be filtered based on enabled APIs
  const enabledApis = ENABLED_APIS;
  
  return ciscoPrompts.filter(prompt => {
    const requiredApis = promptApiMapping[prompt.name];
    if (!requiredApis) {
      // If no API mapping defined, include the prompt by default
      return true;
    }
    
    // Include prompt if at least one of its required APIs is enabled
    return requiredApis.some(api => enabledApis.includes(api));
  });
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

    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
}

// Format results based on API type
function formatResults(result: ApiResponse, apiName: string, toolName: string, args: Record<string, any>): string {
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

// Create MCP server
export function createMCPServer(): Server {
  const server = new Server(
    {
      name: 'mcp-cisco-support',
      version: VERSION,
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
      },
    }
  );

  // Ping handler
  server.setRequestHandler(PingRequestSchema, async () => {
    logger.info('Ping request received');
    return {};
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
    
    try {
      logger.info('Tool call started', { name, args });
      
      const { result, apiName } = await apiRegistry.executeTool(name, args || {});
      
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