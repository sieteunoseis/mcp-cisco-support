import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  PingRequestSchema,
  Tool,
  Prompt,
  PromptMessage,
  TextContent
} from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load environment variables
dotenv.config();

// Get version from package.json
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const VERSION = packageJson.version;

// Supported API configuration
type SupportedAPI = 'asd' | 'bug' | 'case' | 'eox' | 'product' | 'serial' | 'rma' | 'software';

const SUPPORTED_APIS: SupportedAPI[] = ['asd', 'bug', 'case', 'eox', 'product', 'serial', 'rma', 'software'];

// Get enabled APIs from environment
function getEnabledAPIs(): SupportedAPI[] {
  const supportApiEnv = process.env.SUPPORT_API || 'bug';
  
  if (supportApiEnv.toLowerCase() === 'all') {
    return SUPPORTED_APIS;
  }
  
  const requestedAPIs = supportApiEnv.toLowerCase().split(',').map(api => api.trim()) as SupportedAPI[];
  return requestedAPIs.filter(api => SUPPORTED_APIS.includes(api));
}

const ENABLED_APIS = getEnabledAPIs();

// Types
interface TokenData {
  access_token: string;
  expires_in: number;
}

interface CiscoApiResponse {
  bugs?: Array<{
    bug_id: string;
    headline: string;
    status: string;
    severity: string;
    last_modified_date: string;
    [key: string]: any;
  }>;
  total_results?: number;
  [key: string]: any;
}

interface Logger {
  info: (message: string, data?: any) => void;
  error: (message: string, data?: any) => void;
  warn: (message: string, data?: any) => void;
}

interface ToolArgs {
  [key: string]: any;
}

// Global variables for OAuth2 token management
let accessToken: string | null = null;
let tokenExpiry: number | null = null;
const TOKEN_REFRESH_MARGIN = 30 * 60 * 1000; // 30 minutes in milliseconds

// Logger implementation - can be controlled externally
let loggingEnabled = true;

export const logger: Logger = {
  info: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'info', message, ...(data && { data }) };
      console.log(JSON.stringify(logEntry));
    }
  },
  error: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'error', message, ...(data && { data }) };
      console.error(JSON.stringify(logEntry));
    }
  },
  warn: (message: string, data?: any) => {
    if (loggingEnabled) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'warn', message, ...(data && { data }) };
      console.warn(JSON.stringify(logEntry));
    }
  }
};

// Control logging externally
export function setLogging(enabled: boolean) {
  loggingEnabled = enabled;
}

// OAuth2 authentication
async function authenticateWithCisco(): Promise<string> {
  const { CISCO_CLIENT_ID, CISCO_CLIENT_SECRET } = process.env;
  
  if (!CISCO_CLIENT_ID || !CISCO_CLIENT_SECRET) {
    throw new Error('Missing Cisco API credentials in environment variables');
  }

  const tokenUrl = 'https://id.cisco.com/oauth2/default/v1/token';
  const credentials = Buffer.from(`${CISCO_CLIENT_ID}:${CISCO_CLIENT_SECRET}`).toString('base64');
  
  try {
    logger.info('Requesting OAuth2 token from Cisco');
    
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: 'grant_type=client_credentials'
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OAuth2 authentication failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const tokenData = await response.json() as TokenData;
    
    if (!tokenData.access_token) {
      throw new Error('No access token received from Cisco OAuth2 API');
    }

    // Calculate token expiry (default 12 hours if not provided)
    const expiresIn = tokenData.expires_in || 43200; // 12 hours default
    tokenExpiry = Date.now() + (expiresIn * 1000);
    accessToken = tokenData.access_token;

    logger.info('Successfully obtained OAuth2 token', {
      expiresIn: expiresIn,
      expiryTime: new Date(tokenExpiry).toISOString()
    });

    return accessToken;
  } catch (error) {
    logger.error('OAuth2 authentication failed', error);
    throw error;
  }
}

// Get valid access token, refreshing if necessary
async function getValidToken(): Promise<string> {
  const now = Date.now();
  
  // Check if token exists and is not expired (with margin)
  if (accessToken && tokenExpiry && (tokenExpiry - now) > TOKEN_REFRESH_MARGIN) {
    return accessToken;
  }
  
  logger.info('Token expired or missing, refreshing...');
  return await authenticateWithCisco();
}

// Make authenticated API call to Cisco Bug API
async function makeCiscoApiCall(endpoint: string, params: Record<string, any> = {}): Promise<CiscoApiResponse> {
  const token = await getValidToken();
  const baseUrl = 'https://apix.cisco.com/bug/v2.0';
  
  // Build query string
  const queryParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      queryParams.append(key, String(value));
    }
  });
  
  const queryString = queryParams.toString();
  const url = `${baseUrl}${endpoint}${queryString ? '?' + queryString : ''}`;
  
  try {
    logger.info('Making Cisco API call', { endpoint, params });
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'mcp-cisco-support/1.0'
      }
    });

    if (response.status === 401) {
      logger.warn('Received 401, token may be expired, refreshing...');
      // Token expired, refresh and retry once
      const newToken = await authenticateWithCisco();
      const retryResponse = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${newToken}`,
          'Accept': 'application/json',
          'User-Agent': 'mcp-cisco-support/1.0'
        }
      });
      
      if (!retryResponse.ok) {
        const errorText = await retryResponse.text();
        throw new Error(`Cisco API call failed after token refresh: ${retryResponse.status} ${retryResponse.statusText} - ${errorText}`);
      }
      
      const retryData = await retryResponse.json() as CiscoApiResponse;
      return retryData;
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Cisco API call failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json() as CiscoApiResponse;
    logger.info('Cisco API call successful', { endpoint, resultCount: data.bugs ? data.bugs.length : 0 });
    
    return data;
  } catch (error) {
    logger.error('Cisco API call failed', { endpoint, error: error instanceof Error ? error.message : error });
    throw error;
  }
}

// MCP Tools definitions with proper JSON Schema format - organized by API
const bugApiTools: Tool[] = [
  {
    name: 'get_bug_details',
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
    description: 'Search bugs by specific base product ID (e.g., WS-C3560-48PS-S). Use when you have an exact Cisco product ID. For general product searches by name, consider using keyword search instead.',
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

// Placeholder tools for future APIs with helpful error messages
const asdApiTools: Tool[] = [];
const caseApiTools: Tool[] = [
  {
    name: 'search_case_placeholder',
    description: '⚠️ Case API not yet implemented. Please use Bug API tools instead to search for related issues.',
    inputSchema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          description: 'This is a placeholder - Case API is not yet implemented'
        }
      },
      required: []
    }
  }
];
const eoxApiTools: Tool[] = [];
const productApiTools: Tool[] = [];
const serialApiTools: Tool[] = [];
const rmaApiTools: Tool[] = [];
const softwareApiTools: Tool[] = [];

// Map API names to their tool arrays
const API_TOOLS_MAP: Record<SupportedAPI, Tool[]> = {
  asd: asdApiTools,
  bug: bugApiTools,
  case: caseApiTools,
  eox: eoxApiTools,
  product: productApiTools,
  serial: serialApiTools,
  rma: rmaApiTools,
  software: softwareApiTools
};

// Generate tools array based on enabled APIs
export function getAvailableTools(): Tool[] {
  const availableTools: Tool[] = [];
  
  for (const api of ENABLED_APIS) {
    const apiTools = API_TOOLS_MAP[api];
    if (apiTools && apiTools.length > 0) {
      availableTools.push(...apiTools);
    }
  }
  
  return availableTools;
}

// Cisco Support MCP Prompts
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
        description: 'Product version if applicable (e.g., "12.5", "15.2(4)S")',
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
        description: 'Cisco product experiencing the issue (e.g., "Cisco ASR 1000", "Catalyst 3560")',
        required: true
      },
      {
        name: 'severity',
        description: 'Incident severity level (1=Critical, 2=High, 3=Medium)',
        required: false
      },
      {
        name: 'software_version',
        description: 'Current software version if known (e.g., "15.2(4)S2")',
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
        description: 'Current software version (e.g., "15.2(4)S")',
        required: true
      },
      {
        name: 'target_version',
        description: 'Target upgrade version (e.g., "15.2(4)S5")',
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
  }
];

// Get available prompts (for now, return all prompts regardless of API configuration)
export function getAvailablePrompts(): Prompt[] {
  return ciscoPrompts;
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

    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
}

// Format bug results with hyperlinks
function formatBugResults(data: CiscoApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
  // Handle special error responses (like Case API placeholder)
  if (data && typeof data === 'object' && 'error' in data && 'message' in data) {
    let formatted = `# ⚠️ ${data.error}\n\n`;
    formatted += `**${data.message}**\n\n`;
    
    if (data.alternatives && Array.isArray(data.alternatives)) {
      formatted += `## Alternative Approaches:\n\n`;
      data.alternatives.forEach((alt: string, index: number) => {
        formatted += `${index + 1}. ${alt}\n`;
      });
      formatted += `\n`;
    }
    
    if (data.example) {
      formatted += `## Example:\n${data.example}\n\n`;
    }
    
    if (data.available_apis) {
      formatted += `**Currently Available APIs:** ${data.available_apis.join(', ')}\n\n`;
    }
    
    if (data.planned_apis) {
      formatted += `**Planned APIs:** ${data.planned_apis.join(', ')}\n\n`;
    }
    
    return formatted;
  }
  
  if (!data.bugs || data.bugs.length === 0) {
    return JSON.stringify(data, null, 2);
  }

  let formatted = `# Cisco Bug Search Results\n\n`;
  
  // Add search context if available
  if (searchContext) {
    if (searchContext.toolName === 'search_bugs_by_keyword' && searchContext.args.keyword) {
      formatted += `**Search Keywords:** "${searchContext.args.keyword}"\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_id' && searchContext.args.base_pid) {
      formatted += `**Product ID:** ${searchContext.args.base_pid}\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_and_release') {
      formatted += `**Product ID:** ${searchContext.args.base_pid}\n\n`;
      formatted += `**Software Releases:** ${searchContext.args.software_releases}\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_series_affected') {
      formatted += `**Product Series:** ${searchContext.args.product_series}\n\n`;
      formatted += `**Affected Releases:** ${searchContext.args.affected_releases}\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_series_fixed') {
      formatted += `**Product Series:** ${searchContext.args.product_series}\n\n`;
      formatted += `**Fixed Releases:** ${searchContext.args.fixed_releases}\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_name_affected') {
      formatted += `**Product Name:** ${searchContext.args.product_name}\n\n`;
      formatted += `**Affected Releases:** ${searchContext.args.affected_releases}\n\n`;
    } else if (searchContext.toolName === 'search_bugs_by_product_name_fixed') {
      formatted += `**Product Name:** ${searchContext.args.product_name}\n\n`;
      formatted += `**Fixed Releases:** ${searchContext.args.fixed_releases}\n\n`;
    }
    
    // Add filters if specified
    if (searchContext.args.status) {
      const statusMap: {[key: string]: string} = {
        'O': 'Open',
        'F': 'Fixed', 
        'T': 'Terminated'
      };
      formatted += `**Status Filter:** ${statusMap[searchContext.args.status] || searchContext.args.status}\n\n`;
    }
    if (searchContext.args.severity) {
      formatted += `**Severity Filter:** Severity ${searchContext.args.severity}\n\n`;
    }
    if (searchContext.args.modified_date && searchContext.args.modified_date !== '5') {
      const dateMap: {[key: string]: string} = {
        '1': 'Last Week',
        '2': 'Last 30 Days', 
        '3': 'Last 6 Months',
        '4': 'Last Year',
        '5': 'All'
      };
      formatted += `**Modified Date Filter:** ${dateMap[searchContext.args.modified_date] || searchContext.args.modified_date}\n\n`;
    }
  }
  
  if (data.total_results) {
    formatted += `**Total Results:** ${data.total_results}\n\n`;
  }

  data.bugs.forEach((bug, index) => {
    const bugUrl = `https://bst.cisco.com/bugsearch/bug/${bug.bug_id}`;
    
    formatted += `## ${index + 1}. [${bug.bug_id}](${bugUrl})\n\n`;
    formatted += `**Headline:** ${bug.headline}\n\n`;
    formatted += `**Status:** ${bug.status}\n\n`;
    formatted += `**Severity:** ${bug.severity}\n\n`;
    formatted += `**Last Modified:** ${bug.last_modified_date}\n\n`;
    
    // Add additional fields if they exist
    Object.keys(bug).forEach(key => {
      if (!['bug_id', 'headline', 'status', 'severity', 'last_modified_date'].includes(key)) {
        const value = bug[key];
        if (value && value !== '' && value !== null && value !== undefined) {
          const fieldName = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          formatted += `**${fieldName}:** ${value}\n\n`;
        }
      }
    });
    
    formatted += `**Bug URL:** ${bugUrl}\n\n`;
    formatted += `---\n\n`;
  });

  return formatted;
}

// Execute tool function
export async function executeTool(name: string, args: ToolArgs): Promise<CiscoApiResponse> {
  const tools = getAvailableTools();
  const tool = tools.find(t => t.name === name);
  if (!tool) {
    throw new Error(`Unknown tool: ${name}`);
  }

  // Basic validation - ensure required fields are present
  const schema = tool.inputSchema;
  if (schema.required) {
    for (const field of schema.required) {
      if (!args[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }
  }

  // Set defaults
  const processedArgs = { ...args };
  if (!processedArgs.page_index) processedArgs.page_index = 1;
  if (!processedArgs.modified_date) processedArgs.modified_date = '5';
  
  // Build API parameters
  const apiParams: Record<string, any> = {
    page_index: processedArgs.page_index
  };
  
  // Add optional filters - only if explicitly provided
  if (processedArgs.status) apiParams.status = processedArgs.status;
  if (processedArgs.severity) apiParams.severity = processedArgs.severity;
  if (processedArgs.modified_date) apiParams.modified_date = processedArgs.modified_date;
  if (processedArgs.sort_by) apiParams.sort_by = processedArgs.sort_by;
  
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
      
    case 'search_case_placeholder':
      // Return helpful error message for Case API
      return {
        error: 'Case API Not Implemented',
        message: 'The Cisco Case Management API is not yet implemented in this MCP server. Currently, only the Bug Search API is available.',
        alternatives: [
          'Use search_bugs_by_keyword to find bugs related to your case topic',
          'Use search_bugs_by_product_id if you have a specific product ID',
          'Use search_bugs_by_product_series_affected for product series searches'
        ],
        example: 'Try: "Search for bugs related to \'Unified Communications Manager\' with keyword search"',
        available_apis: ['bug'],
        planned_apis: ['case', 'eox', 'product', 'serial', 'rma', 'software', 'asd']
      } as any;
      
    default:
      throw new Error(`Tool implementation not found: ${name}`);
  }
  
  return await makeCiscoApiCall(endpoint, apiParams);
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
      tools: getAvailableTools(),
    };
  });

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    
    try {
      logger.info('Tool call started', { name, args });
      
      const result = await executeTool(name, args || {});
      
      logger.info('Tool call completed', { 
        name, 
        resultCount: result.bugs ? result.bugs.length : 0
      });
      
      const content: TextContent = {
        type: 'text',
        text: formatBugResults(result, { toolName: name, args: args || {} })
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
          getAvailableTools().map(t => `• ${t.name}: ${t.description}`).join('\n');
      }
      
      if (errorMessage.includes('Tool implementation not found')) {
        errorMessage += '\n\nℹ️ This tool may require an API that is not yet implemented. Currently only the Bug API is available.';
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

// Export the main server instance
export const mcpServer = createMCPServer();