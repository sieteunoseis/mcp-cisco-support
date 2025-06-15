import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  PingRequestSchema,
  Tool,
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
    description: 'Search for bugs using keywords in descriptions and headlines. Use this when searching by general terms, symptoms, or when product-specific tools are not applicable.',
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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
          description: 'Bug status filter. Values: O=Open, F=Fixed, T=Terminated, or comma-separated combination (e.g., "O,F"). Default: all statuses (O,F,T)',
          default: 'O,F,T'
        },
        severity: {
          type: 'string',
          description: 'Bug severity filter. Values: 1=Severity 1, 2=Severity 2, 3=Severity 3, 4=Severity 4, 5=Severity 5, 6=Severity 6, or comma-separated combination (e.g., "1,2,3"). Default: all severities (1,2,3,4,5,6)',
          default: '1,2,3,4,5,6'
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

// Placeholder tools for future APIs
const asdApiTools: Tool[] = [];
const caseApiTools: Tool[] = [];
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

// Format bug results with hyperlinks
function formatBugResults(data: CiscoApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
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
    if (searchContext.args.status && searchContext.args.status !== 'O,F,T') {
      formatted += `**Status Filter:** ${searchContext.args.status}\n\n`;
    }
    if (searchContext.args.severity && searchContext.args.severity !== '1,2,3,4,5,6') {
      formatted += `**Severity Filter:** ${searchContext.args.severity}\n\n`;
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
  if (processedArgs.status && processedArgs.status !== 'O,F,T') apiParams.status = processedArgs.status;
  if (processedArgs.severity && processedArgs.severity !== '1,2,3,4,5,6') apiParams.severity = processedArgs.severity;
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
      
      const errorContent: TextContent = {
        type: 'text',
        text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
      
      return {
        content: [errorContent],
        isError: true,
      };
    }
  });

  return server;
}

// Export the main server instance
export const mcpServer = createMCPServer();