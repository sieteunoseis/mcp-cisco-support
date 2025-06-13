#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  PingRequestSchema,
  Tool,
  TextContent
} from '@modelcontextprotocol/sdk/types.js';
import dotenv from 'dotenv';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

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

// SSE clients management for HTTP mode
const sseClients = new Map<string, Response>();

// Logger implementation - disabled in stdio mode to prevent interference with MCP protocol
const isStdioMode = !process.argv.includes('--http');

const logger: Logger = {
  info: (message: string, data?: any) => {
    if (!isStdioMode) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'info', message, ...(data && { data }) };
      console.log(JSON.stringify(logEntry));
    }
  },
  error: (message: string, data?: any) => {
    if (!isStdioMode) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'error', message, ...(data && { data }) };
      console.error(JSON.stringify(logEntry));
    }
  },
  warn: (message: string, data?: any) => {
    if (!isStdioMode) {
      const timestamp = new Date().toISOString();
      const logEntry = { timestamp, level: 'warn', message, ...(data && { data }) };
      console.warn(JSON.stringify(logEntry));
    }
  }
};

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

// MCP Tools definitions with proper JSON Schema format
const tools: Tool[] = [
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
    description: 'Search for bugs using keywords in descriptions and headlines',
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
    description: 'Search bugs by base product ID',
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
async function executeTool(name: string, args: ToolArgs): Promise<CiscoApiResponse> {
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
  // Don't set default status - let API use its own defaults
  // Don't set default severity - let API use its own defaults
  
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
function createMCPServer(): Server {
  const server = new Server(
    {
      name: 'mcp-cisco-support',
      version: '1.0.0',
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
      tools: tools,
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

// Broadcast SSE event to all connected clients (HTTP mode only)
function broadcastSSE(event: string, data: any): void {
  const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach((client, clientId) => {
    try {
      client.write(message);
    } catch (error) {
      logger.error('Failed to send SSE message to client', { clientId, error });
    }
  });
}

// Create Express server for HTTP transport
function createHTTPServer(): express.Application {
  const app = express();
  
  // Security middleware
  app.use(helmet());
  app.use(cors());
  app.use(morgan('combined'));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Server info
  app.get('/', (_req: Request, res: Response) => {
    res.json({
      name: 'Cisco Support MCP Server',
      version: '1.0.0',
      description: 'MCP server for Cisco Support APIs including Bug Search and future tools',
      transports: ['stdio', 'http'],
      currentTools: ['bug-search'],
      plannedTools: ['case-management', 'product-alerts', 'field-notices'],
      endpoints: {
        mcp: '/mcp',
        ping: '/ping',
        sse: '/sse',
        health: '/health'
      },
      documentation: 'https://developer.cisco.com/docs/support-apis/'
    });
  });

  // Dedicated ping endpoint for simple HTTP testing
  app.get('/ping', (_req: Request, res: Response) => {
    logger.info('Ping request received via GET /ping');
    res.json({
      status: 'pong',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      server: 'mcp-cisco-support'
    });
  });

  // Main MCP endpoint
  app.post('/mcp', async (req: Request, res: Response) => {
    const message = req.body;
    
    try {
      // Handle MCP message manually since we're using HTTP transport
      if (message.method === 'initialize') {
        res.json({
          jsonrpc: '2.0',
          id: message.id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: {},
            },
            serverInfo: {
              name: 'mcp-cisco-support',
              version: '1.0.0'
            }
          }
        });
      } else if (message.method === 'ping') {
        logger.info('Ping request received via HTTP');
        res.json({
          jsonrpc: '2.0',
          id: message.id,
          result: {}
        });
      } else if (message.method === 'tools/list') {
        res.json({
          jsonrpc: '2.0',
          id: message.id,
          result: {
            tools: tools
          }
        });
      } else if (message.method === 'tools/call') {
        const { name, arguments: args } = message.params;
        const requestId = uuidv4();
        
        logger.info('MCP tool call started', { name, args, requestId });
        
        // Broadcast start event for SSE clients
        broadcastSSE('tool_start', { tool: name, args, requestId, timestamp: new Date().toISOString() });
        
        const result = await executeTool(name, args || {});
        
        // Broadcast completion event
        broadcastSSE('tool_complete', { 
          tool: name, 
          args, 
          requestId, 
          resultCount: result.bugs ? result.bugs.length : 0,
          timestamp: new Date().toISOString()
        });
        
        logger.info('MCP tool call completed', { name, requestId, resultCount: result.bugs ? result.bugs.length : 0 });
        
        res.json({
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [
              {
                type: 'text',
                text: formatBugResults(result, { toolName: name, args: args || {} })
              }
            ]
          }
        });
      } else {
        res.json({
          jsonrpc: '2.0',
          id: message.id,
          error: {
            code: -32601,
            message: 'Method not found',
            data: { method: message.method }
          }
        });
      }
    } catch (error) {
      logger.error('MCP message handling failed', { error });
      
      // Broadcast error event for tool calls
      if (message.method === 'tools/call') {
        broadcastSSE('tool_error', { 
          tool: message.params?.name, 
          args: message.params?.arguments, 
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32603,
          message: 'Internal error',
          data: { error: error instanceof Error ? error.message : 'Unknown error' }
        }
      });
    }
  });

  // SSE endpoint
  app.get('/sse', (req: Request, res: Response) => {
    const clientId = uuidv4();
    
    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });
    
    // Add client to the map
    sseClients.set(clientId, res);
    
    logger.info('SSE client connected', { clientId, totalClients: sseClients.size });
    
    // Send initial connection message
    res.write(`event: connected\ndata: ${JSON.stringify({ 
      clientId, 
      timestamp: new Date().toISOString(),
      message: 'Connected to Cisco Support MCP Server SSE stream'
    })}\n\n`);
    
    // Set up heartbeat
    const heartbeat = setInterval(() => {
      try {
        res.write(`event: heartbeat\ndata: ${JSON.stringify({ 
          timestamp: new Date().toISOString() 
        })}\n\n`);
      } catch (error) {
        clearInterval(heartbeat);
        sseClients.delete(clientId);
        logger.info('SSE client disconnected (heartbeat failed)', { clientId });
      }
    }, 30000);
    
    // Handle client disconnect
    req.on('close', () => {
      clearInterval(heartbeat);
      sseClients.delete(clientId);
      logger.info('SSE client disconnected', { clientId, totalClients: sseClients.size });
    });
    
    req.on('error', (error: Error) => {
      clearInterval(heartbeat);
      sseClients.delete(clientId);
      logger.error('SSE client error', { clientId, error });
    });
  });

  // Health check
  app.get('/health', async (_req: Request, res: Response) => {
    try {
      // Check if we can get a valid token
      await getValidToken();
      
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        sseClients: sseClients.size,
        tokenStatus: accessToken ? 'valid' : 'missing'
      });
    } catch (error) {
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        sseClients: sseClients.size,
        tokenStatus: 'invalid'
      });
    }
  });

  // Error handling middleware
  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled server error', error);
    
    res.status(500).json({
      error: 'Internal server error',
      timestamp: new Date().toISOString(),
      requestId: uuidv4()
    });
  });

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      error: 'Endpoint not found',
      timestamp: new Date().toISOString(),
      path: _req.path
    });
  });

  return app;
}

// Main function
async function main() {
  const args = process.argv.slice(2);
  const isHTTP = args.includes('--http');
  
  if (isHTTP) {
    // Run as HTTP server
    const PORT = process.env.PORT || 3000;
    const app = createHTTPServer();
    
    // Graceful shutdown handling
    const cleanup = () => {
      logger.info('Shutting down gracefully');
      
      // Close SSE connections
      sseClients.forEach((client, clientId) => {
        try {
          client.write(`event: server_shutdown\ndata: ${JSON.stringify({ 
            message: 'Server shutting down',
            timestamp: new Date().toISOString()
          })}\n\n`);
          client.end();
        } catch (error) {
          logger.error('Error closing SSE client', { clientId, error });
        }
      });
      
      sseClients.clear();
      process.exit(0);
    };

    process.on('SIGTERM', cleanup);
    process.on('SIGINT', cleanup);
    
    app.listen(PORT, () => {
      logger.info(`Cisco Support MCP Server started on port ${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0',
        mode: 'http'
      });
    });
  } else {
    // Run as MCP server over stdio (default)
    logger.info('Starting Cisco Support MCP Server in stdio mode');
    
    const server = createMCPServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    
    logger.info('Cisco Support MCP Server connected via stdio');
  }
}

// Export for testing
export { createMCPServer, createHTTPServer, executeTool };

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Failed to start server', error);
    process.exit(1);
  });
}