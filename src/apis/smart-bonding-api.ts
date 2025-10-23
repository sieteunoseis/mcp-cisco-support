import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { SmartBondingBaseApi } from './smart-bonding-base-api.js';
import { ToolArgs } from '../utils/validation.js';
import { ApiResponse } from '../utils/formatting.js';

/**
 * ⚠️ EXPERIMENTAL: Smart Bonding Customer API Implementation
 *
 * Provides tools for:
 * - Pulling ticket updates from Cisco Smart Bonding
 * - Pushing (creating/updating) tickets to Cisco Smart Bonding
 *
 * Status: UNTESTED - Requires credentials from Cisco Account Manager
 *
 * Credentials needed:
 * - SMART_BONDING_CLIENT_ID
 * - SMART_BONDING_CLIENT_SECRET
 *
 * Contact your Cisco Account Manager to obtain Smart Bonding API access.
 */
export class SmartBondingApi extends SmartBondingBaseApi {
  getTools(): Tool[] {
    return [
      {
        name: 'get_smart_bonding_tsp_codes',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Retrieve TSP (Technology, Sub-Technology, Problem Code) details for use in ticket classification. TSP codes provide standardized problem categorization for support tickets. Returns taxonomic codes with technical descriptions. Requires SMART_BONDING_CLIENT_ID and SMART_BONDING_CLIENT_SECRET environment variables (contact Cisco Account Manager to obtain).',
        inputSchema: {
          type: 'object',
          properties: {
            since_id: {
              type: 'integer',
              description: 'Only retrieve records with ID greater than this value (optional filter)'
            },
            max_id: {
              type: 'integer',
              description: 'Only retrieve records with ID up to this value (optional filter)'
            },
            limit: {
              type: 'integer',
              description: 'Limit number of returned records. Must be non-negative.'
            }
          },
          required: []
        }
      },
      {
        name: 'pull_smart_bonding_tickets',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Retrieve ticket updates from Cisco Smart Bonding that have not yet been pulled. Returns all new ticket updates since last pull. Requires SMART_BONDING_CLIENT_ID and SMART_BONDING_CLIENT_SECRET environment variables (contact Cisco Account Manager to obtain).',
        inputSchema: {
          type: 'object',
          properties: {
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier for end-to-end traceability. If provided, the response will include a corresponding transaction ID.'
            }
          },
          required: []
        }
      },
      {
        name: 'create_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Create a new support ticket in Cisco Smart Bonding system. Requires complete ticket information including customer ID, description, caller details, and component information. Requires SMART_BONDING_CLIENT_ID and SMART_BONDING_CLIENT_SECRET environment variables (contact Cisco Account Manager to obtain).',
        inputSchema: {
          type: 'object',
          properties: {
            CustCallID: {
              type: 'string',
              description: 'Customer ticket ID (required) - your internal ticket reference'
            },
            ShortDescription: {
              type: 'string',
              description: 'Brief description of the issue (required)'
            },
            DetailedDescription: {
              type: 'string',
              description: 'Full description of the issue with all relevant details'
            },
            Caller: {
              type: 'object',
              description: 'Information about the person reporting the issue (required)',
              properties: {
                Name: { type: 'string', description: 'Full name of the caller' },
                Email: { type: 'string', description: 'Email address of the caller' },
                Phone: { type: 'string', description: 'Phone number of the caller' }
              },
              required: ['Name', 'Email']
            },
            Priority: {
              type: 'string',
              description: 'Priority level of the ticket',
              enum: ['Low', 'Medium', 'High', 'Critical', 'Escalated']
            },
            Severity: {
              type: 'string',
              description: 'Severity level (1=Critical, 2=High, 3=Medium, 4=Low)',
              enum: ['1', '2', '3', '4']
            },
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier for end-to-end traceability'
            }
          },
          required: ['CustCallID', 'ShortDescription', 'Caller']
        }
      },
      {
        name: 'update_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Update an existing support ticket with work notes and status changes. Use this to add updates, notes, or modify ticket information.',
        inputSchema: {
          type: 'object',
          properties: {
            CustCallID: {
              type: 'string',
              description: 'Customer ticket ID to update (required)'
            },
            Remarks: {
              type: 'string',
              description: 'Work notes or update comments to add to the ticket'
            },
            Status: {
              type: 'string',
              description: 'New status for the ticket',
              enum: ['Update', 'Open', 'Pending', 'In Progress']
            },
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier for end-to-end traceability'
            }
          },
          required: ['CustCallID']
        }
      },
      {
        name: 'upload_file_to_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Upload a file to a Smart Bonding ticket using credentials from ticket creation response. Upload credentials (Field80-82) are provided when creating a ticket and must be saved. Uses HTTPS PUT to Cisco upload domain (cxd.cisco.com). Files cannot be modified after upload - submit new files for corrections.',
        inputSchema: {
          type: 'object',
          properties: {
            ticket_number: {
              type: 'string',
              description: 'Cisco SR ticket number (username for upload authentication)'
            },
            upload_token: {
              type: 'string',
              description: 'Upload token from Field81 of ticket creation response (password for authentication)'
            },
            upload_domain: {
              type: 'string',
              description: 'Upload domain from Field80 (e.g., cxd.cisco.com). Optional - defaults to cxd.cisco.com',
              default: 'cxd.cisco.com'
            },
            filename: {
              type: 'string',
              description: 'Name of the file to upload (e.g., "showtech.txt", "screenshot.png")'
            },
            file_content: {
              type: 'string',
              description: 'Base64-encoded file content to upload'
            }
          },
          required: ['ticket_number', 'upload_token', 'filename', 'file_content']
        }
      },
      {
        name: 'escalate_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Escalate a support ticket to Cisco by changing priority to "Escalated". Use this for critical issues requiring immediate Cisco attention.',
        inputSchema: {
          type: 'object',
          properties: {
            CustCallID: {
              type: 'string',
              description: 'Customer ticket ID to escalate (required)'
            },
            Remarks: {
              type: 'string',
              description: 'Escalation reason and details'
            },
            Severity: {
              type: 'string',
              description: 'Escalated severity level (typically 1 for critical escalations)',
              enum: ['1', '2', '3', '4']
            },
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier'
            }
          },
          required: ['CustCallID', 'Remarks']
        }
      },
      {
        name: 'resolve_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Mark a support ticket as "Resolved" with resolution notes. Use this when the issue has been fixed but before final closure.',
        inputSchema: {
          type: 'object',
          properties: {
            CustCallID: {
              type: 'string',
              description: 'Customer ticket ID to resolve (required)'
            },
            Remarks: {
              type: 'string',
              description: 'Resolution details and work notes (required)'
            },
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier'
            }
          },
          required: ['CustCallID', 'Remarks']
        }
      },
      {
        name: 'close_smart_bonding_ticket',
        description: '⚠️ EXPERIMENTAL/UNTESTED: Close a completed support ticket with diagnosis and solution. This is the final state for a ticket after resolution and customer confirmation.',
        inputSchema: {
          type: 'object',
          properties: {
            CustCallID: {
              type: 'string',
              description: 'Customer ticket ID to close (required)'
            },
            Solution: {
              type: 'string',
              description: 'Final solution description (required)'
            },
            Diagnosis: {
              type: 'string',
              description: 'Problem diagnosis details'
            },
            correlation_id: {
              type: 'string',
              description: 'Optional tracking identifier'
            }
          },
          required: ['CustCallID', 'Solution']
        }
      }
    ];
  }

  async executeTool(name: string, args: ToolArgs, meta?: { progressToken?: string }): Promise<ApiResponse> {
    const { tool, processedArgs } = this.validateTool(name, args);

    switch (name) {
      case 'get_smart_bonding_tsp_codes':
        return await this.getTspCodes(processedArgs);

      case 'pull_smart_bonding_tickets':
        return await this.pullTickets(processedArgs);

      case 'create_smart_bonding_ticket':
        return await this.createTicket(processedArgs);

      case 'update_smart_bonding_ticket':
        return await this.updateTicket(processedArgs);

      case 'upload_file_to_smart_bonding_ticket':
        return await this.uploadFile(processedArgs);

      case 'escalate_smart_bonding_ticket':
        return await this.escalateTicket(processedArgs);

      case 'resolve_smart_bonding_ticket':
        return await this.resolveTicket(processedArgs);

      case 'close_smart_bonding_ticket':
        return await this.closeTicket(processedArgs);

      default:
        throw new Error(`Unknown Smart Bonding tool: ${name}`);
    }
  }

  /**
   * Get TSP (Technology, Sub-Technology, Problem Code) details
   * GET /tspcodes
   */
  private async getTspCodes(args: ToolArgs): Promise<ApiResponse> {
    const params: Record<string, any> = {};

    if (args.since_id !== undefined) {
      params.since_id = args.since_id;
    }
    if (args.max_id !== undefined) {
      params.max_id = args.max_id;
    }
    if (args.limit !== undefined) {
      params.limit = args.limit;
    }

    const result = await this.makeApiCall(
      '/tspcodes',
      'GET',
      undefined,
      params
    );

    // Add experimental warning to response
    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature. Smart Bonding API requires credentials from Cisco Account Manager.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _usage_note: 'Use these TSP codes when creating tickets to ensure proper problem categorization.'
    };
  }

  /**
   * Pull ticket updates from Cisco Smart Bonding
   * GET /pull/call
   */
  private async pullTickets(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    const result = await this.makeApiCall(
      '/pull/call',
      'GET',
      undefined,
      {},
      correlationId
    );

    // Add experimental warning to response
    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature. Smart Bonding API requires credentials from Cisco Account Manager.',
      _environment: process.env.SMART_BONDING_ENV || 'production'
    };
  }

  /**
   * Create a new ticket in Cisco Smart Bonding
   * POST /push/call
   */
  private async createTicket(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    // Build ticket creation payload
    const ticketData: Record<string, any> = {
      CustCallID: args.CustCallID,
      ShortDescription: args.ShortDescription,
      Caller: args.Caller
    };

    if (args.DetailedDescription) {
      ticketData.DetailedDescription = args.DetailedDescription;
    }
    if (args.Priority) {
      ticketData.Priority = args.Priority;
    }
    if (args.Severity) {
      ticketData.Severity = args.Severity;
    }

    const result = await this.makeApiCall(
      '/push/call',
      'POST',
      ticketData,
      {},
      correlationId
    );

    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature. Smart Bonding API requires credentials from Cisco Account Manager.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _operation: 'create_ticket'
    };
  }

  /**
   * Update an existing ticket with work notes
   * POST /push/call
   */
  private async updateTicket(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    const ticketData: Record<string, any> = {
      CustCallID: args.CustCallID
    };

    if (args.Remarks) {
      ticketData.Remarks = args.Remarks;
    }
    if (args.Status) {
      ticketData.CallStates = args.Status;
    }

    const result = await this.makeApiCall(
      '/push/call',
      'POST',
      ticketData,
      {},
      correlationId
    );

    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _operation: 'update_ticket'
    };
  }

  /**
   * Upload file to Smart Bonding ticket using credentials from ticket creation
   * HTTPS PUT to cxd.cisco.com (separate from Smart Bonding API)
   */
  private async uploadFile(args: ToolArgs): Promise<ApiResponse> {
    const ticketNumber = args.ticket_number as string;
    const uploadToken = args.upload_token as string;
    const uploadDomain = (args.upload_domain as string) || 'cxd.cisco.com';
    const filename = args.filename as string;
    const fileContent = args.file_content as string;

    // Decode Base64 file content
    let fileBuffer: Buffer;
    try {
      fileBuffer = Buffer.from(fileContent, 'base64');
    } catch (error) {
      throw new Error('Invalid Base64 file content');
    }

    const uploadUrl = `https://${uploadDomain}/home/${filename}`;
    const credentials = Buffer.from(`${ticketNumber}:${uploadToken}`).toString('base64');

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minute timeout for file uploads

      const response = await fetch(uploadUrl, {
        method: 'PUT',
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/octet-stream',
          'Content-Length': fileBuffer.length.toString()
        },
        body: fileBuffer,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.status === 201) {
        return {
          status: 'success',
          message: 'File uploaded successfully',
          filename: filename,
          upload_url: uploadUrl,
          http_status: 201,
          _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature.',
          _operation: 'file_upload',
          _note: 'Files cannot be modified after upload. Submit new files for corrections.'
        };
      } else {
        const errorText = await response.text();
        throw new Error(`File upload failed: ${response.status} ${response.statusText} - ${errorText}`);
      }
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error('File upload timed out after 2 minutes. Please try with a smaller file.');
        }
      }
      throw error;
    }
  }

  /**
   * Escalate ticket to Cisco
   * POST /push/call
   */
  private async escalateTicket(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    const ticketData: Record<string, any> = {
      CustCallID: args.CustCallID,
      Priorities: 'Escalated'
    };

    if (args.Remarks) {
      ticketData.Remarks = args.Remarks;
    }
    if (args.Severity) {
      ticketData.Severities = args.Severity;
    }

    const result = await this.makeApiCall(
      '/push/call',
      'POST',
      ticketData,
      {},
      correlationId
    );

    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _operation: 'escalate_ticket'
    };
  }

  /**
   * Resolve ticket with resolution notes
   * POST /push/call
   */
  private async resolveTicket(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    const ticketData: Record<string, any> = {
      CustCallID: args.CustCallID,
      CallStates: 'Resolved',
      Remarks: args.Remarks
    };

    const result = await this.makeApiCall(
      '/push/call',
      'POST',
      ticketData,
      {},
      correlationId
    );

    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _operation: 'resolve_ticket'
    };
  }

  /**
   * Close ticket with diagnosis and solution
   * POST /push/call
   */
  private async closeTicket(args: ToolArgs): Promise<ApiResponse> {
    const correlationId = args.correlation_id as string | undefined;

    const ticketData: Record<string, any> = {
      CustCallID: args.CustCallID,
      CallStates: 'Closed',
      Solution: args.Solution
    };

    if (args.Diagnosis) {
      ticketData.Diagnosis = args.Diagnosis;
    }

    const result = await this.makeApiCall(
      '/push/call',
      'POST',
      ticketData,
      {},
      correlationId
    );

    return {
      ...result,
      _experimental_warning: '⚠️ This is an EXPERIMENTAL/UNTESTED feature.',
      _environment: process.env.SMART_BONDING_ENV || 'production',
      _operation: 'close_ticket'
    };
  }
}
