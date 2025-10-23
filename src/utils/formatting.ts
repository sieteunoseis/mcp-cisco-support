import { ToolArgs } from './validation.js';

// Generic API response interface
export interface ApiResponse {
  [key: string]: any;
}

// Bug-specific response interface (for backward compatibility)
export interface BugApiResponse extends ApiResponse {
  bugs?: Array<{
    bug_id: string;
    headline: string;
    status: string;
    severity: string;
    last_modified_date: string;
    [key: string]: any;
  }>;
  total_results?: number;
}

// Case-specific response interface
export interface CaseApiResponse extends ApiResponse {
  cases?: Array<{
    case_id: string;
    title: string;
    status: string;
    severity: string;
    created_date: string;
    last_modified_date: string;
    [key: string]: any;
  }>;
  total_results?: number;
}

// EoX-specific response interface (based on actual API responses)
export interface EoxApiResponse extends ApiResponse {
  EOXRecord?: Array<{
    EOLProductID?: any;  // Can be string or object
    ProductIDDescription?: any;
    ProductBulletinNumber?: any;
    LinkToProductBulletinURL?: any;
    EOXExternalAnnouncementDate?: any;  // Objects with nested date values
    EndOfSaleDate?: any;
    EndOfSWMaintenanceReleases?: any;
    EndOfRoutineFailureAnalysisDate?: any;
    EndOfServiceContractRenewal?: any;
    LastDateOfSupport?: any;
    EndOfSvcAttachDate?: any;
    UpdatedTimeStamp?: any;
    EOXError?: {
      ErrorID: string;
      ErrorDescription: string;
      ErrorDataType?: string;
      ErrorDataValue?: string;
    };
    EOXMigrationDetails?: any;
    EOXInputType?: string;
    EOXInputValue?: string;
    [key: string]: any;
  }>;
  PaginationResponseRecord?: {
    PageIndex: number;
    LastIndex: number;
    TotalRecords: number;
    PageRecords: number;
  };
}

// Format bug results with hyperlinks (existing functionality)
export function formatBugResults(data: BugApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
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
    formatted += formatSearchContext(searchContext);
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

// Format case results with hyperlinks
export function formatCaseResults(data: CaseApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
  // Handle special error responses
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
    
    return formatted;
  }
  
  if (!data.cases || data.cases.length === 0) {
    return JSON.stringify(data, null, 2);
  }

  let formatted = `# Cisco Case Search Results\n\n`;
  
  // Add search context if available
  if (searchContext) {
    formatted += formatSearchContext(searchContext);
  }
  
  if (data.total_results) {
    formatted += `**Total Results:** ${data.total_results}\n\n`;
  }

  data.cases.forEach((caseItem, index) => {
    // Note: Cisco Case Manager URL format may need adjustment based on actual Cisco portal
    const caseUrl = `https://mycase.cloudapps.cisco.com/case/${caseItem.case_id}`;
    
    formatted += `## ${index + 1}. [${caseItem.case_id}](${caseUrl})\n\n`;
    formatted += `**Title:** ${caseItem.title}\n\n`;
    formatted += `**Status:** ${caseItem.status}\n\n`;
    formatted += `**Severity:** ${caseItem.severity}\n\n`;
    formatted += `**Created:** ${caseItem.created_date}\n\n`;
    formatted += `**Last Modified:** ${caseItem.last_modified_date}\n\n`;
    
    // Add additional fields if they exist
    Object.keys(caseItem).forEach(key => {
      if (!['case_id', 'title', 'status', 'severity', 'created_date', 'last_modified_date'].includes(key)) {
        const value = caseItem[key];
        if (value && value !== '' && value !== null && value !== undefined) {
          const fieldName = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
          formatted += `**${fieldName}:** ${value}\n\n`;
        }
      }
    });
    
    formatted += `**Case URL:** ${caseUrl}\n\n`;
    formatted += `---\n\n`;
  });

  return formatted;
}

// Format EoX results with hyperlinks
export function formatEoxResults(data: EoxApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
  // Handle special error responses
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
    
    return formatted;
  }
  
  if (!data.EOXRecord || data.EOXRecord.length === 0) {
    return JSON.stringify(data, null, 2);
  }

  let formatted = `# Cisco End-of-Life (EoX) Results\n\n`;
  
  // Add search context if available
  if (searchContext) {
    formatted += formatEoxSearchContext(searchContext);
  }
  
  // Add pagination info if available
  if (data.PaginationResponseRecord) {
    const pagination = data.PaginationResponseRecord;
    formatted += `**Page:** ${pagination.PageIndex} of ${pagination.LastIndex}\n\n`;
    formatted += `**Records:** ${pagination.PageRecords} of ${pagination.TotalRecords} total\n\n`;
  }

  data.EOXRecord.forEach((eoxItem, index) => {
    // Check for errors first
    const eoxError = eoxItem.EOXError;
    if (eoxError && eoxError.ErrorID) {
      formatted += `## ${index + 1}. ⚠️ EoX Lookup Error\n\n`;
      formatted += `**Error ID:** ${eoxError.ErrorID}\n\n`;
      formatted += `**Error Description:** ${eoxError.ErrorDescription}\n\n`;
      formatted += `**Search Input:** ${eoxItem.EOXInputValue || 'N/A'} (${eoxItem.EOXInputType || 'Unknown Type'})\n\n`;
      
      if (eoxError.ErrorDataType && eoxError.ErrorDataValue) {
        formatted += `**Failed Lookup:** ${eoxError.ErrorDataType} = ${eoxError.ErrorDataValue}\n\n`;
      }
      
      formatted += `---\n\n`;
      return; // Skip normal processing for error records
    }
    
    // Extract product ID (handle object structure)
    const productId = extractValue(eoxItem.EOLProductID) || 'Unknown Product';
    formatted += `## ${index + 1}. ${productId}\n\n`;
    
    // Extract and format core fields
    const description = extractValue(eoxItem.ProductIDDescription);
    if (description) {
      formatted += `**Product Description:** ${description}\n\n`;
    }
    
    // Format all date fields consistently
    const dateFields = [
      { key: 'EOXExternalAnnouncementDate', label: 'End of Life Announcement' },
      { key: 'EndOfSaleDate', label: 'End of Sale Date' },
      { key: 'LastDateOfSupport', label: 'Last Date of Support' },
      { key: 'EndOfSWMaintenanceReleases', label: 'End of SW Maintenance' },
      { key: 'EndOfRoutineFailureAnalysisDate', label: 'End of Failure Analysis' },
      { key: 'EndOfServiceContractRenewal', label: 'End of Service Contract Renewal' },
      { key: 'UpdatedTimeStamp', label: 'Updated' }
    ];
    
    dateFields.forEach(({ key, label }) => {
      const dateValue = formatDate(eoxItem[key]);
      if (dateValue && dateValue !== 'Not specified') {
        formatted += `**${label}:** ${dateValue}\n\n`;
      }
    });
    
    // Handle bulletin information
    const bulletinNumber = extractValue(eoxItem.ProductBulletinNumber);
    const bulletinURL = extractValue(eoxItem.LinkToProductBulletinURL);
    
    if (bulletinNumber || bulletinURL) {
      if (bulletinNumber) {
        formatted += `**Product Bulletin:** ${bulletinNumber}\n\n`;
      }
      if (bulletinURL) {
        formatted += `**Bulletin URL:** [${bulletinNumber || 'View Bulletin'}](${bulletinURL})\n\n`;
      }
    }
    
    // Show additional fields that aren't explicitly handled
    const handledKeys = [
      'EOLProductID', 'ProductIDDescription', 'ProductBulletinNumber', 
      'LinkToProductBulletinURL', 'EOXExternalAnnouncementDate', 'EndOfSaleDate',
      'EndOfSWMaintenanceReleases', 'EndOfRoutineFailureAnalysisDate', 
      'EndOfServiceContractRenewal', 'LastDateOfSupport', 'EndOfSvcAttachDate',
      'UpdatedTimeStamp'
    ];
    
    Object.keys(eoxItem).forEach(key => {
      if (!handledKeys.includes(key)) {
        const value = extractValue(eoxItem[key]);
        if (value) {
          const fieldName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
          formatted += `**${fieldName}:** ${value}\n\n`;
        }
      }
    });
    
    formatted += `---\n\n`;
  });

  return formatted;
}

// Helper function to format EoX search context
function formatEoxSearchContext(searchContext: { toolName: string; args: ToolArgs }): string {
  let formatted = '';
  
  if (searchContext.toolName === 'get_eox_by_date') {
    formatted += `**Date Range:** ${searchContext.args.start_date} to ${searchContext.args.end_date}\n\n`;
    if (searchContext.args.eox_attrib && searchContext.args.eox_attrib !== 'UPDATED_TIMESTAMP') {
      formatted += `**EoX Attribute Filter:** ${searchContext.args.eox_attrib}\n\n`;
    }
  } else if (searchContext.toolName === 'get_eox_by_product_id') {
    formatted += `**Product IDs:** ${searchContext.args.product_ids}\n\n`;
  } else if (searchContext.toolName === 'get_eox_by_serial_number') {
    formatted += `**Serial Numbers:** ${searchContext.args.serial_numbers}\n\n`;
  } else if (searchContext.toolName === 'get_eox_by_software_release') {
    const inputs: string[] = [];
    ['input1', 'input2', 'input3', 'input4', 'input5'].forEach(inputKey => {
      if (searchContext.args[inputKey]) {
        inputs.push(searchContext.args[inputKey] as string);
      }
    });
    formatted += `**Software Releases:** ${inputs.join(', ')}\n\n`;
  }
  
  return formatted;
}

// Helper function to extract values from EoX API object structures
function extractValue(value: any): string | null {
  if (!value) {
    return null;
  }
  
  if (typeof value === 'string') {
    return value.trim() || null;
  }
  
  if (typeof value === 'object') {
    // Try common object properties
    const valueKeys = ['value', '#text', 'text'];
    for (const key of valueKeys) {
      if (value[key]) {
        const extracted = String(value[key]).trim();
        return extracted || null;
      }
    }
    return null;
  }
  
  return String(value).trim() || null;
}

// Helper function to format EoX date objects
function formatDate(dateValue: any): string {
  const extracted = extractValue(dateValue);
  return extracted || 'Not specified';
}

// Helper function to format search context
function formatSearchContext(searchContext: { toolName: string; args: ToolArgs }): string {
  let formatted = '';
  
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
  } else if (searchContext.toolName.startsWith('get_case') || searchContext.toolName.includes('case')) {
    // Case API context formatting
    if (searchContext.args.case_id || searchContext.args.case_ids) {
      formatted += `**Case ID(s):** ${searchContext.args.case_id || searchContext.args.case_ids}\n\n`;
    }
    if (searchContext.args.contract_id) {
      formatted += `**Contract ID:** ${searchContext.args.contract_id}\n\n`;
    }
    if (searchContext.args.user_id) {
      formatted += `**User ID:** ${searchContext.args.user_id}\n\n`;
    }
  }
  
  // Add filters if specified
  if (searchContext.args.status) {
    const statusMap: {[key: string]: string} = {
      'O': 'Open',
      'F': 'Fixed', 
      'T': 'Terminated',
      'C': 'Closed',
      'W': 'Waiting',
      'I': 'In Progress'
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
  
  return formatted;
}
// Smart Bonding-specific response interface
export interface SmartBondingTicket {
  SDCallID?: string;
  CustCallID?: string;
  ShortDescription?: string;
  DetailedDescription?: string;
  CallerInfo?: any;
  ComponentInfo?: any;
  Status?: string;
  Priority?: string;
  Severity?: string;
  CreatedDate?: string;
  ModifiedDate?: string;
  [key: string]: any;
}

export interface SmartBondingApiResponse extends ApiResponse {
  tickets?: SmartBondingTicket[];
  total_results?: number;
  status?: string;
  message?: string;
  SDCallID?: string;
  CustCallID?: string;
  correlation_id?: string;
  _experimental_warning?: string;
  _environment?: string;
}

/**
 * ⚠️ EXPERIMENTAL: Format Smart Bonding API results
 * UNTESTED - Requires Smart Bonding credentials to validate
 */
export function formatSmartBondingResults(data: SmartBondingApiResponse, searchContext?: { toolName: string; args: ToolArgs }): string {
  // Add experimental warning
  let formatted = `# ⚠️ EXPERIMENTAL/UNTESTED: Smart Bonding API Results\n\n`;

  if (data._experimental_warning) {
    formatted += `> ${data._experimental_warning}\n\n`;
  }

  if (data._environment) {
    formatted += `**Environment:** ${data._environment}\n\n`;
  }

  // Add search context if available
  if (searchContext) {
    formatted += `## Search Context\n\n`;
    formatted += `**Tool:** ${searchContext.toolName}\n\n`;
    if (searchContext.args.correlation_id) {
      formatted += `**Correlation ID:** ${searchContext.args.correlation_id}\n\n`;
    }
  }

  // Handle push ticket response (create/update)
  if (data.status && data.SDCallID) {
    formatted += `## Ticket Operation Result\n\n`;
    formatted += `**Status:** ${data.status}\n\n`;
    if (data.message) {
      formatted += `**Message:** ${data.message}\n\n`;
    }
    formatted += `**Cisco Ticket ID (SDCallID):** ${data.SDCallID}\n\n`;
    if (data.CustCallID) {
      formatted += `**Customer Ticket ID:** ${data.CustCallID}\n\n`;
    }
    if (data.correlation_id) {
      formatted += `**Correlation ID:** ${data.correlation_id}\n\n`;
    }

    // Extract and highlight file upload credentials if present (for create operations)
    if (data.ExtTableValues) {
      const extValues = data.ExtTableValues;
      if (extValues.Field80 || extValues.Field81 || extValues.Field82) {
        formatted += `## 📎 File Upload Credentials\n\n`;
        formatted += `> ⚠️ **SAVE THESE CREDENTIALS** - They cannot be retrieved later!\n\n`;

        if (extValues.Field80) {
          formatted += `**Upload Domain (Field80):** ${extValues.Field80}\n\n`;
        }
        if (extValues.Field81) {
          formatted += `**Upload Token (Field81):** ${extValues.Field81}\n\n`;
        }
        if (extValues.Field82) {
          formatted += `**Token Expires (Field82):** ${new Date(parseInt(extValues.Field82) * 1000).toISOString()} (Unix: ${extValues.Field82})\n\n`;
        }

        formatted += `**Upload Instructions:**\n`;
        formatted += `Use the \`upload_file_to_smart_bonding_ticket\` tool with:\n`;
        formatted += `- ticket_number: ${data.SDCallID}\n`;
        formatted += `- upload_token: ${extValues.Field81 || '(from Field81)'}\n`;
        if (extValues.Field80) {
          formatted += `- upload_domain: ${extValues.Field80}\n`;
        }
        formatted += `- filename: your file name\n`;
        formatted += `- file_content: Base64-encoded file data\n\n`;

        formatted += `**Alternative (curl):**\n`;
        formatted += `\`\`\`bash\n`;
        formatted += `curl -X PUT "https://${extValues.Field80 || 'cxd.cisco.com'}/home/yourfile.txt" \\\n`;
        formatted += `  -u "${data.SDCallID}:${extValues.Field81 || 'TOKEN'}" \\\n`;
        formatted += `  --data-binary @yourfile.txt\n`;
        formatted += `\`\`\`\n\n`;
      }
    }

    return formatted;
  }

  // Handle pull tickets response (retrieve updates)
  if (data.tickets && Array.isArray(data.tickets)) {
    if (data.tickets.length === 0) {
      formatted += `**No ticket updates available.**\n\n`;
      return formatted;
    }

    formatted += `**Total Tickets:** ${data.total_results || data.tickets.length}\n\n`;

    data.tickets.forEach((ticket, index) => {
      formatted += `## ${index + 1}. Ticket: ${ticket.SDCallID || 'Unknown'}\n\n`;

      if (ticket.CustCallID) {
        formatted += `**Customer Ticket ID:** ${ticket.CustCallID}\n\n`;
      }

      if (ticket.ShortDescription) {
        formatted += `**Summary:** ${ticket.ShortDescription}\n\n`;
      }

      if (ticket.DetailedDescription) {
        formatted += `**Description:** ${ticket.DetailedDescription}\n\n`;
      }

      if (ticket.Status) {
        formatted += `**Status:** ${ticket.Status}\n\n`;
      }

      if (ticket.Priority) {
        formatted += `**Priority:** ${ticket.Priority}\n\n`;
      }

      if (ticket.Severity) {
        formatted += `**Severity:** ${ticket.Severity}\n\n`;
      }

      if (ticket.CreatedDate) {
        formatted += `**Created:** ${ticket.CreatedDate}\n\n`;
      }

      if (ticket.ModifiedDate) {
        formatted += `**Last Modified:** ${ticket.ModifiedDate}\n\n`;
      }

      // Add caller information if available
      if (ticket.CallerInfo) {
        formatted += `**Caller Information:**\n`;
        if (typeof ticket.CallerInfo === 'object') {
          Object.entries(ticket.CallerInfo).forEach(([key, value]) => {
            if (value) {
              formatted += `  - ${key}: ${value}\n`;
            }
          });
          formatted += `\n`;
        } else {
          formatted += `  ${ticket.CallerInfo}\n\n`;
        }
      }

      // Add component information if available
      if (ticket.ComponentInfo) {
        formatted += `**Component Information:**\n`;
        if (typeof ticket.ComponentInfo === 'object') {
          Object.entries(ticket.ComponentInfo).forEach(([key, value]) => {
            if (value) {
              formatted += `  - ${key}: ${value}\n`;
            }
          });
          formatted += `\n`;
        } else {
          formatted += `  ${ticket.ComponentInfo}\n\n`;
        }
      }

      formatted += `---\n\n`;
    });

    return formatted;
  }

  // Fallback: return JSON
  return JSON.stringify(data, null, 2);
}
