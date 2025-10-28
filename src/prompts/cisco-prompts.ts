/**
 * Cisco Support MCP Prompts
 *
 * Pre-defined prompts for common Cisco Support workflows.
 * These prompts guide users through bug searches, incident investigations,
 * upgrade planning, and other Cisco-specific tasks.
 */

import { Prompt } from '@modelcontextprotocol/sdk/types.js';
import { SupportedAPI } from '../apis/index.js';

/**
 * Cisco Support MCP Prompts
 * These prompts provide guided workflows for common Cisco support scenarios
 */
export const ciscoPrompts: Prompt[] = [
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
  },
  {
    name: 'cisco-smart-search',
    description: 'Intelligent search strategy with automatic refinement and comprehensive analysis. Uses multiple search techniques and provides web search guidance.',
    arguments: [
      {
        name: 'search_query',
        description: 'What you want to search for (e.g., "ISR4431 17.09.06 high severity bugs", "memory leak CallManager")',
        required: true
      },
      {
        name: 'search_context',
        description: 'Context for the search to optimize strategy',
        required: false
      },
      {
        name: 'include_web_guidance',
        description: 'Include web search recommendations for additional research (true/false)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-interactive-search',
    description: '⚠️ EXPERIMENTAL: Interactive search with elicitation requests for missing parameters. Note: ElicitationRequest support is limited in current MCP clients (Claude Desktop uses conversational follow-ups instead). Kept for future client support.',
    arguments: [
      {
        name: 'initial_query',
        description: 'Initial search query (optional - if not provided, will use elicitation to gather)',
        required: false
      },
      {
        name: 'use_elicitation',
        description: 'Whether to use elicitation to gather additional search parameters (true/false)',
        required: false
      }
    ]
  }
];

/**
 * Prompt to API mapping
 * Defines which APIs each prompt uses for filtering based on enabled APIs
 */
export const promptApiMapping: Record<string, SupportedAPI[]> = {
  'cisco-high-severity-search': ['bug'],
  'cisco-incident-investigation': ['bug'],
  'cisco-upgrade-planning': ['bug'],
  'cisco-maintenance-prep': ['bug'],
  'cisco-security-advisory': ['bug'],
  'cisco-known-issues': ['bug'],
  'cisco-case-investigation': ['case'],
  'cisco-lifecycle-planning': ['eox'],
  'cisco-eox-research': ['eox'],
  'cisco-smart-search': ['bug'],
  'cisco-interactive-search': ['bug']
};

/**
 * Get available prompts filtered by enabled APIs
 * @param enabledApis - Array of enabled API names
 * @returns Filtered array of prompts
 */
export function getFilteredPrompts(enabledApis: SupportedAPI[]): Prompt[] {
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
