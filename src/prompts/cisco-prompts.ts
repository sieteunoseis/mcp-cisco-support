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
    name: 'cisco-incident-investigation',
    title: 'Cisco Incident Investigation',
    description: 'Investigate Cisco bugs related to specific incident symptoms and errors. Provide either product OR serial_number.',
    arguments: [
      {
        name: 'symptom',
        description: 'The error message, symptom, or behavior observed during the incident',
        required: true
      },
      {
        name: 'product',
        description: 'Cisco product experiencing the issue (e.g., "Cisco ASR 1000", "Cisco Catalyst 9200"). Either this OR serial_number is required.',
        required: false
      },
      {
        name: 'serial_number',
        description: 'Serial number of device experiencing the issue (e.g., "SAL09232Q0Z"). Either this OR product is required. Will automatically look up product details.',
        required: false
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
    title: 'Cisco Upgrade Planning',
    description: 'Research known issues and bugs before upgrading Cisco software or hardware. Provide either product OR serial_number.',
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
        description: 'Cisco product being upgraded (e.g., "Cisco ASR 9000 Series"). Either this OR serial_number is required.',
        required: false
      },
      {
        name: 'serial_number',
        description: 'Serial number of device being upgraded (e.g., "SAL09232Q0Z"). Either this OR product is required. Will automatically look up product details.',
        required: false
      },
      {
        name: 'environment',
        description: 'Environment type (production, staging, lab)',
        required: false
      }
    ]
  },
  {
    name: 'cisco-security-advisory',
    title: 'Cisco Security Advisory',
    description: 'Research security-related bugs and vulnerabilities for Cisco products. Provide either product OR serial_number.',
    arguments: [
      {
        name: 'product',
        description: 'Cisco product to check for security issues. Either this OR serial_number is required.',
        required: false
      },
      {
        name: 'serial_number',
        description: 'Serial number of device to check for security issues (e.g., "SAL09232Q0Z"). Either this OR product is required. Will automatically look up product details.',
        required: false
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
    title: 'Cisco Known Issues',
    description: 'Known open bugs (worst first) and security advisories for a Cisco product or release, e.g. before a change or maintenance window. Provide product OR serial_number.',
    arguments: [
      {
        name: 'product',
        description: 'Cisco product to check. Either this OR serial_number is required.',
        required: false
      },
      {
        name: 'serial_number',
        description: 'Serial number of device to check (e.g., "SAL09232Q0Z"). Either this OR product is required. Will automatically look up product details.',
        required: false
      },
      {
        name: 'software_version',
        description: 'Software release to check (e.g. "17.9.4"). Without it, searches by product keyword.',
        required: false
      },
      {
        name: 'max_severity',
        description: 'Include severities 1..max_severity (default 3)',
        required: false
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
    title: 'Cisco Case Investigation',
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
    title: 'Cisco Lifecycle Planning',
    description: 'End-of-life dates, migration products and contract coverage for products, serial numbers, software releases or an announcement date range',
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
        name: 'software_releases',
        description: 'Software releases to check, as "version,OS" pairs separated by ";" (e.g. "15.4(3)M,IOS")',
        required: false
      },
      {
        name: 'date_range_start',
        description: 'Start date for EoX announcements (YYYY-MM-DD)',
        required: false
      },
      {
        name: 'date_range_end',
        description: 'End date for lifecycle search (YYYY-MM-DD)',
        required: false
      }
    ]
  }
];

/**
 * Prompt to API mapping
 * Defines which APIs each prompt uses for filtering based on enabled APIs
 * Prompts with serial_number support require 'serial' API for product lookups
 */
export const promptApiMapping: Record<string, SupportedAPI[]> = {
  'cisco-upgrade-planning': ['bug'],
  'cisco-known-issues': ['bug'],
  'cisco-incident-investigation': ['bug'],
  'cisco-security-advisory': ['psirt'],
  'cisco-lifecycle-planning': ['eox', 'serial'],
  'cisco-case-investigation': ['case'],
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
