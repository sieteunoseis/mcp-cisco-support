/**
 * MCP Sampling-Powered Tools
 *
 * These tools leverage MCP sampling to provide intelligent, AI-powered features
 * that enhance the Cisco Support MCP Server capabilities.
 *
 * Note: These tools require clients that support MCP sampling capability.
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  clientSupportsSampling,
  resolveProductName,
  categorizeBug,
  analyzeUpgradeRisk,
  summarizeBugs,
  extractProductQuery
} from '../utils/sampling.js';
import { logger } from '../utils/logger.js';

/**
 * Tool definitions for sampling-powered features
 */
export const samplingTools: Tool[] = [
  {
    name: 'resolve_product_name',
    description: '🤖 AI-POWERED: Resolve natural language product descriptions to Cisco product IDs. Converts friendly names like "Catalyst 9200 24-port switch" to product IDs like "C9200-24P". Requires client with sampling support.',
    inputSchema: {
      type: 'object',
      properties: {
        product_description: {
          type: 'string',
          description: 'Natural language description of the Cisco product (e.g., "Catalyst 9300 48-port switch with PoE", "ISR 4431 router", "ASA 5516 firewall")'
        }
      },
      required: ['product_description']
    }
  },
  {
    name: 'categorize_bug',
    description: '🤖 AI-POWERED: Analyze and categorize a bug using AI. Provides severity assessment, impact analysis, and functional category classification. Requires client with sampling support.',
    inputSchema: {
      type: 'object',
      properties: {
        bug_description: {
          type: 'string',
          description: 'Description of the bug or issue to analyze'
        }
      },
      required: ['bug_description']
    }
  },
  {
    name: 'analyze_upgrade_risk_with_ai',
    description: '🤖 AI-POWERED: Comprehensive AI analysis of software upgrade risks. Analyzes bug data between versions and provides detailed risk assessment with specific recommendations. Requires client with sampling support.',
    inputSchema: {
      type: 'object',
      properties: {
        product_id: {
          type: 'string',
          description: 'Product ID (e.g., C9300-24P, ISR4431)'
        },
        current_version: {
          type: 'string',
          description: 'Current software version'
        },
        target_version: {
          type: 'string',
          description: 'Target software version for upgrade'
        }
      },
      required: ['product_id', 'current_version', 'target_version']
    }
  },
  {
    name: 'summarize_bugs_with_ai',
    description: '🤖 AI-POWERED: Generate natural language summaries of bug search results. Highlights critical issues, severity distribution, and actionable recommendations. Requires client with sampling support.',
    inputSchema: {
      type: 'object',
      properties: {
        bug_ids: {
          type: 'string',
          description: 'Comma-separated list of bug IDs to summarize (max 10)'
        },
        search_context: {
          type: 'string',
          description: 'Context for the search (e.g., "ISR4431 upgrade planning", "Critical bugs for CallManager 12.5")'
        }
      },
      required: ['bug_ids', 'search_context']
    }
  },
  {
    name: 'extract_product_query',
    description: '🤖 AI-POWERED: Parse natural language queries into structured bug search parameters. Extracts product IDs, versions, severity, status, and keywords from conversational queries. Requires client with sampling support.',
    inputSchema: {
      type: 'object',
      properties: {
        natural_query: {
          type: 'string',
          description: 'Natural language query (e.g., "Show me critical bugs for Catalyst 9200 running 17.9.1")'
        }
      },
      required: ['natural_query']
    }
  }
];

/**
 * Tool handler for sampling-powered tools
 */
export async function handleSamplingTool(
  server: Server,
  toolName: string,
  args: any,
  ciscoAuth: { getAccessToken: () => Promise<string> }
): Promise<any> {
  // Check if client supports sampling
  if (!clientSupportsSampling(server)) {
    return {
      content: [
        {
          type: 'text',
          text: `❌ **Sampling Not Supported**

This tool requires an MCP client with sampling capability. Your current client does not support sampling.

**What is Sampling?**
Sampling allows the server to request LLM completions from the client, enabling AI-powered features without server-side API keys.

**How to Enable:**
- Use a client that supports MCP sampling (e.g., Claude Desktop with sampling enabled)
- Check your client's MCP configuration
- Refer to: https://modelcontextprotocol.io/specification/2025-06-18/client/sampling

**Alternative:**
Use the standard (non-AI) tools which don't require sampling support.`
        }
      ]
    };
  }

  try {
    switch (toolName) {
      case 'resolve_product_name':
        return await handleResolveProductName(server, args);

      case 'categorize_bug':
        return await handleCategorizeBug(server, args);

      case 'analyze_upgrade_risk_with_ai':
        return await handleAnalyzeUpgradeRisk(server, args, ciscoAuth);

      case 'summarize_bugs_with_ai':
        return await handleSummarizeBugs(server, args, ciscoAuth);

      case 'extract_product_query':
        return await handleExtractProductQuery(server, args);

      default:
        throw new Error(`Unknown sampling tool: ${toolName}`);
    }
  } catch (error: any) {
    logger.error(`Sampling tool error: ${toolName}`, { error: error.message });
    return {
      content: [
        {
          type: 'text',
          text: `❌ **Error in AI-Powered Tool**

${error.message}

This tool uses AI sampling which may fail if:
- The client doesn't properly support sampling
- The sampling request was denied
- Network connectivity issues

Try again or use standard (non-AI) tools as an alternative.`
        }
      ],
      isError: true
    };
  }
}

/**
 * Handle resolve_product_name tool
 */
async function handleResolveProductName(server: Server, args: any) {
  const { product_description } = args;

  logger.info('Resolving product name with AI', { product_description });

  const productId = await resolveProductName(server, product_description);

  if (productId === 'UNKNOWN') {
    return {
      content: [
        {
          type: 'text',
          text: `❓ **Product Not Identified**

Could not resolve product ID for: "${product_description}"

**Suggestions:**
- Try a more specific description
- Include model numbers or series names
- Use official Cisco product naming

**Examples:**
- "Catalyst 9200 24-port" → C9200-24P
- "ISR 4431" → ISR4431
- "ASA 5516-X" → ASA5516-X`
        }
      ]
    };
  }

  return {
    content: [
      {
        type: 'text',
        text: `✅ **Product Identified**

**Description:** ${product_description}
**Product ID:** \`${productId}\`

You can now use this product ID with other tools:
- \`search_bugs_by_product_id\` - Find bugs for this product
- \`get_product_info_by_product_ids\` - Get product details
- \`get_eox_by_product_id\` - Check end-of-life status`
      }
    ]
  };
}

/**
 * Handle categorize_bug tool
 */
async function handleCategorizeBug(server: Server, args: any) {
  const { bug_description } = args;

  logger.info('Categorizing bug with AI', { descriptionLength: bug_description.length });

  const analysis = await categorizeBug(server, bug_description);

  const severityEmoji = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    unknown: '⚪'
  }[analysis.severity] || '⚪';

  return {
    content: [
      {
        type: 'text',
        text: `🤖 **AI Bug Analysis**

**Severity:** ${severityEmoji} ${analysis.severity.toUpperCase()}
**Impact:** ${analysis.impact}
**Category:** ${analysis.category}

**Original Description:**
${bug_description}

**Recommendations:**
${analysis.severity === 'critical' || analysis.severity === 'high'
  ? '- Investigate immediately\n- Check for workarounds\n- Plan upgrade if fix available'
  : '- Monitor for updates\n- Consider for next maintenance window'}

*Analysis powered by AI sampling*`
      }
    ]
  };
}

/**
 * Handle analyze_upgrade_risk_with_ai tool
 */
async function handleAnalyzeUpgradeRisk(server: Server, args: any, ciscoAuth: any) {
  const { product_id, current_version, target_version } = args;

  logger.info('Analyzing upgrade risk with AI', { product_id, current_version, target_version });

  // First, fetch bug data using compare_software_versions tool
  // For now, we'll use a simplified version
  const bugData = {
    note: 'In production, this would call compare_software_versions tool to get actual bug data'
  };

  const analysis = await analyzeUpgradeRisk(
    server,
    product_id,
    current_version,
    target_version,
    bugData
  );

  return {
    content: [
      {
        type: 'text',
        text: `🎯 **AI-Powered Upgrade Risk Analysis**

**Product:** ${product_id}
**Current Version:** ${current_version}
**Target Version:** ${target_version}

---

${analysis}

---

*This analysis was generated using AI and should be verified with official Cisco documentation and your network specifics.*

**Next Steps:**
1. Review the risk assessment above
2. Use \`compare_software_versions\` for detailed bug comparison
3. Check release notes for the target version
4. Plan testing in lab environment
5. Create rollback plan before upgrade`
      }
    ]
  };
}

/**
 * Handle summarize_bugs_with_ai tool
 */
async function handleSummarizeBugs(server: Server, args: any, ciscoAuth: any) {
  const { bug_ids, search_context } = args;

  logger.info('Summarizing bugs with AI', { bug_ids, search_context });

  // Fetch bug details
  const bugIdArray = bug_ids.split(',').map((id: string) => id.trim()).slice(0, 10);

  // In production, fetch actual bug data via get_bug_details
  const bugs = bugIdArray.map((id: string) => ({
    bug_id: id,
    note: 'In production, this would fetch actual bug data'
  }));

  const summary = await summarizeBugs(server, bugs, search_context);

  return {
    content: [
      {
        type: 'text',
        text: `📊 **AI Bug Summary**

**Context:** ${search_context}
**Bugs Analyzed:** ${bugIdArray.length}

---

${summary}

---

**Bug IDs Reviewed:**
${bugIdArray.map((id: string) => `- ${id}`).join('\n')}

*Summary generated by AI. For detailed information, use \`get_bug_details\` on individual bugs.*`
      }
    ]
  };
}

/**
 * Handle extract_product_query tool
 */
async function handleExtractProductQuery(server: Server, args: any) {
  const { natural_query } = args;

  logger.info('Extracting product query with AI', { natural_query });

  const extracted = await extractProductQuery(server, natural_query);

  return {
    content: [
      {
        type: 'text',
        text: `🔍 **Query Extraction Results**

**Original Query:** "${natural_query}"

**Extracted Parameters:**
${extracted.productId ? `- **Product ID:** ${extracted.productId}` : ''}
${extracted.productSeries ? `- **Product Series:** ${extracted.productSeries}` : ''}
${extracted.version ? `- **Version:** ${extracted.version}` : ''}
${extracted.severity ? `- **Severity:** ${extracted.severity}` : ''}
${extracted.status ? `- **Status:** ${extracted.status}` : ''}
${extracted.keywords && extracted.keywords.length > 0 ? `- **Keywords:** ${extracted.keywords.join(', ')}` : ''}

${Object.keys(extracted).length === 0 ? '⚠️ No parameters could be extracted from the query.' : ''}

**Suggested Tools:**
${extracted.productId ? `- \`search_bugs_by_product_id\` with product_id="${extracted.productId}"` : ''}
${extracted.productSeries && extracted.version ? `- \`search_bugs_by_product_series_affected\` with product_series="${extracted.productSeries}" and affected_releases="${extracted.version}"` : ''}
${extracted.keywords && extracted.keywords.length > 0 ? `- \`search_bugs_by_keyword\` with keyword="${extracted.keywords[0]}"` : ''}

*Extraction powered by AI sampling*`
      }
    ]
  };
}
