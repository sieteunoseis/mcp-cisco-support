import { Server } from "@modelcontextprotocol/sdk/server/index.js";
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
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import dotenv from "dotenv";
import { readFileSync } from "fs";
import { join } from "path";

// Import modular API system
import {
  createApiRegistry,
  ApiRegistry,
  SupportedAPI,
  getEnabledAPIs,
} from "./apis/index.js";
import { encodeResult } from "./utils/gcf.js";
import { UI_EXTENSION_ID, UI_MIME_TYPE, RESULTS_APP_URI, RESULTS_APP_HTML, UI_TOOLS } from "./ui/results-app.js";
import { setLogging, logger } from "./utils/logger.js";
import { SERVER_ICON } from "./utils/icon.js";
import { registerProgressContext } from "./utils/progress.js";
import { getFilteredPrompts } from "./prompts/cisco-prompts.js";

// Load environment variables
dotenv.config();

// Get version from package.json (handle different working directories)
function findPackageJson(): string {
  const possiblePaths = [
    join(__dirname, "../../package.json"), // When compiled to dist/src/
    join(__dirname, "../package.json"), // When running from src/
    join(process.cwd(), "package.json"), // When running from project root
  ];

  for (const path of possiblePaths) {
    try {
      return readFileSync(path, "utf8");
    } catch (error) {
      // Continue to next path
    }
  }

  // Fallback version
  return JSON.stringify({ version: "1.5.0" });
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

// Get available prompts (filtered by enabled APIs)
export function getAvailablePrompts(): Prompt[] {
  return getFilteredPrompts(ENABLED_APIS);
}

// Generate prompt content based on prompt name and arguments.
// Each workflow names the v3 tools so the model calls them directly.
export function generatePrompt(
  name: string,
  args: Record<string, any>,
): PromptMessage[] {
  const user = (text: string): PromptMessage[] => [
    { role: "user", content: { type: "text", text } },
  ];
  const line = (label: string, value: unknown) =>
    value ? `- ${label}: ${value}\n` : "";
  // When the user gives a serial number, resolve it to a product first
  const identify = (serial?: string, product?: string) =>
    serial
      ? `1. Call \`device_lookup\` with serial_numbers "${serial}" to get the product ID, coverage and end-of-life status.\n`
      : product
        ? `1. If "${product}" is not an exact product ID, call \`product_get\` to confirm the product ID and series.\n`
        : "";

  switch (name) {
    case "cisco-incident-investigation":
      return user(`Help investigate a Cisco incident.

${line("Symptom", args.symptom)}${line("Product", args.product)}${line("Serial number", args.serial_number)}${line("Severity", args.severity)}${line("Software version", args.software_version)}
${identify(args.serial_number, args.product)}2. Call \`bug_search\` with keyword terms from the symptom (max 50 characters), severity ["1","2","3"]; if the product and version are known, also search with product_id and releases "${args.software_version ?? "<version>"}".
3. Call \`bug_get\` with response_format "detailed" for the most likely matches to read symptoms, conditions and workarounds.
4. If the symptom could be security related, call \`psirt_search\` with os_type and version.

Report the likely matching bugs, workarounds, and the first release that fixes each.`);

    case "cisco-upgrade-planning":
      return user(`Plan a Cisco software upgrade from ${args.current_version} to ${args.target_version}.

${line("Product", args.product)}${line("Serial number", args.serial_number)}${line("Environment", args.environment)}
${identify(args.serial_number, args.product)}2. Call \`assess_upgrade\` with product_id, current_version "${args.current_version}", target_version "${args.target_version}" and os_type (e.g. iosxe, ios, nxos, asa). It returns open bugs on both releases, bugs the target fixes, security advisories fixed/remaining/new, and end-of-life dates.
3. Call \`software_get\` to check whether the target is Cisco's suggested release; if not, mention the suggested one.
4. Call \`bug_get\` with response_format "detailed" for any severity 1-2 bug that still affects the target.

Give a go/no-go recommendation with the main risks and pre-checks.`);

    case "cisco-security-advisory":
      return user(`Review Cisco security advisories.

${line("Product", args.product)}${line("Serial number", args.serial_number)}${line("Software version", args.software_version)}${line("Focus", args.security_focus)}
${identify(args.serial_number, args.product)}2. ${args.software_version ? `Call \`psirt_search\` with os_type (e.g. iosxe) and version "${args.software_version}" to list advisories affecting that release, with first fixed releases.` : "Call `psirt_search` with product (name) to list advisories for the product."}
3. Call \`psirt_get\` with response_format "detailed" for critical and high advisories.
4. Call \`software_get\` for Cisco's suggested release, and check it is not affected.

Summarize by Security Impact Rating (sir), with the fix release for each.`);

    case "cisco-known-issues": {
      const max = Math.min(6, Math.max(1, parseInt(args.max_severity, 10) || 3));
      const severities = Array.from({ length: max }, (_, n) => `"${n + 1}"`).join(",");
      const subject = args.product || args.serial_number || "the product";
      return user(`List known open issues for ${subject}${args.software_version ? ` on ${args.software_version}` : ""} (severity 1-${max}).

${line("Product", args.product)}${line("Serial number", args.serial_number)}${line("Issue type", args.issue_type)}
${identify(args.serial_number, args.product)}2. Call \`bug_search\` once with severity [${severities}], status "O" and ${args.software_version ? `product_id (or product_series) with releases "${args.software_version}"` : `keyword "${args.product ?? ""}"`}${args.issue_type ? `; add a second keyword search for "${args.issue_type}"` : ""}. One call covers all severities; check \`total_by_severity\` and \`paging.next_page\`.
3. ${args.software_version ? `Call \`psirt_search\` with os_type and version "${args.software_version}" for security advisories affecting the release.` : "If a release is known, call `psirt_search` with os_type and version."}
4. If nothing matches, follow the \`hint\` in the result (base product ID without the license suffix, or the full product series name).

Summarize the issues by severity with workarounds and the releases that fix them.`);
    }

    case "cisco-case-investigation":
      return user(`Investigate Cisco TAC cases.

${line("Case ID", args.case_id)}${line("Contract ID", args.contract_id)}${line("User ID", args.user_id)}${line("Status", args.status)}
1. ${args.case_id ? `Call \`case_get\` with case_ids "${args.case_id}" and response_format "detailed" for notes, owner and linked RMAs/bugs.` : `Call \`case_search\` with ${args.contract_id ? `contract_ids "${args.contract_id}"` : `user_ids "${args.user_id ?? ""}"`}${args.status ? ` and status_flag "${args.status === "open" ? "O" : args.status === "closed" ? "C" : args.status}"` : ""}.`}
2. For linked bugs call \`bug_get\`; for linked RMAs call \`rma_get\`.

Summarize status, history and next steps.`);

    case "cisco-lifecycle-planning":
      return user(`Plan Cisco hardware lifecycle and refresh.

${line("Product IDs", args.product_ids)}${line("Serial numbers", args.serial_numbers)}${line("Software releases", args.software_releases)}${line("Date range", args.date_range_start && `${args.date_range_start} to ${args.date_range_end ?? ""}`)}
1. ${args.serial_numbers ? `Call \`device_lookup\` with serial_numbers "${args.serial_numbers}" for coverage, warranty and end-of-life per device.` : args.product_ids ? `Call \`eox_get\` with product_ids "${args.product_ids}".` : args.software_releases ? `Call \`eox_get\` with software_releases "${args.software_releases}".` : `Call \`eox_get\` with start_date "${args.date_range_start ?? ""}" and end_date "${args.date_range_end ?? ""}".`}
2. For products with an EoX announcement, note the migration product ID and call \`product_get\` on it.

Produce a timeline of end-of-sale, end-of-security-support and last-date-of-support, and flag devices without contract coverage.`);

    default:
      throw new McpError(ErrorCode.InvalidParams, `Unknown prompt: ${name}`);
  }
}



// Re-export progress utilities for backward compatibility
export { sendProgress, createProgressTracker } from "./utils/progress.js";

// Create MCP server
// Argument names whose values must never reach the logs
const SENSITIVE_ARG_PATTERN = /token|secret|password|credential|auth|content|file_data|base64/i;

function redactArgs(args: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!args) return args;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (SENSITIVE_ARG_PATTERN.test(key)) {
      out[key] = '[redacted]';
    } else if (typeof value === 'string' && value.length > 200) {
      out[key] = `${value.slice(0, 200)}… [${value.length} chars]`;
    } else {
      out[key] = value;
    }
  }
  return out;
}

export function createMCPServer(): Server {
  const server = new Server(
    {
      name: "mcp-cisco-support",
      version: VERSION,
      icons: [{ src: SERVER_ICON, mimeType: "image/svg+xml" }],
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {},
      },
    },
  );

  // Per-server API registry (sampling requests go back through this server)
  ENABLED_APIS = getEnabledAPIs(); // Refresh enabled APIs list
  const apiRegistry = createApiRegistry(server);

  // MCP Apps: only clients that advertise the UI extension get UI links and structuredContent
  const clientSupportsUi = (): boolean => {
    const ext = (server.getClientCapabilities() as any)?.extensions?.[UI_EXTENSION_ID];
    return Array.isArray(ext?.mimeTypes) && ext.mimeTypes.includes(UI_MIME_TYPE);
  };

  // Ping handler
  server.setRequestHandler(PingRequestSchema, async () => {
    logger.info("Ping request received");
    return {};
  });

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = apiRegistry.getAvailableTools();
    if (!clientSupportsUi()) return { tools };
    return {
      tools: tools.map((tool) =>
        UI_TOOLS.includes(tool.name)
          ? { ...tool, _meta: { ...tool._meta, ui: { resourceUri: RESULTS_APP_URI } } }
          : tool,
      ),
    };
  });

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args } = request.params;
    const clientProgressToken = request.params._meta?.progressToken;

    // Progress notifications are routed back to the session that made this call
    const progress = registerProgressContext(clientProgressToken, extra.sendNotification);
    const meta = { progressToken: progress.token, signal: extra.signal };

    try {
      logger.info("Tool call started", {
        name,
        args: redactArgs(args),
        hasProgressToken: clientProgressToken !== undefined,
      });

      const { result, apiName } = await apiRegistry.executeTool(
        name,
        args || {},
        meta,
      );

      logger.info("Tool call completed", {
        name,
        apiName,
        resultCount:
          "bugs" in result && Array.isArray(result.bugs)
            ? result.bugs.length
            : "cases" in result && Array.isArray(result.cases)
              ? result.cases.length
              : "EOXRecord" in result && Array.isArray(result.EOXRecord)
                ? result.EOXRecord.length
                : 0,
      });

      const content: TextContent = {
        type: "text",
        text: encodeResult(result),
      };

      return {
        content: [content],
        // The results view renders structuredContent; plain clients only get the text
        ...(clientSupportsUi() && UI_TOOLS.includes(name) ? { structuredContent: result } : {}),
        isError: false,
      };
    } catch (error) {
      logger.error("Tool call failed", {
        name,
        error: error instanceof Error ? error.message : error,
      });

      // Provide helpful error messages for common issues
      let errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      if (errorMessage.includes("Unknown tool")) {
        errorMessage +=
          "\n\nℹ️ Available tools: " +
          apiRegistry
            .getAvailableTools()
            .map((t) => t.name)
            .join(", ");

        errorMessage += `\n\nℹ️ Enabled APIs: ${ENABLED_APIS.join(", ")}`;
      }

      if (errorMessage.includes("Tool implementation not found")) {
        errorMessage +=
          "\n\nℹ️ This tool may require an API that is not yet implemented or enabled.";
        errorMessage += `\nCurrently enabled APIs: ${ENABLED_APIS.join(", ")}`;
        errorMessage += `\nTo enable more APIs, set SUPPORT_API environment variable (e.g., SUPPORT_API=bug,case)`;
      }

      const errorContent: TextContent = {
        type: "text",
        text: `Error: ${errorMessage}`,
      };

      return {
        content: [errorContent],
        isError: true,
      };
    } finally {
      progress.release();
    }
  });

  // List prompts handler
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    logger.info("List prompts request received");
    return {
      prompts: getAvailablePrompts(),
    };
  });

  // Get prompt handler
  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      logger.info("Get prompt request", { name, args });

      const messages = generatePrompt(name, args || {});

      logger.info("Prompt generated", { name, messageCount: messages.length });

      return {
        messages,
      };
    } catch (error) {
      logger.error("Prompt generation failed", {
        name,
        error: error instanceof Error ? error.message : error,
      });

      throw error;
    }
  });

  // ---------------------------------------------------------------------------
  // Resources: thin views over the v3 tools (same concise output)

  // Static resources
  const staticResources = [
    {
      api: "psirt" as SupportedAPI,
      uri: "cisco://security/advisories/recent",
      name: "Recent Security Advisories",
      description: "The 20 most recent Cisco PSIRT security advisories",
      tool: "psirt_search",
      args: { latest: 20, page_size: 20 },
    },
    {
      api: "psirt" as SupportedAPI,
      uri: "cisco://security/advisories/critical",
      name: "Critical Security Advisories",
      description: "Most recent critical-severity Cisco security advisories",
      tool: "psirt_search",
      args: { severity: "critical", page_size: 20 },
    },
  ];

  // Templated resources: cisco://<prefix>{id}
  const templateResources = [
    {
      api: "bug" as SupportedAPI,
      uriTemplate: "cisco://bugs/{bug_id}",
      prefix: "cisco://bugs/",
      name: "Cisco Bug",
      description: "A Cisco bug by ID, e.g. cisco://bugs/CSCwh87343",
      tool: "bug_get",
      argsFor: (id: string) => ({ bug_ids: id }),
    },
    {
      api: "product" as SupportedAPI,
      uriTemplate: "cisco://products/{product_id}",
      prefix: "cisco://products/",
      name: "Cisco Product",
      description: "Product details by product ID, e.g. cisco://products/C9300-48P",
      tool: "product_get",
      argsFor: (id: string) => ({ product_ids: id }),
    },
    {
      api: "psirt" as SupportedAPI,
      uriTemplate: "cisco://security/advisories/{advisory_id}",
      prefix: "cisco://security/advisories/",
      name: "Cisco Security Advisory",
      description: "A security advisory by ID, e.g. cisco://security/advisories/cisco-sa-iosxe-webui-privesc-j22SaA4z",
      tool: "psirt_get",
      argsFor: (id: string) => ({ advisory_id: id }),
    },
    {
      api: "psirt" as SupportedAPI,
      uriTemplate: "cisco://security/cve/{cve_id}",
      prefix: "cisco://security/cve/",
      name: "Cisco Security Advisory by CVE",
      description: "Security advisories for a CVE, e.g. cisco://security/cve/CVE-2023-20198",
      tool: "psirt_get",
      argsFor: (id: string) => ({ cve: id }),
    },
  ];

  const enabled = (api: SupportedAPI) => ENABLED_APIS.includes(api);

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: staticResources
      .filter(r => enabled(r.api))
      .map(({ uri, name, description }) => ({ uri, name, description, mimeType: "application/json" })),
  }));

  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
    resourceTemplates: templateResources
      .filter(t => enabled(t.api))
      .map(({ uriTemplate, name, description }) => ({ uriTemplate, name, description, mimeType: "application/json" })),
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    logger.info("Read resource request", { uri });

    if (uri === RESULTS_APP_URI) {
      return {
        contents: [{ uri, mimeType: UI_MIME_TYPE, text: RESULTS_APP_HTML, _meta: { ui: { prefersBorder: true } } }],
      };
    }

    let tool: string | undefined;
    let args: Record<string, any> = {};

    const fixed = staticResources.find(r => r.uri === uri && enabled(r.api));
    if (fixed) {
      tool = fixed.tool;
      args = fixed.args;
    } else {
      // Longest prefix first so cisco://security/advisories/{id} doesn't swallow the static URIs
      const template = templateResources
        .filter(t => enabled(t.api) && uri.startsWith(t.prefix))
        .sort((a, b) => b.prefix.length - a.prefix.length)[0];
      const id = template ? decodeURIComponent(uri.slice(template.prefix.length)) : "";
      if (template && id && !id.includes("/")) {
        tool = template.tool;
        args = template.argsFor(id);
      }
    }

    if (!tool) {
      throw new McpError(ErrorCode.InvalidParams, `Unknown resource URI: ${uri}`);
    }

    const { result } = await apiRegistry.executeTool(tool, args);
    return {
      contents: [{ uri, mimeType: "application/json", text: JSON.stringify(result, null, 2) }],
    };
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
