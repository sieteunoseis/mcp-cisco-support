import { Server } from "@modelcontextprotocol/server";
import {
  type Prompt,
  type PromptMessage,
  type TextContent,
  type ServerContext,
  ProtocolError,
  ProtocolErrorCode,
  inputRequired,
  acceptedContent,
} from "@modelcontextprotocol/server";
import { VersionNeeded } from "./tools/versions.js";
import dotenv from "dotenv";

// Import modular API system
import {
  createApiRegistry,
  ApiRegistry,
} from "./apis/index.js";
import { encodeResult } from "./utils/gcf.js";

// _meta key carrying client capabilities on each request (protocol 2026-07-28)
const CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities";
import { UI_EXTENSION_ID, UI_MIME_TYPE, RESULTS_APP_URI, RESULTS_APP_HTML, UI_TOOLS, UI_RESULT_NOTE } from "./ui/results-app.js";
import { setLogging, logger } from "./utils/logger.js";
import { SERVER_ICON } from "./utils/icon.js";
import { registerProgressContext } from "./utils/progress.js";
import { ciscoPrompts } from "./prompts/cisco-prompts.js";

// Load environment variables
dotenv.config();

import { VERSION } from "./utils/version.js";

// Module-level registry for the exported test helpers below
const apiRegistry: ApiRegistry = createApiRegistry();

// All prompts are always available
export function getAvailablePrompts(): Prompt[] {
  return ciscoPrompts;
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
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Unknown prompt: ${name}`);
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

const HOUR = 60 * 60_000;

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
      // 2026-07-28 cache hints. Lists only change between releases; tools/list
      // is private because the MCP Apps metadata depends on the client's UI
      // support; resource reads are live Cisco data.
      cacheHints: {
        "server/discover": { ttlMs: HOUR, cacheScope: "public" },
        "tools/list": { ttlMs: HOUR, cacheScope: "private" },
        "prompts/list": { ttlMs: HOUR, cacheScope: "public" },
        "resources/list": { ttlMs: HOUR, cacheScope: "public" },
        "resources/templates/list": { ttlMs: HOUR, cacheScope: "public" },
        "resources/read": { ttlMs: 5 * 60_000, cacheScope: "private" },
      },
    },
  );

  // Per-server API registry
  const apiRegistry = createApiRegistry(server);

  // MCP Apps: only clients that advertise the UI extension get UI links and structuredContent
  // 'yes' / 'no' when the client declared its capabilities (initialize on
  // this server instance); 'unknown' on stateless HTTP requests that arrive
  // without an initialize on the same instance.
  const uiSupport = (ctx?: ServerContext): 'yes' | 'no' | 'unknown' => {
    const envelope = (ctx?.mcpReq as any)?.envelope as Record<string, any> | undefined;
    const caps = (envelope?.[CLIENT_CAPABILITIES_META_KEY] ?? server.getClientCapabilities()) as any;
    if (!caps) return 'unknown';
    const ext = caps.extensions?.[UI_EXTENSION_ID];
    return Array.isArray(ext?.mimeTypes) && ext.mimeTypes.includes(UI_MIME_TYPE) ? 'yes' : 'no';
  };

  // Ping handler
  server.setRequestHandler("ping", async () => {
    logger.info("Ping request received");
    return {};
  });

  // List tools handler
  server.setRequestHandler("tools/list", async (_request, ctx) => {
    const tools = apiRegistry.getAvailableTools();
    // Advertise the view unless the client said it has no UI support; hosts
    // without MCP Apps ignore _meta.ui
    if (uiSupport(ctx) === 'no') return { tools };
    return {
      tools: tools.map((tool) =>
        UI_TOOLS.includes(tool.name)
          ? { ...tool, _meta: { ...tool._meta, ui: { resourceUri: RESULTS_APP_URI } } }
          : tool,
      ),
    };
  });

  // ---------------------------------------------------------------------------
  // Exact-release questions (elicitation). Tools raise VersionNeeded for a
  // partial or unknown release; ask the user when the client can show a form,
  // otherwise hand the candidates to the model.

  const clientCapabilities = (ctx: ServerContext): any => {
    const envelope = (ctx.mcpReq as any)?.envelope as Record<string, any> | undefined;
    return envelope?.[CLIENT_CAPABILITIES_META_KEY] ?? server.getClientCapabilities();
  };
  const isModernRequest = (ctx: ServerContext) =>
    !!((ctx.mcpReq as any)?.envelope?.[CLIENT_CAPABILITIES_META_KEY]);
  const canElicitForm = (ctx: ServerContext) => {
    const e = clientCapabilities(ctx)?.elicitation;
    // A bare `elicitation: {}` means form mode (pre-2025-11 clients)
    return !!e && (e.form !== undefined || Object.keys(e).length === 0 || e.url === undefined);
  };

  const releaseForm = (e: VersionNeeded) => {
    const what = e.osType ? `${e.osType.toUpperCase()} ` : "";
    const message = e.level === "train"
      ? `"${e.given}" covers several ${what}trains. Which one?`
      : e.options.length
        ? `Which ${what}release did you mean by "${e.given}"?`
        : `"${e.given}" isn't an exact ${what}release. Which release (for example 17.9.4)?`;
    const fullMessage = e.allowAsIs && e.level === "release"
      ? `"${e.given}" is a whole ${what}train. Pick an exact release for more precise results, or keep ${e.given}.`
      : message;
    const field: Record<string, unknown> = { type: "string", title: e.level === "train" ? "Train" : "Release" };
    if (e.options.length) {
      // A train can be kept as is (Bug API): offer it first
      field.enum = e.allowAsIs ? [e.given, ...e.options.filter(o => o !== e.given)] : e.options;
      if (e.allowAsIs) field.description = `Choose ${e.given} to search the whole train`;
    } else field.description = "Exact release, e.g. 17.9.4";
    return { mode: "form" as const, message: fullMessage, requestedSchema: { type: "object" as const, properties: { value: field as any }, required: ["value"] } };
  };

  const MAX_QUESTIONS = 3;
  const runResolvingVersions = async (
    name: string, args: Record<string, any>, meta: { progressToken?: string; signal?: AbortSignal }, ctx: ServerContext,
  ): Promise<
    | { kind: 'done'; result: any; apiName: string }
    | { kind: 'input_required'; result: any }
    | { kind: 'needs_version'; result: Record<string, unknown> }
  > => {
    const mcpReq = ctx.mcpReq as any;
    // Answers from earlier rounds (2026-07-28 multi-round-trip) travel in requestState
    let state: { resolved: Record<string, string>; keep: string[] } = { resolved: {}, keep: [] };
    try {
      // SDK v2 exposes it as an accessor function (ctx.mcpReq.requestState())
      const raw = typeof mcpReq.requestState === "function" ? mcpReq.requestState() : mcpReq.requestState;
      if (typeof raw === "string") state = { resolved: {}, keep: [], ...JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) };
    } catch { /* ignore tampered state: it only carries the user's own choices */ }
    let resolved = state.resolved;
    const keep = new Set(state.keep);
    let fallbackHint: Record<string, unknown> | undefined;

    // Apply a chosen release: replace one item of a comma list, or the whole value
    const choose = (e: VersionNeeded, value: string, current: Record<string, any>) => {
      if (value === e.given) { keep.add(`${e.argument}:${e.given}`); return; }
      const next = e.listItem
        ? String(current[e.argument]).split(",").map(x => (x.trim() === e.given ? value : x.trim())).join(",")
        : value;
      resolved = { ...resolved, [e.argument]: next };
    };

    for (let round = 0; round <= MAX_QUESTIONS; round++) {
      const effective = { ...args, ...resolved };
      try {
        const { result, apiName } = await apiRegistry.executeTool(name, effective, { ...meta, acceptPartial: keep });
        return { kind: 'done', result: fallbackHint ? { ...result, release_hint: fallbackHint } : result, apiName };
      } catch (error) {
        if (!(error instanceof VersionNeeded) || round === MAX_QUESTIONS) throw error;
        const key = `release:${error.argument}:${error.given}`;

        // Answered in this round's input responses (2026-07-28)?
        const answered = acceptedContent<{ value?: string }>(mcpReq.inputResponses, key)?.value;
        if (answered) { choose(error, String(answered), effective); continue; }

        if (!canElicitForm(ctx) && error.allowAsIs) {
          // The partial value works as is: run it, and tell the model it can narrow it
          keep.add(`${error.argument}:${error.given}`);
          fallbackHint = {
            searched: error.given,
            note: `Results cover the whole ${error.given} train.`,
            exact_releases: error.options,
            hint: `For more precise results, ask the user which exact release they run and call ${name} again with it.`,
          };
          continue;
        }

        if (!canElicitForm(ctx)) {
          return { kind: 'needs_version', result: {
            status: "needs_exact_release",
            argument: error.argument,
            given: error.given,
            [error.level === "train" ? "trains" : "candidates"]: error.options,
            hint: error.options.length
              ? `Ask the user which ${error.level === "train" ? "train, then which release," : "exact release"} they mean, then call ${name} again with ${error.argument} set to it.`
              : `Ask the user for the exact release (for example 17.9.4), then call ${name} again with ${error.argument} set to it.`,
          } };
        }

        const form = releaseForm(error);
        if (isModernRequest(ctx)) {
          const requestState = Buffer.from(JSON.stringify({ resolved, keep: [...keep] }), "utf8").toString("base64url");
          return { kind: 'input_required', result: inputRequired({
            inputRequests: { [key]: inputRequired.elicit(form) },
            requestState,
          }) };
        }
        // 2025-era connection: push an elicitation request and wait
        const reply = await ctx.mcpReq.elicitInput(form);
        const value = reply.action === "accept" ? (reply.content as any)?.value : undefined;
        if (!value && error.allowAsIs) { keep.add(`${error.argument}:${error.given}`); continue; }
        if (!value) {
          return { kind: 'needs_version', result: {
            status: "release_not_chosen",
            argument: error.argument,
            given: error.given,
            hint: `The user didn't choose a release. Ask them which exact release they mean before calling ${name} again.`,
          } };
        }
        choose(error, String(value), effective);
      }
    }
    throw new Error("unreachable");
  };

  // Call tool handler
  server.setRequestHandler("tools/call", async (request, ctx) => {
    const { name, arguments: args } = request.params;
    const clientProgressToken = request.params._meta?.progressToken;

    // Progress notifications are routed back to the session that made this call
    const progress = registerProgressContext(clientProgressToken, (n) => ctx.mcpReq.notify(n as any));
    const meta = { progressToken: progress.token, signal: ctx.mcpReq.signal };

    try {
      logger.info("Tool call started", {
        name,
        args: redactArgs(args),
        hasProgressToken: clientProgressToken !== undefined,
      });

      const outcome = await runResolvingVersions(name, { ...(args || {}) }, meta, ctx);
      if (outcome.kind === 'input_required') return outcome.result;
      if (outcome.kind === 'needs_version') {
        return { content: [{ type: "text" as const, text: encodeResult(outcome.result) }], isError: false };
      }
      const { result, apiName } = outcome;

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

      // When the client renders the MCP Apps view, the user already sees the
      // rows as a table. Tell the model, so it adds analysis instead of
      // rebuilding the same table in its reply.
      const ui = UI_TOOLS.includes(name) ? uiSupport(ctx) : 'no';
      const content: TextContent = {
        type: "text",
        // Only claim the user sees a table when the client said it renders views
        text: (ui === 'yes' ? `${UI_RESULT_NOTE}\n\n` : "") + encodeResult(result),
      };

      return {
        content: [content],
        // The view renders structuredContent; skipped for clients that declared no UI support
        ...(ui !== 'no' ? { structuredContent: result } : {}),
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
  server.setRequestHandler("prompts/list", async () => {
    logger.info("List prompts request received");
    return {
      prompts: getAvailablePrompts(),
    };
  });

  // Get prompt handler
  server.setRequestHandler("prompts/get", async (request) => {
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
      uri: "cisco://security/advisories/recent",
      name: "Recent Security Advisories",
      description: "The 20 most recent Cisco PSIRT security advisories",
      tool: "psirt_search",
      args: { latest: 20, page_size: 20 },
    },
    {
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
      uriTemplate: "cisco://bugs/{bug_id}",
      prefix: "cisco://bugs/",
      name: "Cisco Bug",
      description: "A Cisco bug by ID, e.g. cisco://bugs/CSCwh87343",
      tool: "bug_get",
      argsFor: (id: string) => ({ bug_ids: id }),
    },
    {
      uriTemplate: "cisco://products/{product_id}",
      prefix: "cisco://products/",
      name: "Cisco Product",
      description: "Product details by product ID, e.g. cisco://products/C9300-48P",
      tool: "product_get",
      argsFor: (id: string) => ({ product_ids: id }),
    },
    {
      uriTemplate: "cisco://security/advisories/{advisory_id}",
      prefix: "cisco://security/advisories/",
      name: "Cisco Security Advisory",
      description: "A security advisory by ID, e.g. cisco://security/advisories/cisco-sa-iosxe-webui-privesc-j22SaA4z",
      tool: "psirt_get",
      argsFor: (id: string) => ({ advisory_id: id }),
    },
    {
      uriTemplate: "cisco://security/cve/{cve_id}",
      prefix: "cisco://security/cve/",
      name: "Cisco Security Advisory by CVE",
      description: "Security advisories for a CVE, e.g. cisco://security/cve/CVE-2023-20198",
      tool: "psirt_get",
      argsFor: (id: string) => ({ cve: id }),
    },
  ];


  server.setRequestHandler("resources/list", async () => ({
    resources: staticResources
      .map(({ uri, name, description }) => ({ uri, name, description, mimeType: "application/json" })),
  }));

  server.setRequestHandler("resources/templates/list", async () => ({
    resourceTemplates: templateResources
      .map(({ uriTemplate, name, description }) => ({ uriTemplate, name, description, mimeType: "application/json" })),
  }));

  server.setRequestHandler("resources/read", async (request) => {
    const { uri } = request.params;
    logger.info("Read resource request", { uri });

    if (uri === RESULTS_APP_URI) {
      return {
        contents: [{ uri, mimeType: UI_MIME_TYPE, text: RESULTS_APP_HTML, _meta: { ui: { prefersBorder: true } } }],
      };
    }

    let tool: string | undefined;
    let args: Record<string, any> = {};

    const fixed = staticResources.find(r => r.uri === uri);
    if (fixed) {
      tool = fixed.tool;
      args = fixed.args;
    } else {
      // Longest prefix first so cisco://security/advisories/{id} doesn't swallow the static URIs
      const template = templateResources
        .filter(t => uri.startsWith(t.prefix))
        .sort((a, b) => b.prefix.length - a.prefix.length)[0];
      const id = template ? decodeURIComponent(uri.slice(template.prefix.length)) : "";
      if (template && id && !id.includes("/")) {
        tool = template.tool;
        args = template.argsFor(id);
      }
    }

    if (!tool) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Unknown resource URI: ${uri}`);
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
export { setLogging, logger, apiRegistry };

// Export functions for backward compatibility with tests
export function getAvailableTools() {
  return apiRegistry.getAvailableTools();
}

export async function executeTool(name: string, args: Record<string, any>) {
  const { result } = await apiRegistry.executeTool(name, args);
  return result;
}
