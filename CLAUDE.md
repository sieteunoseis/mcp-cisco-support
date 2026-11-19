# Cisco Support MCP Server: developer guide

TypeScript MCP server for the Cisco Support APIs (Bug, PSIRT, EoX, Product, Serial/coverage, Software Suggestion, Case, RMA). stdio by default; `--http` serves stateless Streamable HTTP at `/mcp` with bearer-token auth.

## Layout

```
src/
  index.ts            entry point: stdio or --http
  mcp-server.ts       createMCPServer(): tools, prompts, cisco:// resources
  http-server.ts      stateless Streamable HTTP (new MCP server per POST), bearer auth, origin checks
  tools/index.ts      the 12 v3 tools: schemas + handlers (TOOL_SPECS, RENAMED_TOOLS)
  tools/shape.ts      concise/detailed shaping and pagination normalization
  apis/*.ts           one client per Cisco API (base URL, auth, request()); index.ts = registry
  utils/auth.ts       Cisco OAuth client-credentials token (cached, shared in-flight refresh)
  utils/progress.ts   per-call progress notifications
tests/
  tools.test.ts       v3 tools against recorded responses
  fixtures/cisco/     responses recorded from apix.cisco.com (lists trimmed, customer data scrubbed)
api_docs/             downloaded Cisco WADL/OpenAPI files: hints only, not verified
```

The 2.x per-endpoint tool definitions still live in `src/apis/*-api.ts` (`getTools`/`executeTool`). They are not advertised; only the `cisco://` resources call them through `ApiRegistry.executeLegacyTool`.

## Tools (v3)

| Tool | Cisco API |
|------|--------------------------|
| bug_get, bug_search, assess_upgrade | bug |
| psirt_get, psirt_search | psirt |
| eox_get | eox |
| device_lookup | serial, product, eox |
| product_get | product |
| software_get | software |
| case_get, case_search | case |
| rma_get | rma |

All 12 tools are always listed (no `SUPPORT_API` filter since 3.0.0); a non-rate-limit 403 is reported as a missing API entitlement. All tools are read-only (`readOnlyHint`, `openWorldHint`), return concise output unless `response_format: "detailed"`, and list tools return `paging: { page, total_records, last_page, next_page }`. Calling a 2.x tool name returns an error naming its replacement.

## Cisco API behaviour (verified live 2026-11-18)

Do not trust `api_docs/` or the developer.cisco.com docs alone. Verify endpoint changes with a live read-only call (see "Recording fixtures").

- **Gateway rejects `%2F`.** Product IDs like `ISR4431/K9` must keep a literal `/` (`BaseApi.encodePathValue`), and `.`/`..` segments are refused.
- **Rate limit = 403 "Developer Over Qps"**, not 429. `BaseApi.makeApiCall` retries with 1s/2s/4s backoff.
- **Bug API:** product name search is `/bugs/product_name/{name}/affected_releases|fixed_in_releases/{rels}` (not `/bugs/products/product_name`). Totals are in `pagination_response_record.total_records`. Unknown bug IDs come back as placeholder records with severity `"0"`. One severity per call.
- **PSIRT (openVuln):** "no results" is `404 {"errorCode":"NO_DATA_FOUND"}` and should be treated as zero advisories. Severity is `sir`. Paging uses `pageIndex`/`pageSize` and returns `paging.count`. `/OSType/{os}?version=` and `/latest/{n}` are not paged; `/severity` and `/year` are about 1.8 MB unpaged.
- **Four pagination envelopes:** `pagination_response_record` (Bug, Product, Case, Serial), `PaginationResponseRecord` (EoX), `paginationResponseRecord` (Software, string values), `APIPagination` (RMA). Use `pagingFrom()` in `tools/shape.ts`.
- **EoX:** products without an announcement return a record with empty fields plus `EOXError`. Date and software-release lookups can return 100+ records in one page, so they are paged locally.
- **RMA:** `/returns/rma_numbers/{n}` returns `returns.RmaRecord[]`; user search is `/returns/users/user_ids/{id}` with camelCase `pageIndex`/`fromDate`/`toDate`.
- **Case:** `page_index` starts at 1. `/cases/details/case_id/{id}` is the only endpoint with notes and owner.

## Commands

```bash
npm ci
npx tsc --noEmit          # type check
npm test                  # unit tests (mocked fetch, recorded fixtures)
npm run build             # dist/index.js (tsconfig.build.json, src only)
npm run dev               # tsx watch, stdio
npm run dev:http          # tsx watch, HTTP on 127.0.0.1:3000
```

Integration tests are opt-in: `RUN_INTEGRATION=1 CISCO_CLIENT_ID=... CISCO_CLIENT_SECRET=... npm test`.

## Recording fixtures

When adding or changing an endpoint, record a real response into `tests/fixtures/cisco/<name>.json` (`{ _source, status, body }`):
- Use public identifiers where possible (bug IDs, CVEs, product IDs).
- Case, RMA, serial/coverage and EoX-by-serial responses contain customer data. Replace names, contacts, addresses, notes, contract/case/RMA/serial numbers with placeholders before committing, and grep the fixtures for the real values.
- Trim long lists to about 3 items.

## HTTP mode

- Stateless: every `POST /mcp` gets a fresh MCP server and transport, no `Mcp-Session-Id`, nothing kept between requests (any instance can serve any request). `GET`/`DELETE /mcp` return 405. Progress notifications go out on the response stream of the call.
- `/.well-known/*` returns 404 (no OAuth) so clients don't mistake the bearer-token 401 for broken OAuth.
- Bearer token only in the `Authorization` header (`MCP_BEARER_TOKEN`, or a generated token printed once at startup).
- Binds `HOST` (default `127.0.0.1`; the Docker image sets `0.0.0.0`).
- Browser origins other than localhost need `MCP_ALLOWED_ORIGINS`.
- `DANGEROUSLY_OMIT_AUTH=true` disables auth (local testing only).
- The built-in OAuth 2.1 server was removed in 2.0.0. External IdP token validation (Authelia/Kong) is tracked in issue #14.

## Release

1. Bump `version` in `package.json` (the server reads its version from there) and add a CHANGELOG entry.
2. CI (`.github/workflows/ci.yml`) must pass. The Docker image (`:latest`, `:v<version>`) is built only after CI passes on `main`.
3. npm publish runs on a GitHub Release whose tag equals `v<package.json version>`.

Wiki: https://github.com/sieteunoseis/mcp-cisco-support/wiki
