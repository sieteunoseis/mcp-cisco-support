---
name: cisco-support-mcp
description: Use when answering Cisco support questions through the cisco-support MCP server (mcp-cisco-support) — whether a software release is vulnerable, upgrade go/no-go, known bugs for a product or release, end-of-life dates, contract and warranty coverage by serial number, Cisco suggested releases, TAC cases and RMAs. Covers its 12 tools (bug_get, bug_search, assess_upgrade, psirt_get, psirt_search, eox_get, device_lookup, product_get, software_get, case_get, case_search, rma_get), exact-release questions, and its status results.
license: MIT
metadata:
  author: sieteunoseis
  version: "3.3.0"
---

# Cisco Support MCP server

The `cisco-support` MCP server ([mcp-cisco-support](https://github.com/sieteunoseis/mcp-cisco-support)) answers questions from the Cisco Support APIs. Every tool is read-only. Results are concise unless `response_format: "detailed"`; list results carry `paging` (`total_records`, `next_page`).

## Question → tool

| Question | Call |
|----------|------|
| Is release X vulnerable? | `psirt_search { os_type, version }`; add `severity: "critical"` to keep only critical |
| Should we upgrade from X (to Y)? | `assess_upgrade { product_id, current_version, os_type[, target_version] }`. Without a target it uses Cisco's suggested release |
| Known bugs on a product/release | `bug_search { product_id, releases, severity: ["1","2","3"], status: "O" }`: one call covers all severities |
| Bugs matching a symptom | `bug_search { keyword }` (max 50 chars), then `bug_get { bug_ids, response_format: "detailed" }` for workarounds |
| Advisory or CVE details | `psirt_get { cve }` / `{ advisory_id }` / `{ bug_id }` |
| Coverage, warranty, EoL for serials | `device_lookup { serial_numbers }`: contract, product and EoX in one call (max 20) |
| EoL by product or release | `eox_get { product_ids }` or `{ software_releases: "15.4(3)M,IOS" }` |
| Recommended release | `software_get { product_ids }` (`view: "compatible"` + `current_release` for upgrade paths) |
| TAC case / RMA | `case_get { case_ids }` (`detailed` adds notes), `case_search { contract_ids }`, `rma_get { rma_number }` |

For a fleet on several releases, make one `psirt_search` or `assess_upgrade` call per release and compare them.

## Cisco input formats

- **Product IDs:** base PID for bugs (`ISR4431`, `C9300-48P`); `ISR4431/K9` also works.
- **Releases:** Cisco's own strings (`17.9.4a`, `17.15.4b`, `12.5(1)SU3`). Leading zeros are removed (`17.09.04` → `17.9.4`).
- **Trains:** `bug_search` accepts a train (`releases: "17.9"`) and searches the whole train. Pass `os_type` and the server offers the exact releases. `psirt_search` and `assess_upgrade` need an exact release.
- **`os_type` values:** `ios`, `iosxe`, `nxos`, `asa`, `ftd`, `fxos`, `fmc`, `aci`.
- **`bug_search` modes:** exactly one of `keyword`, `product_id`, `product_series`, `product_name`. Series and name searches need `releases`.

## Results that need a response

| Result | What to do |
|--------|------------|
| `status: "needs_exact_release"` with `candidates` (or `trains`) | Ask the user which one they run, offering those values, then call again with that release. Never pick one yourself |
| `status: "release_not_chosen"` | The user dismissed the question; ask in chat before retrying |
| `release_hint` on bug results | The search covered the whole train; offer to narrow it to an exact release from `exact_releases` |
| `hint` on an empty result | Follow it (base PID, full series name, broader keyword) |
| `access denied (403) … not entitled to the X API` | The Cisco API Console app lacks that API; tell the user, and don't retry |
| HTTP 429 / `Rate limit exceeded` | Wait for `Retry-After` |
| Text starting `[Shown to the user as an interactive table…]` | The user already sees the rows. Reply with findings, risks and recommendations, not the table |

Some clients show a form for exact-release questions themselves (elicitation). The tool then returns normal results after the user picks.

## Prompts

`cisco-upgrade-planning`, `cisco-known-issues`, `cisco-incident-investigation`, `cisco-security-advisory`, `cisco-lifecycle-planning`, `cisco-case-investigation`. Each one lays out the tool sequence for its task.

## Common mistakes

- Calling `bug_search` once per severity: pass `severity: ["1","2","3"]` in one call.
- Guessing a release from a train or major version: ask the user, or use the candidates the server returns.
- Using 2.x tool names (`search_bugs_by_keyword`, `get_bug_details`, …): the server names the replacement in its error.
- Treating `eox_announced: false` as an error: it means no end-of-life has been announced yet.
