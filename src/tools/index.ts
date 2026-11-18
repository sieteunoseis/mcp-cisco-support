/**
 * v3 tool surface: 12 resource-oriented tools over the Cisco Support APIs.
 *
 * Endpoints and response fields were verified against apix.cisco.com
 * (see tests/fixtures/cisco). Every list tool returns normalized `paging`
 * and a concise view unless response_format = "detailed".
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BaseApi } from '../apis/base-api.js';
import { sendProgress } from '../utils/progress.js';
import {
  ResponseFormat, Paging, compact, pagingFrom,
  shapeBug, shapeAdvisory, shapeEox, shapeProduct, shapeCoverage,
  shapeSoftwareRelease, shapeCase, shapeRma,
} from './shape.js';

export type ApiName = 'bug' | 'psirt' | 'eox' | 'product' | 'serial' | 'software' | 'case' | 'rma';

/** What a tool handler can do with an API: GET an endpoint (cancellation is wired in) */
export interface ApiClient {
  request(endpoint: string, params?: Record<string, any>): Promise<any>;
}

export interface ToolContext {
  apis: Record<ApiName, ApiClient>;
  enabled: Set<ApiName>;
  progressToken?: string;
}

type Args = Record<string, any>;

interface ToolSpec {
  tool: Tool;
  /** The tool is listed when any of these APIs is enabled */
  requires: ApiName[];
  handler: (args: Args, ctx: ToolContext) => Promise<any>;
}

// ---------------------------------------------------------------------------
// Shared schema pieces

const responseFormat = {
  type: 'string',
  enum: ['concise', 'detailed'],
  default: 'concise',
  description: 'concise (default) returns key fields only; detailed adds descriptions, notes and secondary fields.',
};
const page = { type: 'integer', minimum: 1, default: 1, description: 'Page number (see paging.next_page in the result).' };
const PSIRT_OS_TYPES = ['ios', 'iosxe', 'nxos', 'asa', 'ftd', 'fxos', 'fmc', 'aci'];

const READ_ONLY = { readOnlyHint: true, openWorldHint: true };

// ---------------------------------------------------------------------------
// Helpers

const enc = (v: unknown) => BaseApi.encodePathValue(String(v ?? '').trim());

function list(value: unknown, max: number, label: string): string[] {
  const items = String(value ?? '').split(',').map(s => s.trim()).filter(Boolean);
  if (items.length === 0) throw new Error(`${label} is required`);
  if (items.length > max) throw new Error(`${label}: at most ${max} values per call (got ${items.length}); split into several calls`);
  return items;
}
const encList = (items: string[]) => items.map(enc).join(',');

function exactlyOne(args: Args, keys: string[]): string {
  const present = keys.filter(k => args[k] !== undefined && args[k] !== null && args[k] !== '');
  if (present.length !== 1) {
    throw new Error(`Provide exactly one of: ${keys.join(', ')}${present.length ? ` (got ${present.join(', ')})` : ''}`);
  }
  return present[0];
}

const fmt = (args: Args): ResponseFormat => (args.response_format === 'detailed' ? 'detailed' : 'concise');
const pageOf = (args: Args): number => Math.max(1, parseInt(args.page ?? 1, 10) || 1);

/** Cisco wants 17.9.6, not 17.09.06 */
const normalizeVersion = (v: string) => v.replace(/\.0+(\d)/g, '.$1');

function withHint<T extends { count: number }>(result: T, hint: string): T & { hint?: string } {
  return result.count === 0 ? { ...result, hint } : result;
}

// ---------------------------------------------------------------------------
// Bug

async function bugGet(args: Args, ctx: ToolContext) {
  const ids = list(args.bug_ids, 5, 'bug_ids');
  const body = await ctx.apis.bug.request(`/bugs/bug_ids/${encList(ids)}`);
  // Unknown IDs come back as placeholder records with severity "0" and no headline
  const real = (body.bugs || []).filter((b: any) => b.headline || (b.severity && b.severity !== '0'));
  const bugs = real.map((b: any) => shapeBug(b, fmt(args)));
  const found = new Set(bugs.map((b: any) => b.bug_id));
  return compact({ count: bugs.length, bugs, not_found: ids.filter(id => !found.has(id)) });
}

function bugSearchEndpoint(args: Args): string {
  const mode = exactlyOne(args, ['keyword', 'product_id', 'product_series', 'product_name']);
  const rels = args.releases ? list(args.releases, 75, 'releases').map(normalizeVersion) : undefined;
  const match = args.release_match === 'fixed' ? 'fixed' : 'affected';

  switch (mode) {
    case 'keyword': {
      const kw = String(args.keyword).trim();
      if (kw.length > 50) throw new Error('keyword: Cisco limits keyword searches to 50 characters');
      if (rels) throw new Error('releases cannot be combined with keyword; use product_id, product_series or product_name');
      return `/bugs/keyword/${enc(kw)}`;
    }
    case 'product_id': {
      if (rels && match === 'fixed') throw new Error('release_match "fixed" is not supported with product_id; use product_series or product_name');
      const base = `/bugs/products/product_id/${enc(args.product_id)}`;
      return rels ? `${base}/software_releases/${encList(rels)}` : base;
    }
    case 'product_series':
    case 'product_name': {
      if (!rels) throw new Error(`releases is required with ${mode}`);
      const segment = match === 'fixed' ? 'fixed_in_releases' : 'affected_releases';
      return `/bugs/${mode}/${enc(args[mode])}/${segment}/${encList(rels)}`;
    }
  }
  throw new Error('unreachable');
}

async function bugSearch(args: Args, ctx: ToolContext) {
  const endpoint = bugSearchEndpoint(args);
  const pageNum = pageOf(args);
  const severities: string[] = Array.isArray(args.severity) ? args.severity.map(String)
    : args.severity ? [String(args.severity)] : [];
  const base: Args = {
    page_index: pageNum,
    modified_date: args.modified_date ?? '5',
    ...(args.status ? { status: args.status } : {}),
    ...(args.sort_by ? { sort_by: args.sort_by } : {}),
  };

  // The Bug API takes one severity per call: fan out and merge
  const runs = severities.length ? severities : [undefined];
  const bugs: any[] = [];
  const bySeverity: Record<string, number | null> = {};
  const failures: Record<string, string> = {};
  let total = 0;
  let lastPage = 0;

  for (const [i, sev] of runs.entries()) {
    sendProgress(ctx.progressToken, i, runs.length);
    try {
      const body = await ctx.apis.bug.request(endpoint, sev ? { ...base, severity: sev } : base);
      const p = pagingFrom(body, pageNum);
      total += p.total_records ?? (body.bugs?.length || 0);
      lastPage = Math.max(lastPage, p.last_page ?? pageNum);
      if (sev) bySeverity[sev] = p.total_records;
      bugs.push(...(body.bugs || []));
    } catch (error) {
      if (!sev) throw error;
      failures[sev] = error instanceof Error ? error.message : String(error);
    }
  }
  sendProgress(ctx.progressToken, runs.length, runs.length);
  if (severities.length && Object.keys(failures).length === severities.length) {
    throw new Error(`Bug search failed for every severity: ${Object.values(failures)[0]}`);
  }

  const seen = new Set<string>();
  const unique = bugs.filter(b => !seen.has(b.bug_id) && seen.add(b.bug_id));
  const paging: Paging = { page: pageNum, total_records: total, last_page: lastPage || null, next_page: pageNum < lastPage ? pageNum + 1 : null };
  return withHint(compact({
    count: unique.length,
    paging,
    total_by_severity: severities.length ? bySeverity : undefined,
    failed_severities: Object.keys(failures).length ? failures : undefined,
    bugs: unique.map(b => shapeBug(b, fmt(args))),
  }) as any, 'No bugs matched. Try a base product ID without the license suffix (e.g. ISR4431 not ISR4431/K9), a broader keyword, modified_date "5" (all), or product_series with the full series name.');
}

// ---------------------------------------------------------------------------
// PSIRT

/** openVuln answers "nothing matched" with 404 NO_DATA_FOUND; treat it as an empty list */
async function psirtRequest(ctx: ToolContext, path: string, params: Args = {}): Promise<any> {
  try {
    return await ctx.apis.psirt.request(path, params);
  } catch (error) {
    if (error instanceof Error && /404/.test(error.message) && /NO_DATA_FOUND/.test(error.message)) {
      return { advisories: [] };
    }
    throw error;
  }
}

async function psirtGet(args: Args, ctx: ToolContext) {
  const key = exactlyOne(args, ['advisory_id', 'cve', 'bug_id']);
  const path = key === 'advisory_id' ? `/advisory/${enc(args.advisory_id)}`
    : key === 'cve' ? `/cve/${enc(args.cve)}` : `/bugid/${enc(args.bug_id)}`;
  const body = await psirtRequest(ctx, path);
  const advisories = (body.advisories || []).map((a: any) => shapeAdvisory(a, fmt(args)));
  return { count: advisories.length, advisories };
}

async function psirtSearch(args: Args, ctx: ToolContext) {
  const mode = exactlyOne(args, ['os_type', 'product', 'severity', 'year', 'latest', 'first_published_from']);
  const pageNum = pageOf(args);
  const pageSize = Math.min(100, Math.max(1, parseInt(args.page_size ?? 10, 10) || 10));
  const paged = { pageIndex: pageNum, pageSize };
  let path: string;
  let params: Args = paged;

  switch (mode) {
    case 'os_type':
      if (!args.version) throw new Error('version is required with os_type (e.g. os_type "iosxe", version "17.9.4")');
      path = `/OSType/${enc(args.os_type)}`;
      params = { version: args.version };     // not paged by Cisco
      break;
    case 'product': path = '/product'; params = { ...paged, product: args.product }; break;
    case 'severity': path = `/severity/${enc(String(args.severity).toLowerCase())}`; break;
    case 'year': path = `/year/${enc(args.year)}`; break;
    case 'latest': path = `/latest/${enc(Math.min(100, parseInt(args.latest, 10) || 10))}`; params = {}; break;
    default:
      if (!args.first_published_to) throw new Error('first_published_to is required with first_published_from (YYYY-MM-DD)');
      path = '/all/firstpublished';
      params = { ...paged, startDate: args.first_published_from, endDate: args.first_published_to };
  }

  const body = await psirtRequest(ctx, path, params);
  let advisories: any[] = body.advisories || [];
  let paging = pagingFrom(body, pageNum, pageSize);

  // OSType and latest return everything at once: page locally
  if (mode === 'os_type' || mode === 'latest') {
    const total = advisories.length;
    const last = Math.max(1, Math.ceil(total / pageSize));
    advisories = advisories.slice((pageNum - 1) * pageSize, pageNum * pageSize);
    paging = { page: pageNum, total_records: total, last_page: last, next_page: pageNum < last ? pageNum + 1 : null };
  }

  return withHint({
    count: advisories.length,
    paging,
    advisories: advisories.map(a => shapeAdvisory(a, fmt(args))),
  }, mode === 'os_type'
    ? `No advisories list ${args.os_type} ${args.version} as affected. Check the version string matches Cisco's format (e.g. 17.9.4a).`
    : 'No advisories matched.');
}

// ---------------------------------------------------------------------------
// EoX

async function eoxGet(args: Args, ctx: ToolContext) {
  const mode = exactlyOne(args, ['product_ids', 'serial_numbers', 'software_releases', 'start_date']);
  const pageNum = pageOf(args);
  let path: string;
  let params: Args = {};
  if (mode === 'product_ids') path = `/EOXByProductID/${pageNum}/${encList(list(args.product_ids, 20, 'product_ids'))}`;
  else if (mode === 'serial_numbers') path = `/EOXBySerialNumber/${pageNum}/${encList(list(args.serial_numbers, 20, 'serial_numbers'))}`;
  else if (mode === 'software_releases') {
    const tuples = String(args.software_releases).split(';').map(s => s.trim()).filter(Boolean);
    if (tuples.length > 20) throw new Error('software_releases: at most 20 "version,OS" entries');
    path = `/EOXBySWReleaseString/1`;
    tuples.forEach((t, i) => { params[`input${i + 1}`] = t; });
  } else {
    if (!args.end_date) throw new Error('end_date is required with start_date (YYYY-MM-DD)');
    path = `/EOXByDates/1/${enc(args.start_date)}/${enc(args.end_date)}`;
  }
  const body = await ctx.apis.eox.request(path, params);
  let all: any[] = body.EOXRecord || [];
  let paging = pagingFrom(body, pageNum);
  // Date and software-release lookups can return 100+ records in one page: page locally
  if (mode === 'software_releases' || mode === 'start_date') {
    const pageSize = Math.min(100, Math.max(1, parseInt(args.page_size ?? 20, 10) || 20));
    const last = Math.max(1, Math.ceil(all.length / pageSize));
    paging = { page: pageNum, total_records: all.length, last_page: last, next_page: pageNum < last ? pageNum + 1 : null };
    all = all.slice((pageNum - 1) * pageSize, pageNum * pageSize);
  }
  const records = all.map((r: any) => shapeEox(r, fmt(args)));
  return { count: records.length, paging, records };
}

// ---------------------------------------------------------------------------
// Device lookup (serial numbers): coverage + product + EoX in one call

async function deviceLookup(args: Args, ctx: ToolContext) {
  const serials = list(args.serial_numbers, 20, 'serial_numbers');
  const want = new Set<string>(Array.isArray(args.include) && args.include.length ? args.include : ['coverage', 'product', 'eox']);
  const format = fmt(args);
  const devices = new Map<string, Record<string, any>>(serials.map(s => [s.toUpperCase(), { serial_number: s }]));
  const errors: Record<string, string> = {};
  const key = (s: unknown) => String(s ?? '').toUpperCase();

  const tasks: Promise<void>[] = [];
  if (want.has('coverage') && ctx.enabled.has('serial')) {
    tasks.push(ctx.apis.serial.request(`/coverage/summary/serial_numbers/${encList(serials)}`).then(body => {
      for (const c of body.serial_numbers || []) devices.get(key(c.sr_no))!.coverage = shapeCoverage(c, format);
    }).catch(e => { errors.coverage = e.message; }));
  }
  if (want.has('product') && ctx.enabled.has('product')) {
    tasks.push(ctx.apis.product.request(`/serial_numbers/${encList(serials)}`).then(body => {
      for (const p of body.product_list || []) {
        const d = devices.get(key(p.sr_no));
        if (d) d.product = shapeProduct(p, format);
      }
    }).catch(e => { errors.product = e.message; }));
  }
  if (want.has('eox') && ctx.enabled.has('eox')) {
    tasks.push(ctx.apis.eox.request(`/EOXBySerialNumber/1/${encList(serials)}`).then(body => {
      for (const r of body.EOXRecord || []) {
        for (const s of String(r.EOXInputValue || '').split(',')) {
          const d = devices.get(key(s.trim()));
          if (d) d.eox = shapeEox(r, format);
        }
      }
    }).catch(e => { errors.eox = e.message; }));
  }
  await Promise.all(tasks);
  if (tasks.length && Object.keys(errors).length === tasks.length) {
    throw new Error(`Device lookup failed: ${Object.entries(errors).map(([k, v]) => `${k}: ${v}`).join('; ')}`);
  }
  return compact({ count: devices.size, devices: [...devices.values()], errors: Object.keys(errors).length ? errors : undefined });
}

// ---------------------------------------------------------------------------
// Product

async function productGet(args: Args, ctx: ToolContext) {
  const ids = list(args.product_ids, 5, 'product_ids');
  const body = await ctx.apis.product.request(`/product_ids/${encList(ids)}`);
  const products = (body.product_list || []).map((p: any) => shapeProduct(p, fmt(args)));
  if (args.include_mdf) {
    const mdf = await ctx.apis.product.request(`/product_ids_mdf/${encList(ids)}`);
    const byId = new Map((mdf.product_list || []).map((m: any) => [m.product_id, m]));
    for (const p of products as any[]) {
      const m: any = byId.get(p.product_id);
      if (m) Object.assign(p, compact({ mdf_name: m.product_name_mdf, mdf_series: m.product_series_mdf }));
    }
  }
  return withHint({ count: products.length, products }, 'No products found. Use orderable or base product IDs such as C9300-48P or ISR4431/K9.');
}

// ---------------------------------------------------------------------------
// Software suggestions

async function softwareGet(args: Args, ctx: ToolContext) {
  const view = args.view === 'releases' || args.view === 'compatible' ? args.view : 'suggested';
  const key = exactlyOne(args, ['product_ids', 'mdf_ids']);
  const byMdf = key === 'mdf_ids';
  const pageNum = pageOf(args);
  const format = fmt(args);

  if (view === 'compatible') {
    const ids = list(args[key], 1, key);
    const path = byMdf ? `/suggestions/compatible/mdfId/${enc(ids[0])}` : `/suggestions/compatible/productId/${enc(ids[0])}`;
    const params = compact({ pageIndex: pageNum, currentImage: args.current_image, currentRelease: args.current_release });
    const body = await ctx.apis.software.request(path, params);
    const releases = (body.suggestions || []).map((s: any) => shapeSoftwareRelease(s, format));
    return { count: releases.length, paging: pagingFrom(body, pageNum), releases };
  }

  const ids = list(args[key], 10, key);
  const kind = view === 'releases' ? 'releases' : 'software';
  const body = await ctx.apis.software.request(`/suggestions/${kind}/${byMdf ? 'mdfIds' : 'productIds'}/${encList(ids)}`, { pageIndex: pageNum });
  const products = (body.productList || []).map((p: any) => compact({
    product_id: p.product?.basePID,
    mdf_id: p.product?.mdfId,
    name: p.product?.productName,
    software_type: p.product?.softwareType,
    releases: (p.suggestions || []).map((s: any) => shapeSoftwareRelease(s, format)),
  }));
  return { count: products.length, paging: pagingFrom(body, pageNum), products };
}

// ---------------------------------------------------------------------------
// Case

async function caseGet(args: Args, ctx: ToolContext) {
  const ids = list(args.case_ids, 30, 'case_ids');
  const format = fmt(args);
  if (format === 'detailed') {
    // Only the details endpoint returns notes and owner; one call per case
    const cases = await Promise.all(ids.map(async id => {
      const body = await ctx.apis.case.request(`/cases/details/case_id/${enc(id)}`);
      return shapeCase(body.caseDetail || {}, 'detailed');
    }));
    return { count: cases.length, cases };
  }
  const body = await ctx.apis.case.request(`/cases/case_ids/${encList(ids)}`);
  const cases = (body.cases || []).map((c: any) => shapeCase(c, 'concise'));
  return { count: cases.length, cases };
}

async function caseSearch(args: Args, ctx: ToolContext) {
  const key = exactlyOne(args, ['contract_ids', 'user_ids']);
  const ids = list(args[key], 10, key);
  const pageNum = pageOf(args);
  const path = key === 'contract_ids'
    ? `/cases/contracts/contract_ids/${encList(ids)}`
    : `/cases/users/user_ids/${encList(ids)}`;
  const params = compact({
    status_flag: args.status_flag,
    date_created_from: args.date_created_from,
    date_created_to: args.date_created_to,
    sort_by: args.sort_by || 'UPDATED_DATE',
    page_index: pageNum,
  });
  const body = await ctx.apis.case.request(path, params);
  const cases = (body.cases || []).map((c: any) => shapeCase(c, fmt(args)));
  return withHint({ count: cases.length, paging: pagingFrom(body, pageNum), cases },
    'No cases found. Cisco returns at most 90 days of cases per search; widen date_created_from/date_created_to or drop status_flag.');
}

// ---------------------------------------------------------------------------
// RMA

async function rmaGet(args: Args, ctx: ToolContext) {
  const key = exactlyOne(args, ['rma_number', 'user_id']);
  const pageNum = pageOf(args);
  const body = key === 'rma_number'
    ? await ctx.apis.rma.request(`/returns/rma_numbers/${enc(args.rma_number)}`)
    : await ctx.apis.rma.request(`/returns/users/user_ids/${enc(args.user_id)}`, compact({
        pageIndex: pageNum, fromDate: args.from_date, toDate: args.to_date, status: args.status,
      }));
  const records = body.returns?.RmaRecord ?? [];
  const rmas = (Array.isArray(records) ? records : [records]).map((r: any) => shapeRma(r, fmt(args)));
  return { count: rmas.length, paging: pagingFrom(body, pageNum), rmas };
}

// ---------------------------------------------------------------------------
// Upgrade assessment

const releaseList = (v: unknown) => (typeof v === 'string' ? v.split(/\s+/).filter(Boolean) : []);

async function assessUpgrade(args: Args, ctx: ToolContext) {
  if (!args.product_id || !args.current_version) throw new Error('product_id and current_version are required');
  const pid = String(args.product_id).trim();
  const current = normalizeVersion(String(args.current_version).trim());
  const maxSeverity = Math.min(6, Math.max(1, parseInt(args.max_severity ?? 3, 10) || 3));
  const notes: string[] = [];
  const steps = 5;
  let step = 0;
  const tick = () => sendProgress(ctx.progressToken, ++step, steps);

  // 1. Target: given, or Cisco's suggested release
  let target = args.target_version ? normalizeVersion(String(args.target_version).trim()) : undefined;
  let suggested: any;
  if (ctx.enabled.has('software')) {
    try {
      const body = await ctx.apis.software.request(`/suggestions/software/productIds/${enc(pid)}`);
      const releases = body.productList?.[0]?.suggestions || [];
      const pick = releases.find((s: any) => s.isSuggested === 'Y') || releases[0];
      if (pick) suggested = shapeSoftwareRelease(pick, 'concise');
    } catch (e: any) { notes.push(`Software suggestion lookup failed: ${e.message}`); }
  }
  if (!target && suggested?.release) {
    target = suggested.release;
    notes.push(`target_version not given; using Cisco's suggested release ${target}`);
  }
  if (!target) throw new Error('target_version is required (no suggested release available; enable the software API or pass target_version)');
  tick();

  // 2. Bugs affecting the current release (severity 1..max), and whether the target fixes them
  const bugsCurrent: any[] = [];
  for (let sev = 1; sev <= maxSeverity; sev++) {
    try {
      const body = await ctx.apis.bug.request(`/bugs/products/product_id/${enc(pid)}/software_releases/${enc(current)}`,
        { severity: String(sev), status: 'O', modified_date: '5' });
      bugsCurrent.push(...(body.bugs || []));
    } catch (e: any) { notes.push(`Bug search (severity ${sev}) failed: ${e.message}`); }
  }
  tick();
  const dedupe = (bugs: any[]) => { const seen = new Set(); return bugs.filter(b => !seen.has(b.bug_id) && seen.add(b.bug_id)); };
  bugsCurrent.splice(0, bugsCurrent.length, ...dedupe(bugsCurrent));
  const fixedByTarget = bugsCurrent.filter(b => releaseList(b.known_fixed_releases).includes(target!));
  const stillOpen = bugsCurrent.filter(b => !fixedByTarget.includes(b));

  // 3. Bugs known to affect the target release
  const bugsTarget: any[] = [];
  for (let sev = 1; sev <= maxSeverity; sev++) {
    try {
      const body = await ctx.apis.bug.request(`/bugs/products/product_id/${enc(pid)}/software_releases/${enc(target)}`,
        { severity: String(sev), status: 'O', modified_date: '5' });
      bugsTarget.push(...(body.bugs || []));
    } catch (e: any) { notes.push(`Bug search on target (severity ${sev}) failed: ${e.message}`); }
  }
  bugsTarget.splice(0, bugsTarget.length, ...dedupe(bugsTarget));
  tick();

  // 4. PSIRT advisories for both releases (needs the OS type)
  let security: any;
  if (ctx.enabled.has('psirt') && args.os_type) {
    try {
      const [cur, tgt] = await Promise.all([
        psirtRequest(ctx, `/OSType/${enc(args.os_type)}`, { version: current }),
        psirtRequest(ctx, `/OSType/${enc(args.os_type)}`, { version: target }),
      ]);
      const curIds = new Set((cur.advisories || []).map((a: any) => a.advisoryId));
      const tgtAdv: any[] = tgt.advisories || [];
      const tgtIds = new Set(tgtAdv.map(a => a.advisoryId));
      security = {
        current_affected: curIds.size,
        target_affected: tgtIds.size,
        fixed_by_upgrade: (cur.advisories || []).filter((a: any) => !tgtIds.has(a.advisoryId)).map((a: any) => shapeAdvisory(a, 'concise')),
        still_affected_after_upgrade: tgtAdv.filter(a => curIds.has(a.advisoryId)).map(a => shapeAdvisory(a, 'concise')),
        new_in_target: tgtAdv.filter(a => !curIds.has(a.advisoryId)).map(a => shapeAdvisory(a, 'concise')),
      };
    } catch (e: any) { notes.push(`PSIRT lookup failed: ${e.message}`); }
  } else if (ctx.enabled.has('psirt')) {
    notes.push('Pass os_type (e.g. iosxe, ios, nxos, asa) to include security advisories for both releases');
  }
  tick();

  // 5. Hardware end-of-life
  let eox: any;
  if (ctx.enabled.has('eox')) {
    try {
      const body = await ctx.apis.eox.request(`/EOXByProductID/1/${enc(pid)}`);
      if (body.EOXRecord?.[0]) eox = shapeEox(body.EOXRecord[0], 'concise');
    } catch (e: any) { notes.push(`EoX lookup failed: ${e.message}`); }
  }
  tick();

  const brief = (b: any) => compact({ bug_id: b.bug_id, severity: b.severity, headline: b.headline });
  const limit = args.response_format === 'detailed' ? 50 : 10;
  return compact({
    product_id: pid,
    current_version: current,
    target_version: target,
    suggested_release: suggested,
    summary: compact({
      open_bugs_current: bugsCurrent.length,
      fixed_by_target: fixedByTarget.length,
      open_bugs_target: bugsTarget.length,
      advisories_fixed_by_upgrade: security?.fixed_by_upgrade.length,
      advisories_new_in_target: security?.new_in_target.length,
      end_of_sale: eox?.end_of_sale,
      last_date_of_support: eox?.last_date_of_support,
    }),
    bugs_fixed_by_target: fixedByTarget.slice(0, limit).map(brief),
    bugs_still_open: stillOpen.slice(0, limit).map(brief),
    bugs_affecting_target: bugsTarget.slice(0, limit).map(brief),
    security,
    eox,
    notes,
    caveat: `Bug counts cover open bugs of severity 1-${maxSeverity}, first page per severity; "fixed by target" means the target appears in the bug's known fixed releases.`,
  });
}

// ---------------------------------------------------------------------------
// Tool table

const spec = (requires: ApiName[], tool: Omit<Tool, 'annotations'>, handler: ToolSpec['handler']): ToolSpec =>
  ({ requires, tool: { ...tool, annotations: { title: tool.title, ...READ_ONLY } } as Tool, handler });

export const TOOL_SPECS: ToolSpec[] = [
  spec(['bug'], {
    name: 'bug_get',
    title: 'Get Cisco bugs by ID',
    description: 'Get Cisco bug (CDETS) details by ID, e.g. CSCwh87343. Up to 5 IDs.',
    inputSchema: { type: 'object', properties: {
      bug_ids: { type: 'string', description: 'Comma-separated bug IDs (max 5), e.g. "CSCwh87343,CSCvi12345"' },
      response_format: responseFormat,
    }, required: ['bug_ids'] },
  }, bugGet),

  spec(['bug'], {
    name: 'bug_search',
    title: 'Search Cisco bugs',
    description: 'Search Cisco bugs by exactly one of keyword, product_id, product_series or product_name. ' +
      'With releases, returns bugs affecting (or fixed in) those releases. Pass several severities to search them in one call.',
    inputSchema: { type: 'object', properties: {
      keyword: { type: 'string', description: 'Keyword(s) in the headline/description (max 50 chars)' },
      product_id: { type: 'string', description: 'Base product ID, e.g. "C9300-48P" or "ISR4431"' },
      product_series: { type: 'string', description: 'Full series name, e.g. "Cisco Catalyst 9300 Series Switches"' },
      product_name: { type: 'string', description: 'Exact product name, e.g. "Cisco Unified Communications Manager (CallManager)"' },
      releases: { type: 'string', description: 'Comma-separated releases, e.g. "17.9.4,17.12.3" (leading zeros are removed). Required with product_series/product_name.' },
      release_match: { type: 'string', enum: ['affected', 'fixed'], default: 'affected', description: 'Match bugs affecting the releases (default) or fixed in them. "fixed" works with product_series/product_name.' },
      severity: { type: 'array', items: { type: 'string', enum: ['1', '2', '3', '4', '5', '6'] }, description: 'Severities to include, e.g. ["1","2","3"]. Omit for all.' },
      status: { type: 'string', enum: ['O', 'F', 'T'], description: 'O = open, F = fixed, T = terminated' },
      modified_date: { type: 'string', enum: ['1', '2', '3', '4', '5'], default: '5', description: 'Last modified: 1 = week, 2 = 30 days, 3 = 6 months, 4 = year, 5 = all' },
      sort_by: { type: 'string', enum: ['status', 'modified_date', 'severity', 'support_case_count', 'modified_date_earliest'] },
      page,
      response_format: responseFormat,
    } },
  }, bugSearch),

  spec(['psirt'], {
    name: 'psirt_get',
    title: 'Get a Cisco security advisory',
    description: 'Get Cisco PSIRT security advisories by exactly one of advisory_id, cve or bug_id.',
    inputSchema: { type: 'object', properties: {
      advisory_id: { type: 'string', description: 'e.g. "cisco-sa-iosxe-webui-privesc-j22SaA4z"' },
      cve: { type: 'string', description: 'e.g. "CVE-2023-20198"' },
      bug_id: { type: 'string', description: 'e.g. "CSCwh87343"' },
      response_format: responseFormat,
    } },
  }, psirtGet),

  spec(['psirt'], {
    name: 'psirt_search',
    title: 'Search Cisco security advisories',
    description: 'Find Cisco security advisories. Use os_type + version to answer "is this software version vulnerable?" ' +
      '(returns advisories affecting that release with first fixed releases). Other modes: product, severity, year, latest, or a first-published date range.',
    inputSchema: { type: 'object', properties: {
      os_type: { type: 'string', enum: PSIRT_OS_TYPES, description: 'Operating system, used with version' },
      version: { type: 'string', description: 'Release for os_type, e.g. "17.9.4" or "17.15.4b"' },
      product: { type: 'string', description: 'Product name to match, e.g. "Cisco Unified Communications Manager"' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'informational'] },
      year: { type: 'integer', minimum: 1995, description: 'Publication year' },
      latest: { type: 'integer', minimum: 1, maximum: 100, description: 'Most recent N advisories' },
      first_published_from: { type: 'string', description: 'YYYY-MM-DD, with first_published_to' },
      first_published_to: { type: 'string', description: 'YYYY-MM-DD' },
      page,
      page_size: { type: 'integer', minimum: 1, maximum: 100, default: 10 },
      response_format: responseFormat,
    } },
  }, psirtSearch),

  spec(['eox'], {
    name: 'eox_get',
    title: 'Get Cisco end-of-life dates',
    description: 'End-of-sale / end-of-support dates by exactly one of product_ids, serial_numbers, software_releases, or an announcement date range (start_date + end_date).',
    inputSchema: { type: 'object', properties: {
      product_ids: { type: 'string', description: 'Comma-separated product IDs (max 20), e.g. "VG224,C9300-48P"' },
      serial_numbers: { type: 'string', description: 'Comma-separated serial numbers (max 20)' },
      software_releases: { type: 'string', description: 'Semicolon-separated "version,OS" pairs (max 20), e.g. "15.4(3)M,IOS;17.9.4,IOS-XE"' },
      start_date: { type: 'string', description: 'YYYY-MM-DD, EoX announcements from this date' },
      end_date: { type: 'string', description: 'YYYY-MM-DD' },
      page,
      page_size: { type: 'integer', minimum: 1, maximum: 100, default: 20, description: 'Records per page for software_releases and date lookups' },
      response_format: responseFormat,
    } },
  }, eoxGet),

  spec(['serial', 'product', 'eox'], {
    name: 'device_lookup',
    title: 'Look up Cisco devices by serial number',
    description: 'For each serial number: contract coverage and warranty, product details, and end-of-life dates, in one call. Up to 20 serials.',
    inputSchema: { type: 'object', properties: {
      serial_numbers: { type: 'string', description: 'Comma-separated serial numbers (max 20), e.g. "FJC29161RHS,FTX1917AJJU"' },
      include: { type: 'array', items: { type: 'string', enum: ['coverage', 'product', 'eox'] }, description: 'Sections to include (default: all available)' },
      response_format: responseFormat,
    }, required: ['serial_numbers'] },
  }, deviceLookup),

  spec(['product'], {
    name: 'product_get',
    title: 'Get Cisco product information',
    description: 'Product name, series, category and support page for product IDs. include_mdf adds the MDF (Cisco software download tree) names used by software_get.',
    inputSchema: { type: 'object', properties: {
      product_ids: { type: 'string', description: 'Comma-separated product IDs (max 5), e.g. "C9300-48P,ISR4431/K9"' },
      include_mdf: { type: 'boolean', default: false },
      response_format: responseFormat,
    }, required: ['product_ids'] },
  }, productGet),

  spec(['software'], {
    name: 'software_get',
    title: 'Get Cisco software recommendations',
    description: 'Cisco suggested software for products. view: "suggested" (Cisco-recommended releases, default), "releases" (latest releases), ' +
      'or "compatible" (releases compatible with one product, optionally from current_release).',
    inputSchema: { type: 'object', properties: {
      product_ids: { type: 'string', description: 'Comma-separated product IDs (max 10; 1 for compatible), e.g. "C9300-48P"' },
      mdf_ids: { type: 'string', description: 'Comma-separated MDF IDs (from product_get include_mdf or a previous software_get)' },
      view: { type: 'string', enum: ['suggested', 'releases', 'compatible'], default: 'suggested' },
      current_release: { type: 'string', description: 'compatible view: the release running today' },
      current_image: { type: 'string', description: 'compatible view: the image file running today' },
      page,
      response_format: responseFormat,
    } },
  }, softwareGet),

  spec(['case'], {
    name: 'case_get',
    title: 'Get Cisco TAC cases',
    description: 'Get Cisco TAC support cases by number. response_format "detailed" adds notes, owner and contact (one API call per case).',
    inputSchema: { type: 'object', properties: {
      case_ids: { type: 'string', description: 'Comma-separated case numbers (max 30), e.g. "701311380"' },
      response_format: responseFormat,
    }, required: ['case_ids'] },
  }, caseGet),

  spec(['case'], {
    name: 'case_search',
    title: 'Search Cisco TAC cases',
    description: 'Find Cisco TAC cases by exactly one of contract_ids or user_ids. Cisco returns at most 90 days per search.',
    inputSchema: { type: 'object', properties: {
      contract_ids: { type: 'string', description: 'Comma-separated contract numbers (max 10)' },
      user_ids: { type: 'string', description: 'Comma-separated Cisco.com user IDs (max 10)' },
      status_flag: { type: 'string', enum: ['O', 'C'], description: 'O = open, C = closed (default: both)' },
      date_created_from: { type: 'string', description: 'UTC, e.g. 2026-09-01T00:00:00Z' },
      date_created_to: { type: 'string', description: 'UTC, e.g. 2026-11-18T23:59:59Z' },
      sort_by: { type: 'string', enum: ['STATUS', 'UPDATED_DATE'], default: 'UPDATED_DATE' },
      page,
      response_format: responseFormat,
    } },
  }, caseSearch),

  spec(['rma'], {
    name: 'rma_get',
    title: 'Get Cisco RMAs',
    description: 'Get a Cisco RMA (return) by rma_number, or list RMAs for a Cisco.com user_id (optionally filtered by date and status).',
    inputSchema: { type: 'object', properties: {
      rma_number: { type: 'string', description: 'e.g. "804891407"' },
      user_id: { type: 'string', description: 'Cisco.com user ID' },
      from_date: { type: 'string', description: 'user_id search: YYYY-MM-DD (max 90-day range)' },
      to_date: { type: 'string', description: 'user_id search: YYYY-MM-DD' },
      status: { type: 'string', enum: ['open', 'booked', 'hold', 'closed', 'cancelled'] },
      page,
      response_format: responseFormat,
    } },
  }, rmaGet),

  spec(['bug'], {
    name: 'assess_upgrade',
    title: 'Assess a Cisco software upgrade',
    description: 'Compare a current and target release for a product: open bugs on each, bugs the target fixes, and (with os_type) security advisories fixed, remaining and new; plus hardware end-of-life. ' +
      'Without target_version, uses Cisco\'s suggested release.',
    inputSchema: { type: 'object', properties: {
      product_id: { type: 'string', description: 'Base product ID, e.g. "C9300-48P"' },
      current_version: { type: 'string', description: 'Release running today, e.g. "17.9.4"' },
      target_version: { type: 'string', description: 'Release to evaluate (default: Cisco suggested release)' },
      os_type: { type: 'string', enum: PSIRT_OS_TYPES, description: 'OS for the security advisory comparison, e.g. "iosxe"' },
      max_severity: { type: 'integer', minimum: 1, maximum: 6, default: 3, description: 'Include open bugs of severity 1..max_severity' },
      response_format: responseFormat,
    }, required: ['product_id', 'current_version'] },
  }, assessUpgrade),
];

/** Tool names from 2.x mapped to their 3.0 replacement, for helpful errors */
export const RENAMED_TOOLS: Record<string, string> = {
  get_bug_details: 'bug_get',
  search_bugs_by_keyword: 'bug_search', search_bugs_by_product_id: 'bug_search', search_bugs_by_product_and_release: 'bug_search',
  search_bugs_by_product_series_affected: 'bug_search', search_bugs_by_product_series_fixed: 'bug_search',
  search_bugs_by_product_name_affected: 'bug_search', search_bugs_by_product_name_fixed: 'bug_search',
  multi_severity_search: 'bug_search', progressive_bug_search: 'bug_search',
  compare_software_versions: 'assess_upgrade', comprehensive_analysis: 'assess_upgrade',
  get_security_advisory_by_id: 'psirt_get', get_security_advisory_by_cve: 'psirt_get', get_security_advisory_by_bug_id: 'psirt_get',
  get_all_security_advisories: 'psirt_search', get_latest_security_advisories: 'psirt_search', get_security_advisories_by_severity: 'psirt_search',
  get_security_advisories_by_year: 'psirt_search', get_security_advisories_by_first_published: 'psirt_search',
  get_eox_by_date: 'eox_get', get_eox_by_product_id: 'eox_get', get_eox_by_serial_number: 'eox_get', get_eox_by_software_release: 'eox_get',
  get_coverage_status_by_serial: 'device_lookup', get_coverage_summary_by_serial: 'device_lookup', get_coverage_summary_by_instance: 'device_lookup',
  get_product_info_by_serial_numbers: 'device_lookup',
  get_product_info_by_product_ids: 'product_get', get_product_mdf_info_by_product_ids: 'product_get', product_name_resolver: 'product_get',
  get_software_suggestions_by_product_ids: 'software_get', get_software_releases_by_product_ids: 'software_get', get_compatible_software_by_product_id: 'software_get',
  get_software_suggestions_by_mdf_ids: 'software_get', get_software_releases_by_mdf_ids: 'software_get', get_compatible_software_by_mdf_id: 'software_get',
  get_case_details: 'case_get', get_case_summary: 'case_get', search_cases_by_contract: 'case_search', search_cases_by_user: 'case_search',
  get_rma_details: 'rma_get', get_rmas_by_user: 'rma_get',
};
