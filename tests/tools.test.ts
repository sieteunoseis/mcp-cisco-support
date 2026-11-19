/**
 * v3 tools against responses recorded from apix.cisco.com (tests/fixtures/cisco).
 * The fetch mock routes each Cisco URL to its fixture, so these tests check
 * the endpoints we call and how real response shapes are turned into output.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { executeTool, getAvailableTools } from '../src/mcp-server';
import { createApiRegistry } from '../src/apis/index';
import { mockFetch } from './setup';

const FIXTURES = join(__dirname, 'fixtures', 'cisco');
const fixture = (name: string) => JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8'));

// URL pattern -> fixture name (first match wins)
const ROUTES: [RegExp, string][] = [
  [/\/bug\/v2\.0\/bugs\/bug_ids\//, 'get_bug_details'],
  [/\/bugs\/keyword\//, 'search_bugs_by_keyword'],
  [/\/bugs\/products\/product_id\/[^/]+\/software_releases\//, 'search_bugs_by_product_and_release'],
  [/\/bugs\/products\/product_id\//, 'search_bugs_by_product_id'],
  [/\/bugs\/product_series\/.+\/fixed_in_releases\//, 'search_bugs_by_product_series_fixed'],
  [/\/bugs\/product_name\//, 'search_bugs_by_product_name_affected'],
  [/\/advisories\/v2\/OSType\//, 'psirt_ostype_iosxe'],
  [/\/advisories\/v2\/severity\//, 'psirt_severity_paged'],
  [/\/advisories\/v2\/cve\//, 'get_security_advisory_by_cve'],
  [/\/EOXByProductID\//, 'get_eox_by_product_id'],
  [/\/EOXBySerialNumber\//, 'get_eox_by_serial_number'],
  [/\/EOXByDates\//, 'get_eox_by_date'],
  [/\/sn2info\/v2\/coverage\/summary\//, 'get_coverage_summary_by_serial'],
  [/\/product\/v1\/information\/serial_numbers\//, 'get_product_info_by_serial_numbers'],
  [/\/product\/v1\/information\/product_ids_mdf\//, 'get_product_mdf_info_by_product_ids'],
  [/\/product\/v1\/information\/product_ids\//, 'get_product_info_by_product_ids'],
  [/\/suggestions\/software\/productIds\//, 'get_software_suggestions_by_product_ids'],
  [/\/suggestions\/compatible\/productId\//, 'get_compatible_software_by_product_id'],
  [/\/cases\/details\/case_id\//, 'get_case_details'],
  [/\/cases\/case_ids\//, 'get_case_summary'],
  [/\/cases\/contracts\//, 'search_cases_by_contract'],
  [/\/returns\/rma_numbers\//, 'get_rma_details'],
];

const calls: string[] = [];

function respond(status: number, body: unknown): Response {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(typeof body === 'string' ? JSON.parse(body) : body),
    text: () => Promise.resolve(text),
  } as Response;
}

function routeFixtures(overrides: [RegExp, () => Response][] = []) {
  mockFetch!.mockImplementation((input: any) => {
    const url = String(input);
    if (url.includes('oauth2')) {
      return Promise.resolve(respond(200, { access_token: 'tok', token_type: 'Bearer', expires_in: 43199 }));
    }
    calls.push(url);
    for (const [pattern, make] of overrides) if (pattern.test(url)) return Promise.resolve(make());
    const route = ROUTES.find(([pattern]) => pattern.test(url));
    if (!route) return Promise.reject(new Error(`No fixture for ${url}`));
    const f = fixture(route[1]);
    return Promise.resolve(respond(f.status, f.body));
  });
}

beforeEach(() => {
  calls.length = 0;
  mockFetch!.mockReset();
  routeFixtures();
});

describe('tool listing', () => {
  test('all 12 v3 tools are listed, with annotations', () => {
    const tools = getAvailableTools();
    expect(tools.map(t => t.name).sort()).toEqual([
      'assess_upgrade', 'bug_get', 'bug_search', 'case_get', 'case_search', 'device_lookup',
      'eox_get', 'product_get', 'psirt_get', 'psirt_search', 'rma_get', 'software_get',
    ]);
    for (const tool of tools) {
      expect(tool.annotations).toMatchObject({ readOnlyHint: true, openWorldHint: true });
      expect(tool.description!.length).toBeLessThan(400);
    }
  });

  test('SUPPORT_API no longer filters tools', () => {
    process.env.SUPPORT_API = 'case,rma';
    try {
      expect(getAvailableTools()).toHaveLength(12);
    } finally {
      delete process.env.SUPPORT_API;
    }
  });

  test('tools/list stays small', () => {
    expect(JSON.stringify(getAvailableTools()).length).toBeLessThan(16000);
  });
});

describe('bug tools', () => {
  test('bug_get shapes a real bug', async () => {
    const r: any = await executeTool('bug_get', { bug_ids: 'CSCwh87343' });
    expect(calls[0]).toContain('/bugs/bug_ids/CSCwh87343');
    expect(r.count).toBe(1);
    expect(r.bugs[0]).toMatchObject({ bug_id: 'CSCwh87343', severity: '1' });
    expect(Array.isArray(r.bugs[0].fixed_releases)).toBe(true);
    expect(r.bugs[0].description).toBeUndefined(); // concise
  });

  test('bug_get treats placeholder records as not found', async () => {
    routeFixtures([[/bug_ids/, () => respond(200, { bugs: [{ bug_id: 'CSCzz99999', severity: '0', id: '1' }] })]]);
    const r: any = await executeTool('bug_get', { bug_ids: 'CSCzz99999' });
    expect(r.count).toBe(0);
    expect(r.not_found).toEqual(['CSCzz99999']);
  });

  test('bug_search reads the real total from pagination_response_record', async () => {
    const r: any = await executeTool('bug_search', { keyword: 'memory leak' });
    expect(r.paging).toEqual({ page: 1, total_records: 5727, last_page: 573, next_page: 2 });
  });

  test('bug_search fans out one call per severity and sums totals', async () => {
    const r: any = await executeTool('bug_search', { keyword: 'memory leak', severity: ['1', '2'] });
    expect(calls.filter(u => u.includes('/bugs/keyword/'))).toHaveLength(2);
    expect(calls.some(u => u.includes('severity=1'))).toBe(true);
    expect(calls.some(u => u.includes('severity=2'))).toBe(true);
    expect(r.paging.total_records).toBe(5727 * 2);
  });

  test('bug_search builds verified paths for each mode', async () => {
    await executeTool('bug_search', { product_id: 'ISR4431/K9', releases: '17.09.04' });
    await executeTool('bug_search', { product_series: 'Cisco Catalyst 9200 Series Switches', releases: '17.9.5', release_match: 'fixed' });
    await executeTool('bug_search', { product_name: 'Cisco Unified Communications Manager (CallManager)', releases: '12.5(1)' });
    // literal slash in PIDs (gateway rejects %2F); leading zeros removed
    expect(calls[0]).toContain('/bugs/products/product_id/ISR4431/K9/software_releases/17.9.4');
    expect(calls[1]).toContain('/bugs/product_series/Cisco%20Catalyst%209200%20Series%20Switches/fixed_in_releases/17.9.5');
    expect(calls[2]).toContain('/bugs/product_name/Cisco%20Unified%20Communications%20Manager%20(CallManager)/affected_releases/12.5(1)');
  });

  test('arguments are checked against the tool schema before calling Cisco', async () => {
    await expect(executeTool('bug_search', { keyword: 'x', severity: ['high'] }))
      .rejects.toThrow('severity[0] must be one of: 1, 2, 3, 4, 5, 6');
    await expect(executeTool('bug_search', { keyword: 'x', page: 'two' })).rejects.toThrow('page must be an integer');
    await expect(executeTool('bug_search', { keyword: 'x', product: 'C9300' })).rejects.toThrow('unknown argument "product"');
    await expect(executeTool('psirt_search', { latest: 500 })).rejects.toThrow('latest must be <= 100');
    await expect(executeTool('bug_get', {})).rejects.toThrow('bug_ids is required');
    expect(calls).toHaveLength(0);
    // A single severity string is accepted where an array is expected
    await expect(executeTool('bug_search', { keyword: 'x', severity: '2' })).resolves.toBeDefined();
  });

  test('bug_search validates its inputs', async () => {
    await expect(executeTool('bug_search', {})).rejects.toThrow('Provide exactly one of');
    await expect(executeTool('bug_search', { keyword: 'a', product_id: 'b' })).rejects.toThrow('Provide exactly one of');
    await expect(executeTool('bug_search', { product_series: 'X' })).rejects.toThrow('releases is required');
    await expect(executeTool('bug_search', { keyword: 'x'.repeat(51) })).rejects.toThrow('50 characters');
    await expect(executeTool('bug_search', { product_id: '../case/v3' })).rejects.toThrow('Invalid identifier');
  });
});

describe('psirt tools', () => {
  test('psirt_get by CVE uses sir and CVSS', async () => {
    const r: any = await executeTool('psirt_get', { cve: 'CVE-2023-20198' });
    expect(r.advisories[0]).toMatchObject({ advisory_id: 'cisco-sa-iosxe-webui-privesc-j22SaA4z', sir: 'Critical' });
    expect(r.advisories[0].cvss_base_score).toBeDefined();
  });

  test('psirt_search os_type pages locally', async () => {
    const r: any = await executeTool('psirt_search', { os_type: 'iosxe', version: '17.15.4b', page_size: 2 });
    expect(calls[0]).toContain('/OSType/iosxe?version=17.15.4b');
    expect(r.count).toBe(2);
    expect(r.paging.next_page).toBe(2);
  });

  test('psirt_search os_type + severity filters the release advisories', async () => {
    const all: any = await executeTool('psirt_search', { os_type: 'iosxe', version: '17.15.4b', page_size: 100 });
    const critical: any = await executeTool('psirt_search', { os_type: 'iosxe', version: '17.15.4b', severity: 'critical', page_size: 100 });
    expect(critical.advisories.every((a: any) => a.sir === 'Critical')).toBe(true);
    expect(critical.count).toBeLessThan(all.count);
    expect(critical.paging.total_records).toBe(critical.count);
  });

  test('psirt_search severity uses Cisco paging', async () => {
    const r: any = await executeTool('psirt_search', { severity: 'critical', page_size: 5 });
    expect(calls[0]).toContain('pageIndex=1&pageSize=5');
    expect(r.paging).toEqual({ page: 1, total_records: 405, last_page: 81, next_page: 2 });
  });

  test('NO_DATA_FOUND means zero advisories, not an error', async () => {
    routeFixtures([[/OSType/, () => respond(404, '{"errorCode":"NO_DATA_FOUND","errorMessage":"No advisories found"}')]]);
    const r: any = await executeTool('psirt_search', { os_type: 'iosxe', version: '99.1.1' });
    expect(r.count).toBe(0);
    expect(r.hint).toMatch(/No advisories/);
  });
});

describe('eox, device, product, software', () => {
  test('eox_get reports products without an EoX announcement', async () => {
    const r: any = await executeTool('eox_get', { product_ids: 'C9300-48P' });
    expect(r.records[0].eox_announced).toBe(false);
    expect(r.records[0].error).toMatch(/does not exist/);
  });

  test('eox_get pages large date lookups locally', async () => {
    const r: any = await executeTool('eox_get', { start_date: '2026-01-01', end_date: '2026-01-31', page_size: 2 });
    expect(calls[0]).toContain('/EOXByDates/1/2026-01-01/2026-01-31');
    expect(r.count).toBe(2);
  });

  test('device_lookup merges coverage, product and eox per serial', async () => {
    const serials = fixture('get_coverage_summary_by_serial').body.serial_numbers.map((s: any) => s.sr_no);
    const r: any = await executeTool('device_lookup', { serial_numbers: serials.join(',') });
    expect(calls.some(u => u.includes('/coverage/summary/serial_numbers/'))).toBe(true);
    expect(calls.some(u => u.includes('/product/v1/information/serial_numbers/'))).toBe(true);
    expect(calls.some(u => u.includes('/EOXBySerialNumber/'))).toBe(true);
    expect(r.devices[0].coverage).toMatchObject({ is_covered: false, warranty_end_date: '2035-08-13' });
  });

  test('product_get adds MDF names', async () => {
    const r: any = await executeTool('product_get', { product_ids: 'C9300-48P,ISR4431/K9', include_mdf: true });
    expect(calls.some(u => u.includes('/product_ids_mdf/'))).toBe(true);
    expect(r.products.length).toBeGreaterThan(0);
  });

  test('software_get suggested and compatible views', async () => {
    const s: any = await executeTool('software_get', { product_ids: 'C9300-48P' });
    expect(s.products[0]).toMatchObject({ product_id: 'C9300-48P', name: 'Catalyst 9300 Switch' });
    expect(s.products[0].releases[0]).toMatchObject({ release: '17.18.4', suggested: true });

    const c: any = await executeTool('software_get', { product_ids: 'ISR4431/K9', view: 'compatible' });
    expect(calls[calls.length - 1]).toContain('/suggestions/compatible/productId/ISR4431/K9');
    expect(c.releases[0].release).toBe('17.12.8');
  });
});

describe('case and rma', () => {
  test('case_get concise vs detailed', async () => {
    const concise: any = await executeTool('case_get', { case_ids: '701311380' });
    expect(calls[0]).toContain('/cases/case_ids/701311380');
    expect(concise.cases[0].notes).toBeUndefined();

    const detailed: any = await executeTool('case_get', { case_ids: '701311380', response_format: 'detailed' });
    expect(calls[1]).toContain('/cases/details/case_id/701311380');
    expect(Array.isArray(detailed.cases[0].notes)).toBe(true);
  });

  test('case_search defaults to page 1', async () => {
    const r: any = await executeTool('case_search', { contract_ids: '202612207' });
    expect(calls[0]).toContain('page_index=1');
    expect(r.paging.total_records).toBe(4);
  });

  test('rma_get unwraps returns.RmaRecord', async () => {
    const r: any = await executeTool('rma_get', { rma_number: '804891407' });
    expect(r.count).toBe(1);
    expect(r.rmas[0].status).toBeDefined();
    expect(Array.isArray(r.rmas[0].replacement_parts)).toBe(true);
  });
});

describe('assess_upgrade', () => {
  test('uses the suggested release and compares advisories', async () => {
    const r: any = await executeTool('assess_upgrade', { product_id: 'C9300-48P', current_version: '17.15.4b', os_type: 'iosxe' });
    expect(r.target_version).toBe('17.18.4');
    expect(r.notes[0]).toMatch(/suggested release 17.18.4/);
    expect(r.security).toBeDefined();
    expect(r.summary).toHaveProperty('open_bugs_current');
    // Bug rows carry status and fixed releases for the results view
    for (const b of [...(r.bugs_still_open || []), ...(r.bugs_affecting_target || [])]) {
      expect(b.status).toBeDefined();
      expect(b.url).toContain(b.bug_id);
    }
  });

  test('requires product_id and current_version', async () => {
    await expect(executeTool('assess_upgrade', { product_id: 'C9300-48P' })).rejects.toThrow('required');
  });
});

describe('resilience', () => {
  test('a cancelled call never reaches Cisco', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(createApiRegistry().executeTool('bug_get', { bug_ids: 'CSCwh87343' }, { signal: controller.signal }))
      .rejects.toThrow('cancelled by the client');
    expect(calls).toHaveLength(0);
  });

  test('cancelling during a rate-limit backoff stops retrying', async () => {
    const controller = new AbortController();
    let hits = 0;
    routeFixtures([[/bug_ids/, () => { hits++; setTimeout(() => controller.abort(), 50); return respond(403, '<h1>Developer Over Qps</h1>'); }]]);
    await expect(createApiRegistry().executeTool('bug_get', { bug_ids: 'CSCwh87343' }, { signal: controller.signal }))
      .rejects.toThrow();
    expect(hits).toBe(1);
  });

  test('a 403 that is not rate limiting explains the missing API entitlement', async () => {
    routeFixtures([[/\/cases\//, () => respond(403, '<h1>Developer Inactive</h1>')]]);
    await expect(executeTool('case_get', { case_ids: '700000001' }))
      .rejects.toThrow(/Case API: access denied \(403: Developer Inactive\).*not entitled to the Case API/);
  });

  test('retries when Cisco rate-limits with 403 Over Qps', async () => {
    let hits = 0;
    routeFixtures([[/bug_ids/, () => (++hits === 1
      ? respond(403, '<h1>Developer Over Qps</h1>')
      : respond(200, fixture('get_bug_details').body))]]);
    const r: any = await executeTool('bug_get', { bug_ids: 'CSCwh87343' });
    expect(hits).toBe(2);
    expect(r.count).toBe(1);
  }, 10000);
});
