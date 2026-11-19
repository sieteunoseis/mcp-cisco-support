/**
 * Asking for an exact release: psirt_search / assess_upgrade with a partial
 * release ("17", "17.9"). Cisco responses come from recorded fixtures: the
 * PSIRT OS version list, the 406 for unknown releases, and advisories.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client, InMemoryTransport, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { createMCPServer } from '../src/mcp-server';
import { optionsFor, isPartialRelease, compareReleasesDesc } from '../src/tools/versions';
import { mockFetch } from './setup';

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, 'fixtures', 'cisco', `${name}.json`), 'utf8'));
const osVersions = fixture('psirt_os_versions_iosxe');
const KNOWN = new Set<string>(osVersions.body.map((v: any) => v.nos_version));

function respond(status: number, body: unknown): Response {
  return { ok: status < 300, status, statusText: status === 200 ? 'OK' : 'Not Acceptable',
    json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)) } as Response;
}

beforeEach(() => {
  mockFetch!.mockReset();
  mockFetch!.mockImplementation((input: any) => {
    const url = new URL(String(input));
    if (url.href.includes('oauth2')) return Promise.resolve(respond(200, { access_token: 'tok', expires_in: 43199 }));
    if (url.pathname.endsWith('/OS_version/OS_data')) return Promise.resolve(respond(200, osVersions.body));
    if (url.pathname.includes('/OSType/')) {
      const v = url.searchParams.get('version') || '';
      return Promise.resolve(KNOWN.has(v) ? respond(200, fixture('psirt_ostype_iosxe').body)
        : respond(406, fixture('psirt_ostype_invalid_version').body));
    }
    return Promise.resolve(respond(200, {}));
  });
});

type Answer = (form: { message: string; options: string[] }) => string | null;

function client(opts: { elicit: boolean; answer?: Answer }) {
  const forms: { message: string; options: string[] }[] = [];
  const c = new Client({ name: 't', version: '1' }, { capabilities: (opts.elicit ? { elicitation: { form: {} } } : {}) as any });
  if (opts.elicit) {
    c.setRequestHandler('elicitation/create', async (req: any) => {
      const field = req.params.requestedSchema.properties.value;
      const form = { message: req.params.message, options: field.enum ?? [] };
      forms.push(form);
      const value = opts.answer!(form);
      return value ? { action: 'accept', content: { value } } : { action: 'decline' };
    });
  }
  return { c, forms };
}

async function legacy(opts: { elicit: boolean; answer?: Answer }) {
  const { c, forms } = client(opts);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([createMCPServer().connect(st), c.connect(ct)]);
  return { c, forms };
}

async function modern(opts: { elicit: boolean; answer?: Answer }) {
  const { c, forms } = client(opts);
  (c as any)._options = { ...(c as any)._options };
  const handler = createMcpHandler(createMCPServer);
  const transport = new StreamableHTTPClientTransport(new URL('http://localhost/mcp'),
    { fetch: (u: any, i?: any) => handler.fetch(new Request(u, i)) });
  // pin 2026-07-28 (set on construction in the other suites)
  const pinned = new Client({ name: 't', version: '1' }, {
    capabilities: (opts.elicit ? { elicitation: { form: {} } } : {}) as any,
    versionNegotiation: { mode: { pin: '2026-07-28' } },
  });
  if (opts.elicit) pinned.setRequestHandler('elicitation/create', (c as any)._requestHandlers.get('elicitation/create'));
  await pinned.connect(transport);
  return { c: pinned, forms };
}

const pick = (answers: Record<string, string>): Answer => (form) => {
  for (const [needle, value] of Object.entries(answers)) if (form.message.includes(needle)) return value;
  return null;
};

describe('release candidates', () => {
  test('partial releases and option grouping', () => {
    expect(isPartialRelease('17')).toBe(true);
    expect(isPartialRelease('17.9')).toBe(true);
    expect(isPartialRelease('17.9.4')).toBe(false);
    expect(isPartialRelease('17.9.4a')).toBe(false);
    const all = [...KNOWN];
    const train = optionsFor(all, '17');
    expect(train.level).toBe('train');
    expect(train.options).toContain('17.9');
    const releases = optionsFor(all, '17.9');
    expect(releases.level).toBe('release');
    expect(releases.options[0]).toBe('17.9.10'); // newest first
    expect(releases.options).toContain('17.9.4a');
    expect(['17.9.4', '17.9.10', '17.9.4a'].sort(compareReleasesDesc)).toEqual(['17.9.10', '17.9.4a', '17.9.4']);
  });
});

describe.each([['2025-era (elicitInput)', legacy], ['2026-07-28 (input_required)', modern]])('%s', (_label, connect) => {
  test('"17.9" asks for the exact release, then answers', async () => {
    const { c, forms } = await connect({ elicit: true, answer: pick({ '"17.9"': '17.9.4' }) });
    const r: any = await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17.9' } });
    expect(forms).toHaveLength(1);
    expect(forms[0].options).toContain('17.9.4');
    expect(r.isError).toBe(false);
    expect(r.content[0].text).toContain('advisories');
  });

  test('"17" asks for the train, then the release', async () => {
    const { c, forms } = await connect({ elicit: true, answer: pick({ '"17"': '17.9', '"17.9"': '17.9.4' }) });
    const r: any = await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17' } });
    expect(forms.map(f => f.message)).toEqual([
      expect.stringContaining('covers several IOSXE trains'),
      expect.stringContaining('Which IOSXE release did you mean by "17.9"'),
    ]);
    expect(r.content[0].text).toContain('advisories');
  });

  test('without elicitation support, returns candidates for the model to ask about', async () => {
    const { c } = await connect({ elicit: false });
    const r: any = await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17.9' } });
    expect(r.isError).toBe(false);
    expect(r.content[0].text).toContain('needs_exact_release');
    expect(r.content[0].text).toContain('17.9.4a');
  });
});

describe('other paths', () => {
  test('declining the form tells the model to ask', async () => {
    const { c } = await legacy({ elicit: true, answer: () => null });
    const r: any = await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17.9' } });
    expect(r.content[0].text).toContain('release_not_chosen');
  });

  test('an exact release Cisco knows is not questioned', async () => {
    const { c, forms } = await legacy({ elicit: true, answer: () => '17.9.4' });
    await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17.9.4' } });
    expect(forms).toHaveLength(0);
  });

  test('an exact-looking release Cisco rejects (406) is questioned too', async () => {
    const { c, forms } = await legacy({ elicit: true, answer: pick({ '"17.9.99"': '17.9.4' }) });
    const r: any = await c.callTool({ name: 'psirt_search', arguments: { os_type: 'iosxe', version: '17.9.99' } });
    expect(forms).toHaveLength(1);
    expect(forms[0].options).toContain('17.9.4');
    expect(r.content[0].text).toContain('advisories');
  });

  test('assess_upgrade asks for an exact current_version', async () => {
    const { c } = await legacy({ elicit: false });
    const r: any = await c.callTool({ name: 'assess_upgrade', arguments: { product_id: 'C9300-48P', current_version: '17.9', os_type: 'iosxe' } });
    expect(r.content[0].text).toContain('needs_exact_release');
    expect(r.content[0].text).toContain('current_version');
  });
});

describe('bug_search: a train is valid, an exact release is offered', () => {
  const bugUrls = () => mockFetch!.mock.calls.map(([u]) => String(u)).filter(u => u.includes('/bug/v2.0/'));

  test.each([['2025-era', legacy], ['2026-07-28', modern]])('%s: picking 17.9.5 searches that release', async (_l, connect) => {
    const { c, forms } = await connect({ elicit: true, answer: pick({ 'whole IOSXE train': '17.9.5' }) });
    await c.callTool({ name: 'bug_search', arguments: { product_id: 'C9300-48P', releases: '17.9', os_type: 'iosxe' } });
    expect(forms[0].options[0]).toBe('17.9');        // keeping the train is the first choice
    expect(forms[0].options).toContain('17.9.5');
    expect(bugUrls().every(u => u.includes('/software_releases/17.9.5'))).toBe(true);
  });

  test('keeping the train searches 17.9', async () => {
    const { c } = await legacy({ elicit: true, answer: () => '17.9' });
    await c.callTool({ name: 'bug_search', arguments: { product_id: 'C9300-48P', releases: '17.9', os_type: 'iosxe' } });
    expect(bugUrls().some(u => u.includes('/software_releases/17.9?'))).toBe(true);
  });

  test('only the partial item of a release list is replaced', async () => {
    const { c } = await legacy({ elicit: true, answer: pick({ 'whole IOSXE train': '17.9.5' }) });
    await c.callTool({ name: 'bug_search', arguments: { product_id: 'C9300-48P', releases: '17.12.4,17.9', os_type: 'iosxe' } });
    expect(bugUrls().some(u => u.includes('/software_releases/17.12.4,17.9.5'))).toBe(true);
  });

  test('without elicitation it still searches the train and offers exact releases', async () => {
    const { c } = await legacy({ elicit: false });
    const r: any = await c.callTool({ name: 'bug_search', arguments: { product_id: 'C9300-48P', releases: '17.9', os_type: 'iosxe' } });
    expect(bugUrls().some(u => u.includes('/software_releases/17.9?'))).toBe(true);
    expect(r.content[0].text).toContain('release_hint');
    expect(r.content[0].text).toContain('17.9.5');
  });

  test('without os_type there is no question', async () => {
    const { c, forms } = await legacy({ elicit: true, answer: () => '17.9.5' });
    await c.callTool({ name: 'bug_search', arguments: { product_id: 'C9300-48P', releases: '17.9' } });
    expect(forms).toHaveLength(0);
  });
});

