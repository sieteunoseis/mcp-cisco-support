/**
 * End-to-end over the MCP protocol: an SDK Client talks to createMCPServer()
 * through an in-memory transport, with Cisco responses served from fixtures.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMCPServer } from '../src/mcp-server';
import { mockFetch } from './setup';

const fixture = (name: string) =>
  JSON.parse(readFileSync(join(__dirname, 'fixtures', 'cisco', `${name}.json`), 'utf8'));

const ROUTES: [RegExp, string][] = [
  [/\/bugs\/bug_ids\//, 'get_bug_details'],
  [/\/product\/v1\/information\/product_ids\//, 'get_product_info_by_product_ids'],
  [/\/advisories\/v2\/cve\//, 'get_security_advisory_by_cve'],
  [/\/advisories\/v2\/advisory\//, 'get_security_advisory_by_id'],
  [/\/advisories\/v2\/latest\//, 'get_latest_security_advisories'],
  [/\/advisories\/v2\/severity\//, 'psirt_severity_paged'],
];

/** Read a JSON resource body */
async function readJson(client: Client, uri: string): Promise<any> {
  const { contents } = await client.readResource({ uri });
  return JSON.parse((contents[0] as { text: string }).text);
}

async function connect(supportApi: string) {
  process.env.SUPPORT_API = supportApi;
  const server = createMCPServer();
  const client = new Client({ name: 'test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server };
}

beforeEach(() => {
  mockFetch!.mockReset();
  mockFetch!.mockImplementation((input: any) => {
    const url = String(input);
    const json = (status: number, body: unknown) => Promise.resolve({
      ok: status < 300, status, statusText: 'OK',
      json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)),
    } as Response);
    if (url.includes('oauth2')) return json(200, { access_token: 'tok', expires_in: 43199 });
    const route = ROUTES.find(([re]) => re.test(url));
    if (!route) return Promise.reject(new Error(`No fixture for ${url}`));
    const f = fixture(route[1]);
    return json(f.status, f.body);
  });
});

afterAll(() => {
  process.env.SUPPORT_API = 'bug';
});

describe('MCP protocol', () => {
  test('initialize advertises tools, prompts and resources (no elicitation)', async () => {
    const { client } = await connect('bug');
    const caps = client.getServerCapabilities()!;
    expect(caps.tools).toBeDefined();
    expect(caps.prompts).toBeDefined();
    expect(caps.resources).toBeDefined();
    expect((caps as any).elicitation).toBeUndefined();
    expect(client.getServerVersion()?.icons?.[0]?.mimeType).toBe('image/svg+xml');
  });

  test('tools/call returns GCF text; bad input is isError', async () => {
    const { client } = await connect('bug');
    const ok: any = await client.callTool({ name: 'bug_get', arguments: { bug_ids: 'CSCwh87343' } });
    expect(ok.isError).toBe(false);
    expect(ok.content[0].text).toContain('CSCwh87343');

    const bad: any = await client.callTool({ name: 'bug_search', arguments: {} });
    expect(bad.isError).toBe(true);
    expect(bad.content[0].text).toContain('Provide exactly one of');
  });

  test('unknown prompt is InvalidParams (-32602)', async () => {
    const { client } = await connect('bug');
    await expect(client.getPrompt({ name: 'nope' })).rejects.toMatchObject({ code: -32602 });
  });

  test('prompts have titles and the interactive prompt is gone', async () => {
    const { client } = await connect('all');
    const { prompts } = await client.listPrompts();
    expect(prompts.every(p => p.title)).toBe(true);
    expect(prompts.map(p => p.name)).not.toContain('cisco-interactive-search');
  });
});

describe('resources', () => {
  test('lists only resources for enabled APIs', async () => {
    const { client } = await connect('bug');
    expect((await client.listResources()).resources).toHaveLength(0);
    expect((await client.listResourceTemplates()).resourceTemplates.map(t => t.uriTemplate))
      .toEqual(['cisco://bugs/{bug_id}']);
  });

  test('all resources when everything is enabled; scraping and recent-bug resources are gone', async () => {
    const { client } = await connect('all');
    const uris = (await client.listResources()).resources.map(r => r.uri);
    expect(uris.sort()).toEqual(['cisco://security/advisories/critical', 'cisco://security/advisories/recent']);
    const templates = (await client.listResourceTemplates()).resourceTemplates.map(t => t.uriTemplate);
    expect(templates).toEqual([
      'cisco://bugs/{bug_id}', 'cisco://products/{product_id}',
      'cisco://security/advisories/{advisory_id}', 'cisco://security/cve/{cve_id}',
    ]);
    expect(JSON.stringify(templates)).not.toContain('autocomplete');
  });

  test('templated reads return the v3 tool output', async () => {
    const { client } = await connect('all');
    const bug = await readJson(client, 'cisco://bugs/CSCwh87343');
    expect(bug.bugs[0].bug_id).toBe('CSCwh87343');

    const cve = await readJson(client, 'cisco://security/cve/CVE-2023-20198');
    expect(cve.advisories[0].sir).toBe('Critical');

    const product = await readJson(client, 'cisco://products/C9300-48P');
    expect(product.count).toBeGreaterThan(0);
  });

  test('static advisory resources resolve before the advisory template', async () => {
    const { client } = await connect('psirt');
    const recent = await readJson(client, 'cisco://security/advisories/recent');
    expect(recent.advisories.length).toBeGreaterThan(0);
    expect(mockFetch!.mock.calls.some(([u]) => String(u).includes('/latest/20'))).toBe(true);
  });

  test('unknown or disabled resource URIs are InvalidParams', async () => {
    const { client } = await connect('bug');
    await expect(client.readResource({ uri: 'cisco://products/autocomplete/9300' })).rejects.toMatchObject({ code: -32602 });
    await expect(client.readResource({ uri: 'cisco://bugs/recent/critical' })).rejects.toMatchObject({ code: -32602 });
  });
});
