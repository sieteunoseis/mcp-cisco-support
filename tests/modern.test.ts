/**
 * Protocol revision 2026-07-28 end to end: an SDK v2 client pinned to
 * 2026-07-28 talks to the server through the SDK's createMcpHandler (no
 * initialize, no sessions, capabilities sent in each request's _meta).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { createMCPServer } from '../src/mcp-server';
import { mockFetch } from './setup';

const bugFixture = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'cisco', 'get_bug_details.json'), 'utf8'));
const UI = { 'io.modelcontextprotocol/ui': { mimeTypes: ['text/html;profile=mcp-app'] } };

async function connect(withUi: boolean) {
  const handler = createMcpHandler(createMCPServer, { legacy: 'stateless' });
  const client = new Client({ name: 'modern-test', version: '1.0.0' }, {
    capabilities: (withUi ? { extensions: UI } : {}) as any,
    versionNegotiation: { mode: { pin: '2026-07-28' } },
  });
  const transport = new StreamableHTTPClientTransport(new URL('http://localhost/mcp'), {
    fetch: (url: any, init?: any) => handler.fetch(new Request(url, init)),
  });
  await client.connect(transport);
  return client;
}

beforeEach(() => {
  // Cisco API calls (OAuth + Bug API) are served from fixtures
  mockFetch!.mockReset();
  mockFetch!.mockImplementation((input: any) => {
    const url = String(input);
    const body = url.includes('oauth2') ? { access_token: 'tok', expires_in: 43199 } : bugFixture.body;
    return Promise.resolve({ ok: true, status: 200, statusText: 'OK',
      json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)) } as Response);
  });
});

describe('MCP 2026-07-28 via SDK v2', () => {
  test('negotiates 2026-07-28 and lists the 12 tools', async () => {
    const client = await connect(false);
    expect(client.getNegotiatedProtocolVersion()).toBe('2026-07-28');
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(12);
  });

  test('list results carry 2026-07-28 cache hints', async () => {
    const handler = createMcpHandler(createMCPServer);
    const call = async (method: string, id: number) => {
      const res = await handler.fetch(new Request('http://localhost/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2026-07-28', 'mcp-method': method },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' },
          'io.modelcontextprotocol/clientCapabilities': {},
        } } }),
      }));
      const text = await res.text();
      const line = text.split('\n').find(l => l.startsWith('data: '));
      return JSON.parse(line ? line.slice(6) : text).result;
    };
    const prompts = await call('prompts/list', 1);
    expect(prompts).toMatchObject({ ttlMs: 3_600_000, cacheScope: 'public' });
    const tools = await call('tools/list', 2);
    expect(tools).toMatchObject({ ttlMs: 3_600_000, cacheScope: 'private' });
  });

  test('per-request UI capability: view metadata, structuredContent and the model note', async () => {
    const client = await connect(true);
    const { tools } = await client.listTools();
    expect((tools.find(t => t.name === 'bug_get')!._meta as any).ui.resourceUri).toBe('ui://mcp-cisco-support/results.html');

    const r: any = await client.callTool({ name: 'bug_get', arguments: { bug_ids: 'CSCwh87343' } });
    expect(r.structuredContent.bugs[0].bug_id).toBe('CSCwh87343');
    expect(r.content[0].text).toMatch(/^\[Shown to the user as an interactive table/);
  });

  test('clients without the UI extension get plain text only', async () => {
    const client = await connect(false);
    const { tools } = await client.listTools();
    expect(tools.some(t => (t._meta as any)?.ui)).toBe(false);
    const r: any = await client.callTool({ name: 'bug_get', arguments: { bug_ids: 'CSCwh87343' } });
    expect(r.structuredContent).toBeUndefined();
    expect(r.content[0].text).not.toContain('Shown to the user');
  });

  test('prompts and resources work without initialize', async () => {
    const client = await connect(false);
    expect((await client.listPrompts()).prompts).toHaveLength(6);
    const { contents } = await client.readResource({ uri: 'cisco://bugs/CSCwh87343' });
    expect(JSON.parse((contents[0] as { text: string }).text).bugs[0].bug_id).toBe('CSCwh87343');
  });
});
