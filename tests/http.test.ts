/**
 * HTTP transport: stateless Streamable HTTP, bearer auth, origin checks,
 * OAuth discovery answers and body limits. Uses node:http directly because
 * tests/setup.ts mocks global fetch for the Cisco API calls.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHttpServer } from '../src/http-server';
import { createMCPServer } from '../src/mcp-server';

let server: http.Server;
let port: number;
const TOKEN = 'test-token-123';

function call(method: string, path: string, opts: { body?: string; headers?: Record<string, string> } = {}) {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...opts.headers,
    } }, res => {
      let body = '';
      res.on('data', chunk => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}
const auth = { authorization: `Bearer ${TOKEN}` };
const rpc = (method: string, id = 1) => JSON.stringify({ jsonrpc: '2.0', id, method, params: {} });
const sseJson = (body: string) => JSON.parse(body.split('\n').find(l => l.startsWith('data: '))!.slice(6));

beforeAll(async () => {
  process.env.MCP_BEARER_TOKEN = TOKEN;
  process.env.SUPPORT_API = 'bug';
  const app = createHttpServer(createMCPServer);
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()); });
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  delete process.env.MCP_BEARER_TOKEN;
  await new Promise(resolve => server.close(resolve));
});

describe('stateless Streamable HTTP', () => {
  test('tools/list works without initialize and returns no session id', async () => {
    const res = await call('POST', '/mcp', { body: rpc('tools/list'), headers: auth });
    expect(res.status).toBe(200);
    expect(res.headers['mcp-session-id']).toBeUndefined();
    expect(sseJson(res.body).result.tools.map((t: any) => t.name)).toContain('bug_search');
  });

  test('GET and DELETE /mcp are 405', async () => {
    expect((await call('GET', '/mcp', { headers: auth })).status).toBe(405);
    expect((await call('DELETE', '/mcp', { headers: auth })).status).toBe(405);
  });

  test('concurrent requests are independent', async () => {
    const results = await Promise.all([1, 2, 3, 4].map(id => call('POST', '/mcp', { body: rpc('ping', id), headers: auth })));
    expect(results.map(r => sseJson(r.body).id).sort()).toEqual([1, 2, 3, 4]);
  });
});

describe('auth and request checks', () => {
  test('requires the bearer token in the Authorization header', async () => {
    expect((await call('POST', '/mcp', { body: rpc('tools/list') })).status).toBe(401);
    expect((await call('POST', `/mcp?token=${TOKEN}`, { body: rpc('tools/list') })).status).toBe(401);
    expect((await call('POST', '/mcp', { body: rpc('tools/list'), headers: { authorization: 'Bearer wrong' } })).status).toBe(401);
  });

  test('OAuth discovery answers 404 (no OAuth), not 401', async () => {
    expect((await call('GET', '/.well-known/oauth-protected-resource')).status).toBe(404);
    expect((await call('GET', '/.well-known/oauth-protected-resource/mcp')).status).toBe(404);
    expect((await call('GET', '/.well-known/oauth-authorization-server')).status).toBe(404);
  });

  test('rejects disallowed browser origins, allows localhost', async () => {
    expect((await call('POST', '/mcp', { body: rpc('ping'), headers: { ...auth, origin: 'https://evil.example' } })).status).toBe(403);
    expect((await call('POST', '/mcp', { body: rpc('ping'), headers: { ...auth, origin: 'http://localhost:6274' } })).status).toBe(200);
  });

  test('oversized bodies are 413, malformed JSON is 400', async () => {
    const big = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: { pad: 'x'.repeat(1_100_000) } });
    expect((await call('POST', '/mcp', { body: big, headers: auth })).status).toBe(413);
    expect((await call('POST', '/mcp', { body: '{not json', headers: auth })).status).toBe(400);
  });

  test('health and info need no auth', async () => {
    const health = await call('GET', '/health');
    expect(health.status).toBe(200);
    expect(JSON.parse(health.body).mode).toBe('stateless');
    expect((await call('GET', '/')).status).toBe(200);
  });
});
