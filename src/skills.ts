import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { join, relative, sep } from 'path';
import { ProtocolError, ProtocolErrorCode } from '@modelcontextprotocol/server';
import type { Server } from '@modelcontextprotocol/server';
import { SKILLS_EXTENSION_ID, SKILLS_GET_METHOD, SKILLS_LIST_METHOD, skillEntry } from '@modelcontextprotocol/server/ext/skills';
import type { Skill } from '@modelcontextprotocol/server/ext/skills';
import { z } from 'zod';
import { logger } from './utils/logger.js';

// MCP Skills extension (SEP-2640): serves the bundled skills/ folder as
// skill://<name>/<path>. The SDK's `skills.attach()` needs the high-level
// McpServer; this server is the low-level Server with its own resources/*
// handlers, so the two methods and the skill:// reads are wired here instead.

const SKILL_URI_PREFIX = 'skill://';
const HOUR = 60 * 60_000;

/** The packaged skills/ folder (dist/ or src/ layouts, or the cwd) */
function findSkillsRoot(): string | undefined {
  for (const dir of [join(__dirname, '../skills'), join(process.cwd(), 'skills')]) {
    if (existsSync(dir) && statSync(dir).isDirectory()) return dir;
  }
  return undefined;
}

function walk(dir: string, root: string, out: Record<string, Uint8Array>): void {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, root, out);
    else if (st.isFile()) out[relative(root, full).split(sep).join('/')] = readFileSync(full);
  }
}

/** uri -> file bytes for every published skill file */
const files = new Map<string, Uint8Array>();
let entries: Promise<Skill[]> | undefined;

function loadEntries(): Promise<Skill[]> {
  if (entries) return entries;
  const root = findSkillsRoot();
  entries = (async () => {
    if (!root) return [];
    const skills: Skill[] = [];
    for (const name of readdirSync(root).sort()) {
      const dir = join(root, name);
      if (!statSync(dir).isDirectory() || !existsSync(join(dir, 'SKILL.md'))) continue;
      const skillFiles: Record<string, Uint8Array> = {};
      walk(dir, dir, skillFiles);
      try {
        const skill = await skillEntry(name, skillFiles);
        for (const [path, bytes] of Object.entries(skillFiles)) files.set(`${SKILL_URI_PREFIX}${name}/${path}`, bytes);
        skills.push(skill);
      } catch (error) {
        logger.warn('Skipping invalid skill', { name, error: error instanceof Error ? error.message : String(error) });
      }
    }
    return skills;
  })();
  return entries;
}

/** Whether a resources/read URI belongs to the skills extension */
export const isSkillUri = (uri: string) => uri.startsWith(SKILL_URI_PREFIX);

export async function readSkillFile(uri: string) {
  await loadEntries();
  const bytes = files.get(uri);
  if (!bytes) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `No skill file is served at ${uri}`);
  const mimeType = uri.endsWith('.md') ? 'text/markdown' : 'text/plain';
  return { contents: [{ uri, mimeType, text: Buffer.from(bytes).toString('utf8') }] };
}

/** Declares the extension and registers skills/list and skills/get (before connecting) */
export function registerSkills(server: Server): void {
  if (!findSkillsRoot()) {
    logger.warn('skills/ folder not found; skills extension not advertised');
    return;
  }
  server.registerCapabilities({ extensions: { [SKILLS_EXTENSION_ID]: {} } } as any);

  const cache = { ttlMs: HOUR, cacheScope: 'public' as const };

  server.setRequestHandler(
    SKILLS_LIST_METHOD,
    { params: z.object({ cursor: z.string().optional() }).passthrough() },
    async () => ({ skills: await loadEntries(), ...cache }),
  );

  server.setRequestHandler(
    SKILLS_GET_METHOD,
    { params: z.object({ uri: z.string() }).passthrough() },
    async (params) => {
      const skill = (await loadEntries()).find((s) => s.uri === params.uri);
      if (!skill) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `No skill is served at ${params.uri}`);
      return { skill, ...cache };
    },
  );
}
