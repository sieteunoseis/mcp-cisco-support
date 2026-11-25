/**
 * MCP Skills extension: the bundled skills/ folder served as skill:// files.
 */
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { isSkillUri, readSkillFile } from '../src/skills';

const SKILL_URI = 'skill://cisco-support-mcp/SKILL.md';

describe('skills', () => {
  test('recognizes skill:// URIs', () => {
    expect(isSkillUri(SKILL_URI)).toBe(true);
    expect(isSkillUri('cisco://bugs/CSCwh87343')).toBe(false);
  });

  test('serves SKILL.md verbatim as markdown', async () => {
    const onDisk = readFileSync(join(__dirname, '../skills/cisco-support-mcp/SKILL.md'), 'utf8');
    const { contents } = await readSkillFile(SKILL_URI);
    expect(contents[0]).toEqual({ uri: SKILL_URI, mimeType: 'text/markdown', text: onDisk });
    expect(createHash('sha256').update(contents[0].text).digest('hex')).toHaveLength(64);
  });

  test('rejects unknown skill files with InvalidParams', async () => {
    await expect(readSkillFile('skill://nope/SKILL.md')).rejects.toMatchObject({ code: -32602 });
  });
});
