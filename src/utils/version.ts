import { readFileSync } from 'fs';
import { join } from 'path';

/** Package version, read from package.json (dist/ or src/ layouts, or the cwd) */
function readVersion(): string {
  for (const path of [
    join(__dirname, '../../package.json'), // dist/utils/ or src/utils/
    join(__dirname, '../package.json'),
    join(process.cwd(), 'package.json'),
  ]) {
    try {
      const pkg = JSON.parse(readFileSync(path, 'utf8'));
      if (pkg.name === 'mcp-cisco-support' && pkg.version) return pkg.version;
    } catch {
      // try the next location
    }
  }
  return '0.0.0';
}

export const VERSION = readVersion();
