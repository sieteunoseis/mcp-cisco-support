/**
 * Exact-release resolution for tools that need one (PSIRT by OS release,
 * upgrade assessment). A partial release ("17", "17.9") or one Cisco rejects
 * raises VersionNeeded with candidate releases; the tools/call handler then
 * asks the user (elicitation) or returns the candidates for the model to ask.
 *
 * Verified live 2026-11-19: PSIRT /OSType answers 406 INVALID_<OS>_VERSION for
 * partial releases; /OS_version/OS_data lists known releases per OS but is not
 * complete (17.15.4b is missing yet valid), so it only supplies candidates and
 * never rejects a release on its own. The Bug API accepts train-level releases
 * ("17.9"), so bug_search does not ask.
 */
import type { ApiClient } from './index.js';

export class VersionNeeded extends Error {
  constructor(
    /** Tool argument to fill in, e.g. "version" or "current_version" */
    readonly argument: string,
    /** What the user typed */
    readonly given: string,
    /** Exact releases (or trains, when `level` is "train") to choose from; may be empty */
    readonly options: string[],
    readonly level: 'release' | 'train',
    readonly osType?: string,
    /** The partial value is itself a valid query (Bug API trains): offer it as a choice, never block on it */
    readonly allowAsIs = false,
    /** The argument is a comma-separated list; only this item gets replaced */
    readonly listItem = false,
  ) {
    super(`${argument} "${given}" is not an exact release${osType ? ` for ${osType}` : ''}`);
  }
}

/** "17" or "17.9": a major or train, not an exact release */
export function isPartialRelease(value: string): boolean {
  return /^\d+(\.\d+)?$/.test(value.trim());
}

/** Cisco answers unknown releases with 406 and errorCode INVALID_<OS>_VERSION */
export function isInvalidVersionError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /\b406\b/.test(message) && /INVALID_[A-Z]+_VERSION/.test(message);
}

const MAX_OPTIONS = 40; // a train has ~30 releases at most (17.9 has 26)
const cache = new Map<string, { at: number; versions: string[] }>();
const CACHE_MS = 6 * 60 * 60_000;

/** Known releases for an OS type from PSIRT (cached 6 h); [] if unavailable */
export async function knownReleases(psirt: ApiClient, osType: string): Promise<string[]> {
  const key = osType.toLowerCase();
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.versions;
  try {
    const body = await psirt.request('/OS_version/OS_data', { OSType: key });
    const list: any[] = Array.isArray(body) ? body : Object.values(body ?? {});
    const versions = [...new Set(list.map(v => v?.nos_version).filter((v): v is string => typeof v === 'string'))];
    cache.set(key, { at: Date.now(), versions });
    return versions;
  } catch {
    return [];
  }
}

/** Newest first: compares numeric and letter parts of Cisco release strings */
export function compareReleasesDesc(a: string, b: string): number {
  const parts = (v: string) => v.split(/[.()]/).map(p => {
    const m = /^(\d+)(.*)$/.exec(p);
    return m ? [Number(m[1]), m[2]] as const : [-1, p] as const;
  });
  const pa = parts(a), pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const [na, sa] = pa[i] ?? [-1, ''];
    const [nb, sb] = pb[i] ?? [-1, ''];
    if (na !== nb) return nb - na;
    if (sa !== sb) return sb > sa ? 1 : -1;
  }
  return 0;
}

/**
 * Options to offer for a partial release: the exact releases under the prefix,
 * or (when there are too many) the trains under it, so the user picks a train
 * first and then a release.
 */
export function optionsFor(all: string[], given: string): { options: string[]; level: 'release' | 'train' } {
  const prefix = given.trim();
  const matches = all.filter(v => v === prefix || v.startsWith(prefix + '.')).sort(compareReleasesDesc);
  if (matches.length <= MAX_OPTIONS) return { options: matches, level: 'release' };
  const depth = prefix.split('.').length + 1;
  const trains = [...new Set(matches.map(v => v.split('.').slice(0, depth).join('.').replace(/[a-z]\w*$/i, '')))].sort(compareReleasesDesc);
  return trains.length > 1
    ? { options: trains.slice(0, MAX_OPTIONS), level: 'train' }
    : { options: matches.slice(0, MAX_OPTIONS), level: 'release' };
}

/** Raise VersionNeeded for a partial release, with candidates from PSIRT */
export async function requireExactRelease(
  psirt: ApiClient, argument: string, value: string, osType: string | undefined,
): Promise<void> {
  if (!isPartialRelease(value)) return;
  await raiseVersionNeeded(psirt, argument, value, osType);
}

export async function raiseVersionNeeded(
  psirt: ApiClient, argument: string, value: string, osType: string | undefined,
  opts: { allowAsIs?: boolean; listItem?: boolean } = {},
): Promise<never> {
  const all = osType ? await knownReleases(psirt, osType) : [];
  const prefix = isPartialRelease(value) ? value : value.split('.').slice(0, 2).join('.');
  const { options, level } = optionsFor(all, prefix);
  throw new VersionNeeded(argument, value, options, level, osType, !!opts.allowAsIs, !!opts.listItem);
}
