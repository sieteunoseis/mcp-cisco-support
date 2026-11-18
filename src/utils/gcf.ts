/**
 * Tool output encoding.
 *
 * Results are encoded as GCF (compact, token-efficient text) by default.
 * Set DISABLE_GCF_FORMAT=true (or the 2.x name DISABLE_TOON_FORMAT=true)
 * to return pretty-printed JSON instead.
 */
import { encodeGeneric } from '@blackwell-systems/gcf';
import { logger } from './logger.js';

export function useGcf(): boolean {
  return process.env.DISABLE_GCF_FORMAT !== 'true' && process.env.DISABLE_TOON_FORMAT !== 'true';
}

export function encodeResult(result: unknown): string {
  if (useGcf()) {
    try {
      return encodeGeneric(result as any);
    } catch (error) {
      logger.warn('GCF encoding failed, returning JSON', { error: error instanceof Error ? error.message : error });
    }
  }
  return JSON.stringify(result, null, 2);
}
