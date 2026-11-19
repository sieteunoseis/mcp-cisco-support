import { createHash } from 'node:crypto';

/**
 * Per-client token bucket for HTTP mode. Each client may make `perMinute`
 * requests per minute, with bursts up to `perMinute`. Kept in memory per
 * process (fine for a stateless server; each replica limits on its own).
 */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; updated: number }>();

  constructor(private perMinute: number, private now: () => number = Date.now) {}

  get enabled(): boolean {
    return this.perMinute > 0;
  }

  /** Returns 0 when allowed, otherwise the seconds to wait before retrying */
  take(key: string): number {
    if (!this.enabled) return 0;
    const t = this.now();
    const refillPerMs = this.perMinute / 60_000;
    const b = this.buckets.get(key) ?? { tokens: this.perMinute, updated: t };
    b.tokens = Math.min(this.perMinute, b.tokens + (t - b.updated) * refillPerMs);
    b.updated = t;
    this.buckets.set(key, b);
    this.prune(t);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil((1 - b.tokens) / refillPerMs / 1000));
  }

  // Drop buckets that have refilled completely, so the map can't grow forever
  private prune(t: number): void {
    if (this.buckets.size < 10_000) return;
    for (const [key, b] of this.buckets) {
      if (b.tokens + (t - b.updated) * (this.perMinute / 60_000) >= this.perMinute) this.buckets.delete(key);
    }
  }
}

/** Bucket key: the bearer token (hashed, never stored raw) or the client IP */
export function rateLimitKey(authorization: string | undefined, ip: string | undefined): string {
  if (authorization?.startsWith('Bearer ')) {
    return 'tok:' + createHash('sha256').update(authorization.slice(7).trim()).digest('hex').slice(0, 32);
  }
  return 'ip:' + (ip || 'unknown');
}
