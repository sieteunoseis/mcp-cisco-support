import { RateLimiter, rateLimitKey } from '../src/utils/rate-limit';

describe('RateLimiter', () => {
  test('allows a burst up to the limit, then asks to wait, then refills', () => {
    let now = 0;
    const limiter = new RateLimiter(3, () => now);
    expect([limiter.take('a'), limiter.take('a'), limiter.take('a')]).toEqual([0, 0, 0]);
    expect(limiter.take('a')).toBeGreaterThan(0);   // 4th request in the same instant
    expect(limiter.take('b')).toBe(0);              // other clients are independent
    now += 20_000;                                  // 3/min = 1 token per 20s
    expect(limiter.take('a')).toBe(0);
  });

  test('0 disables limiting', () => {
    const limiter = new RateLimiter(0);
    for (let i = 0; i < 1000; i++) expect(limiter.take('a')).toBe(0);
  });

  test('keys by hashed bearer token, else by IP', () => {
    const k = rateLimitKey('Bearer secret-token', '10.0.0.1');
    expect(k).toMatch(/^tok:[0-9a-f]{32}$/);
    expect(k).not.toContain('secret-token');
    expect(rateLimitKey(undefined, '10.0.0.1')).toBe('ip:10.0.0.1');
  });
});
