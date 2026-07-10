/**
 * Simple client-side rate limiter.
 */

type RateLimitRecord = {
  count: number;
  resetTime: number;
};

const rateLimitStore: Record<string, RateLimitRecord> = {};

export function checkRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  const record = rateLimitStore[key];

  if (!record || now > record.resetTime) {
    rateLimitStore[key] = {
      count: 1,
      resetTime: now + windowMs,
    };
    return {
      allowed: true,
      remaining: maxRequests - 1,
      resetMs: windowMs,
    };
  }

  if (record.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetMs: record.resetTime - now,
    };
  }

  record.count += 1;
  return {
    allowed: true,
    remaining: maxRequests - record.count,
    resetMs: record.resetTime - now,
  };
}
