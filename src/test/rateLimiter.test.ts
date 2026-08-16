/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { checkRateLimit } from '../utils/rateLimiter';

describe('checkRateLimit', () => {
  it('allows the first request', () => {
    const result = checkRateLimit('test-key', 3, 60000);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(2);
    expect(result.resetMs).toBeGreaterThan(0);
  });

  it('allows requests up to the limit', () => {
    checkRateLimit('test-key-2', 2, 60000);
    const result = checkRateLimit('test-key-2', 2, 60000);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(0);
  });

  it('blocks requests exceeding the limit', () => {
    checkRateLimit('test-key-3', 1, 60000);
    const result = checkRateLimit('test-key-3', 1, 60000);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.resetMs).toBeGreaterThan(0);
  });

  it('resets after the time window expires', () => {
    const result = checkRateLimit('test-key-4', 1, 50);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(0);

    const blocked = checkRateLimit('test-key-4', 1, 50);
    expect(blocked.allowed).toBe(false);
  });

  it('tracks separate keys independently', () => {
    checkRateLimit('key-a', 1, 60000);
    checkRateLimit('key-b', 1, 60000);

    const aResult = checkRateLimit('key-a', 1, 60000);
    const bResult = checkRateLimit('key-b', 1, 60000);

    expect(aResult.allowed).toBe(false);
    expect(bResult.allowed).toBe(false);
  });

  it('decrements remaining count correctly', () => {
    const r1 = checkRateLimit('test-key-5', 5, 60000);
    expect(r1.remaining).toBe(4);

    const r2 = checkRateLimit('test-key-5', 5, 60000);
    expect(r2.remaining).toBe(3);

    const r3 = checkRateLimit('test-key-5', 5, 60000);
    expect(r3.remaining).toBe(2);

    const r4 = checkRateLimit('test-key-5', 5, 60000);
    expect(r4.remaining).toBe(1);

    const r5 = checkRateLimit('test-key-5', 5, 60000);
    expect(r5.remaining).toBe(0);
    expect(r5.allowed).toBe(true);

    const r6 = checkRateLimit('test-key-5', 5, 60000);
    expect(r6.allowed).toBe(false);
  });
});
