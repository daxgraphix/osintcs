/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { detectTargetType, parseInvestigationTarget } from '../services/osintServices';

describe('detectTargetType', () => {
  it('detects email addresses', () => {
    expect(detectTargetType('user@example.com')).toBe('email');
    expect(detectTargetType('admin@sub.domain.co')).toBe('email');
  });

  it('detects IPv4 addresses', () => {
    expect(detectTargetType('192.168.1.1')).toBe('ip');
    expect(detectTargetType('8.8.8.8')).toBe('ip');
    expect(detectTargetType('0.0.0.0')).toBe('ip');
    expect(detectTargetType('255.255.255.255')).toBe('ip');
  });

  it('detects IPv6 addresses', () => {
    expect(detectTargetType('::1')).toBe('ip');
    expect(detectTargetType('2001:db8::1')).toBe('ip');
  });

  it('detects MD5 hashes', () => {
    expect(detectTargetType('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash');
  });

  it('detects SHA-1 hashes', () => {
    expect(detectTargetType('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('hash');
  });

  it('detects SHA-256 hashes', () => {
    expect(detectTargetType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe('hash');
  });

  it('detects URLs', () => {
    expect(detectTargetType('https://example.com')).toBe('website');
    expect(detectTargetType('http://example.com/path')).toBe('website');
  });

  it('detects domains', () => {
    expect(detectTargetType('example.com')).toBe('domain');
    expect(detectTargetType('sub.example.com')).toBe('domain');
    expect(detectTargetType('my-site.co.uk')).toBe('domain');
  });

  it('defaults to username for unrecognized input', () => {
    expect(detectTargetType('johndoe')).toBe('username');
    expect(detectTargetType('user_123')).toBe('username');
  });

  it('returns domain for empty input', () => {
    expect(detectTargetType('')).toBe('domain');
    expect(detectTargetType('   ')).toBe('domain');
  });

  it('rejects invalid IP octets', () => {
    expect(detectTargetType('999.999.999.999')).toBe('username');
    expect(detectTargetType('192.168.1')).toBe('username');
  });

  it('rejects hashes with non-hex characters', () => {
    expect(detectTargetType('xyz123')).toBe('username');
  });

  it('rejects hashes with wrong length', () => {
    expect(detectTargetType('abcd1234')).toBe('username');
  });
});

describe('parseInvestigationTarget', () => {
  it('parses domain input', () => {
    const result = parseInvestigationTarget('example.com');
    expect(result.value).toBe('example.com');
    expect(result.type).toBe('domain');
  });

  it('trims whitespace', () => {
    const result = parseInvestigationTarget('  example.com  ');
    expect(result.value).toBe('example.com');
  });

  it('detects type from input', () => {
    expect(parseInvestigationTarget('user@example.com').type).toBe('email');
    expect(parseInvestigationTarget('https://example.com').type).toBe('website');
    expect(parseInvestigationTarget('192.168.1.1').type).toBe('ip');
  });
});
