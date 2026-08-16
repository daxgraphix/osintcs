/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { escapeHtml, sanitizeText, validateDomain, validateEmail, validateHash, validateIp, validateUrl, validateUsername, sanitizeFilename } from '../utils/security';

describe('escapeHtml', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    expect(escapeHtml('a & b')).toBe('a &amp; b');
    expect(escapeHtml("it's")).toBe("it&#39;s");
  });

  it('passes through safe strings unchanged', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
    expect(escapeHtml('')).toBe('');
  });
});

describe('sanitizeText', () => {
  it('trims and truncates to maxLength', () => {
    const long = 'a'.repeat(3000);
    expect(sanitizeText(long, 500)).toHaveLength(500);
  });

  it('escapes HTML', () => {
    expect(sanitizeText('<b>bold</b>', 100)).toBe('&lt;b&gt;bold&lt;/b&gt;');
  });
});

describe('validateDomain', () => {
  it('accepts valid domains', () => {
    expect(validateDomain('example.com')).toBe(true);
    expect(validateDomain('sub.example.com')).toBe(true);
  });

  it('rejects invalid domains', () => {
    expect(validateDomain('not a domain')).toBe(false);
    expect(validateDomain('')).toBe(false);
  });
});

describe('validateEmail', () => {
  it('accepts valid emails', () => {
    expect(validateEmail('user@example.com')).toBe(true);
  });

  it('rejects invalid emails', () => {
    expect(validateEmail('notanemail')).toBe(false);
    expect(validateEmail('')).toBe(false);
  });
});

describe('validateHash', () => {
  it('accepts valid hash lengths', () => {
    expect(validateHash('a'.repeat(32))).toBe(true);
    expect(validateHash('a'.repeat(40))).toBe(true);
    expect(validateHash('a'.repeat(64))).toBe(true);
  });

  it('rejects invalid hashes', () => {
    expect(validateHash('notahex')).toBe(false);
    expect(validateHash('abc')).toBe(false);
  });
});

describe('validateIp', () => {
  it('accepts valid IPs', () => {
    expect(validateIp('192.168.1.1')).toBe(true);
    expect(validateIp('::1')).toBe(true);
  });

  it('rejects invalid IPs', () => {
    expect(validateIp('999.999.999.999')).toBe(false);
    expect(validateIp('')).toBe(false);
  });
});

describe('validateUrl', () => {
  it('accepts valid URLs', () => {
    expect(validateUrl('https://example.com')).toBe(true);
    expect(validateUrl('http://example.com')).toBe(true);
  });

  it('rejects invalid URLs', () => {
    expect(validateUrl('notaurl')).toBe(false);
    expect(validateUrl('')).toBe(false);
  });
});

describe('validateUsername', () => {
  it('accepts valid usernames', () => {
    expect(validateUsername('john_doe')).toBe(true);
    expect(validateUsername('user123')).toBe(true);
  });

  it('rejects invalid usernames', () => {
    expect(validateUsername('')).toBe(false);
    expect(validateUsername('a'.repeat(101))).toBe(false);
  });
});

describe('sanitizeFilename', () => {
  it('replaces special characters', () => {
    expect(sanitizeFilename('file name.txt')).toBe('file_name.txt');
    expect(sanitizeFilename('../../../etc/passwd')).toBe('.._.._.._etc_passwd');
  });

  it('truncates long names', () => {
    const long = 'a'.repeat(250) + '.txt';
    expect(sanitizeFilename(long)).toHaveLength(200);
  });
});
