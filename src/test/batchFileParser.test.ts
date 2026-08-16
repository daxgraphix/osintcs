/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { validateBatchFile, parseBatchContent } from '../utils/batchFileParser';

describe('validateBatchFile', () => {
  it('rejects files larger than 5MB', () => {
    const file = new File([''], 'large.txt', { type: 'text/plain' });
    Object.defineProperty(file, 'size', { value: 6 * 1024 * 1024 });
    const error = validateBatchFile(file);
    expect(error).toBe('Batch file too large. Maximum size is 5MB.');
  });

  it('rejects invalid file types', () => {
    const file = new File([''], 'image.jpg', { type: 'image/jpeg' });
    const error = validateBatchFile(file);
    expect(error).toBe('Invalid file type. Please upload .txt or .csv files.');
  });

  it('accepts valid txt files', () => {
    const file = new File([''], 'targets.txt', { type: 'text/plain' });
    const error = validateBatchFile(file);
    expect(error).toBeNull();
  });

  it('accepts valid csv files', () => {
    const file = new File([''], 'targets.csv', { type: 'text/csv' });
    const error = validateBatchFile(file);
    expect(error).toBeNull();
  });
});

describe('parseBatchContent', () => {
  it('parses newline-separated targets', () => {
    const targets = parseBatchContent('example.com\ngoogle.com\ncloudflare.com');
    expect(targets).toEqual(['example.com', 'google.com', 'cloudflare.com']);
  });

  it('parses comma-separated targets', () => {
    const targets = parseBatchContent('example.com, google.com, cloudflare.com');
    expect(targets).toEqual(['example.com', 'google.com', 'cloudflare.com']);
  });

  it('parses semicolon-separated targets', () => {
    const targets = parseBatchContent('example.com;google.com;cloudflare.com');
    expect(targets).toEqual(['example.com', 'google.com', 'cloudflare.com']);
  });

  it('filters empty lines and trims whitespace', () => {
    const targets = parseBatchContent('example.com\n\n  google.com  \n;cloudflare.com;');
    expect(targets).toEqual(['example.com', 'google.com', 'cloudflare.com']);
  });

  it('throws for empty content', () => {
    expect(() => parseBatchContent('')).toThrow('File content exceeds maximum allowed size.');
    expect(() => parseBatchContent('   ')).toThrow('No valid targets found in batch file.');
  });

  it('throws for too many targets', () => {
    const manyTargets = Array(201).fill('example.com').join('\n');
    expect(() => parseBatchContent(manyTargets)).toThrow('Batch limit exceeded. Maximum 200 targets per batch.');
  });

  it('accepts content with exactly 200 targets', () => {
    const targets = Array(200).fill('example.com').join('\n');
    expect(() => parseBatchContent(targets)).not.toThrow();
  });
});
