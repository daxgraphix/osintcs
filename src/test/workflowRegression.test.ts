/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { createScanRequestGuard, assignBatchResult, normalizeScanResult } from '../hooks/useScanWorkflow';
import { normalizeSubdomainCandidates } from '../services/osintServices';

describe('scan workflow guards', () => {
  it('preserves original batch order even when results resolve out of order', () => {
    const results: Array<{ riskScore: number } | undefined> = new Array(3);

    assignBatchResult(results, 2, { riskScore: 20 });
    assignBatchResult(results, 0, { riskScore: 10 });
    assignBatchResult(results, 1, { riskScore: 30 });

    expect(results.map((result) => result?.riskScore)).toEqual([10, 30, 20]);
  });

  it('ignores stale scan completions from older requests', () => {
    const guard = createScanRequestGuard();
    const firstRequestId = guard.begin();
    const secondRequestId = guard.begin();

    expect(guard.isCurrent(firstRequestId)).toBe(false);
    expect(guard.isCurrent(secondRequestId)).toBe(true);
  });

  it('deduplicates repeated findings and normalizes aggregated risk scores', () => {
    const normalized = normalizeScanResult({
      target: { value: 'example.com', type: 'domain' },
      scanTime: 'now',
      dataSource: 'mixed',
      findings: [
        { id: 'F-1', module: 'domain', title: 'DNS misconfig', description: 'A', severity: 'high', category: 'DNS', remediation: 'Fix' },
        { id: 'F-1', module: 'domain', title: 'DNS misconfig', description: 'A', severity: 'high', category: 'DNS', remediation: 'Fix' },
        { id: 'F-2', module: 'website', title: 'HSTS missing', description: 'B', severity: 'medium', category: 'TLS', remediation: 'Add HSTS' },
      ],
      recommendations: [],
      timeline: [],
      riskScore: 0,
    });

    expect(normalized.findings).toHaveLength(2);
    expect(normalized.riskScore).toBeGreaterThan(0);
  });

  it('caps and deduplicates subdomain candidates to avoid expensive validation bursts', () => {
    const candidates = Array.from({ length: 120 }, (_, index) => `host-${index % 10}.example.com`);
    const deduped = normalizeSubdomainCandidates(candidates, 32);

    expect(deduped.length).toBeLessThanOrEqual(32);
    expect(new Set(deduped).size).toBe(deduped.length);
  });
});
