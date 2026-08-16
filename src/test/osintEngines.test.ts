/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { calculateRiskScore, generateRecommendations, buildTimeline } from '../engines/osintEngines';
import { generateReportDocument } from '../engines/reportEngine';
import { Finding, TimelineEvent } from '../types';

describe('calculateRiskScore', () => {
  it('returns A+ for no findings', () => {
    const result = calculateRiskScore([]);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('A+');
    expect(result.criticalCount).toBe(0);
    expect(result.highCount).toBe(0);
    expect(result.mediumCount).toBe(0);
    expect(result.lowCount).toBe(0);
    expect(result.passCount).toBe(0);
    expect(result.infoCount).toBe(0);
  });

  it('scores critical findings at 30 points each', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Critical', description: '', severity: 'critical', category: '', remediation: '' },
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(30);
    expect(result.grade).toBe('B');
    expect(result.criticalCount).toBe(1);
  });

  it('scores high findings at 15 points each', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'High', description: '', severity: 'high', category: '', remediation: '' },
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(15);
    expect(result.grade).toBe('A');
    expect(result.highCount).toBe(1);
  });

  it('scores medium findings at 7 points each', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Medium', description: '', severity: 'medium', category: '', remediation: '' },
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(7);
    expect(result.grade).toBe('A');
    expect(result.mediumCount).toBe(1);
  });

  it('scores low findings at 2 points each', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Low', description: '', severity: 'low', category: '', remediation: '' },
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(2);
    expect(result.grade).toBe('A+');
    expect(result.lowCount).toBe(1);
  });

  it('clamps score to 0-100', () => {
    const findings: Finding[] = Array(10).fill({ id: '1', module: 'test', title: 'Critical', description: '', severity: 'critical', category: '', remediation: '' } as Finding);
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('F');
  });

  it('counts pass and info findings without adding to score', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Pass', description: '', severity: 'pass', category: '', remediation: '' },
      { id: '2', module: 'test', title: 'Info', description: '', severity: 'info', category: '', remediation: '' },
    ];
    const result = calculateRiskScore(findings);
    expect(result.score).toBe(0);
    expect(result.passCount).toBe(1);
    expect(result.infoCount).toBe(1);
  });
});

describe('generateRecommendations', () => {
  it('generates recommendations from findings', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Critical Issue', description: '', severity: 'critical', category: 'Test', remediation: 'Fix it' },
    ];
    const recs = generateRecommendations(findings);
    expect(recs).toHaveLength(1);
    expect(recs[0].title).toBe('Remediate Critical Issue');
    expect(recs[0].priority).toBe('high');
  });

  it('excludes pass and info findings', () => {
    const findings: Finding[] = [
      { id: '1', module: 'test', title: 'Pass', description: '', severity: 'pass', category: '', remediation: '' },
      { id: '2', module: 'test', title: 'Info', description: '', severity: 'info', category: '', remediation: '' },
    ];
    const recs = generateRecommendations(findings);
    expect(recs).toHaveLength(1);
    expect(recs[0].id).toBe('REC_DEFAULT_MAINTENANCE');
  });

  it('returns default recommendation when no actionable findings', () => {
    const recs = generateRecommendations([]);
    expect(recs).toHaveLength(1);
    expect(recs[0].id).toBe('REC_DEFAULT_MAINTENANCE');
  });

  it('generates actionable remediation guidance with root-cause and impact details', () => {
    const findings: Finding[] = [
      { id: '1', module: 'dns', title: 'DNSSEC Missing', description: 'DNSSEC is not enabled for the zone.', severity: 'high', category: 'DNS Security', remediation: 'Enable DNSSEC and sign zone data.' },
    ];
    const recs = generateRecommendations(findings);
    expect(recs[0].title).toContain('DNSSEC');
    expect(recs[0].description).toContain('Enable');
    expect(recs[0].impact).toMatch(/risk|security|validate/i);
  });
});

describe('generateReportDocument', () => {
  it('includes a structured summary and evidence section for exported reports', () => {
    const report = generateReportDocument({
      target: { value: 'example.com', type: 'domain' },
      scanTime: '2026-08-16',
      riskScore: 42,
      findings: [
        { id: '1', module: 'dns', title: 'DNSSEC Missing', description: 'DNSSEC is not enabled for the zone.', severity: 'high', category: 'DNS Security', remediation: 'Enable DNSSEC and sign the zone.' },
      ],
      recommendations: [
        { id: 'REC_1', title: 'Enable DNSSEC', description: 'Enable DNSSEC on all authoritative nameservers and validate with dig + DNSViz.', priority: 'high', category: 'DNS Security', impact: 'Reduces spoofing and cache-poisoning risk.' },
      ],
      dns: {
        records: { A: ['93.184.216.34'] },
        spf: { present: false, valid: false },
        dmarc: { present: false },
        dnssec: { enabled: false },
      },
    }, 'markdown', 'detailed');

    expect(report).toContain('EXECUTIVE SUMMARY');
    expect(report).toContain('TECHNICAL EVIDENCE');
    expect(report).toContain('DNSSEC');
  });
});

describe('buildTimeline', () => {
  it('returns empty array when no data provided', () => {
    const events = buildTimeline({});
    expect(events).toEqual([]);
  });

  it('builds timeline from whois data', () => {
    const events = buildTimeline({
      whois: {
        creationDate: '2020-01-01',
        updatedDate: '2023-01-01',
        expiryDate: '2025-01-01',
      } as any,
    });
    expect(events).toHaveLength(3);
    expect(events[0].title).toBe('Initial Domain Registration');
    expect(events[1].title).toBe('Last Registration Update');
    expect(events[2].title).toBe('Domain Registration Expiration');
  });

  it('builds timeline from ssl data', () => {
    const events = buildTimeline({
      ssl: {
        validFrom: '2023-01-01',
        validTo: '2024-01-01',
      } as any,
    });
    expect(events).toHaveLength(2);
    expect(events[0].title).toBe('SSL Certificate Issued');
    expect(events[1].title).toBe('SSL Certificate Expiration');
  });

  it('sorts events chronologically', () => {
    const events = buildTimeline({
      ssl: {
        validTo: '2023-06-01',
        validFrom: '2022-06-01',
      } as any,
      whois: {
        creationDate: '2020-01-01',
      } as any,
    });
    expect(events[0].date).toBe('2020-01-01');
    expect(events[1].date).toBe('2022-06-01');
    expect(events[2].date).toBe('2023-06-01');
  });
});
