/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Finding, Severity } from '../types';

export function calculateRiskScore(findings: Finding[]): {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passCount: number;
  infoCount: number;
} {
  let score = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let passCount = 0;
  let infoCount = 0;

  findings.forEach((f) => {
    switch (f.severity) {
      case 'critical':
        score += 30;
        criticalCount++;
        break;
      case 'high':
        score += 15;
        highCount++;
        break;
      case 'medium':
        score += 7;
        mediumCount++;
        break;
      case 'low':
        score += 2;
        lowCount++;
        break;
      case 'pass':
        passCount++;
        break;
      case 'info':
        infoCount++;
        break;
    }
  });

  score = Math.max(0, Math.min(100, score));

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
  if (score <= 5) grade = 'A+';
  else if (score <= 15) grade = 'A';
  else if (score <= 35) grade = 'B';
  else if (score <= 55) grade = 'C';
  else if (score <= 80) grade = 'D';
  else grade = 'F';

  return {
    score,
    grade,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    passCount,
    infoCount,
  };
}
