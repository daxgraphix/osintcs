/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Finding, Recommendation } from '../types';

export function generateRecommendations(findings: Finding[]): Recommendation[] {
  const recommendations: Recommendation[] = [];

  findings
    .filter((f) => f.severity !== 'pass' && f.severity !== 'info')
    .forEach((f) => {
      let priority: 'high' | 'medium' | 'low' = 'low';
      if (f.severity === 'critical' || f.severity === 'high') priority = 'high';
      else if (f.severity === 'medium') priority = 'medium';

      recommendations.push({
        id: `REC_${f.id}`,
        title: `Remediate ${f.title}`,
        description: f.remediation,
        priority,
        category: f.category,
        impact: `Resolves the identified vulnerability: ${f.title}.`,
      });
    });

  if (recommendations.length === 0) {
    recommendations.push({
      id: 'REC_DEFAULT_MAINTENANCE',
      title: 'Maintain Regular Security Audits',
      description: 'Continue tracking and scanning this endpoint on a monthly cadence to capture configuration drift or key expirations.',
      priority: 'low',
      category: 'General Hygiene',
      impact: 'Establishes secure, consistent baseline awareness.',
    });
  }

  return recommendations;
}
