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

      const rootCause = f.description ? f.description.replace(/\.$/, '') : 'The observed issue is caused by configuration drift or incomplete validation.';
      const actionPlan = f.remediation && f.remediation.trim().length > 0
        ? f.remediation
        : `Review the configuration for ${f.module} and confirm the control is enforced consistently across production and staging.`;

      recommendations.push({
        id: `REC_${f.id}`,
        title: `${f.title.includes('Remediate') ? '' : 'Remediate '}${f.title}`.trim(),
        description: `${actionPlan}. Root cause: ${rootCause}. Validate the fix by re-running the relevant scan and confirming the control is active across all environments.`,
        priority,
        category: f.category || 'Security Hygiene',
        impact: `Reduces exposure from ${f.title.toLowerCase()} and improves baseline security posture while reducing the likelihood of repeat exploitation.`,
      });
    });

  if (recommendations.length === 0) {
    recommendations.push({
      id: 'REC_DEFAULT_MAINTENANCE',
      title: 'Maintain Regular Security Audits',
      description: 'Continue tracking and scanning this endpoint on a monthly cadence to capture configuration drift, certificate expiration, and policy gaps before they become exploitable.',
      priority: 'low',
      category: 'General Hygiene',
      impact: 'Creates a reliable security baseline and helps detect drift before it affects operational exposure.',
    });
  }

  return recommendations.slice(0, 12);
}
