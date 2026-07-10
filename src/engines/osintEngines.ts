/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Finding, Recommendation, TimelineEvent, Severity } from '../types';

/**
 * 1. RISK & SCORE ENGINE
 * Calculates a score from 0 to 100 where 100 represents MAXIMUM risk (Critical Danger).
 */
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

  // Clamp risk score to 0 - 100
  score = Math.max(0, Math.min(100, score));

  // Determine Security Grade (Lower Risk = Higher Letter Grade)
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

/**
 * 2. RECOMMENDATION ENGINE
 * Maps triggered active findings to targeted actions.
 */
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

  // Default recommendation if everything is safe
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

/**
 * 3. TIMELINE ENGINE
 * Aggregates registration, update, and expiration dates into a sorted chronolgical stream.
 */
export function buildTimeline(scanResults: {
  whois?: any;
  ssl?: any;
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  const { whois, ssl } = scanResults;

  if (whois) {
    if (whois.creationDate) {
      events.push({
        id: 'TL_WHOIS_CREATION',
        date: whois.creationDate,
        title: 'Initial Domain Registration',
        description: `Domain was first registered through "${whois.registrar || 'Registrar'}"`,
        category: 'whois',
      });
    }
    if (whois.updatedDate) {
      events.push({
        id: 'TL_WHOIS_UPDATED',
        date: whois.updatedDate,
        title: 'Last Registration Update',
        description: 'Domain details or nameservers were modified or renewed.',
        category: 'whois',
      });
    }
    if (whois.expiryDate) {
      events.push({
        id: 'TL_WHOIS_EXPIRY',
        date: whois.expiryDate,
        title: 'Domain Registration Expiration',
        description: 'The current domain registration lease is scheduled to expire.',
        category: 'whois',
      });
    }
  }

  if (ssl) {
    if (ssl.validFrom) {
      events.push({
        id: 'TL_SSL_START',
        date: ssl.validFrom,
        title: 'SSL Certificate Issued',
        description: `A cryptographic SSL certificate was issued by "${ssl.issuer || 'CA'}"`,
        category: 'ssl',
      });
    }
    if (ssl.validTo) {
      events.push({
        id: 'TL_SSL_EXPIRY',
        date: ssl.validTo,
        title: 'SSL Certificate Expiration',
        description: 'The current certificate expires and must be replaced to prevent browser trust errors.',
        category: 'ssl',
      });
    }
  }

  // Sort events chronologically (oldest to newest)
  return events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}

/**
 * 4. EXECUTIVE REPORT EXPORT BUILDER
 * Generates formatted text documents representing investigation results.
 */
export function generateReportDocument(
  results: any,
  format: 'markdown' | 'json' | 'csv' | 'txt' | 'html',
  template: 'detailed' | 'concise' = 'detailed'
): string {
  const { target, scanTime, riskScore, findings, recommendations } = results;
  const metrics = calculateRiskScore(findings);

  if (format === 'json') {
    if (template === 'concise') {
      // Create a simplified summary JSON
      const conciseResults = {
        target,
        scanTime,
        riskScore,
        grade: metrics.grade,
        summary: {
          critical: metrics.criticalCount,
          high: metrics.highCount,
          medium: metrics.mediumCount,
          low: metrics.lowCount,
          pass: metrics.passCount,
        },
        findings: findings
          .filter((f: Finding) => f.severity !== 'pass' && f.severity !== 'info')
          .map((f: Finding) => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            category: f.category,
            description: f.description,
          })),
        recommendationTitles: recommendations.map((r: Recommendation) => r.title),
      };
      return JSON.stringify(conciseResults, null, 2);
    }
    return JSON.stringify(results, null, 2);
  }

  if (format === 'csv') {
    let csv = 'ID,Module,Severity,Title,Category,Description,Remediation\n';
    const targetsList = template === 'concise' 
      ? findings.filter((f: Finding) => f.severity !== 'pass' && f.severity !== 'info') 
      : findings;

    targetsList.forEach((f: Finding) => {
      const row = [
        f.id,
        f.module,
        f.severity,
        f.title,
        f.category,
        f.description,
        f.remediation,
      ].map((val) => `"${(val || '').replace(/"/g, '""')}"`);
      csv += row.join(',') + '\n';
    });
    return csv;
  }

  if (format === 'markdown') {
    let md = `# OSINTCS SECURITY INVESTIGATION REPORT (${template.toUpperCase()} VIEW)\n\n`;
    md += `**Target:** \`${target.value}\` (${target.type.toUpperCase()})\n`;
    md += `**Scan Timestamp:** ${scanTime}\n`;
    md += `**Overall Risk Score:** **${riskScore}/100** (Grade: **${metrics.grade}**)\n\n`;

    md += `## EXECUTIVE SUMMARY\n`;
    md += `A comprehensive browser-side OSINT audit of \`${target.value}\` was executed. `;
    md += `The analysis identified **${metrics.criticalCount}** critical vulnerabilities, `;
    md += `**${metrics.highCount}** high-risk findings, and **${metrics.mediumCount}** moderate-risk findings. `;
    md += `The overall grade assigned is **${metrics.grade}**.\n\n`;

    md += `## KEY FINDINGS\n\n`;
    findings.forEach((f: Finding) => {
      if (f.severity !== 'pass') {
        md += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
        md += `- **Module:** ${f.module.toUpperCase()}\n`;
        md += `- **Category:** ${f.category}\n`;
        md += `- **Description:** ${f.description}\n`;
        if (template !== 'concise') {
          md += `- **Remediation:** ${f.remediation}\n`;
        }
        md += `\n`;
      }
    });

    md += `## ACTIONABLE RECOMMENDATIONS\n\n`;
    recommendations.forEach((r: Recommendation, index: number) => {
      md += `${index + 1}. **[${r.priority.toUpperCase()}] ${r.title}**\n`;
      if (template !== 'concise') {
        md += `   - **Vulnerability Category:** ${r.category}\n`;
        md += `   - **Action Item:** ${r.description}\n`;
        md += `   - **Expected Impact:** ${r.impact}\n\n`;
      } else {
        md += `   - **Action Item:** ${r.description}\n\n`;
      }
    });

    if (template !== 'concise') {
      md += `## TECHNICAL EVIDENCE\n\n`;
      if (results.dns) {
        md += `### DNS Records Summary\n\`\`\`json\n${JSON.stringify(results.dns.records, null, 2)}\n\`\`\`\n\n`;
      }
      if (results.whois) {
        md += `### WHOIS Registration Raw\n\`\`\`text\n${results.whois.raw}\n\`\`\`\n\n`;
      }
      if (results.ssl) {
        md += `### SSL Handshake Details\n- **Issuer:** ${results.ssl.issuer}\n- **Protocol:** ${results.ssl.protocol}\n- **Cipher Suite:** ${results.ssl.cipher}\n- **Remaining Days:** ${results.ssl.daysRemaining}\n\n`;
      }
    }

    md += `---\n*Generated by OSINTCS. Privacy-First OSINT Workspace.*`;
    return md;
  }

  if (format === 'html') {
    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>OSINTCS Investigation Report: ${target.value}</title>`;
    html += `<style>body{font-family:sans-serif;line-height:1.6;color:#333;padding:40px;max-width:800px;margin:auto;} h1{border-bottom:2px solid #ddd;padding-bottom:10px;color:#1e293b;} .badge{padding:4px 8px;border-radius:4px;font-weight:bold;font-size:12px;color:#fff;} .critical{background:#ef4444;} .high{background:#f97316;} .medium{background:#eab308;} .low{background:#3b82f6;} .card{border:1px solid #e2e8f0;padding:16px;border-radius:8px;margin-bottom:16px;background:#f8fafc;} table{width:100%;border-collapse:collapse;margin:20px 0;} th,td{border:1px solid #cbd5e1;padding:12px;text-align:left;} th{background:#e2e8f0;}</style></head><body>`;
    html += `<h1>OSINTCS Security Investigation Report (${template.toUpperCase()})</h1>`;
    html += `<p><strong>Target:</strong> <code>${target.value}</code> (${target.type.toUpperCase()})</p>`;
    html += `<p><strong>Scan Timestamp:</strong> ${scanTime}</p>`;
    html += `<p><strong>Risk Score:</strong> <strong style="font-size:1.5em;color:#e11d48;">${riskScore}/100</strong> (Grade: ${metrics.grade})</p>`;

    html += `<h2>Executive Summary</h2>`;
    html += `<p>A comprehensive browser-side OSINT audit of <code>${target.value}</code> was executed. The analysis identified <strong>${metrics.criticalCount}</strong> critical issues, <strong>${metrics.highCount}</strong> high-risk findings, and <strong>${metrics.mediumCount}</strong> moderate-risk findings.</p>`;

    html += `<h2>Findings</h2>`;
    findings.forEach((f: Finding) => {
      if (f.severity !== 'pass') {
        html += `<div class="card">`;
        html += `<h3><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span> ${f.title}</h3>`;
        html += `<p><strong>Module:</strong> ${f.module.toUpperCase()} | <strong>Category:</strong> ${f.category}</p>`;
        html += `<p>${f.description}</p>`;
        if (template !== 'concise') {
          html += `<p><strong>Remediation:</strong> <code>${f.remediation}</code></p>`;
        }
        html += `</div>`;
      }
    });

    html += `<h2>Recommendations</h2>`;
    html += `<table><thead><tr><th>Priority</th><th>Action Recommendation</th>${template !== 'concise' ? '<th>Vulnerability Category</th>' : ''}</tr></thead><tbody>`;
    recommendations.forEach((r: Recommendation) => {
      html += `<tr><td><span class="badge ${r.priority === 'high' ? 'critical' : r.priority === 'medium' ? 'high' : 'low'}">${r.priority.toUpperCase()}</span></td><td><strong>${r.title}</strong><br>${r.description}</td>${template !== 'concise' ? `<td>${r.category}</td>` : ''}</tr>`;
    });
    html += `</tbody></table>`;

    if (template !== 'concise') {
      html += `<h2>Technical Evidence Details</h2>`;
      if (results.dns) {
        html += `<h3>DNS Zone Records</h3><pre style="background:#f1f5f9;padding:12px;border-radius:6px;overflow-x:auto;">${JSON.stringify(results.dns.records, null, 2)}</pre>`;
      }
      if (results.whois) {
        html += `<h3>WHOIS Registry Data</h3><pre style="background:#f1f5f9;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;">${results.whois.raw || 'N/A'}</pre>`;
      }
    }

    html += `<p style="margin-top:60px;color:#64748b;font-size:12px;text-align:center;border-top:1px solid #e2e8f0;padding-top:20px;">Report compiled by OSINTCS Privacy-First Workspace.</p>`;
    html += `</body></html>`;
    return html;
  }

  // Fallback: Plain text formatting
  let txt = `==================================================\n`;
  txt += `   OSINTCS SECURITY INVESTIGATION REPORT (${template.toUpperCase()})\n`;
  txt += `==================================================\n\n`;
  txt += `Target: ${target.value} (${target.type.toUpperCase()})\n`;
  txt += `Scan Date: ${scanTime}\n`;
  txt += `Overall Risk Score: ${riskScore}/100 (Grade: ${metrics.grade})\n\n`;
  txt += `Findings Summary:\n`;
  txt += `- Critical: ${metrics.criticalCount}\n`;
  txt += `- High: ${metrics.highCount}\n`;
  txt += `- Medium: ${metrics.mediumCount}\n`;
  txt += `- Low: ${metrics.lowCount}\n\n`;
  txt += `--------------------------------------------------\n\n`;
  findings.forEach((f: Finding) => {
    if (f.severity !== 'pass') {
      txt += `[${f.severity.toUpperCase()}] ${f.title}\n`;
      txt += `Module: ${f.module.toUpperCase()}\n`;
      txt += `Category: ${f.category}\n`;
      txt += `Description: ${f.description}\n`;
      if (template !== 'concise') {
        txt += `Remediation: ${f.remediation}\n`;
      }
      txt += `\n`;
    }
  });

  if (template !== 'concise') {
    txt += `==================================================\n`;
    txt += `               TECHNICAL EVIDENCE\n`;
    txt += `==================================================\n\n`;
    if (results.dns) {
      txt += `DNS Records:\n${JSON.stringify(results.dns.records, null, 2)}\n\n`;
    }
    if (results.whois) {
      txt += `WHOIS Data:\n${results.whois.raw || 'N/A'}\n\n`;
    }
  }

  return txt;
}
