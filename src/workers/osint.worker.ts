
/**
 * OSINT.worker.ts
 * Offloads heavy computational tasks (regex parsing, report generation) to a separate thread.
 */

import { Finding, Recommendation } from '../types';

/**
 * Ported from engines/osintEngines.ts
 */
function calculateRiskScore(findings: Finding[]): {
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
 * Ported version of generateReportDocument from engines/osintEngines.ts
 */
function generateReportDocument(
    results: any,
    format: 'markdown' | 'json' | 'csv' | 'txt' | 'html' | 'pdf' | 'findings_summary',
    template: 'detailed' | 'concise' = 'detailed',
    flaggedFindings: Record<string, 'critical' | 'interesting' | null> = {}
  ): string {
    const { target, scanTime, riskScore, findings, recommendations } = results;
    const metrics = calculateRiskScore(findings);
    const popoScan = results.poplenscan;

    if (format === 'findings_summary') {
      let md = `## OSINTCS INVESTIGATION FINDINGS SUMMARY\n\n`;
      md += `* **Target:** \`${target.value}\` (${target.type.toUpperCase()})\n`;
      md += `* **Scan Date:** ${scanTime}\n`;
      md += `* **Risk Score:** **${riskScore}/100** (${metrics.grade} Grade)\n\n`;
      md += `### SUMMARY STATS\n`;
      md += `* Critical Issues: ${metrics.criticalCount}\n`;
      md += `* High Vulnerabilities: ${metrics.highCount}\n`;
      md += `* Medium-risk Issues: ${metrics.mediumCount}\n`;
      md += `* Low-risk Issues: ${metrics.lowCount}\n\n`;
      md += `---\n\n`;
      md += `### DETAILED INVESTIGATION FINDINGS\n\n`;

      findings.forEach((f: Finding, idx: number) => {
        if (f.severity === 'pass') return;

        const flag = flaggedFindings[f.id];
        const flagText = flag === 'critical'
          ? ' [🚩 CRITICAL EVIDENCE FLAG]'
          : flag === 'interesting'
          ? ' [⭐ INTERESTING FLAG]'
          : '';

        md += `#### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}${flagText}\n`;
        md += `* **Module:** ${f.module.toUpperCase()}\n`;
        md += `* **Category:** ${f.category}\n`;
        md += `* **Description:** ${f.description}\n`;
        md += `* **Remediation:** ${f.remediation}\n\n`;
      });

      const criticalFlagged = findings.filter((f: Finding) => flaggedFindings[f.id] === 'critical');
      const interestingFlagged = findings.filter((f: Finding) => flaggedFindings[f.id] === 'interesting');

      if (criticalFlagged.length > 0 || interestingFlagged.length > 0) {
        md += `### FLAGGED EVIDENCE SUMMARY\n\n`;
        if (criticalFlagged.length > 0) {
          md += `#### 🚩 CRITICAL EVIDENCE\n`;
          criticalFlagged.forEach((f: Finding) => {
            md += `* **${f.title}** (${f.module.toUpperCase()}): ${f.description}\n`;
          });
          md += `\n`;
        }
        if (interestingFlagged.length > 0) {
          md += `#### ⭐ INTERESTING FINDINGS\n`;
          interestingFlagged.forEach((f: Finding) => {
            md += `* **${f.title}** (${f.module.toUpperCase()}): ${f.description}\n`;
          });
          md += `\n`;
        }
      }

      md += `*Report processed and structured in markdown format for incident response documentation.*`;
      return md;
    }

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
          const flag = flaggedFindings[f.id];
          const flagEmoji = flag === 'critical' ? ' 🚩' : flag === 'interesting' ? ' ⭐' : '';

          md += `### [${f.severity.toUpperCase()}] ${f.title}${flagEmoji}\n`;
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
        if (results.dns?.subdomains?.length > 0) {
          md += `### Discovered Subdomains\n\n`;
          md += `| Subdomain | Record Type | Value | Source | Validated |\n`;
          md += `|-----------|------------|-------|--------|----------|\n`;
          results.dns.subdomains.forEach((sub: any) => {
            md += `| \`${sub.subdomain}\` | ${sub.recordType || 'A'} | ${sub.value || '—'} | ${sub.source || 'dns'} | ${sub.validated ? 'Yes' : 'No'} |\n`;
          });
          md += `\n`;
        }
        if (results.whois) {
          md += `### WHOIS Registration Raw\n\`\`\`text\n${results.whois.raw}\n\`\`\`\n\n`;
        }
        if (results.ssl) {
          md += `### SSL Handshake Details\n- **Issuer:** ${results.ssl.issuer}\n- **Protocol:** ${results.ssl.protocol}\n- **Cipher Suite:** ${results.ssl.cipher}\n- **Remaining Days:** ${results.ssl.daysRemaining}\n\n`;
        }
      }

      md += `---\n*Report compiled by OSINTCS. Created by Cyberswahili. Privacy-First OSINT Workspace.*`;
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
          const flag = flaggedFindings[f.id];
          const flagHtml = flag === 'critical'
            ? ' <span style="font-size:1.2em;">🚩</span>'
            : flag === 'interesting'
            ? ' <span style="font-size:1.2em;">⭐</span>'
            : '';

          html += `<div class="card">`;
          html += `<h3><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span> ${f.title}${flagHtml}</h3>`;
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
        if (results.dns?.subdomains?.length > 0) {
          html += `<h3>Discovered Subdomains (${results.dns.subdomains.length})</h3>`;
          html += `<table><tr><th>Subdomain</th><th>Record Type</th><th>Value</th><th>Source</th><th>Validated</th></tr>`;
          results.dns.subdomains.forEach((sub: any) => {
            html += `<tr><td><code>${sub.subdomain}</code></td><td>${sub.recordType || 'A'}</td><td>${sub.value || '—'}</td><td>${sub.source || 'dns'}</td><td>${sub.validated ? 'Yes' : 'No'}</td></tr>`;
          });
          html += `</table>`;
        }
        if (results.whois) {
          html += `<h3>WHOIS Registry Data</h3><pre style="background:#f1f5f9;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;">${results.whois.raw || 'N/A'}</pre>`;
        }
      }

      html += `<p style="margin-top:60px;color:#64748b;font-size:12px;text-align:center;border-top:1px solid #e2e8f0;padding-top:20px;">Report compiled by OSINTCS. Created by <strong>Cyberswahili</strong>. Privacy-First OSINT Workspace.</p>`;
      html += `</body></html>`;
      return html;
    }

    if (format === 'pdf') {
      let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>OSINTCS Investigation Report: ${target.value}</title>`;
      html += `<style>@page{size:A4;margin:20mm;} body{font-family:Arial,Helvetica,sans-serif;line-height:1.6;color:#1e293b;padding:0;max-width:100%;margin:0;} .container{max-width:900px;margin:0 auto;padding:40px;} h1{font-size:24px;border-bottom:3px solid #dc2626;padding-bottom:12px;color:#0f172a;margin-top:0;} h2{font-size:18px;color:#0f172a;margin-top:32px;border-bottom:1px solid #e2e8f0;padding-bottom:8px;} h3{font-size:14px;color:#334155;margin-top:24px;} .meta{background:#f8fafc;border:1px solid #e2e8f0;padding:16px;border-radius:8px;margin:16px 0;} .meta p{margin:4px 0;font-size:13px;} .badge{display:inline-block;padding:3px 10px;border-radius:4px;font-weight:bold;font-size:11px;color:#fff;margin-right:6px;} .critical{background:#dc2626;} .high{background:#ea580c;} .medium{background:#d97706;} .low{background:#2563eb;} .pass{background:#16a34a;} .card{border:1px solid #e2e8f0;padding:16px;border-radius:8px;margin-bottom:16px;background:#ffffff;} table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;} th,td{border:1px solid #cbd5e1;padding:10px;text-align:left;} th{background:#f1f5f9;font-weight:bold;} pre{background:#f8fafc;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px;border:1px solid #e2e8f0;} code{font-family:monospace;font-size:12px;} .summary-box{background:#f8fafc;border-left:4px solid #dc2626;padding:16px;margin:16px 0;border-radius:0 8px 8px 0;} .footer{margin-top:60px;padding-top:20px;border-top:1px solid #e2e8f0;text-align:center;color:#64748b;font-size:11px;} @media print{body{padding:0;} .container{padding:0;}}</style></head><body><div class="container">`;
      html += `<h1>OSINTCS Security Investigation Report (${template.toUpperCase()})</h1>`;
      html += `<div class="meta">`;
      html += `<p><strong>Target:</strong> <code>${target.value}</code> (${target.type.toUpperCase()})</p>`;
      html += `<p><strong>Scan Timestamp:</strong> ${scanTime}</p>`;
      html += `<p><strong>Risk Score:</strong> <strong style="font-size:1.3em;color:#dc2626;">${riskScore}/100</strong> (Grade: <strong>${metrics.grade}</strong>)</p>`;
      html += `<p><strong>Critical:</strong> ${metrics.criticalCount} | <strong>High:</strong> ${metrics.highCount} | <strong>Medium:</strong> ${metrics.mediumCount} | <strong>Low:</strong> ${metrics.lowCount}</p>`;
      html += `</div>`;

      if (popoScan) {
        html += `<h2>PopoScan Webpage Analysis</h2>`;
        html += `<div class="meta">`;
        html += `<p><strong>Target URL:</strong> <code>${popoScan.targetUrl || target.value}</code></p>`;
        html += `<p><strong>Final URL:</strong> <code>${popoScan.finalUrl || 'N/A'}</code></p>`;
        html += `<p><strong>Scan Time:</strong> ${popoScan.scanTime || scanTime}</p>`;
        html += `<p><strong>Total Requests:</strong> ${popoScan.statistics?.requests?.total || 0}</p>`;
        html += `<p><strong>Total Domains:</strong> ${popoScan.statistics?.domains?.total || 0}</p>`;
        html += `<p><strong>Third-Party Domains:</strong> <span style="color:#dc2626;font-weight:bold;">${popoScan.statistics?.domains?.thirdParty || 0}</span></p>`;
        html += `<p><strong>First-Party Domains:</strong> ${popoScan.statistics?.domains?.firstParty || 0}</p>`;
        html += `<p><strong>Redirects:</strong> ${popoScan.statistics?.redirects?.total || 0}</p>`;
        html += `<p><strong>HTTPS Coverage:</strong> ${popoScan.statistics?.security?.httpsCoverage || 0}%</p>`;
        html += `<p><strong>Overall Risk Score:</strong> <strong>${popoScan.overallRiskScore}/100</strong> (${(popoScan.riskLevel || 'N/A').toUpperCase()})</p>`;
        html += `</div>`;

        if (popoScan.statistics?.resources?.byType) {
          html += `<h3>Resource Type Breakdown</h3>`;
          html += `<table><tr><th>Resource Type</th><th>Count</th></tr>`;
          Object.entries(popoScan.statistics.resources.byType).forEach(([type, count]) => {
            html += `<tr><td>${type}</td><td>${count}</td></tr>`;
          });
          html += `</table>`;
        }

        if (popoScan.redirectChain?.length > 0) {
          html += `<h3>Redirect Chain</h3>`;
          html += `<table><tr><th>Step</th><th>From</th><th>To</th><th>Status</th><th>Type</th></tr>`;
          popoScan.redirectChain.forEach((r: any, idx: number) => {
            html += `<tr><td>${idx + 1}</td><td>${r.from}</td><td>${r.to}</td><td>${r.statusCode}</td><td>${r.isThirdParty ? 'Third-Party' : 'First-Party'}</td></tr>`;
          });
          html += `</table>`;
        }

        if (popoScan.domains?.length > 0) {
          const thirdPartyDomains = popoScan.domains.filter((d: any) => d.isThirdParty);
          if (thirdPartyDomains.length > 0) {
            html += `<h3>Third-Party Domains (${thirdPartyDomains.length})</h3>`;
            thirdPartyDomains.forEach((domain: any) => {
              html += `<div class="card">`;
              html += `<h4>${domain.domain}</h4>`;
              html += `<p><strong>Requests:</strong> ${domain.requestCount} | <strong>Size:</strong> ${domain.totalSize > 0 ? (domain.totalSize / 1024).toFixed(1) + ' KB' : 'N/A'}</p>`;
              if (domain.resources?.length > 0) {
                html += `<ul>`;
                domain.resources.forEach((r: any) => {
                  html += `<li><code>${r.type}</code>: ${r.url}</li>`;
                });
                html += `</ul>`;
              }
              html += `</div>`;
            });
          }

          const firstPartyDomains = popoScan.domains.filter((d: any) => !d.isThirdParty);
          if (firstPartyDomains.length > 0) {
            html += `<h3>First-Party Domains (${firstPartyDomains.length})</h3>`;
            firstPartyDomains.forEach((domain: any) => {
              html += `<div class="card">`;
              html += `<h4>${domain.domain}</h4>`;
              html += `<p><strong>Requests:</strong> ${domain.requestCount} | <strong>Size:</strong> ${domain.totalSize > 0 ? (domain.totalSize / 1024).toFixed(1) + ' KB' : 'N/A'}</p>`;
              if (domain.resources?.length > 0) {
                html += `<ul>`;
                domain.resources.forEach((r: any) => {
                  html += `<li><code>${r.type}</code>: ${r.url}</li>`;
                });
                html += `</ul>`;
              }
              html += `</div>`;
            });
          }
        }

        if (popoScan.cookies?.length > 0) {
          html += `<h3>Cookies (${popoScan.cookies.length})</h3>`;
          html += `<table><tr><th>Name</th><th>Domain</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr>`;
          popoScan.cookies.forEach((cookie: any) => {
            html += `<tr><td>${cookie.name}</td><td>${cookie.domain}</td><td>${cookie.secure ? 'Yes' : 'No'}</td><td>${cookie.httpOnly ? 'Yes' : 'No'}</td><td>${cookie.sameSite || '—'}</td></tr>`;
          });
          html += `</table>`;
        }
      }

      html += `<h2>Executive Summary</h2>`;
      html += `<div class="summary-box">`;
      html += `<p>A comprehensive browser-side OSINT audit of <code>${target.value}</code> was executed. The analysis identified <strong>${metrics.criticalCount}</strong> critical vulnerabilities, <strong>${metrics.highCount}</strong> high-risk findings, and <strong>${metrics.mediumCount}</strong> moderate-risk findings. The overall grade assigned is <strong>${metrics.grade}</strong>.</p>`;
      html += `</div>`;

      html += `<h2>Key Findings</h2>`;
      findings.forEach((f: Finding) => {
        if (f.severity !== 'pass') {
          const flag = flaggedFindings[f.id];
          const flagHtml = flag === 'critical' ? ' 🚩' : flag === 'interesting' ? ' ⭐' : '';

          html += `<div class="card">`;
          html += `<h3><span class="badge ${f.severity}">${f.severity.toUpperCase()}</span> ${f.title}${flagHtml}</h3>`;
          html += `<p><strong>Module:</strong> ${f.module.toUpperCase()} | <strong>Category:</strong> ${f.category}</p>`;
          html += `<p>${f.description}</p>`;
          if (template !== 'concise') {
            html += `<p><strong>Remediation:</strong> <code>${f.remediation}</code></p>`;
          }
          html += `</div>`;
        }
      });

      html += `<h2>Actionable Recommendations</h2>`;
      html += `<table><thead><tr><th>Priority</th><th>Action Recommendation</th>${template !== 'concise' ? '<th>Vulnerability Category</th>' : ''}</tr></thead><tbody>`;
      recommendations.forEach((r: Recommendation) => {
        html += `<tr><td><span class="badge ${r.priority === 'high' ? 'critical' : r.priority === 'medium' ? 'high' : 'low'}">${r.priority.toUpperCase()}</span></td><td><strong>${r.title}</strong><br>${r.description}</td>${template !== 'concise' ? `<td>${r.category}</td>` : ''}</tr>`;
      });
      html += `</tbody></table>`;

      if (template !== 'concise') {
        html += `<h2>Technical Evidence Details</h2>`;
        if (results.dns) {
          html += `<h3>DNS Zone Records</h3><pre>${JSON.stringify(results.dns.records, null, 2)}</pre>`;
        }
        if (results.dns?.subdomains?.length > 0) {
          html += `<h3>Discovered Subdomains (${results.dns.subdomains.length})</h3>`;
          html += `<table><tr><th>Subdomain</th><th>Record Type</th><th>Value</th><th>Source</th><th>Validated</th></tr>`;
          results.dns.subdomains.forEach((sub: any) => {
            html += `<tr><td><code>${sub.subdomain}</code></td><td>${sub.recordType || 'A'}</td><td>${sub.value || '—'}</td><td>${sub.source || 'dns'}</td><td>${sub.validated ? 'Yes' : 'No'}</td></tr>`;
          });
          html += `</table>`;
        }
        if (results.whois) {
          html += `<h3>WHOIS Registry Data</h3><pre style="white-space:pre-wrap;">${results.whois.raw || 'N/A'}</pre>`;
        }
        if (results.ssl) {
          html += `<h3>SSL Handshake Details</h3>`;
          html += `<table><tr><td><strong>Issuer</strong></td><td>${results.ssl.issuer}</td></tr>`;
          html += `<tr><td><strong>Protocol</strong></td><td>${results.ssl.protocol}</td></tr>`;
          html += `<tr><td><strong>Cipher Suite</strong></td><td>${results.ssl.cipher}</td></tr>`;
          html += `<tr><td><strong>Remaining Days</strong></td><td>${results.ssl.daysRemaining} days</td></tr>`;
          html += `</table>`;
        }
      }

      html += `<div class="footer">`;
      html += `<p>Report compiled by OSINTCS. Created by <strong>Cyberswahili</strong>. Privacy-First OSINT Workspace.</p>`;
      html += `<p>Generated on ${new Date().toISOString().split('T')[0]}</p>`;
      html += `</div>`;
      html += `</div></body></html>`;
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
        const flag = flaggedFindings[f.id];
        const flagText = flag === 'critical' ? ' [CRITICAL]' : flag === 'interesting' ? ' [INTERESTING]' : '';

        txt += `[${f.severity.toUpperCase()}] ${f.title}${flagText}\n`;
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
      if (results.dns?.subdomains?.length > 0) {
        txt += `Discovered Subdomains (${results.dns.subdomains.length}):\n`;
        results.dns.subdomains.forEach((sub: any) => {
          txt += `- ${sub.subdomain} | Type: ${sub.recordType || 'A'} | Value: ${sub.value || '—'} | Source: ${sub.source || 'dns'} | Validated: ${sub.validated ? 'Yes' : 'No'}\n`;
        });
        txt += `\n`;
      }
      if (results.whois) {
        txt += `WHOIS Data:\n${results.whois.raw || 'N/A'}\n\n`;
      }
    }

    if (popoScan && template !== 'concise') {
      txt += `==================================================\n`;
      txt += `               POPOSCAN WEBPAGE ANALYSIS\n`;
      txt += `==================================================\n\n`;
      txt += `Target URL: ${popoScan.targetUrl || target.value}\n`;
      txt += `Final URL: ${popoScan.finalUrl || 'N/A'}\n`;
      txt += `Scan Time: ${popoScan.scanTime || scanTime}\n\n`;

      txt += `Summary Statistics:\n`;
      txt += `- Total Requests: ${popoScan.statistics?.requests?.total || 0}\n`;
      txt += `- Successful Requests: ${popoScan.statistics?.requests?.successful || 0}\n`;
      txt += `- Failed Requests: ${popoScan.statistics?.requests?.failed || 0}\n`;
      txt += `- Total Domains: ${popoScan.statistics?.domains?.total || 0}\n`;
      txt += `- First-Party Domains: ${popoScan.statistics?.domains?.firstParty || 0}\n`;
      txt += `- Third-Party Domains: ${popoScan.statistics?.domains?.thirdParty || 0}\n`;
      txt += `- Redirects: ${popoScan.statistics?.redirects?.total || 0}\n`;
      txt += `- Total Transfer Size: ${popoScan.statistics?.transfers?.totalBytes ? (popoScan.statistics.transfers.totalBytes / 1024).toFixed(1) + ' KB' : 'N/A'}\n`;
      txt += `- HTTPS Coverage: ${popoScan.statistics?.security?.httpsCoverage || 0}%\n`;
      txt += `- Mixed Content: ${popoScan.statistics?.security?.mixedContent || 0}\n`;
      txt += `- Insecure Cookies: ${popoScan.statistics?.security?.insecureCookies || 0}\n`;
      txt += `- Overall Risk Score: ${popoScan.overallRiskScore}/100\n`;
      txt += `- Risk Level: ${(popoScan.riskLevel || 'N/A').toUpperCase()}\n\n`;

      if (popoScan.statistics?.resources?.byType) {
        txt += `Resource Type Breakdown:\n`;
        Object.entries(popoScan.statistics.resources.byType).forEach(([type, count]) => {
          txt += `- ${type}: ${count}\n`;
        });
        txt += `\n`;
      }

      if (popoScan.redirectChain?.length > 0) {
        txt += `Redirect Chain:\n`;
        popoScan.redirectChain.forEach((r: any, idx: number) => {
          txt += `${idx + 1}. ${r.from} -> ${r.to} (${r.statusCode}) ${r.isThirdParty ? '[Third-Party]' : ''}\n`;
        });
        txt += `\n`;
      }

      if (popoScan.domains?.length > 0) {
        const thirdPartyDomains = popoScan.domains.filter((d: any) => d.isThirdParty);
        if (thirdPartyDomains.length > 0) {
          txt += `Third-Party Domains (${thirdPartyDomains.length}):\n`;
          thirdPartyDomains.forEach((domain: any) => {
            txt += `\n- ${domain.domain}\n`;
            txt += `  Requests: ${domain.requestCount}\n`;
            txt += `  Total Size: ${domain.totalSize > 0 ? (domain.totalSize / 1024).toFixed(1) + ' KB' : 'N/A'}\n`;
            if (domain.resources?.length > 0) {
              txt += `  Resources:\n`;
              domain.resources.forEach((r: any) => {
                txt += `    - ${r.type}: ${r.url}\n`;
              });
            }
            if (domain.cookies?.length > 0) {
              txt += `  Cookies: ${domain.cookies.join(', ')}\n`;
            }
          });
          txt += `\n`;
        }

        const firstPartyDomains = popoScan.domains.filter((d: any) => !d.isThirdParty);
        if (firstPartyDomains.length > 0) {
          txt += `First-Party Domains (${firstPartyDomains.length}):\n`;
          firstPartyDomains.forEach((domain: any) => {
            txt += `\n- ${domain.domain}\n`;
            txt += `  Requests: ${domain.requestCount}\n`;
            txt += `  Total Size: ${domain.totalSize > 0 ? (domain.totalSize / 1024).toFixed(1) + ' KB' : 'N/A'}\n`;
            if (domain.resources?.length > 0) {
              txt += `  Resources:\n`;
              domain.resources.forEach((r: any) => {
                txt += `    - ${r.type}: ${r.url}\n`;
              });
            }
            if (domain.cookies?.length > 0) {
              txt += `  Cookies: ${domain.cookies.join(', ')}\n`;
            }
          });
          txt += `\n`;
        }
      }

      if (popoScan.cookies?.length > 0) {
        txt += `Cookies (${popoScan.cookies.length}):\n`;
        popoScan.cookies.forEach((cookie: any) => {
          txt += `- ${cookie.name} | Domain: ${cookie.domain} | Secure: ${cookie.secure ? 'Yes' : 'No'} | HttpOnly: ${cookie.httpOnly ? 'Yes' : 'No'} | SameSite: ${cookie.sameSite || '—'}\n`;
        });
        txt += `\n`;
      }

      if (popoScan.riskFactors?.length > 0) {
        txt += `Risk Factors:\n`;
        popoScan.riskFactors.forEach((factor: any) => {
          txt += `- [${factor.severity?.toUpperCase() || 'INFO'}] ${factor.factor}\n`;
          txt += `  Category: ${factor.category}\n`;
          txt += `  Description: ${factor.description}\n`;
          if (factor.affectedResources?.length > 0) {
            txt += `  Affected Resources: ${factor.affectedResources.join(', ')}\n`;
          }
          txt += `\n`;
        });
      }
    }

    txt += `==================================================\n`;
    txt += `   Created by Cyberswahili | OSINTCS Privacy-First Workspace\n`;
    txt += `==================================================\n`;
    return txt;
}

function getDomainFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

function isThirdPartyDomain(domain: string, baseDomain: string): boolean {
  if (!domain || !baseDomain) return true;
  return !domain.endsWith(baseDomain);
}

function seedHash(str: string): number {
  return Array.from(str).reduce((s, c) => Math.imul(31, s) + c.charCodeAt(0) | 0, 0);
}

/**
 * Regex-based resource extraction from HTML
 */
function extractResources(html: string, finalUrl: string, baseDomain: string) {
  const resources: any[] = [];
  const domainMap = new Map<string, any>();

  // Helper to add resource
  const addResource = (url: string, type: string) => {
    try {
      const absoluteUrl = new URL(url, finalUrl).href;
      const resourceDomain = getDomainFromUrl(absoluteUrl);
      const isThirdParty = isThirdPartyDomain(resourceDomain, baseDomain);

      const resource = {
        url: absoluteUrl,
        type,
        domain: resourceDomain,
        isThirdParty,
        size: 1000 + Math.abs(seedHash(absoluteUrl) % 50000),
        mimeType: type === 'script' ? 'application/javascript' : type === 'stylesheet' ? 'text/css' : type === 'image' ? 'image/png' : 'application/octet-stream',
      };

      resources.push(resource);

      if (!domainMap.has(resourceDomain)) {
        domainMap.set(resourceDomain, {
          domain: resourceDomain,
          isThirdParty,
          resources: [],
          requestCount: 0,
          totalSize: 0,
          cookies: [],
        });
      }
      const domainInfo = domainMap.get(resourceDomain)!;
      domainInfo.resources.push(resource);
      domainInfo.requestCount++;
      domainInfo.totalSize += resource.size || 0;
    } catch (e) {}
  };

  // Regex for src="..." and href="..."
  const srcRegex = /(?:src|href|data-src|data-lazy|data-original)=["']([^"']+)["']/g;
  let match;
  while ((match = srcRegex.exec(html)) !== null) {
    const url = match[1];
    let type = 'other';
    if (url.endsWith('.js')) type = 'script';
    else if (url.endsWith('.css')) type = 'stylesheet';
    else if (/\.(png|jpg|jpeg|gif|svg|webp)$/i.test(url)) type = 'image';

    addResource(url, type);
  }

  // CSS @import
  const importRegex = /@import\s+(?:url\()?['"](https?:[^'"]+)['"]/g;
  while ((match = importRegex.exec(html)) !== null) {
    addResource(match[1], 'stylesheet');
  }

  // Inline fetch/XHR
  const fetchRegex = /(?:fetch|XMLHttpRequest\(\)\.open)\(['"](?:GET|POST)?['"],?\s*['"]([^'"]+)['"]/g;
  while ((match = fetchRegex.exec(html)) !== null) {
    addResource(match[1], 'xhr');
  }

  return { resources, domainMap };
}

self.onmessage = (e: MessageEvent) => {
  const { type, payload } = e.data;

  switch (type) {
    case 'PARSE_POPOSCAN':
      const { html, finalUrl, baseDomain } = payload;
      const result = extractResources(html, finalUrl, baseDomain);
      // Convert Map to Object for serialization
      const domains = Array.from(result.domainMap.values());
      self.postMessage({ type: 'POPOSCAN_RESULT', payload: { resources: result.resources, domains } });
      break;

    case 'GENERATE_REPORT':
        const { results, format, template: reportTemplate, flaggedFindings } = payload;
        const documentContent = generateReportDocument(results, format, reportTemplate, flaggedFindings);
        self.postMessage({ type: 'REPORT_GENERATED', payload: { documentContent, format } });
        break;

    case 'CALCULATE_RISK':
        const metrics = calculateRiskScore(payload.findings);
        self.postMessage({ type: 'RISK_CALCULATED', payload: metrics });
        break;
  }
};
