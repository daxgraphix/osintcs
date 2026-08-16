/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ScanResults, MyIpResult, IpAdvanceResult, TechLookupResult, GeoLookupResult, SpeedTestResult, PopoScanResult, ReconResult } from '../types';

export function makeMyIpResults(result: MyIpResult): ScanResults {
  return {
    target: { value: result.ip, type: 'myip' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: [
      {
        id: 'MYIP_DETECTED',
        module: 'myip',
        title: 'Public IP Detected',
        description: `Your public IP is ${result.ip} (${result.ipVersion}), provided by ${result.isp || 'Unknown ISP'} in ${result.country || 'Unknown'}.`,
        severity: 'pass',
        category: 'Network Identity',
        remediation: 'Consider using a reputable VPN or proxy if IP exposure and geolocation leakage are a concern.',
      },
    ],
    riskScore: 0,
    timeline: [],
    myip: result,
    recommendations: [
      {
        id: 'MYIP_PRIVACY',
        title: 'Mask Your Public IP With a Trusted VPN',
        description: 'Your public IP exposes your ISP, approximate geolocation, and a stable network fingerprint that can be used for tracking and regional content profiling.',
        priority: 'medium',
        category: 'Network Privacy',
        impact: 'Reduces trackability and prevents location-based leakage of your connection identity.',
      },
    ],
  };
}

export function makeIpAdvanceResults(result: IpAdvanceResult): ScanResults {
  return {
    target: { value: result.ip, type: 'ipadvance' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: [
      {
        id: 'IPADV_SUMMARY',
        module: 'ipadvance',
        title: 'IP Advance Intelligence Complete',
        description: `Analysed ${result.ip} (${result.ipVersion}) — ${result.ipType} IP with ${result.riskGrade} purity (${result.riskScore}/100). ${result.neighbors.flagged} of ${result.neighbors.total} /24 neighbours flagged; ${result.sources.length} sources cross-validated.`,
        severity: result.riskScore >= 70 ? 'pass' : 'medium',
        category: 'IP Reputation',
        remediation: 'Cross-validate across sources. Residential/native IPs are best for low-risk operations; datacenter IPs trigger platform risk controls.',
      },
    ],
    riskScore: 100 - result.riskScore,
    timeline: [],
    ipadvance: result,
    recommendations: [
      {
        id: 'IPADV_NATIVE',
        title: result.isNativeIp ? 'Native IP Confirmed' : 'IP Location Mismatch',
        description: result.isNativeIp
          ? 'The country of registration matches the country of location, making this a locally located IP that is favourable for risk control.'
          : 'The country of registration and country of location differ, which can raise risk-control flags during business operations.',
        priority: result.isNativeIp ? 'low' : 'medium',
        category: 'IP Posture',
        impact: 'Native IPs improve trust scores across platforms; mismatched IPs are easier to flag.',
      },
    ],
  };
}

export function makeTechLookupResults(result: TechLookupResult): ScanResults {
  return {
    target: { value: result.domain, type: 'techlookup' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: [
      {
        id: 'TECH_SUMMARY',
        module: 'techlookup',
        title: 'Technology Stack Identified',
        description: `Website ${result.domain} runs ${result.cms} on ${result.server} with ${result.jsFramework}. CDN: ${result.cdn} · WAF: ${result.waf}.`,
        severity: result.cms === 'WordPress' ? 'medium' : 'info',
        category: 'Web Stack',
        remediation: result.cms === 'WordPress'
          ? 'Keep CMS, themes, and plugins patched; WordPress is the most targeted web platform.'
          : 'No action required.',
      },
    ],
    riskScore: result.cms === 'WordPress' ? 35 : 8,
    timeline: [],
    techlookup: result,
    recommendations: result.cms === 'WordPress' ? [
      {
        id: 'TECH_WP',
        title: 'Harden the WordPress Deployment',
        description: 'WordPress sites are the most attacked on the web; unpatched core, themes, and plugins are the leading breach vector.',
        priority: 'medium',
        category: 'Web Stack',
        impact: 'Reduces exploit exposure from automated wp-login and plugin CVE scanning.',
      },
    ] : [],
  };
}

export function makeGeoLookupResults(result: GeoLookupResult): ScanResults {
  return {
    target: { value: result.target, type: 'geolookup' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: (() => {
      const threats: string[] = [];
      if (result.isTor) threats.push('Tor exit node');
      if (result.isProxy) threats.push('proxy');
      if (result.isVpn) threats.push('VPN');
      if (result.isHosting) threats.push('hosting provider');
      if (threats.length > 0) {
        return [{
          id: 'GEO_THREAT',
          module: 'geolookup',
          title: 'Anonymity / Threat Indicators Detected',
          description: `Target ${result.target} resolves to ${result.city}, ${result.country} with flags: ${threats.join(', ')}.`,
          severity: result.isTor || result.isProxy ? 'high' : 'medium',
          category: 'Geo Intelligence',
          remediation: 'Correlate with other modules before trusting geolocation — proxies and VPNs can misrepresent true location.',
        }];
      }
      return [{
        id: 'GEO_CLEAN',
        module: 'geolookup',
        title: 'Geolocation Resolved',
        description: `Target ${result.target} maps to ${result.city}, ${result.region}, ${result.country} (AS${result.asn}). No anonymizing indicators.`,
        severity: 'pass',
        category: 'Geo Intelligence',
        remediation: 'No action required.',
      }];
    })(),
    riskScore: result.isTor || result.isProxy ? 75 : result.isVpn ? 45 : 12,
    timeline: [],
    geolookup: result,
    recommendations: [],
  };
}

export function makeSpeedTestResults(result: SpeedTestResult): ScanResults {
  return {
    target: { value: result.outgoingIp, type: 'speedtest' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: [
      {
        id: 'SPEED_SUMMARY',
        module: 'speedtest',
        title: 'Internet Speed Test Complete',
        description: `Outgoing route ${result.outgoingIp}. Cloudflare edge: ${result.cloudflare.downloadMbps}↓/${result.cloudflare.uploadMbps}↑ Mbps. M-Lab (MSAK): ${result.mlab.downloadMbps}↓/${result.mlab.uploadMbps}↑ Mbps.`,
        severity: result.cloudflare.downloadMbps < 10 ? 'medium' : 'pass',
        category: 'Network Performance',
        remediation: 'Cross-validate with a native speed test. Use a wired connection and pause background downloads for the most accurate reading.',
      },
    ],
    riskScore: 0,
    timeline: [],
    speedtest: result,
    recommendations: [],
  };
}

export function makePopoScanResults(result: PopoScanResult): ScanResults {
  const thirdPartyCount = result.statistics.domains.thirdParty;
  const redirectCount = result.statistics.redirects.total;
  const cookieCount = result.statistics.cookies.total;
  
  const findings: any[] = [];
  const recs: any[] = [];
  
  if (thirdPartyCount > 10) {
    findings.push({
      id: 'POPO_THIRD_PARTY_HIGH',
      module: 'poplenscan',
      title: 'High Number of Third-Party Connections',
      description: `The page loads resources from ${thirdPartyCount} third-party domains (${result.statistics.requests.total} total requests). This increases attack surface and tracking exposure.`,
      severity: 'medium',
      category: 'Third-Party Exposure',
      remediation: 'Review and minimize third-party dependencies. Implement CSP to restrict unauthorized domains.',
    });
  } else if (thirdPartyCount > 5) {
    findings.push({
      id: 'POPO_THIRD_PARTY_MEDIUM',
      module: 'poplenscan',
      title: 'Moderate Third-Party Connections',
      description: `The page loads resources from ${thirdPartyCount} third-party domains (${result.statistics.requests.total} total requests).`,
      severity: 'low',
      category: 'Third-Party Exposure',
      remediation: 'Audit third-party domains for necessity and security posture.',
    });
  } else {
    findings.push({
      id: 'POPO_THIRD_PARTY_LOW',
      module: 'poplenscan',
      title: 'Limited Third-Party Connections',
      description: `The page loads resources from only ${thirdPartyCount} third-party domains.`,
      severity: 'pass',
      category: 'Third-Party Exposure',
      remediation: 'Good — minimal third-party attack surface.',
    });
  }
  
  if (redirectCount > 3) {
    findings.push({
      id: 'POPO_REDIRECT_CHAIN_LONG',
      module: 'poplenscan',
      title: 'Long Redirect Chain Detected',
      description: `The page follows ${redirectCount} redirects before reaching the final destination. Long chains can hide malicious destinations and degrade performance.`,
      severity: 'medium',
      category: 'Redirect Security',
      remediation: 'Minimize redirect chains. Ensure all redirects are intentional and point to trusted destinations.',
    });
  } else if (redirectCount > 0) {
    findings.push({
      id: 'POPO_REDIRECT_CHAIN',
      module: 'poplenscan',
      title: 'Redirect Chain Detected',
      description: `The page follows ${redirectCount} redirect(s) before reaching the final destination.`,
      severity: 'info',
      category: 'Redirect Security',
      remediation: 'Verify all redirects are intentional and necessary.',
    });
  }
  
  if (cookieCount > 0) {
    const thirdPartyCookies = result.cookies.filter(c => 
      !result.finalUrl.includes(c.domain.replace(/^\./, ''))
    ).length;
    if (thirdPartyCookies > 0) {
      findings.push({
        id: 'POPO_THIRD_PARTY_COOKIES',
        module: 'poplenscan',
        title: 'Third-Party Cookies Detected',
        description: `Found ${thirdPartyCookies} third-party cookie(s) that may track users across sites.`,
        severity: 'medium',
        category: 'Privacy Exposure',
        remediation: 'Review cookie purposes. Set SameSite=Lax/Strict and Secure flags. Implement consent management for tracking cookies.',
      });
    }
  }
  
  if (thirdPartyCount <= 5 && redirectCount <= 1) {
    findings.push({
      id: 'POPO_CLEAN',
      module: 'poplenscan',
      title: 'PopoScan Completed — No Significant Issues',
      description: `Analyzed ${result.statistics.requests.total} requests across ${result.statistics.domains.total} domains with ${thirdPartyCount} third-party connections and ${redirectCount} redirects.`,
      severity: 'pass',
      category: 'Web Forensics',
      remediation: 'No action required.',
    });
  }
  
  if (thirdPartyCount > 10) {
    recs.push({
      id: 'POPO_REC_TP_HIGH',
      title: 'Reduce Third-Party Domain Exposure',
      description: `The page loads resources from ${thirdPartyCount} third-party domains. Each domain increases tracking risk and potential data leakage.`,
      priority: 'high',
      category: 'Third-Party Exposure',
      impact: 'Reduces attack surface and minimizes cross-site tracking vectors.',
    });
  } else if (thirdPartyCount > 5) {
    recs.push({
      id: 'POPO_REC_TP_MED',
      title: 'Audit Third-Party Dependencies',
      description: `The page loads resources from ${thirdPartyCount} third-party domains. Review each for necessity and security posture.`,
      priority: 'medium',
      category: 'Third-Party Exposure',
      impact: 'Identifies unnecessary tracking and reduces external dependency risk.',
    });
  }
  
  if (redirectCount > 3) {
    recs.push({
      id: 'POPO_REC_REDIR_LONG',
      title: 'Shorten Redirect Chains',
      description: `The page follows ${redirectCount} redirects. Long chains obscure final destinations and increase latency.`,
      priority: 'medium',
      category: 'Redirect Security',
      impact: 'Improves transparency, performance, and reduces malicious-redirect risk.',
    });
  } else if (redirectCount > 0) {
    recs.push({
      id: 'POPO_REC_REDIR',
      title: 'Verify Redirect Necessity',
      description: `The page follows ${redirectCount} redirect(s). Confirm each redirect is intentional and points to a trusted destination.`,
      priority: 'low',
      category: 'Redirect Security',
      impact: 'Ensures no unintended routing to suspicious endpoints.',
    });
  }
  
  if (cookieCount > 0) {
    const thirdPartyCookies = result.cookies.filter(c =>
      !result.finalUrl.includes(c.domain.replace(/^\./, ''))
    ).length;
    if (thirdPartyCookies > 0) {
      recs.push({
        id: 'POPO_REC_COOKIES',
        title: 'Harden Cookie Security and Consent',
        description: `Found ${thirdPartyCookies} third-party cookie(s) that may track users across sites.`,
        priority: 'high',
        category: 'Privacy Exposure',
        impact: 'Reduces cross-site tracking and improves compliance with privacy regulations.',
      });
    }
  }
  
  if (result.statistics.security.httpsCoverage < 100) {
    recs.push({
      id: 'POPO_REC_HTTPS',
      title: 'Enforce Full HTTPS Coverage',
      description: `${result.statistics.security.httpsCoverage}% of resources are loaded over HTTPS. Mixed content exposes data to interception.`,
      priority: 'high',
      category: 'Transport Security',
      impact: 'Eliminates mixed-content downgrade attacks and ensures encrypted delivery.',
    });
  }
  
  if (result.statistics.security.mixedContent > 0) {
    recs.push({
      id: 'POPO_REC_MIXED',
      title: 'Eliminate Mixed Content',
      description: `${result.statistics.security.mixedContent} mixed-content resource(s) detected.`,
      priority: 'high',
      category: 'Transport Security',
      impact: 'Prevents protocol downgrade and man-in-the-middle risks.',
    });
  }
  
  if (result.statistics.security.insecureCookies > 0) {
    recs.push({
      id: 'POPO_REC_INSECURE_COOKIES',
      title: 'Secure Cookie Attributes',
      description: `${result.statistics.security.insecureCookies} cookie(s) missing Secure or HttpOnly flags.`,
      priority: 'medium',
      category: 'Cookie Security',
      impact: 'Reduces XSS and network eavesdropping exposure for session cookies.',
    });
  }
  
  if (recs.length === 0) {
    recs.push({
      id: 'POPO_REC_CLEAN',
      title: 'Maintain Current Security Posture',
      description: 'No significant third-party or redirect risks detected. Continue monitoring for changes.',
      priority: 'low',
      category: 'Maintenance',
      impact: 'Sustains current low-risk footprint.',
    });
  }
  
  return {
    target: { value: result.targetUrl, type: 'poplenscan' },
    scanTime: result.scanTime,
    dataSource: 'mixed',
    findings,
    riskScore: Math.min(100, thirdPartyCount * 5 + redirectCount * 10 + (cookieCount > 0 ? 15 : 0)),
    timeline: [],
    poplenscan: result,
    recommendations: recs,
  };
}

export function makeSubdomainResults(result: ReconResult): ScanResults {
  const sensitiveCount = result.items.filter(i => i.severity === 'medium').length;
  const subItems: any[] = result.items.map((it: any) => ({
    subdomain: it.label,
    recordType: it.recordTypes?.join(',') || 'A',
    value: it.value || '',
    source: it.source || 'wordlist',
    validated: it.status !== 'wildcard',
    status: it.status === 'wildcard' ? 'unresolved' : 'verified',
    sensitivity: it.severity === 'medium' ? 'high' : 'low',
  }));
  return {
    target: { value: result.target, type: 'subdomain' },
    scanTime: new Date().toLocaleTimeString(),
    dataSource: 'mixed',
    findings: [{
      id: 'SUBDOMAIN_SCAN',
      module: 'subdomain',
      title: `Subdomain Discovery Complete — ${result.items.length} found`,
      description: result.summary,
      severity: sensitiveCount > 0 ? 'medium' : 'pass',
      category: 'Subdomain Discovery',
      remediation: sensitiveCount > 0
        ? 'Review sensitive subdomains for exposure. Ensure internal/admin endpoints are not publicly accessible.'
        : 'No sensitive subdomains detected. Continue monitoring for new subdomain registrations.',
    }],
    riskScore: Math.min(100, sensitiveCount * 10 + Math.max(0, result.items.length - 5) * 2),
    timeline: [],
    dns: { records: {}, spf: { present: false, valid: false }, dmarc: { present: false }, dnssec: { enabled: false }, subdomains: subItems },
    recon: { subdomain: result },
    recommendations: [],
  };
}
