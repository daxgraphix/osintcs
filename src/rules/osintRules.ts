/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Finding, Severity } from '../types';

/**
 * Creates a standard Finding structure.
 */
function createFinding(
  id: string,
  module: string,
  title: string,
  description: string,
  severity: Severity,
  category: string,
  remediation: string
): Finding {
  return { id, module, title, description, severity, category, remediation };
}

/**
 * DNS Rules Engine
 */
export function analyzeDnsRules(dns: any, domain: string): Finding[] {
  const findings: Finding[] = [];

  // SPF Checks
  if (!dns.spf.present) {
    findings.push(
      createFinding(
        'DNS_SPF_MISSING',
        'dns',
        'Missing Sender Policy Framework (SPF) Record',
        'No SPF record was found in the DNS configuration. SPF protects your domain from email spoofing by specifying authorized sending servers.',
        'high',
        'Email Security',
        'Add a TXT record to your DNS zone containing your authorized email servers (e.g., "v=spf1 include:_spf.google.com ~all").'
      )
    );
  } else if (!dns.spf.valid) {
    findings.push(
      createFinding(
        'DNS_SPF_INVALID',
        'dns',
        'Suboptimal SPF Fail Policy',
        `The current SPF record uses an permissive configuration: "${dns.spf.record}". It lacks a strict fail mechanism (~all or -all).`,
        'medium',
        'Email Security',
        'Update your SPF record to terminate with "~all" (SoftFail) or "-all" (HardFail) to enforce sender domain authorization.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'DNS_SPF_PASS',
        'dns',
        'SPF Record Present and Valid',
        `An authorized SPF record was successfully identified: "${dns.spf.record}".`,
        'pass',
        'Email Security',
        'No action required.'
      )
    );
  }

  // DMARC Checks
  if (!dns.dmarc.present) {
    findings.push(
      createFinding(
        'DNS_DMARC_MISSING',
        'dns',
        'Missing DMARC Record',
        'Domain-based Message Authentication, Reporting, and Conformance (DMARC) is not configured. DMARC prevents email spoofing and domain phishing.',
        'high',
        'Email Security',
        'Create a TXT record for "_dmarc.yourdomain.com" containing a standard policy statement (e.g., "v=DMARC1; p=quarantine; pct=100;").'
      )
    );
  } else {
    const policy = dns.dmarc.policy;
    if (policy === 'none') {
      findings.push(
        createFinding(
          'DNS_DMARC_WEAK_POLICY',
          'dns',
          'DMARC Policy Set to "none"',
          `DMARC record was found, but the policy is set to "p=none" (${dns.dmarc.record}). This mode only monitors spoofing and does not block unauthorized emails.`,
          'medium',
          'Email Security',
          'After validating email flows, upgrade your DMARC policy from "p=none" to "p=quarantine" or "p=reject".'
        )
      );
    } else {
      findings.push(
        createFinding(
          'DNS_DMARC_PASS',
          'dns',
          'Strict DMARC Policy Configured',
          `An active DMARC record is enforcing a secure policy: "${dns.dmarc.record}".`,
          'pass',
          'Email Security',
          'No action required.'
        )
      );
    }
  }

  // DNSSEC Check
  if (!dns.dnssec.enabled) {
    findings.push(
      createFinding(
        'DNS_DNSSEC_DISABLED',
        'dns',
        'DNSSEC is Disabled',
        'DNS Security Extensions (DNSSEC) are not enabled for this domain. Without DNSSEC, attackers can perform DNS cache poisoning and redirect visitors.',
        'low',
        'Domain Integrity',
        'Enable DNSSEC at your domain registrar and publish the DS record in your parent domain registrar panel.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'DNS_DNSSEC_PASS',
        'dns',
        'DNSSEC Enabled',
        'DNSSEC is active and prevents DNS spoofing/cache poisoning by cryptographically signing records.',
        'pass',
        'Domain Integrity',
        'No action required.'
      )
    );
  }

   // Check MX record presence
   if (!dns.records.MX || dns.records.MX.length === 0) {
     findings.push(
       createFinding(
         'DNS_MX_MISSING',
         'dns',
         'No Mail Exchange (MX) Records Found',
         'This domain does not publish any MX records, meaning it cannot receive incoming emails directly.',
         'info',
         'Mail Configuration',
         'If this domain is intended to receive email, configure MX records pointing to your email hosting provider.'
       )
     );
   }

   // Subdomain Enumeration Findings
   const subdomains = dns.subdomains || [];
   const validatedSubs = subdomains.filter((s) => s.validated);
   const unvalidatedSubs = subdomains.filter((s) => !s.validated);

   if (subdomains.length > 0) {
     findings.push(
       createFinding(
         'DNS_SUBDOMAIN_DISCOVERED',
         'dns',
         `Subdomain Enumeration: ${subdomains.length} Subdomain(s) Discovered`,
         `Passive certificate transparency logs and active DNS validation discovered ${subdomains.length} subdomain(s) for ${domain}. ${validatedSubs.length} were validated via DNS A records; ${unvalidatedSubs.length} remain unvalidated (DNS response was empty or timed out).`,
         validatedSubs.length > 10 ? 'medium' : 'low',
         'Subdomain Discovery',
         'Review all discovered subdomains for exposure of sensitive services, stale endpoints, or misconfigured DNS records. Validate unvalidated subdomains with direct DNS queries.'
       )
     );

     // Flag high-risk subdomains commonly associated with sensitive services
     const sensitivePrefixes = ['admin', 'dev', 'staging', 'test', 'internal', 'intranet', 'vpn', 'remote', 'portal', 'backup', 'db', 'database', 'api', 'secret', 'private'];
     const sensitiveSubs = subdomains.filter((s) =>
       sensitivePrefixes.some((p) => s.subdomain.startsWith(p + '.'))
     );
     if (sensitiveSubs.length > 0) {
       findings.push(
         createFinding(
           'DNS_SENSITIVE_SUBDOMAINS',
           'dns',
           `Sensitive Subdomains Exposed`,
           `Found ${sensitiveSubs.length} subdomain(s) with sensitive naming patterns (admin, dev, staging, vpn, db, internal, etc.): ${sensitiveSubs.map((s) => s.subdomain).join(', ')}. These may expose internal infrastructure or development environments to the public internet.`,
           'high',
           'Subdomain Discovery',
           'Audit sensitive subdomains for authentication, authorization, and encryption. Restrict access to internal subdomains via network-level controls and ensure they are not indexed by search engines.'
         )
       );
     }

     // Validate subdomain count — if few subdomains found, note it
     if (subdomains.length <= 3) {
       findings.push(
         createFinding(
           'DNS_SUBDOMAIN_FEW',
           'dns',
           'Limited Subdomain Footprint',
           `Only ${subdomains.length} subdomain(s) were discovered for ${domain}. This may indicate a small attack surface or that subdomains are not publicly resolvable.`,
           'info',
           'Subdomain Discovery',
           'A limited subdomain footprint reduces the attack surface but does not eliminate risk. Consider using alternate passive sources (e.g., SecurityTrails, SecurityScorecard) for a more complete picture.'
         )
       );
     }
   } else {
     findings.push(
       createFinding(
         'DNS_SUBDOMAIN_NONE',
         'dns',
         'No Subdomains Discovered',
         `No subdomains were discovered for ${domain} via certificate transparency logs or DNS wordlist validation. A single-wordlist check may not be sufficient for comprehensive discovery.`,
         'info',
         'Subdomain Discovery',
         'Consider using additional passive sources (e.g., crt.sh with wider wildcards, SecurityTrails, SecurityScorecard) or active brute-forcing with a larger wordlist for thorough subdomain enumeration.'
       )
     );
   }

   return findings;
}

/**
 * SSL Rules Engine
 */
export function analyzeSslRules(ssl: any, domain: string): Finding[] {
  const findings: Finding[] = [];

  if (ssl.isExpired) {
    findings.push(
      createFinding(
        'SSL_EXPIRED',
        'ssl',
        'SSL Certificate Expired',
        `The SSL certificate for ${domain} expired on ${ssl.validTo}. Browsers will display security warnings, blocking user access.`,
        'critical',
        'Transport Security',
        'Renew your SSL certificate immediately using Let\'s Encrypt, ACM, or your certificate authority.'
      )
    );
    return findings; // Stop here if expired
  }

  // Certificate Expiry Warning
  if (ssl.daysRemaining && ssl.daysRemaining <= 15) {
    findings.push(
      createFinding(
        'SSL_NEAR_EXPIRY',
        'ssl',
        `SSL Certificate Expires Soon (${ssl.daysRemaining} days left)`,
        `The certificate is scheduled to expire on ${ssl.validTo}. It must be renewed soon to avoid service disruption.`,
        'high',
        'Transport Security',
        'Ensure automatic certificate renewal triggers are active or perform manual renewal.'
      )
    );
  } else if (ssl.daysRemaining && ssl.daysRemaining <= 30) {
    findings.push(
      createFinding(
        'SSL_MEDIUM_EXPIRY',
        'ssl',
        `SSL Certificate Expires in ${ssl.daysRemaining} days`,
        `The certificate will expire on ${ssl.validTo}.`,
        'medium',
        'Transport Security',
        'Monitor certificate renewal pipeline to confirm automated updates.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'SSL_EXPIRY_PASS',
        'ssl',
        'SSL Certificate is Active and Valid',
        `The SSL certificate is valid until ${ssl.validTo} (${ssl.daysRemaining} days remaining).`,
        'pass',
        'Transport Security',
        'No action required.'
      )
    );
  }

  // Protocol Checks
  if (ssl.protocol === 'TLSv1.0' || ssl.protocol === 'TLSv1.1') {
    findings.push(
      createFinding(
        'SSL_DEPRECATED_PROTOCOL',
        'ssl',
        `Legacy Protocol Detected: ${ssl.protocol}`,
        'TLS 1.0 and 1.1 are deprecated protocols containing known cryptographic weaknesses (e.g., POODLE, BEAST).',
        'high',
        'Cryptographic Strength',
        'Disable TLS 1.0 and TLS 1.1 on your server or CDN, enforcing a minimum of TLS 1.2, or preferably TLS 1.3.'
      )
    );
  } else if (ssl.protocol === 'TLSv1.2') {
    findings.push(
      createFinding(
        'SSL_TLS12_MODERATE',
        'ssl',
        'Using TLSv1.2 Protocol',
        'The server uses TLS 1.2, which is secure but does not benefit from the speed and full security improvements of TLS 1.3.',
        'info',
        'Cryptographic Strength',
        'Consider enabling TLS 1.3 support on your server alongside TLS 1.2.'
      )
    );
  } else if (ssl.protocol === 'TLSv1.3') {
    findings.push(
      createFinding(
        'SSL_PROTOCOL_PASS',
        'ssl',
        'TLSv1.3 Modern Protocol Configured',
        'The server uses the modern TLS 1.3 protocol, which provides optimal speed and high security.',
        'pass',
        'Cryptographic Strength',
        'No action required.'
      )
    );
  }

  // Cipher strength check
  if (ssl.strength === 'weak') {
    findings.push(
      createFinding(
        'SSL_WEAK_CIPHER',
        'ssl',
        'Weak Cipher Suite Configured',
        `The active connection is secured with a weak or legacy cipher: "${ssl.cipher}". It may be vulnerable to interception.`,
        'medium',
        'Cryptographic Strength',
        'Configure your server to disable weak ciphers (e.g. 3DES, RC4, CBC ciphers) and prioritize AEAD-based ciphers like AES-GCM or CHACHA-POLY.'
      )
    );
  } else if (ssl.strength === 'strong') {
    findings.push(
      createFinding(
        'SSL_CIPHER_PASS',
        'ssl',
        'Strong Cryptographic Ciphers Configured',
        `The connection uses a high-strength modern cipher: "${ssl.cipher}".`,
        'pass',
        'Cryptographic Strength',
        'No action required.'
      )
    );
  }

  return findings;
}

/**
 * HTTP Security Headers Rules Engine
 */
export function analyzeHeaderRules(headers: any): Finding[] {
  const findings: Finding[] = [];
  const sh = headers.securityHeaders;

  // HSTS Check
  if (!sh.hsts.present) {
    findings.push(
      createFinding(
        'HDR_HSTS_MISSING',
        'headers',
        'Missing HTTP Strict Transport Security (HSTS)',
        'HSTS forces browsers to connect to your website exclusively over HTTPS, protecting visitors against SSL downgrade and cookie hijacking attacks.',
        'high',
        'Web Server Hardening',
        'Add the header: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload" in your server configuration.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'HDR_HSTS_PASS',
        'headers',
        'HSTS Header Configured',
        'Strict-Transport-Security is enabled, preventing connection downgrades.',
        'pass',
        'Web Server Hardening',
        'No action required.'
      )
    );
  }

  // CSP Check
  if (!sh.csp.present) {
    findings.push(
      createFinding(
        'HDR_CSP_MISSING',
        'headers',
        'Missing Content Security Policy (CSP)',
        'No Content Security Policy was detected. CSP protects websites against Cross-Site Scripting (XSS), data injection, and clickjacking by restricting resource loading.',
        'high',
        'Web Server Hardening',
        'Define a tailored Content-Security-Policy header outlining trusted sources for scripts, styles, images, and other resources.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'HDR_CSP_PASS',
        'headers',
        'Content Security Policy Enabled',
        'A Content Security Policy is defined to protect against XSS and injection vectors.',
        'pass',
        'Web Server Hardening',
        'No action required.'
      )
    );
  }

  // X-Frame-Options Check
  if (!sh.xFrameOptions.present) {
    findings.push(
      createFinding(
        'HDR_XFRAME_MISSING',
        'headers',
        'Missing X-Frame-Options Header',
        'The X-Frame-Options header is missing, making this page vulnerable to Clickjacking attacks where it can be loaded inside malicious iframes.',
        'medium',
        'Web Server Hardening',
        'Set the "X-Frame-Options: SAMEORIGIN" header, or use the CSP "frame-ancestors" directive.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'HDR_XFRAME_PASS',
        'headers',
        'Clickjacking Protection (X-Frame-Options) Enabled',
        'The X-Frame-Options is configured to restrict framing to local domains or SAMEORIGIN.',
        'pass',
        'Web Server Hardening',
        'No action required.'
      )
    );
  }

  // X-Content-Type-Options Check
  if (!sh.xContentTypeOptions.present) {
    findings.push(
      createFinding(
        'HDR_XCONTENT_MISSING',
        'headers',
        'Missing X-Content-Type-Options Header',
        'The absence of "X-Content-Type-Options: nosniff" allows browsers to perform MIME-sniffing, possibly executing uploaded text or media as executable scripts.',
        'medium',
        'Web Server Hardening',
        'Add the header "X-Content-Type-Options: nosniff" to all HTTP responses.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'HDR_XCONTENT_PASS',
        'headers',
        'MIME Sniffing Protection Enabled',
        'X-Content-Type-Options is set to "nosniff" to enforce structural mime-types.',
        'pass',
        'Web Server Hardening',
        'No action required.'
      )
    );
  }

  // Server Leakage Checks
  if (headers.poweredBy) {
    findings.push(
      createFinding(
        'HDR_SOFTWARE_LEAK',
        'headers',
        `Software Disclosure via X-Powered-By Header`,
        `The header exposes underlying frameworks: "${headers.poweredBy}". Attackers can use this to identify and target version-specific vulnerabilities.`,
        'low',
        'Information Disclosure',
        'Remove or disable the "X-Powered-By" header from your server configurations.'
      )
    );
  }

  return findings;
}

/**
 * Cookies Rules Engine
 */
export function analyzeCookieRules(cookies: any[]): Finding[] {
  const findings: Finding[] = [];

  if (!cookies || cookies.length === 0) return findings;

  cookies.forEach((cookie) => {
    if (!cookie.secure) {
      findings.push(
        createFinding(
          `COOKIE_INSECURE_${cookie.name.toUpperCase()}`,
          'headers',
          `Insecure Cookie Flag: "${cookie.name}"`,
          `The cookie "${cookie.name}" lacks the "Secure" attribute, meaning it can be transmitted in plain text over HTTP, exposing it to eavesdropping.`,
          'high',
          'Session Security',
          `Add the "Secure" flag to the "${cookie.name}" cookie to guarantee it is only transmitted over HTTPS connections.`
        )
      );
    }
    if (!cookie.httpOnly) {
      findings.push(
        createFinding(
          `COOKIE_HTTPONLY_${cookie.name.toUpperCase()}`,
          'headers',
          `Missing HttpOnly Flag: "${cookie.name}"`,
          `The cookie "${cookie.name}" is accessible to browser-side JavaScript. If the site is vulnerable to XSS, an attacker can steal sessions easily.`,
          'high',
          'Session Security',
          `Add the "HttpOnly" attribute to the "${cookie.name}" cookie configuration, preventing client-side scripts from reading session tokens.`
        )
      );
    }
  });

  return findings;
}

/**
 * WHOIS Rules Engine
 */
export function analyzeWhoisRules(whois: any): Finding[] {
  const findings: Finding[] = [];

  if (whois.domainAgeDays && whois.domainAgeDays <= 30) {
    findings.push(
      createFinding(
        'WHOIS_BRAND_NEW',
        'whois',
        'Extremely New Domain Registration',
        `The domain is only ${whois.domainAgeDays} days old (registered on ${whois.creationDate}). Brand new domains are frequently utilized in phishing, malicious redirects, and spam campaigns.`,
        'high',
        'Domain Reputation',
        'Verify identity of the domain operator through independent means before conducting business or entering credentials.'
      )
    );
  } else if (whois.domainAgeDays && whois.domainAgeDays <= 365) {
    findings.push(
      createFinding(
        'WHOIS_NEW_DOMAIN',
        'whois',
        'Recently Registered Domain',
        `The domain is less than 1 year old (${whois.domainAgeDays} days old). Caution should be exercised if evaluating as a high-risk brand endpoint.`,
        'medium',
        'Domain Reputation',
        'Correlate this with other signals (SSL reputation, threat intelligence) to assess trustworthiness.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'WHOIS_REPUTATION_PASS',
        'whois',
        'Established Domain Age',
        `The domain was registered ${Math.floor(whois.domainAgeDays / 365)} years ago (${whois.domainAgeDays} days ago). Established domains carry higher inherent reputation score.`,
        'pass',
        'Domain Reputation',
        'No action required.'
      )
    );
  }

  // Days to Expiry Check
  if (whois.daysToExpiry && whois.daysToExpiry <= 30) {
    findings.push(
      createFinding(
        'WHOIS_NEAR_EXPIRY',
        'whois',
        `Domain Name Expires in ${whois.daysToExpiry} days`,
        `The domain name registration is expiring on ${whois.expiryDate}. If it expires, services will halt, and the domain may be re-registered by squatted third parties.`,
        'high',
        'Domain Lifecycle',
        'Renew domain registration immediately at the registrar panel.'
      )
    );
  }

  return findings;
}

/**
 * IP and Open Ports Rules Engine
 */
export function analyzeIpRules(ip: any): Finding[] {
  const findings: Finding[] = [];

  if (ip.isTor) {
    findings.push(
      createFinding(
        'IP_TOR_NODE',
        'ip',
        'Connection origin is a Tor Exit Node',
        'This IP is cataloged as an active Tor network exit point. Many automated scanning clusters and brute force tools tunnel through Tor.',
        'high',
        'Threat Intelligence',
        'Audit web logs for requests coming from this IP and verify whether to block anonymizer access.'
      )
    );
  }

  if (ip.isVpn || ip.isProxy) {
    findings.push(
      createFinding(
        'IP_VPN_PROXY',
        'ip',
        'Hosting/VPN/Proxy Network Detected',
        'The IP belongs to a proxy service, VPN network, or hosting data center (not a standard consumer ISP).',
        'medium',
        'Threat Intelligence',
        'Determine if users are bypassing geographic or logical boundaries using data center endpoints.'
      )
    );
  }

  // Port checks
  const openPorts = ip.ports.filter((p: any) => p.state === 'open');
  openPorts.forEach((p: any) => {
    if (p.port === 22) {
      findings.push(
        createFinding(
          'PORT_SSH_OPEN',
          'ip',
          'Open SSH Service (Port 22)',
          'SSH terminal access is publicly exposed to the internet, inviting automated brute-force attacks and active dictionary probing.',
          'medium',
          'Network Hardening',
          'Restrict SSH port 22 access via firewall to specific trusted source IPs, or enable VPN-only SSH tunnels.'
        )
      );
    } else if (p.port === 21) {
      findings.push(
        createFinding(
          'PORT_FTP_OPEN',
          'ip',
          'Open FTP Port Detected',
          'FTP exposes file structures and credentials in cleartext if unencrypted. It represents a highly legacy security compromise.',
          'high',
          'Network Hardening',
          'Decommission FTP services on port 21 and transition to SFTP or SSH-based key transport.'
        )
      );
    }
  });

  return findings;
}

/**
 * Email Rules Engine
 */
export function analyzeEmailRules(email: any): Finding[] {
  const findings: Finding[] = [];

  if (!email.syntaxValid) {
    findings.push(
      createFinding(
        'EMAIL_INVALID_SYNTAX',
        'email',
        'Invalid Email Formatting Syntax',
        'The provided string fails standard email syntax specifications (RFC 5322 regex validation).',
        'critical',
        'Email Validity',
        'Re-verify email formatting. Ensure correct position of characters, domains, and domain dots.'
      )
    );
    return findings; // Stop evaluation
  }

  if (!email.mxRecordsPresent) {
    findings.push(
      createFinding(
        'EMAIL_NO_MX',
        'email',
        `No Active Email Servers on domain: "${email.domain}"`,
        `The domain "${email.domain}" does not contain any Mail Exchange (MX) records. This email is technically unable to receive messages.`,
        'critical',
        'Email Deliverability',
        'Check DNS settings of the destination email domain. Correct spelling if entered in error.'
      )
    );
  }

  if (email.isDisposable) {
    findings.push(
      createFinding(
        'EMAIL_DISPOSABLE',
        'email',
        'Disposable/Temporary Email Service',
        `The address belongs to a disposable email provider ("${email.domain}"). These are frequently used to sign up for spam accounts or avoid identity validation.`,
        'high',
        'Reputation Analysis',
        'Require a business or verified personal email address and filter transient email endpoints from registry pipelines.'
      )
    );
  }

  if (email.isRoleBased) {
    findings.push(
      createFinding(
        'EMAIL_ROLE_BASED',
        'email',
        'Role-Based Contact Address',
        'This email uses a generic organizational prefix (e.g., info@, sales@). It points to list distributions or team queues rather than an individual person.',
        'info',
        'Reputation Analysis',
        'Confirm if you intended to inspect a functional group email rather than an individual contact.'
      )
    );
  }

  return findings;
}

/**
 * File Metadata & EXIF Rules Engine
 */
export function analyzeMetadataRules(metadata: any): Finding[] {
  const findings: Finding[] = [];

  // GPS presence warning
  if (metadata.gps && (metadata.gps.latitude || metadata.gps.longitude)) {
    findings.push(
      createFinding(
        'EXIF_GPS_FOUND',
        'metadata',
        'Geographic GPS Location Coordinates Disclosed',
        `The metadata embedded in this file discloses precise location coordinates: Latitude ${metadata.gps.latitude}, Longitude ${metadata.gps.longitude}. This poses physical privacy leakage risks.`,
        'high',
        'Privacy Exposure',
        'Strip GPS coordinates and EXIF tags using metadata-cleaning libraries (e.g. exiftool, or browser canvasing) prior to web distribution.'
      )
    );
  }

  // Camera make/model disclosure
  if (metadata.exif && metadata.exif.Make && metadata.exif.Model) {
    findings.push(
      createFinding(
        'EXIF_HARDWARE_FOUND',
        'metadata',
        `Hardware Signature Disclosed: ${metadata.exif.Make} ${metadata.exif.Model}`,
        'The file contains detailed metadata on the camera/hardware used to capture or create it.',
        'low',
        'Information Exposure',
        'Strip metadata before hosting files publicly to protect creator hardware and software details.'
      )
    );
  }

  // Large size warning
  if (metadata.fileSize && metadata.fileSize > 15 * 1024 * 1024) {
    findings.push(
      createFinding(
        'FILE_LARGE_SIZE',
        'metadata',
        'Oversized Document File',
        `This file is ${(metadata.fileSize / (1024 * 1024)).toFixed(1)} MB. Oversized files consume server bandwidth, drag load times, and can sometimes be utilized in zip-bomb resource exhausts.`,
        'low',
        'Performance Optimizations',
        'Compress files or scale resolution down to maintain optimal web hosting footprint.'
      )
    );
  }

  return findings;
}

/**
 * Recon Toolkit Rules Engine
 * Converts recon items that carry an actionable severity into findings.
 */
export function analyzeReconResult(result: any): Finding[] {
  const findings: Finding[] = [];
  const module = result?.module || 'recon';
  const target = result?.target || '';

  (result?.items || []).forEach((item: any, idx: number) => {
    const sev = item?.severity;
    if (!sev || sev === 'pass' || sev === 'info') return;

    const description = item.detail
      ? `${item.detail}`
      : item.value
      ? `Observed: ${item.value}`
      : `${item.label} detected during ${module} reconnaissance.`;

    findings.push(
      createFinding(
        `RECON_${module.toUpperCase()}_${idx}`,
        module,
        item.label,
        description,
        sev,
        `${module.toUpperCase()} Recon`,
        `Review "${item.label}" in the ${module} report and apply remediation per your security policy.`
      )
    );
  });

  if (findings.length === 0) {
    findings.push(
      createFinding(
        `RECON_${module.toUpperCase()}_PASS`,
        module,
        `${module} scan completed — no high-risk anomalies`,
        `Reconnaissance of ${target} returned no medium or high severity indicators.`,
        'pass',
        `${module.toUpperCase()} Recon`,
        'No action required.'
      )
    );
  }

  return findings;
}

/**
 * PopoScan Rules Engine
 * Analyzes webpage resource mapping results for security findings.
 */
export function analyzePopoScanResult(result: any): Finding[] {
  const findings: Finding[] = [];
  
  if (!result?.domains || !Array.isArray(result.domains)) {
    return findings;
  }
  
  const thirdPartyDomains = result.domains.filter((d: any) => d.isThirdParty);
  const totalThirdPartyRequests = thirdPartyDomains.reduce((sum: number, d: any) => sum + (d.requestCount || 0), 0);
  const redirectChain = result.redirectChain || [];
  
  // High number of third-party connections
  if (thirdPartyDomains.length > 10) {
    findings.push(
      createFinding(
        'POPO_THIRD_PARTY_HIGH',
        'poplenscan',
        'High Number of Third-Party Connections',
        `The page loads resources from ${thirdPartyDomains.length} third-party domains (${totalThirdPartyRequests} requests). This increases attack surface and tracking exposure.`,
        'medium',
        'Third-Party Exposure',
        'Review and minimize third-party dependencies. Implement CSP to restrict unauthorized domains.'
      )
    );
  } else if (thirdPartyDomains.length > 5) {
    findings.push(
      createFinding(
        'POPO_THIRD_PARTY_MEDIUM',
        'poplenscan',
        'Moderate Third-Party Connections',
        `The page loads resources from ${thirdPartyDomains.length} third-party domains (${totalThirdPartyRequests} requests).`,
        'low',
        'Third-Party Exposure',
        'Audit third-party domains for necessity and security posture.'
      )
    );
  } else {
    findings.push(
      createFinding(
        'POPO_THIRD_PARTY_LOW',
        'poplenscan',
        'Limited Third-Party Connections',
        `The page loads resources from only ${thirdPartyDomains.length} third-party domains.`,
        'pass',
        'Third-Party Exposure',
        'Good - minimal third-party attack surface.'
      )
    );
  }
  
  // Redirect chain analysis
  if (redirectChain.length > 3) {
    findings.push(
      createFinding(
        'POPO_REDIRECT_CHAIN_LONG',
        'poplenscan',
        'Long Redirect Chain Detected',
        `The page follows ${redirectChain.length} redirects before reaching the final destination. Long chains can hide malicious destinations and degrade performance.`,
        'medium',
        'Redirect Security',
        'Minimize redirect chains. Ensure all redirects are intentional and point to trusted destinations.'
      )
    );
  } else if (redirectChain.length > 0) {
    // Check for cross-domain redirects
    const crossDomainRedirects = redirectChain.filter((r: any) => r.isThirdParty);
    if (crossDomainRedirects.length > 0) {
      findings.push(
        createFinding(
          'POPO_CROSS_DOMAIN_REDIRECT',
          'poplenscan',
          'Cross-Domain Redirects Detected',
          `${crossDomainRedirects.length} redirect(s) point to external domains. This can be used for tracking or phishing.`,
          'medium',
          'Redirect Security',
          'Verify all cross-domain redirects are intentional and necessary.'
        )
      );
    }
  }
  
  // Check for suspicious third-party domains
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.online', '.site', '.info'];
  const suspiciousDomains = thirdPartyDomains.filter((d: any) => 
    suspiciousTlds.some(tld => d.domain.endsWith(tld))
  );
  
  if (suspiciousDomains.length > 0) {
    findings.push(
      createFinding(
        'POPO_SUSPICIOUS_TLDS',
        'poplenscan',
        'Resources from Suspicious TLDs',
        `Found ${suspiciousDomains.length} third-party domain(s) using TLDs commonly associated with abuse: ${suspiciousDomains.map((d: any) => d.domain).join(', ')}.`,
        'high',
        'Threat Intelligence',
        'Investigate these domains. Consider blocking resources from suspicious TLDs via CSP.'
      )
    );
  }
  
  // Check for tracking/analytics domains
  const trackingDomains = thirdPartyDomains.filter((d: any) => 
    /google-analytics|googletagmanager|facebook\.net|doubleclick|scorecardresearch|quantserve|mixpanel|segment|hotjar|newrelic|datadog|sentry|logrocket|fullstory|mouseflow|inspectlet|clicky|statcounter|addthis|sharethis|disqus|outbrain|taboola|adnxs|rubicon|pubmatic|openx|criteo|adroll|appnexus|bluekai|exelate|lotame|neustar|turn|media6degrees|33across|adhigh|adblade|content\.ad|revcontent|mgid|advertising|analytics|tracking|beacon|pixel|collector|telemetry/i.test(d.domain)
  );
  
  if (trackingDomains.length > 0) {
    findings.push(
      createFinding(
        'POPO_TRACKING_DOMAINS',
        'poplenscan',
        'Tracking and Analytics Domains Detected',
        `Found ${trackingDomains.length} tracking/analytics domain(s): ${trackingDomains.map((d: any) => d.domain).join(', ')}. These collect user behavior data.`,
        'info',
        'Privacy Exposure',
        'Review privacy policy compliance. Consider implementing consent management and allowing users to opt-out.'
      )
    );
  }
  
  // Check for CDN domains
  const cdnDomains = thirdPartyDomains.filter((d: any) => 
    /cloudflare|cloudfront|akamai|fastly|maxcdn|bootstrapcdn|jsdelivr|cdnjs|unpkg|netdna|edgecast|stackpath|keycdn|cdn\.jsdelivr|cdn\.cdnjs|cdn\.bootstrap|cdn\.google|ajax\.googleapis|code\.jquery|cdnjs\.cloudflare/i.test(d.domain)
  );
  
  if (cdnDomains.length > 0) {
    findings.push(
      createFinding(
        'POPO_CDN_DOMAINS',
        'poplenscan',
        'CDN Resources Detected',
        `Found ${cdnDomains.length} CDN domain(s): ${cdnDomains.map((d: any) => d.domain).join(', ')}. CDNs improve performance but should be verified for integrity.`,
        'info',
        'Infrastructure',
        'Verify CDN domains use Subresource Integrity (SRI) for critical resources.'
      )
    );
  }
  
  // Check for cookies
  if (result.cookies && result.cookies.length > 0) {
    const thirdPartyCookies = result.cookies.filter((c: any) => {
      try {
        return !result.finalUrl.includes(c.domain.replace(/^\./, ''));
      } catch {
        return true;
      }
    });
    
    if (thirdPartyCookies.length > 0) {
      findings.push(
        createFinding(
          'POPO_THIRD_PARTY_COOKIES',
          'poplenscan',
          'Third-Party Cookies Detected',
          `Found ${thirdPartyCookies.length} third-party cookie(s) that may track users across sites.`,
          'medium',
          'Privacy Exposure',
          'Review cookie purposes. Set SameSite=Lax/Strict and Secure flags. Implement consent management for tracking cookies.'
        )
      );
    }
    
    const insecureCookies = result.cookies.filter((c: any) => !c.secure || !c.httpOnly);
    if (insecureCookies.length > 0) {
      findings.push(
        createFinding(
          'POPO_INSECURE_COOKIES',
          'poplenscan',
          'Insecure Cookie Flags',
          `Found ${insecureCookies.length} cookie(s) missing Secure and/or HttpOnly flags.`,
          'high',
          'Session Security',
          'Set Secure and HttpOnly flags on all session cookies. Use SameSite=Lax or Strict.'
        )
      );
    }
  }
  
  // Check for mixed content (HTTP resources on HTTPS page)
  if (result.finalUrl.startsWith('https://')) {
    const httpResources = result.domains.flatMap((d: any) => 
      d.resources?.filter((r: any) => r.url.startsWith('http://')) || []
    );
    
    if (httpResources.length > 0) {
      findings.push(
        createFinding(
          'POPO_MIXED_CONTENT',
          'poplenscan',
          'Mixed Content Detected',
          `Found ${httpResources.length} HTTP resource(s) loaded on HTTPS page. This breaks encryption guarantees.`,
          'high',
          'Transport Security',
          'Migrate all resources to HTTPS. Use CSP upgrade-insecure-requests directive.'
        )
      );
    }
  }
  
  // Resource type analysis — use statistics.resources.byType (not summary)
  const resourceTypes = result.statistics?.resources?.byType || {};
  const scriptCount = resourceTypes.script || 0;
  const iframeCount = resourceTypes.iframe || 0;
  
  if (iframeCount > 5) {
    findings.push(
      createFinding(
        'POPO_MANY_IFRAMES',
        'poplenscan',
        'High Number of Iframes',
        `The page embeds ${iframeCount} iframes. Iframes can be used for clickjacking, tracking, or malicious content injection.`,
        'medium',
        'Content Security',
        'Minimize iframe usage. Use sandbox attribute and CSP frame-ancestors directive.'
      )
    );
  }
  
  if (scriptCount > 30) {
    findings.push(
      createFinding(
        'POPO_HIGH_SCRIPT_COUNT',
        'poplenscan',
        'High JavaScript Resource Count',
        `The page loads ${scriptCount} external scripts. Large script counts increase attack surface and performance overhead.`,
        'low',
        'Performance & Security',
        'Audit scripts for necessity. Consider bundling, defer/async loading, and removing unused scripts.'
      )
    );
  }
  
  // Check for advertising/ad-network domains
  const adDomains = thirdPartyDomains.filter((d: any) =>
    /doubleclick|googlesyndication|googleadservices|amazon-adsystem|adsystem|adnxs|rubicon|pubmatic|openx|criteo|adroll|appnexus|bluekai|exelate|lotame|prebid|33across|adhigh|adblade|mgid|revcontent|moatads|casalemedia|rlcdn|demdex|advertising\.com|ad\.com/i.test(d.domain)
  );
  if (adDomains.length > 0) {
    findings.push(
      createFinding(
        'POPO_ADVERTISING_DOMAINS',
        'poplenscan',
        'Ad Network Domains Detected',
        `Found ${adDomains.length} ad network domain(s): ${adDomains.slice(0, 5).map((d: any) => d.domain).join(', ')}${adDomains.length > 5 ? ` (+${adDomains.length - 5} more)` : ''}. These can serve targeted ads and track users across sites.`,
        'medium',
        'Privacy Exposure',
        'Consider implementing an ad-blocker CSP policy. Disclose ad network usage in your privacy policy.'
      )
    );
  }

  // Check for social media tracking pixels
  const socialPixels = thirdPartyDomains.filter((d: any) =>
    /connect\.facebook\.net|fbcdn|graph\.facebook|platform\.twitter|t\.co|analytics\.twitter|linkedin\.com\/px|snap\.licdn|sc-static\.net|static\.ads-twitter|platform\.linkedin|ads\.tiktok|business\.snapchat/i.test(d.domain)
  );
  if (socialPixels.length > 0) {
    findings.push(
      createFinding(
        'POPO_SOCIAL_PIXELS',
        'poplenscan',
        'Social Media Tracking Pixels Detected',
        `Found ${socialPixels.length} social media tracking pixel(s): ${socialPixels.map((d: any) => d.domain).join(', ')}. These track conversions and user behavior across the web.`,
        'low',
        'Privacy Exposure',
        'Disclose social pixel usage in your privacy policy. Implement a cookie consent banner for GDPR compliance.'
      )
    );
  }

  // Check for no HTTPS on landing page
  if (result.targetUrl && result.targetUrl.startsWith('http://') &&
      (!result.redirectChain || !result.redirectChain.some((r: any) => r.to && r.to.startsWith('https://')))) {
    findings.push(
      createFinding(
        'POPO_NO_HTTPS',
        'poplenscan',
        'Landing Page Not Served Over HTTPS',
        'The target URL uses HTTP without redirecting to HTTPS. This exposes all page content and user data to eavesdropping and man-in-the-middle attacks.',
        'high',
        'Transport Security',
        'Obtain an SSL/TLS certificate and configure your web server to redirect all HTTP traffic to HTTPS with a 301 permanent redirect. Enable HSTS.'
      )
    );
  }

  // Overall pass if no significant issues
  const significantFindings = findings.filter(f => f.severity !== 'info' && f.severity !== 'pass');
  if (significantFindings.length === 0) {
    findings.push(
      createFinding(
        'POPO_CLEAN',
        'poplenscan',
        'PopoScan Completed - No Significant Issues',
        `Analyzed ${result.statistics?.requests?.total || 0} requests across ${result.statistics?.domains?.total || 0} domains with ${thirdPartyDomains.length} third-party connections.`,
        'pass',
        'Web Forensics',
        'No action required.'
      )
    );
  }
  
  return findings;
}

/**
 * Hash Rules Engine
 */
export function analyzeHashRules(hash: any): Finding[] {
  const findings: Finding[] = [];

  if (hash.type === 'unknown') {
    findings.push(
      createFinding(
        'HASH_UNKNOWN_TYPE',
        'hash',
        'Unrecognized Cryptographic Hash Format',
        'The length of this string does not align with MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) signatures.',
        'critical',
        'Hash Format',
        'Input a clean hex string of exactly 32, 40, or 64 characters representing standard cryptographic file digests.'
      )
    );
    return findings;
  }

  if (hash.threatLevel === 'malicious') {
    findings.push(
      createFinding(
        'HASH_MALWARE_MATCH',
        'hash',
        `Malicious Threat Match: ${hash.matchedSignature?.name}`,
        `This file signature matches a recorded database entry for: ${hash.matchedSignature?.name} (${hash.matchedSignature?.threatType}). This points to highly dangerous files.`,
        'critical',
        'Malware Intelligence',
        'Isolate this file immediately. Run full machine antivirus assessments, inspect registry changes, and do not execute this file on local systems.'
      )
    );
  } else if (hash.threatLevel === 'suspicious') {
    findings.push(
      createFinding(
        'HASH_SUSPICIOUS_SIGN',
        'hash',
        'Suspicious Threat Signal Detected',
        'The checksum of this file displays high entropy or exhibits traits frequently matched in grayware or dynamic keygen structures.',
        'high',
        'Malware Intelligence',
        'Evaluate the file in a secure sandbox workspace before running it on production networks.'
      )
    );
  } else if (hash.threatLevel === 'safe') {
    findings.push(
      createFinding(
        'HASH_SAFE_PASS',
        'hash',
        'No Recorded Threats Matched',
        'This file signature does not trigger malware intelligence signatures or threat logs in standard catalogs.',
        'pass',
        'Malware Intelligence',
        'No immediate threat actions required. Continue routine security audits.'
      )
    );
  }

  return findings;
}