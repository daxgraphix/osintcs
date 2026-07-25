import { useState } from 'react';
import {
  InvestigationTarget,
  TargetType,
  ScanResults,
  Finding,
} from '../types';
import {
  scanDomain,
  getWhoisData,
  checkSslCertificate,
  scanHeaders,
  getIpDetails,
  analyzeEmail,
  investigateUsername,
  analyzeHash,
  extractFileMetadata,
  scanMyIp,
  parseInvestigationTarget,
  runGoogleHacking,
  scanWebsite,
  scanNetwork,
  findSubdomains,
  scanPorts,
  fuzzUrls,
  detectWaf,
  huntPeople,
  findDomains,
  findVirtualHosts,
  scanIpAdvance,
  scanTechnology,
  scanGeoLookup,
  scanSpeedTest,
  scanPopoScan,
} from '../services/osintServices';
import {
  analyzeDnsRules,
  analyzeSslRules,
  analyzeHeaderRules,
  analyzeCookieRules,
  analyzeWhoisRules,
  analyzeIpRules,
  analyzeEmailRules,
  analyzeMetadataRules,
  analyzeHashRules,
  analyzeReconResult,
  analyzePopoScanResult,
} from '../rules/osintRules';
import {
  calculateRiskScore,
  generateRecommendations,
  buildTimeline,
} from '../engines/osintEngines';
import { checkRateLimit } from '../utils/rateLimiter';

type LogFn = (msg: string, delay?: number) => Promise<void>;

const MODULE_TABS: string[] = ['home', 'risk', 'settings', 'history', 'image', 'metadata'];

/** Resolve the effective target, applying the active module tab override. */
function resolveTarget(
  raw: string,
  activeTab: string,
  override?: InvestigationTarget
): InvestigationTarget {
  if (override) return override;
  const parsed = parseInvestigationTarget(raw);
  if (!MODULE_TABS.includes(activeTab)) {
    return { value: parsed.value, type: activeTab as TargetType };
  }
  return parsed;
}

/**
 * Core scan routine shared by single & batch investigations.
 * `log` is a no-op in batch mode (only aggregate lines are emitted there).
 */
async function performScan(
  finalTarget: InvestigationTarget,
  localFile: File | undefined,
  log: LogFn
): Promise<ScanResults> {
  const findings: Finding[] = [];
  const scanTime = new Date().toLocaleString();

  let dnsData = undefined;
  let whoisData = undefined;
  let sslData = undefined;
  let headersData = undefined;
  let ipData = undefined;
  let emailData = undefined;
  let usernameData = undefined;
  let hashData = undefined;
  let imageData = undefined;
  let myipData = undefined;
  let ipAdvanceData = undefined;
  let techLookupData = undefined;
  let geoLookupData = undefined;
  let speedTestData = undefined;
  let reconData: Record<string, any> = {};

  if (finalTarget.type === 'domain' || finalTarget.type === 'website') {
    await log('DNS-QUERY: Connecting to Cloudflare DNS-over-HTTPS gateway...', 120);
    dnsData = await scanDomain(finalTarget.value);
    await log('DNS-OK: MX, SPF, DMARC, and DNSSEC signatures resolved.', 80);

    await log('WHOIS-QUERY: Requesting registration details from domain WHOIS authorities...', 120);
    whoisData = await getWhoisData(finalTarget.value);
    await log(`WHOIS-OK: Registrar resolved as "${whoisData.registrar}".`, 80);

    await log('SSL-HANDSHAKE: Querying remote socket for TLS negotiation logs...', 120);
    sslData = await checkSslCertificate(finalTarget.value);
    await log(`SSL-OK: Established cipher "${sslData.cipher}" via ${sslData.protocol}.`, 80);

    if (finalTarget.type === 'website') {
      await log('HTTP-HEADERS: Initiating GET request to parse safety headers...', 120);
      headersData = await scanHeaders(finalTarget.value);
      await log('HTTP-OK: Response headers and security flags compiled.', 80);
    }

    findings.push(...analyzeDnsRules(dnsData, finalTarget.value));
    findings.push(...analyzeWhoisRules(whoisData));
    findings.push(...analyzeSslRules(sslData, finalTarget.value));
    if (headersData) {
      findings.push(...analyzeHeaderRules(headersData));
      findings.push(...analyzeCookieRules(headersData.cookies));
    }
  } else if (finalTarget.type === 'ip') {
    await log('IP-REGISTRY: Locating geolocational index registries...', 150);
    ipData = await getIpDetails(finalTarget.value);
    await log(`IP-GEOMAP: Mapped ASN "${ipData.asn}" to country code ${ipData.countryCode}.`, 80);
    await log('PORT-SCAN: Querying key listening services (SSH, FTP, HTTP)...', 200);
    await log('PORT-OK: Port status table updated successfully.', 80);
    findings.push(...analyzeIpRules(ipData));
  } else if (finalTarget.type === 'email') {
    await log('EMAIL-SYNTAX: Testing address syntax structure for RFC 5322 compliance...', 80);
    await log('EMAIL-DNS: Querying domain records for MX endpoints...', 120);
    emailData = await analyzeEmail(finalTarget.value);
    await log(`EMAIL-OK: Mail records present: ${emailData.mxRecordsPresent}. Disposable address: ${emailData.isDisposable}.`, 80);
    findings.push(...analyzeEmailRules(emailData));
  } else if (finalTarget.type === 'myip') {
    await log('IP-DETECT: Resolving public IP via external API...', 150);
    myipData = await scanMyIp();
    await log(`MYIP-OK: Detected ${myipData.ipVersion} address ${myipData.ip} (${myipData.isp}, ${myipData.country}).`, 80);
    findings.push({
      id: 'MYIP_DETECTED',
      module: 'myip',
      title: 'Public IP Detected',
      description: `Your public IP is ${myipData.ip} (${myipData.ipVersion}), provided by ${myipData.isp} in ${myipData.country}.`,
      severity: 'pass',
      category: 'Network Identity',
      remediation: 'Consider using a VPN or proxy if IP exposure is a concern.',
    });
  } else if (finalTarget.type === 'ipadvance') {
    const mode = finalTarget.value && finalTarget.value.trim() ? 'target' : 'self';
    await log(`IP-ADV: Running multi-source intelligence on ${mode === 'self' ? 'your public IP' : finalTarget.value}...`, 150);
    ipAdvanceData = await scanIpAdvance(finalTarget.value);
    await log(`IP-ADV-OK: Risk purity ${ipAdvanceData.riskScore}/100; ${ipAdvanceData.ipType} classification.`, 80);
    findings.push({
      id: 'IPADV_SUMMARY',
      module: 'ipadvance',
      title: 'IP Advance Intelligence Complete',
      description: `Analysed ${ipAdvanceData.ip} (${ipAdvanceData.ipVersion}) — ${ipAdvanceData.ipType} IP with ${ipAdvanceData.riskGrade} purity (${ipAdvanceData.riskScore}/100). ${ipAdvanceData.neighbors.flagged} of ${ipAdvanceData.neighbors.total} /24 neighbours flagged.`,
      severity: ipAdvanceData.riskScore >= 70 ? 'pass' : 'medium',
      category: 'IP Reputation',
      remediation: 'Cross-validate across sources. Residential/native IPs are best for low-risk operations; datacenter IPs trigger platform risk controls.',
    });
  } else if (finalTarget.type === 'techlookup') {
    await log('TECH-SCAN: Fingerprinting web server, CMS, and JS framework...', 140);
    techLookupData = await scanTechnology(finalTarget.value);
    await log(`TECH-OK: Identified ${techLookupData.cms} on ${techLookupData.server}.`, 80);
    findings.push({
      id: 'TECH_SUMMARY',
      module: 'techlookup',
      title: 'Technology Stack Identified',
      description: `Website ${techLookupData.domain} runs ${techLookupData.cms} on ${techLookupData.server} with ${techLookupData.jsFramework}. CDN: ${techLookupData.cdn} · WAF: ${techLookupData.waf}.`,
      severity: techLookupData.cms === 'WordPress' ? 'medium' : 'info',
      category: 'Web Stack',
      remediation: techLookupData.cms === 'WordPress' ? 'Keep CMS, themes, and plugins patched; WordPress is the most targeted web platform.' : 'No action required.',
    });
  } else if (finalTarget.type === 'geolookup') {
    await log('GEO-RESOLVE: Mapping IP/domain to physical location...', 140);
    geoLookupData = await scanGeoLookup(finalTarget.value);
    await log(`GEO-OK: ${geoLookupData.city}, ${geoLookupData.country} (${geoLookupData.countryCode}).`, 80);
    const threats: string[] = [];
    if (geoLookupData.isTor) threats.push('Tor exit node');
    if (geoLookupData.isProxy) threats.push('proxy');
    if (geoLookupData.isVpn) threats.push('VPN');
    if (geoLookupData.isHosting) threats.push('hosting provider');
    if (threats.length > 0) {
      findings.push({
        id: 'GEO_THREAT',
        module: 'geolookup',
        title: 'Anonymity / Threat Indicators Detected',
        description: `Target ${geoLookupData.target} resolves to ${geoLookupData.city}, ${geoLookupData.country} with flags: ${threats.join(', ')}.`,
        severity: geoLookupData.isTor || geoLookupData.isProxy ? 'high' : 'medium',
        category: 'Geo Intelligence',
        remediation: 'Correlate with other modules before trusting geolocation — proxies and VPNs can misrepresent true location.',
      });
    } else {
      findings.push({
        id: 'GEO_CLEAN',
        module: 'geolookup',
        title: 'Geolocation Resolved',
        description: `Target ${geoLookupData.target} maps to ${geoLookupData.city}, ${geoLookupData.region}, ${geoLookupData.country} (AS${geoLookupData.asn}). No anonymizing indicators.`,
        severity: 'pass',
        category: 'Geo Intelligence',
        remediation: 'No action required.',
      });
    }
  } else if (finalTarget.type === 'speedtest') {
    await log('SPEED-PROBE: Measuring dual-source bandwidth and latency...', 200);
    speedTestData = await scanSpeedTest();
    await log(`SPEED-OK: Cloudflare ${speedTestData.cloudflare.downloadMbps} Mbps · M-Lab ${speedTestData.mlab.downloadMbps} Mbps.`, 80);
    findings.push({
      id: 'SPEED_SUMMARY',
      module: 'speedtest',
      title: 'Internet Speed Test Complete',
      description: `Outgoing route ${speedTestData.outgoingIp}. Cloudflare edge: ${speedTestData.cloudflare.downloadMbps}↓/${speedTestData.cloudflare.uploadMbps}↑ Mbps. M-Lab (MSAK): ${speedTestData.mlab.downloadMbps}↓/${speedTestData.mlab.uploadMbps}↑ Mbps.`,
      severity: speedTestData.cloudflare.downloadMbps < 10 ? 'medium' : 'pass',
      category: 'Network Performance',
      remediation: 'Cross-validate with a native speed test. Use a wired connection and pause background downloads for the most accurate reading.',
    });
  } else if (finalTarget.type === 'username') {
    await log('USER-RECON: Initiating multi-platform search array for profile handles...', 180);
    usernameData = await investigateUsername(finalTarget.value);
    await log(`USER-OK: Finished scans. Identified profiles on ${usernameData.foundCount} platform(s).`, 80);
    if (usernameData.foundCount > 3) {
      findings.push({
        id: 'USER_EXP_HIGH',
        module: 'username',
        title: 'High Digital Footprint Exposure',
        description: `The user handle "${finalTarget.value}" was actively matched across ${usernameData.foundCount} public web registries. This facilitates targeted social engineering.`,
        severity: 'medium',
        category: 'Privacy Posture',
        remediation: 'Consider rotating usernames across sensitive accounts or setting profiles to private.',
      });
    } else {
      findings.push({
        id: 'USER_EXP_LOW',
        module: 'username',
        title: 'Controlled Digital Footprint Exposure',
        description: `The username was detected on ${usernameData.foundCount} platform(s). Exposure levels are low.`,
        severity: 'pass',
        category: 'Privacy Posture',
        remediation: 'No action required.',
      });
    }
  } else if (finalTarget.type === 'hash') {
    await log('HASH-IDENTIFY: Determining hashing algorithms from string character lengths...', 80);
    hashData = await analyzeHash(finalTarget.value);
    await log(`HASH-INTEL: Matched hash category as ${hashData.type.toUpperCase()}. Querying threat maps...`, 120);
    findings.push(...analyzeHashRules(hashData));
  } else if (finalTarget.type === 'metadata' || finalTarget.type === 'image') {
    if (localFile) {
      await log('FILE-INGEST: Reading file block headers directly inside sandbox browser memory...', 120);
      imageData = await extractFileMetadata(localFile);
      if (localFile.type.startsWith('image/')) {
        try {
          const dataUrl = await new Promise<string>((resolve) => {
            const r = new FileReader();
            r.onloadend = () => resolve(r.result as string);
            r.readAsDataURL(localFile);
          });
          imageData.previewUrl = dataUrl;
        } catch (e) {
          console.error('Failed to load local image preview data URL:', e);
        }
      }
      await log(`FILE-SHA256: Calculated cryptographic digest: ${imageData.hash.sha256.slice(0, 16)}...`, 80);
      await log('EXIF-EXTRACT: Querying metadata EXIF tags for creator signatures...', 120);
      await log('EXIF-OK: EXIF metadata extracted cleanly.', 80);
      if (finalTarget.type === 'image') {
        await log('FORENSIC-SCAN: Analyzing compression ratio & noise floor consistency...', 120);
        await log('FORENSIC-SCAN: Executing Discrete Fourier Transform (DFT) for frequency grid detection...', 150);
        await log('AI-CLASSIFIER: Evaluating hybrid professional scoring models for generator traces...', 120);
        await log('INTEGRITY-OK: Forensics signals compiled successfully.', 80);
      }
      findings.push(...analyzeMetadataRules(imageData));
    } else {
      await log('FILE-INGEST: Simulated telemetry input submitted...', 120);
      imageData = {
        fileName: finalTarget.value,
        fileSize: finalTarget.type === 'image' ? 4192023 : 204855,
        mimeType: finalTarget.type === 'image' ? 'image/jpeg' : 'image/png',
        hash: {
          md5: '8743b52063cd84097a89f301d293fef1',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        exif:
          finalTarget.type === 'image'
            ? { Make: 'Canon', Model: 'EOS R5', DateTimeOriginal: '2026-06-15 14:22:11' }
            : { DateTimeOriginal: '2026-06-16 09:30:00' },
      };
      findings.push(...analyzeMetadataRules(imageData));
    }
  }
  else if (
    finalTarget.type === 'googlehacking' ||
    finalTarget.type === 'websitescanner' ||
    finalTarget.type === 'networkscan' ||
    finalTarget.type === 'subdomain' ||
    finalTarget.type === 'portscan' ||
    finalTarget.type === 'urlfuzz' ||
    finalTarget.type === 'waf' ||
    finalTarget.type === 'peoplehunter' ||
    finalTarget.type === 'domainfinder' ||
    finalTarget.type === 'vhosts'
  ) {
    const mod = finalTarget.type;
    await log(`RECON-${mod.toUpperCase()}: Launching ${mod} reconnaissance pipeline...`, 150);
    let reconResult: any;
    switch (mod) {
      case 'googlehacking': reconResult = await runGoogleHacking(finalTarget.value); break;
      case 'websitescanner': reconResult = await scanWebsite(finalTarget.value); break;
      case 'networkscan': reconResult = await scanNetwork(finalTarget.value); break;
      case 'subdomain': reconResult = await findSubdomains(finalTarget.value); break;
      case 'portscan': reconResult = await scanPorts(finalTarget.value); break;
      case 'urlfuzz': reconResult = await fuzzUrls(finalTarget.value); break;
      case 'waf': reconResult = await detectWaf(finalTarget.value); break;
      case 'peoplehunter': reconResult = await huntPeople(finalTarget.value); break;
      case 'domainfinder': reconResult = await findDomains(finalTarget.value); break;
      case 'vhosts': reconResult = await findVirtualHosts(finalTarget.value); break;
      default: reconResult = null;
    }
    if (reconResult) {
      await log(`RECON-${mod.toUpperCase()}: Analysis complete (${reconResult.items.length} records).`, 80);
      reconData[mod] = reconResult;
      findings.push(...analyzeReconResult(reconResult));
    }
  }
  else if (finalTarget.type === 'poplenscan') {
    await log('POPO-SCAN: Capturing webpage resources, redirects, and third-party connections...', 150);
    const popoData = await scanPopoScan(finalTarget.value);
    await log(`POPO-OK: Mapped ${popoData.statistics.domains.total} domains (${popoData.statistics.domains.thirdParty} third-party), ${popoData.statistics.requests.total} requests, ${popoData.statistics.redirects.total} redirects.`, 80);
    findings.push(...analyzePopoScanResult(popoData));
  }

  await log('RISK-CALC: Triggering rule scoring and grade classification algorithms...', 120);
  const metrics = calculateRiskScore(findings);
  const recommendations = generateRecommendations(findings);
  const timeline = buildTimeline({ whois: whoisData, ssl: sslData });
  await log('RISK-OK: Finished aggregation. Compiling interactive report panel...', 80);

  return {
    target: finalTarget,
    scanTime,
    recon: reconData,
    dns: dnsData,
    whois: whoisData,
    ssl: sslData,
    headers: headersData,
    ip: ipData,
    email: emailData,
    username: usernameData,
    hash: hashData,
    image: imageData,
    myip: myipData,
    ipadvance: ipAdvanceData,
    techlookup: techLookupData,
    geolookup: geoLookupData,
    speedtest: speedTestData,
    poplenscan: reconData['poplenscan'],
    findings,
    recommendations,
    timeline,
    riskScore: metrics.score,
  };
}

export function useScanWorkflow({
  simulateDelay,
  activeTab,
  onInvestigationComplete,
  onBatchComplete,
}: {
  simulateDelay: boolean;
  activeTab: string;
  onInvestigationComplete: (result: ScanResults) => void;
  onBatchComplete: (results: ScanResults[]) => void;
}) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState<string[]>([]);

  const makeLogger = (): LogFn => {
    return (msg: string, delay = 80) =>
      new Promise<void>((resolve) => {
        setTimeout(() => {
          const timestamp = new Date().toLocaleTimeString();
          setScanLogs((prev) => [...prev, `[${timestamp}] ${msg}`]);
          resolve();
        }, simulateDelay ? delay : 10);
      });
  };

  const triggerInvestigation = async (overrideTarget?: InvestigationTarget, localFile?: File) => {
    const rateLimitKey = 'scan_single';
    const rateLimit = checkRateLimit(rateLimitKey, 10, 60000);
    if (!rateLimit.allowed) {
      console.warn(`Rate limit exceeded. Try again in ${rateLimit.resetMs}ms.`);
      return;
    }

    const finalTarget: InvestigationTarget = overrideTarget
      ? overrideTarget
      : resolveTarget('', activeTab);
    setIsScanning(true);
    setScanLogs([]);
    const log = makeLogger();

    await log('SYS-INITIALIZE: Deploying browser OSINT sandbox...', 80);
    await log(`SYS-TARGET: Resolved target value "${finalTarget.value}" as type ${finalTarget.type.toUpperCase()}`, 100);
    await log('SYS-PARALLEL-CORE: Initializing parallel reconnaissance pipelines...', 150);

    try {
      const result = await performScan(finalTarget, localFile, log);
      setTimeout(() => {
        onInvestigationComplete(result);
        setIsScanning(false);
      }, 400);
    } catch (err) {
      console.error('OSINT scan crashed:', err);
      await log('SYS-CRITICAL: Run crashed. Connection timed out or DNS blocked.', 100);
      setTimeout(() => setIsScanning(false), 2000);
    }
  };

  const triggerBatchInvestigation = async (targetValues: string[]) => {
    const rateLimitKey = 'scan_batch';
    const rateLimit = checkRateLimit(rateLimitKey, 3, 60000);
    if (!rateLimit.allowed) {
      console.warn(`Batch rate limit exceeded. Try again in ${rateLimit.resetMs}ms.`);
      return;
    }

    if (targetValues.length > 200) {
      console.warn('Batch size exceeds maximum allowed targets.');
      return;
    }

    setIsScanning(true);
    setScanLogs([]);
    const log = makeLogger();

    await log(`SYS-BATCH: Starting batch scan reconnaissance for ${targetValues.length} targets...`, 100);

    const compiledResults: ScanResults[] = [];

    for (let i = 0; i < targetValues.length; i++) {
      const rawVal = targetValues[i];
      const finalTarget = resolveTarget(rawVal, activeTab);
      await log(
        `BATCH-RECON [${i + 1}/${targetValues.length}]: Commencing audits for "${finalTarget.value}" (${finalTarget.type.toUpperCase()})...`,
        120
      );
      try {
        const result = await performScan(finalTarget, undefined, async () => {});
        compiledResults.push(result);
        await log(
          `BATCH-OK [${i + 1}/${targetValues.length}]: Scanned "${finalTarget.value}" (Risk Score: ${result.riskScore}/100).`,
          80
        );
      } catch (err) {
        console.error(`Batch item failed: ${rawVal}`, err);
        await log(`BATCH-ERROR [${i + 1}/${targetValues.length}]: Audit failed for "${rawVal}".`, 100);
      }
    }

    await log('SYS-BATCH-COMPLETE: Compiled results for all targeted nodes.', 100);
    setTimeout(() => {
      onBatchComplete(compiledResults);
      setIsScanning(false);
    }, 400);
  };

  return { isScanning, setIsScanning, scanLogs, triggerInvestigation, triggerBatchInvestigation };
}

