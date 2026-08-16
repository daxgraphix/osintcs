/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type TargetType =
  | 'domain'
  | 'website'
  | 'ip'
  | 'email'
  | 'username'
  | 'image'
  | 'hash'
  | 'metadata'
  | 'myip'
  | 'googlehacking'
  | 'websitescanner'
  | 'networkscan'
  | 'subdomain'
  | 'portscan'
  | 'urlfuzz'
  | 'waf'
  | 'peoplehunter'
  | 'domainfinder'
  | 'vhosts'
  | 'ipadvance'
  | 'techlookup'
  | 'geolookup'
  | 'speedtest'
  | 'poplenscan';

export interface InvestigationTarget {
  value: string;
  type: TargetType;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

export interface Finding {
  id: string;
  module: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  remediation: string;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'high' | 'medium' | 'low';
  category: string;
  impact: string;
}

export interface TimelineEvent {
  id: string;
  date: string;
  title: string;
  description: string;
  category: 'whois' | 'ssl' | 'history' | 'dns';
}

export interface DNSResult {
  records: {
    A?: string[];
    AAAA?: string[];
    MX?: string[];
    TXT?: string[];
    NS?: string[];
    CNAME?: string[];
    SOA?: string[];
    CAA?: string[];
    SRV?: string[];
  };
  spf: {
    present: boolean;
    record?: string;
    valid: boolean;
  };
  dmarc: {
    present: boolean;
    record?: string;
    policy?: 'none' | 'quarantine' | 'reject';
    rua?: string;
    ruf?: string;
    adkim?: 'r' | 's';
    aspf?: 'r' | 's';
    pct?: number;
  };
  dnssec: {
    enabled: boolean;
  };
  mxDetails?: Array<{ priority: number; host: string }>;
  nameservers?: string[];
  soa?: string;
  caa?: string[];
  subdomains?: SubdomainResult[];
}

export interface SubdomainResult {
  subdomain: string;
  recordType: string;
  value: string;
  source: 'crt' | 'wordlist' | 'dns';
  validated: boolean;
  status: 'verified' | 'unresolved' | 'wildcard';
  sensitivity: 'high' | 'low';
}

export interface WHOISResult {
  domainName: string;
  registrar?: string;
  creationDate?: string;
  expiryDate?: string;
  updatedDate?: string;
  domainAgeDays?: number;
  daysToExpiry?: number;
  status?: string[];
  raw?: string;
}

export interface SSLResult {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  protocol?: string;
  cipher?: string;
  strength?: 'strong' | 'moderate' | 'weak';
  isExpired: boolean;
  sans?: string[];
  keyExchange?: string;
  hasPerfectForwardSecrecy?: boolean;
  certificateTransparency?: boolean;
  serialNumber?: string;
  signatureAlgorithm?: string;
}

export interface HeaderResult {
  headers: Record<string, string>;
  securityHeaders: {
    hsts: { present: boolean; value?: string };
    csp: { present: boolean; value?: string };
    xFrameOptions: { present: boolean; value?: string };
    xContentTypeOptions: { present: boolean; value?: string };
    referrerPolicy: { present: boolean; value?: string };
  };
  server?: string;
  poweredBy?: string;
  cookies: Array<{
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: string;
  }>;
}

export interface IPResult {
  ip: string;
  hostname?: string;
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string;
  loc?: string;
  org?: string;
  asn?: string;
  threatLevel: 'safe' | 'low' | 'medium' | 'high';
  isTor: boolean;
  isProxy: boolean;
  isVpn: boolean;
  isHosting: boolean;
  ports: Array<{ port: number; service: string; state: 'open' | 'closed'; version?: string }>;
  timezone?: string;
  currency?: string;
}

export interface EmailResult {
  email: string;
  syntaxValid: boolean;
  domain: string;
  mxRecordsPresent: boolean;
  isDisposable: boolean;
  isRoleBased: boolean;
  isDeliverableSimulated: boolean;
  mxDetails?: Array<{ priority: number; host: string }>;
  spfRecord?: string;
  dkimRecord?: string;
}

export interface MyIpResult {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6';
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  org?: string;
  asn?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  userAgent?: string;
  platform?: string;
  language?: string;
}

export interface RiskSource {
  name: string;
  score: number;
  verdict: string; // e.g. "Mobile network", "clean"
}

export interface BgpRelation {
  asn: string;
  holder: string;
  role: 'upstream' | 'downstream';
}

export interface NeighborScan {
  total: number;
  flagged: number;
  vpn: number;
  abuse: number;
  tor: number;
}

export interface FingerprintCheck {
  label: string;
  category: 'network' | 'software' | 'hardware';
  status: 'normal' | 'exposed';
  detail: string;
}

export interface IpAdvanceResult {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6';
  queryMode: 'self' | 'target';
  targetInput?: string;

  // Core geo / network identity
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
  asn?: string;
  hostname?: string;
  reverseDns?: string;

  // Risk scoring
  riskScore: number; // 0-100 (higher = purer / safer)
  riskGrade: string; // e.g. "Extremely pure"
  ipType?: string; // e.g. "Residential", "Mobile cellular", "Data center"
  proxyUsersEstimate?: string; // e.g. "1-5"
  isNativeIp?: boolean;
  anonymityScore?: number; // 0-100

  // Multi-source validation
  sources: RiskSource[];

  // BGP / network topology
  bgp: {
    announcementPrefix: string;
    rpki: string; // e.g. "ROA not issued"
    holders: string[];
    relations: BgpRelation[];
  };

  // Neighbor scan (current /24 segment)
  neighbors: NeighborScan;

  // Browser fingerprint checks
  fingerprint: FingerprintCheck[];

  // WebRTC / DNS leak
  webrtcLeak: boolean;
  webrtcIp?: string;
  dnsLeak: boolean;

  // Regional availability (reference only)
  aiServices: Array<{ name: string; supported: boolean }>;
  streamingZones: Array<{ name: string; supported: boolean }>;

  userAgent?: string;
  platform?: string;
  language?: string;
}

export interface TechItem {
  label: string;
  value: string;
  category: 'server' | 'cms' | 'framework' | 'analytics' | 'security' | 'hosting' | 'misc';
}

export interface TechLookupResult {
  domain: string;
  resolvedIp?: string;
  tech: TechItem[];
  cms?: string;
  server?: string;
  jsFramework?: string;
  cdn?: string;
  waf?: string;
  hosting?: string;
  liveHeaders: boolean;
  summary: string;
}

export interface GeoLookupResult {
  target: string;
  targetType: 'ip' | 'domain';
  ip?: string;
  hostname?: string;
  ipVersion?: 'IPv4' | 'IPv6';
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
  asn?: string;
  isProxy?: boolean;
  isVpn?: boolean;
  isTor?: boolean;
  isHosting?: boolean;
  threatLevel?: 'safe' | 'low' | 'medium' | 'high';
  live: boolean;
  summary: string;
}

export interface SpeedNode {
  name: string;
  location?: string;
  flag?: string;
  latencyMs: number;
}

export interface SpeedTestResult {
  // The IP route being measured (proxy exit if using a proxy).
  outgoingIp: string;
  ipVersion: 'IPv4' | 'IPv6';

  cloudflare: {
    downloadMbps: number;
    uploadMbps: number;
    node: string;
  };
  mlab: {
    downloadMbps: number;
    uploadMbps: number;
    node: string;
  };

  latency: SpeedNode[];

  note: string;
  ranAt: string;
}

/* ═══════════════════════════════════════════════════════════════════════
   POPO SCAN — Enhanced Webpage Forensics & Resource Mapping
   ═══════════════════════════════════════════════════════════════════════ */

// ── Capture Details ─────────────────────────────────────────────────────
export interface PopoScanCaptureDetails {
  captureId: string;
  captureDate: string;
  captureTime: string;
  captureDuration: number; // ms
  userAgent: string;
  viewport: { width: number; height: number };
  devicePixelRatio: number;
  connectionType?: string;
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  storageState: 'empty' | 'partial' | 'full';
  cookiesStored: number;
  localStorageKeys: number;
  sessionStorageKeys: number;
  indexedDBCount: number;
  cacheStorageCount: number;
}

// ── Statistics ──────────────────────────────────────────────────────────
export interface PopoScanStatistics {
  requests: {
    total: number;
    successful: number;
    failed: number;
    redirected: number;
    blocked: number;
    fromCache: number;
  };
  domains: {
    total: number;
    firstParty: number;
    thirdParty: number;
    malicious: number;
    suspicious: number;
  };
  resources: {
    total: number;
    byType: Record<string, number>;
    byMimeType: Record<string, number>;
  };
  transfers: {
    totalBytes: number;
    encodedBytes: number;
    decodedBytes: number;
    compressionRatio: number;
  };
  timing: {
    totalTime: number;
    dnsTime: number;
    connectTime: number;
    tlsTime: number;
    ttfbTime: number;
    downloadTime: number;
  };
  cookies: {
    total: number;
    firstParty: number;
    thirdParty: number;
    session: number;
    persistent: number;
    secure: number;
    httpOnly: number;
    sameSiteStrict: number;
    sameSiteLax: number;
    sameSiteNone: number;
  };
  redirects: {
    total: number;
    httpToHttps: number;
    crossDomain: number;
    chainLength: number;
  };
  security: {
    httpsCoverage: number;
    hstsCoverage: number;
    cspCoverage: number;
    mixedContent: number;
    insecureCookies: number;
  };
}

// ── Storage State ───────────────────────────────────────────────────────
export interface PopoScanStorageState {
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number | null;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'Strict' | 'Lax' | 'None' | null;
    session: boolean;
    isThirdParty: boolean;
  }>;
  localStorage: Array<{ origin: string; key: string; value: string; isThirdParty: boolean }>;
  sessionStorage: Array<{ origin: string; key: string; value: string; isThirdParty: boolean }>;
  indexedDB: Array<{ origin: string; database: string; objectStores: number; isThirdParty: boolean }>;
  cacheStorage: Array<{ origin: string; cacheName: string; entries: number; isThirdParty: boolean }>;
}

// ── Tree Node for Domain/Resource Hierarchy ─────────────────────────────
export interface PopoScanTreeNode {
  id: string;
  name: string;
  type: 'root' | 'domain' | 'resource' | 'redirect' | 'cookie' | 'storage';
  domain?: string;
  isThirdParty?: boolean;
  isFirstParty?: boolean;
  resourceType?: string;
  url?: string;
  statusCode?: number;
  size?: number;
  mimeType?: string;
  timing?: {
    dns?: number;
    tcp?: number;
    tls?: number;
    ttfb?: number;
    download?: number;
  };
  children?: PopoScanTreeNode[];
  metadata?: Record<string, any>;
  riskLevel?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  tags?: string[];
}

// ── Third Party Report ──────────────────────────────────────────────────
export interface PopoScanThirdPartyReport {
  domain: string;
  category: 'cdn' | 'analytics' | 'advertising' | 'social' | 'tracking' | 'font' | 'cdn' | 'utility' | 'unknown' | 'malicious' | 'suspicious';
  requestCount: number;
  totalBytes: number;
  resources: PopoScanTreeNode[];
  reputation: {
    score: number; // 0-100
    sources: Array<{ source: string; score: number; category: string }>;
    malicious: boolean;
    suspicious: boolean;
  };
  riskIndicators: Array<{
    type: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    description: string;
  }>;
  certifications: string[];
  privacyPolicy?: string;
  dataCollection: string[];
  cookies: Array<{
    name: string;
    purpose: string;
    expiration: string;
  }>;
}

// ── Historical Lookup ───────────────────────────────────────────────────
export interface PopoScanHistoricalLookup {
  domain: string;
  firstSeen: string;
  lastSeen: string;
  totalScans: number;
  changes: Array<{
    date: string;
    changeType: 'added' | 'removed' | 'modified';
    field: string;
    oldValue?: string;
    newValue?: string;
  }>;
  snapshots: Array<{
    date: string;
    resourceCount: number;
    domainCount: number;
    totalBytes: number;
    riskScore: number;
  }>;
  relationships: Array<{
    type: 'parent' | 'child' | 'sibling' | 'redirect' | 'cname' | 'shared_ip';
    target: string;
    confidence: number;
  }>;
}

// ── Hashlookup Hit ──────────────────────────────────────────────────────
export interface PopoScanHashlookupHit {
  hash: string;
  hashType: 'md5' | 'sha1' | 'sha256' | 'tlsh' | 'ssdeep' | 'sdhash' | 'imphash';
  matches: Array<{
    source: string;
    family?: string;
    type?: string;
    firstSeen?: string;
    lastSeen?: string;
    confidence: number;
    context?: string;
  }>;
  resourceUrl: string;
  resourceType: string;
}

// ── IP Address Intelligence ─────────────────────────────────────────────
export interface PopoScanIPAddress {
  ip: string;
  version: 'IPv4' | 'IPv6';
  hostname?: string;
  asn?: {
    number: number;
    name: string;
    route?: string;
    country?: string;
  };
  geo?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
    isp?: string;
    org?: string;
  };
  reputation: {
    score: number;
    categories: string[];
    malicious: boolean;
    sources: Array<{ source: string; category: string }>;
  };
  ports?: Array<{ port: number; service: string; state: string }>;
  sslCerts?: Array<{
    fingerprint: string;
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    san: string[];
  }>;
  relationships?: Array<{
    type: 'cname' | 'a' | 'aaaa' | 'ptr' | 'shared_hosting' | 'load_balancer';
    target: string;
    confidence: number;
  }>;
}

// ── Hostname Intelligence ───────────────────────────────────────────────
export interface PopoScanHostname {
  hostname: string;
  fqdn: boolean;
  ipAddresses: string[];
  dnsRecords: {
    A?: string[];
    AAAA?: string[];
    CNAME?: string[];
    MX?: string[];
    NS?: string[];
    TXT?: string[];
    SOA?: string;
  };
  sslCertificates: Array<{
    fingerprint: string;
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    san: string[];
    keyAlgorithm: string;
    signatureAlgorithm: string;
    serialNumber: string;
    transparencyLogs: boolean;
  }>;
  reputation: {
    score: number;
    categories: string[];
    malicious: boolean;
    sources: Array<{ source: string; category: string }>;
  };
  technologies: Array<{
    name: string;
    category: string;
    confidence: number;
    version?: string;
  }>;
  subdomains?: string[];
  redirects?: Array<{
    from: string;
    to: string;
    statusCode: number;
  }>;
}

// ── URL Analysis ────────────────────────────────────────────────────────
export interface PopoScanURLAnalysis {
  url: string;
  parsed: {
    protocol: string;
    hostname: string;
    port?: string;
    pathname: string;
    search: string;
    hash: string;
    username?: string;
    password?: string;
  };
  parameters: Array<{
    name: string;
    value: string;
    suspicious: boolean;
    suspiciousReason?: string;
  }>;
  pathAnalysis: {
    depth: number;
    segments: string[];
    suspiciousSegments: string[];
    encodingIssues: string[];
  };
  riskIndicators: Array<{
    type: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    description: string;
    location: string;
  }>;
  entropy: number;
  isShortened: boolean;
  shortenedTarget?: string;
}

// ── Favicon Analysis ────────────────────────────────────────────────────
export interface PopoScanFavicon {
  url: string;
  type: 'ico' | 'png' | 'svg' | 'webp' | 'gif' | 'jpg' | 'manifest' | 'apple-touch-icon';
  size?: number;
  dimensions?: { width: number; height: number };
  hashes: {
    md5?: string;
    sha1?: string;
    sha256?: string;
    murmur3?: string;
    mmh3?: string;
  };
  matches: Array<{
    source: string;
    product?: string;
    version?: string;
    confidence: number;
    url?: string;
  }>;
  isThirdParty: boolean;
  domain: string;
}

// ── Fuzzy Hash ──────────────────────────────────────────────────────────
export interface PopoScanFuzzyHash {
  hash: string;
  hashType: 'tlsh' | 'ssdeep' | 'sdhash' | 'imphash' | 'vhash' | 'authentihash';
  matches: Array<{
    hash: string;
    similarity: number; // 0-100
    source: string;
    family?: string;
    type?: string;
    firstSeen?: string;
    context?: string;
  }>;
  resourceUrl: string;
  resourceType: string;
  fileSize: number;
}

// ── Other Identifiers ───────────────────────────────────────────────────
export interface PopoScanOtherIdentifier {
  type: 'ga' | 'gtm' | 'fb_pixel' | 'fb_app_id' | 'twitter_site' | 'twitter_creator' | 'amazon_associate' | 'clicky' | 'mixpanel' | 'hotjar' | 'intercom' | 'zendesk' | 'crisp' | 'tawk' | 'olark' | 'drift' | 'hubspot' | 'marketo' | 'pardot' | 'eloqua' | 'adobe_analytics' | 'adobe_target' | 'optimizely' | 'vwo' | 'ab_tasty' | 'kameleoon' | 'convert' | 'google_ads' | 'bing_ads' | 'linkedin_insight' | 'pinterest' | 'snapchat' | 'tiktok' | 'custom';
  value: string;
  source: 'meta_tag' | 'script' | 'cookie' | 'localstorage' | 'url_param' | 'header' | 'dom_attribute';
  context: string;
  domain: string;
  isThirdParty: boolean;
  confidence: number;
}

// ── Flat Resource (used in legacy domains array & internal processing) ───
export interface PopoScanResource {
  url: string;
  type: 'script' | 'stylesheet' | 'image' | 'iframe' | 'media' | 'xhr' | 'other';
  domain: string;
  isThirdParty: boolean;
  statusCode?: number;
  size?: number;
  mimeType?: string;
}

// ── Flat Domain (used in legacy domains array) ───────────────────────────
export interface PopoScanDomain {
  domain: string;
  isThirdParty: boolean;
  resources: PopoScanResource[];
  requestCount: number;
  totalSize: number;
  cookies: string[];
}

// ── Redirect hop ─────────────────────────────────────────────────────────
export interface PopoScanRedirect {
  from: string;
  to: string;
  statusCode: number;
  isThirdParty: boolean;
}

export type PopoScanRedirectInternal = PopoScanRedirect;

// ── Internal processing aliases ──────────────────────────────────────────
export type PopoScanResourceInternal = PopoScanResource;
export type PopoScanDomainInternal = PopoScanDomain;

// ── Main Result ─────────────────────────────────────────────────────────
export interface PopoScanResult {
  // Capture metadata
  captureDetails: PopoScanCaptureDetails;
  statistics: PopoScanStatistics;
  storageState: PopoScanStorageState;
  
  // Tree structures
  domainTree: PopoScanTreeNode;
  resourceTree: PopoScanTreeNode;
  redirectTree: PopoScanTreeNode;
  
  // Analytical reports
  thirdPartyReports: PopoScanThirdPartyReport[];
  historicalLookups: PopoScanHistoricalLookup[];
  hashlookupHits: PopoScanHashlookupHit[];
  ipAddresses: PopoScanIPAddress[];
  hostnames: PopoScanHostname[];
  urlAnalyses: PopoScanURLAnalysis[];
  favicons: PopoScanFavicon[];
  fuzzyHashes: PopoScanFuzzyHash[];
  otherIdentifiers: PopoScanOtherIdentifier[];
  
  // Risk assessment
  overallRiskScore: number; // 0-100
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  riskFactors: Array<{
    category: string;
    factor: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedResources: string[];
  }>;
  
  // Legacy compatibility
  targetUrl: string;
  finalUrl: string;
  redirectChain: Array<{ from: string; to: string; statusCode: number; isThirdParty: boolean }>;
  domains: Array<{
    domain: string;
    isThirdParty: boolean;
    resources: Array<{
      url: string;
      type: string;
      isThirdParty: boolean;
      statusCode?: number;
      size?: number;
      mimeType?: string;
    }>;
    requestCount: number;
    totalSize: number;
    cookies: string[];
  }>;
  totalRequests: number;
  totalSize: number;
  thirdPartyCount: number;
  firstPartyCount: number;
  resources: PopoScanResourceInternal[];
  cookies: Array<{ name: string; value: string; domain: string; secure: boolean; httpOnly: boolean; sameSite?: string }>;
  scanTime: string;
  live: boolean;
}

export interface UsernamePlatformCheck {
  platform: string;
  url: string;
  exists: boolean;
  category: string;
  lastActive?: string;
  confidence?: 'high' | 'medium' | 'low' | 'none';
}

export interface UsernameResult {
  username: string;
  checks: UsernamePlatformCheck[];
  foundCount: number;
}

export interface ImageResult {
  fileName: string;
  fileSize: number;
  mimeType: string;
  hash: {
    md5: string;
    sha256: string;
  };
  dimensions?: {
    width: number;
    height: number;
  };
  exif?: Record<string, any>;
  gps?: {
    latitude?: number;
    longitude?: number;
    mapsLink?: string;
  };
  previewUrl?: string;
  authenticity?: {
    overallScore: number; // 0 to 100 (where 100 is authentic, 0 is fully manipulated/fake)
    aiProbability: number; // 0 to 100
    isAiGenerated: boolean;
    clues: Array<{
      category: 'indicator' | 'exif' | 'fingerprint' | 'forensic';
      title: string;
      description: string;
      severity: 'critical' | 'high' | 'medium' | 'low' | 'pass';
    }>;
    visualForensics?: {
      compressionRatio: number;
      noiseAnomalyScore: number;
      chromaticAberration: 'consistent' | 'inconsistent' | 'none';
      fourierAnalysis: 'natural' | 'periodic_artifacts' | 'high_frequency_anomalies';
      jpegQualitySimulated: number;
      edgeDensity: number;
      colorEntropy: number;
    };
    containerChecks?: {
      softwareTag?: string;
      strippedMetadata: boolean;
      mismatchMime: boolean;
      editingHistoryDetected: boolean;
    };
  };
}

export interface HashResult {
  hash: string;
  type: 'md5' | 'sha1' | 'sha256' | 'unknown';
  matchedSignature?: {
    name: string;
    type: string;
    threatType?: string;
    family?: string;
  };
  threatLevel: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  threatType?: string;
  family?: string;
  firstBytes?: string;
  entropy?: number;
}

export type ReconStatus =
  | 'found'
  | 'open'
  | 'closed'
  | 'available'
  | 'registered'
  | 'detected'
  | 'blocked'
  | 'safe'
  | 'unknown'
  | 'wildcard';

export interface ReconItem {
  label: string;
  value?: string;
  status?: ReconStatus;
  severity?: Severity;
  detail?: string;
}

export interface ReconResult {
  module: string;
  target: string;
  summary: string;
  items: ReconItem[];
  extra?: Record<string, any>;
}

export interface ScanResults {
  target: InvestigationTarget;
  scanTime: string;
  dataSource: 'live' | 'simulated' | 'mixed';
  recon?: Record<string, ReconResult>;
  dns?: DNSResult;
  whois?: WHOISResult;
  ssl?: SSLResult;
  headers?: HeaderResult;
  ip?: IPResult;
  email?: EmailResult;
  username?: UsernameResult;
  image?: ImageResult;
  hash?: HashResult;
  myip?: MyIpResult;
  ipadvance?: IpAdvanceResult;
  techlookup?: TechLookupResult;
  geolookup?: GeoLookupResult;
  speedtest?: SpeedTestResult;
  poplenscan?: PopoScanResult;
  findings: Finding[];
  recommendations: Recommendation[];
  timeline: TimelineEvent[];
  riskScore: number; // 0 - 100 (where 100 is max risk, 0 is perfect security / safe)
}
