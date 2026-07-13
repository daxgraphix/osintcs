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
  | 'phone'
  | 'image'
  | 'hash'
  | 'metadata'
  | 'myip';

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

export interface PhoneResult {
  phoneNumber: string;
  valid: boolean;
  countryCode?: string;
  countryName?: string;
  carrier?: string;
  lineType?: 'mobile' | 'landline' | 'voip' | 'unknown';
  internationalFormat?: string;
  region?: string;
  areaCode?: string;
  localNumber?: string;
  formatValid?: boolean;
  lineTypeConfidence?: 'high' | 'medium' | 'low';
  carrierConfidence?: 'high' | 'medium' | 'low';
  phoneCountryCode?: string;
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

export interface ScanResults {
  target: InvestigationTarget;
  scanTime: string;
  dns?: DNSResult;
  whois?: WHOISResult;
  ssl?: SSLResult;
  headers?: HeaderResult;
  ip?: IPResult;
  email?: EmailResult;
  phone?: PhoneResult;
  username?: UsernameResult;
  image?: ImageResult;
  hash?: HashResult;
  myip?: MyIpResult;
  findings: Finding[];
  recommendations: Recommendation[];
  timeline: TimelineEvent[];
  riskScore: number; // 0 - 100 (where 100 is max risk, 0 is perfect security / safe)
}
