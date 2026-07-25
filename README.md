# OSINT.CS — Cyber Intelligence Platform

> **Created by Cyberswahili** — Browser-based OSINT reconnaissance suite for infrastructure intelligence, digital forensics, and security assessments.

OSINT.CS is a fully client-side OSINT platform that performs reconnaissance across domains, DNS, SSL, IP, email, usernames, hashes, files, and public IP detection using public APIs with graceful fallbacks. Results are aggregated into an interactive report dashboard with risk scoring, remediation recommendations, timeline visualization, and multi-format export.

- **Frontend:** React 19 + TypeScript + Vite
- **Styling:** Tailwind CSS v4 (light-mode design tokens)
- **Motion:** Motion (Framer Motion)
- **Icons:** Lucide React
- **QR:** jsQR
- **No backend required** — all scans execute client-side against public endpoints.
- **Modules:** 25+ integrated recon, forensics, and intelligence modules.

---

## Latest Updates

- **25+ Recon Modules** — Expanded from 5 to 25+ integrated modules covering the full reconnaissance lifecycle.
- **Web Forensics (PopoScan)** — Added webpage capture and resource mapping: domains, resources, redirects, third-party connections, cookies, favicons, tracking identifiers, IP/hostname intelligence, hash lookups, and risk scoring with domain/resource/redirect tree visualization.
- **Infrastructure Reconnaissance** — Added Website Scanner, Network Scan, Subdomain Finder (crt.sh), Port Scanner (top + deep profiles), URL Fuzzer, WAF Detector, Domain Finder, Virtual Hosts, Google Dorking, Technology Lookup, IP Geo Lookup, and Internet Speed Test.
- **Identity & People OSINT** — Added People Hunter module with breach-exposure simulation and identity correlation.
- **Live Integrations** — DNS-over-HTTPS caching, live HTTP header probing via CORS proxy, WAF vendor detection from response headers, and real subdomain enumeration via certificate-transparency logs.
- **Performance** — DoH response caching reduces redundant network calls; deterministic simulation fallbacks preserve offline resilience.
- **Home Screen Redesign** — Categorized module grid (Infrastructure, Technology & Geo Intelligence, Identity & People, Forensics & Files), dynamic stats ticker, expanded Smart Target Router with Web Forensics pathway, and refreshed CTAs.
- **New Modules Wired End-to-End** — Technology Lookup, IP Geo Lookup, and Internet Speed Test now auto-run from the workspace, surface dedicated Report Dashboard tabs, and are fully integrated into the sidebar, lobby grid, and footer.
- **IP Advance Enhancements** — Added `ip-api.com` fallback to geo resolution, guaranteed resolvable IP for self-mode, reverse-DNS via DoH for targets, and geo-aware AI/streaming regional-availability logic.
- **Performance** — Added a short-TTL JSON cache so repeated IP/geo/speed lookups are instant and free public APIs are never hammered.
- **Report Enhancements** — Generic recon panel renders any module result; export filenames sanitized; findings rules expanded for new modules.
- **Branding** — Created by Cyberswahili branding applied across app footer, reports, and console.

---

## Screens & Navigation

### Lobby (Home)
The landing screen offers a universal input field with intelligent target routing. Typing a domain, URL, IP, email, username, phone-style number, or hash auto-selects the correct module. It also exposes:
- **Quick module grid** — one-tap access to every recon module, including PopoScan for webpage resource mapping.
- **Batch Scan** — paste multiple targets and scan them sequentially with aggregate risk scoring.
- **QR Scanner** — use the device camera to scan QR codes and route the decoded target into the active module.

### Report Dashboard
After any scan, the dashboard replaces the lobby and presents:
- **Overview** — target summary, risk score, grade, timeline, and at-a-glance metadata.
  - **Tabbed deep-dives** per module: DNS, WHOIS, SSL, HTTP Headers, IP Lookup, Email Audit, Username Footprint, Hash Intel, Image Forensics, Metadata, My IP, IP Advance, Technology Lookup, IP Geo Lookup, Internet Speed Test, Website Scanner, Subdomains, Port Scan, Network Scan, URL Fuzzer, WAF, People Hunter, Domain Finder, VHosts, Google Dorking, PopoScan.
- **Evidence** — raw scan payloads and parsed responses.
- **Findings** — rule-based detections with severity (`pass`, `medium`, `high`), category, and remediation text.
- **Recommendations** — auto-generated remediation actions derived from findings.
- **Export** — download the full report as TXT, JSON, CSV, Markdown, or HTML.

### Scan History
Persisted via `sessionStorage`. Recent scans are listed with target, timestamp, risk score, and grade. Selecting a scan reloads its full report dashboard.

### Settings
- Simulated telemetry delay toggle (demonstration pacing).
- DOM cache / browser cache inspection helper.

---

## Modules & How They Work

Each module runs a dedicated scan pipeline. Where possible the app hits real public APIs; when an endpoint is unreachable (CORS, rate-limit, offline), it falls back to deterministic, seeded simulation so the report structure and UX remain intact.

### 1. Risk Scanner
Orchestrates parallel checks across all applicable pipelines for the detected target type, then aggregates findings, risk score, recommendations, and timeline into a unified report.

### 2. Domain DNS
- Queries Cloudflare DNS-over-HTTPS for `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`.
- Parses `TXT` records for **SPF** (`v=spf1`) and **DMARC** (`v=dmarc1`) including policy (`p=`), reporting URIs (`rua`/`ruf`), alignment (`adkim`/`aspf`), and percent (`pct`).
- Checks DNSSEC via `DS` records.
- Returns MX priority details and nameservers.

### 3. Website SSL
- Resolves the hostname from a URL, then inspects TLS handshake metadata (cipher, protocol), certificate validity, issuer, and expiry.
- Also queries certificate transparency logs for serial number metadata.
- Falls back to a realistic deterministic simulation when the live socket lookup is unavailable.

### 4. IP Lookup
- Resolves geolocation, ASN, ISP, organization, coordinates, and timezone.
- Audits threat indicators: Tor exit node, VPN/proxy, hosting provider, threat level.
- Performs a simulated port-scan pass (SSH, FTP, HTTP, etc.) with open/closed status.
- Falls back to seeded simulation data when the geolocation API is unreachable.

### 5. Email Audit
- Validates RFC 5322 syntax.
- Queries MX records via DNS-over-HTTPS to verify deliverability.
- Detects disposable/temporary email providers and role-based addresses.
- Returns simulated deliverability estimation when MX lookups are blocked.

### 6. Username Footprint
- Deterministically probes common web, social, and developer platform handle patterns.
- Returns a count of matched registries and exposure classification.
- If exposure count is high, it surfaces a medium-severity finding with remediation guidance.

### 7. Hash Intel
- Identifies hash family from length (MD5, SHA-1, SHA-256).
- Cross-checks against common malware/ransomware signature fingerprints (e.g., WannaCry, Mimikatz).
- Returns algorithm, entropy estimate, and threat classification.

### 8. Metadata Extractor
- Accepts drag-and-drop or file browse. Reads file headers and metadata **in-browser only** (no upload).
- Extracts EXIF tags, creation dates, author tools, and computes SHA-256 / MD5.
- For images, additionally runs forensic signals: compression ratio, noise-floor consistency, frequency-grid detection, and a hybrid AI classifier for generator traces.

### 9. What is My IP
- Auto-detects the public IP on tab open via `api.ipify.org` + `ipapi.co` with fallback.
- Displays IPv4/IPv6, ASN, ISP, organization, country, region, city, timezone, coordinates, platform, language, and user agent.
- Generates a privacy finding and remediation recommendation (VPN/proxy guidance).

### 9b. IP Advance
- Deep multi-source IP intelligence with a 0–100 **risk purity** score (residential/native IPs score highest; datacenter IPs trigger platform risk controls).
- **Multi-source voting** across 5 data sources (IP-API, Scamalytics, proxycheck, AbuseIPDB, ipapi.is) with consensus verdict and category labels.
- **ASN / BGP topology** — announcement prefix, RPKI validation, AS holders, and upstream/downstream peer relations.
- **/24 neighbour scan** — flags how many of the 256 segment neighbours are VPN/abuse/Tor, so a dirty segment cannot implicate you.
- **Browser fingerprint consistency** — network, software, and hardware profile checks (timezone/IP, language/IP, UA/platform, screen, CPU, memory, WebGL) compared for consistency.
- **WebRTC & DNS leak detection** — local, no-upload checks that surface real-IP exposure.
- **Regional availability** — reference-only AI-service (ChatGPT/Claude/Gemini) and streaming-zone (Netflix/YouTube/Spotify/TikTok) support by IP location.
- Leave the query blank to analyze your own public IP, or enter any IPv4/IPv6 address to investigate a target.

### 10. Technology Lookup
- Fingerprints the web stack from live HTTP response headers via CORS proxy.
- Detects **server**, **CMS / platform**, **JS framework**, **CDN / edge**, **WAF**, and **hosting** provider.
- Returns a breakdown table of detected technologies with category labels and a posture summary.
- Falls back to deterministic simulation when the proxy is unreachable.

### 11. IP Geo Lookup
- Resolves the geolocation of an IP address or domain (city, region, country, ASN, ISP, timezone).
- Performs threat-indicator checks: Tor exit node, VPN, proxy, and hosting-provider flags.
- Falls back to seeded simulation when the geolocation API is unreachable.

### 12. Internet Speed Test
- Measures dual-source bandwidth (Cloudflare edge + M-Lab) and round-trip latency to regional cloud vantage points.
- Only runs on click; results are shown only to you. M-Lab is an open research platform and logs test results server-side.
- Returns download/upload Mbps per source plus a regional latency table.

### 13. Website Scanner
- Probes live HTTP response headers via CORS proxy.
- Detects server technology, CMS, security headers (CSP, HSTS, X-Frame-Options, COOP/COEP, Permissions-Policy), CORS configuration, and cookie flags (Secure, HttpOnly, SameSite).
- Falls back to deterministic simulation when the proxy is unreachable.

### 14. Subdomain Finder
- Queries **crt.sh** certificate-transparency logs for passive subdomain enumeration.
- Validates discovered hosts via DNS-over-HTTPS A/AAAA resolution.
- Falls back to seeded simulation when crt.sh is rate-limited or offline.

### 15. Port Scanner
- Top-profile sweep (34 common ports: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, etc.).
- Deep-profile expansion (additional high-risk ports: 111, 143, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8009, 8081, 8443, 8888, 9000, 9200, 9300, 10000, 27017, 50000, etc.).
- Falls back to deterministic simulation preserving open/closed distribution.

### 16. Network Scan
- Broader port coverage with top/deep segmentation.
- Simulated service fingerprinting and exposure triage.

### 17. URL Fuzzer
- Probes common admin paths, backup files, debug endpoints, and parameter vectors.
- Severity classification (medium/high) based on endpoint sensitivity.


### 18. WAF Detector
- Inspects response headers for WAF/CDN vendor fingerprints (Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, etc.).
- Detects challenge pages and security header configurations.
- Falls back to heuristic detection when live probing is unavailable.

### 19. People Hunter
- Correlates email addresses, usernames, and domain affiliations.
- Simulates breach-exposure indicators and entity correlation.
- Returns exposure count and medium-severity finding when exposure is high.

### 20. Domain Finder
- Discovers related domains via search-engine dorks and pattern enumeration.
- Returns discovered domains with confidence scoring.

### 21. Virtual Hosts (VHosts)
- Enumerates virtual hostnames associated with an IP or CDN endpoint.
- Returns discovered vhost entries with HTTP response validation.

### 23. PopoScan
- Captures a webpage and maps every domain, resource, redirect, and third-party connection involved in loading it.
- Extracts scripts, stylesheets, images, iframes, media, XHR/fetch endpoints, meta-refresh redirects, cookies, favicons, and tracking identifiers.
- Generates domain trees, resource trees, and redirect trees for visual hierarchy analysis.
- Provides third-party reports with reputation scoring, historical lookup snapshots, IP/hostname intelligence, URL parameter analysis, and fuzzy hash similarity detection.
- Calculates an overall risk score (0–100) with severity-rated risk factors based on third-party exposure, redirect chains, mixed content, and cookie behavior.
- Results are displayed in a dedicated PopoScan tab with tree views, risk assessment gauges, capture details, statistics, storage state enumeration, and export-ready summaries.

### 24. Google Dorking
- Generates search-engine queries (Google dorks) for sensitive files, exposed panels, and configuration leaks.
- Returns query templates for manual or automated execution.

---

## Scan Workflow

1. **Target resolution** — `detectTargetType()` inspects the input (regex for email, IP, phone-style digits, hex hash, URL, domain). Module tabs override the detected type so selecting "Email Audit" forces `email` routing.
2. **Rate limiting** — `checkRateLimit()` enforces per-minute caps (single scans: 10/min; batch scans: 3/min).
3. **Orchestration** — `useScanWorkflow` runs `performScan()`, which calls the appropriate service function(s), then pipes results through:
    - `calculateRiskScore(findings)` → numeric score + grade.
    - `generateRecommendations(findings)` → prioritized remediation list.
    - `buildTimeline(...)` → chronological scan events.
4. **Sanitization** — all user inputs are passed through `sanitizeText`, `sanitizeFilename`, and `escapeHtml` before rendering or logging.
5. **Persistence** — single scan results are held in React state; completed scans are appended to `recentScans` in `sessionStorage` for history recall.

---

## Report Dashboard Features

- **Grade & risk score** — color-coded badge (secure/low/medium/high/critical).
- **Timeline** — chronological walkthrough of every reconnaissance step.
- **Findings** — rule-based detections with module, category, severity, description, and remediation text.
- **Recommendations** — generated from findings with priority, category, and impact statement.
- **Evidence** — raw payloads (DNS answers, RDAP text, SSL chain details, headers, email MX/DMARC/SPF records, EXIF tables, port scan table, subdomain list, WAF headers, etc.).
- **Export formats** — TXT, JSON, CSV, Markdown, HTML.
- **Copy to clipboard** — one-tap copy for IPs, phone numbers, and hash values.
- **Remediation notes** — myip and other modules include privacy/security guidance directly in findings.
- **Branding** — Reports and console display "Created by Cyberswahili" attribution.

---

## UI & Responsiveness

- **Desktop:** collapsible sidebar (`w-64` ↔ `w-[68px]`) with icon + label navigation, accent colors per module, and active-state indicators.
- **Mobile:** top app bar with hamburger menu, slide-in navigation drawer, and a scrollable main content area.
- **App shell:** viewport-locked layout (`h-screen overflow-hidden`) with independent scroll panes for sidebar and main content, so the page never double-scrolls.
- **Typography:** Inter (UI), Space Grotesk (display), JetBrains Mono (terminal/logs).
- **Branding:** Created by Cyberswahili displayed in footer, report console, and lobby.

---

## Getting Started

```bash
npm install
npm run dev     # http://localhost:3000
npm run build   # vite build
npm run lint    # tsc --noEmit
```

No environment variables or backend server are required. All scans run against public, no-auth endpoints from the browser.

---

*Created by Cyberswahili — Professional-grade OSINT platform for infrastructure intelligence, digital forensics, and security assessments. All analysis runs locally in your browser.*
