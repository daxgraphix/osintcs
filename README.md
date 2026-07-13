# OSINT.CS — Cyber Intelligence Platform

OSINT.CS is a browser-based OSINT (Open Source Intelligence) platform that runs entirely in the client. It performs reconnaissance across domains, DNS, SSL, IP, email, usernames, hashes, files, and public IP detection using public APIs with graceful fallbacks. Results are aggregated into an interactive report dashboard with risk scoring, remediation recommendations, timeline visualization, and multi-format export.

- **Frontend:** React 19 + TypeScript + Vite
- **Styling:** Tailwind CSS v4 (light-mode design tokens)
- **Motion:** Motion (Framer Motion)
- **Icons:** Lucide React
- **QR:** jsQR
- **No backend required** — all scans execute client-side against public endpoints.

---

## Screens & Navigation

### Lobby (Home)
The landing screen offers a universal input field with intelligent target routing. Typing a domain, URL, IP, email, username, phone-style number, or hash auto-selects the correct module. It also exposes:
- **Quick module grid** — one-tap access to every recon module.
- **Batch Scan** — paste multiple targets and scan them sequentially with aggregate risk scoring.
- **QR Scanner** — use the device camera to scan QR codes and route the decoded target into the active module.

### Report Dashboard
After any scan, the dashboard replaces the lobby and presents:
- **Overview** — target summary, risk score, grade, timeline, and at-a-glance metadata.
- **Tabbed deep-dives** per module: DNS, WHOIS, SSL, HTTP Headers, IP Lookup, Email Audit, Username Footprint, Hash Intel, Image Forensics, Metadata, My IP.
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
- **Evidence** — raw payloads (DNS answers, RDAP text, SSL chain details, headers, email MX/DMARC/SPF records, EXIF tables, port scan table, etc.).
- **Export formats** — TXT, JSON, CSV, Markdown, HTML.
- **Copy to clipboard** — one-tap copy for IPs, phone numbers, and hash values.
- **Remediation notes** — myip and other modules include privacy/security guidance directly in findings.

---

## UI & Responsiveness

- **Desktop:** collapsible sidebar (`w-64` ↔ `w-[68px]`) with icon + label navigation, accent colors per module, and active-state indicators.
- **Mobile:** top app bar with hamburger menu, slide-in navigation drawer, and a scrollable main content area.
- **App shell:** viewport-locked layout (`h-screen overflow-hidden`) with independent scroll panes for sidebar and main content, so the page never double-scrolls.
- **Typography:** Inter (UI), Space Grotesk (display), JetBrains Mono (terminal/logs).

---

## Getting Started

```bash
npm install
npm run dev     # http://localhost:3000
npm run build   # vite build
npm run lint    # tsc --noEmit
```

No environment variables or backend server are required. All scans run against public, no-auth endpoints from the browser.
