import React, { useMemo, memo, useCallback } from 'react';
import { Copy, ShieldCheck, ShieldAlert, Globe, Server, Activity, Cpu, Download, Info } from 'lucide-react';
import { IpAdvanceResult } from '../../types';

interface IpAdvanceTabProps {
  results: IpAdvanceResult;
  showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
}

// --- Reusable, Memoized Sub-components for DRY & Performance ---

const Section = memo(({
  title,
  subtitle,
  children,
  icon,
  tooltip
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
  tooltip?: string;
}) => (
  <section className="border rounded-xl p-5 space-y-4 transition-colors border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900/50 shadow-sm dark:shadow-none">
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {icon && <span className="text-slate-400 dark:text-slate-500" aria-hidden="true">{icon}</span>}
          <h4 className="text-xs font-bold tracking-wider font-mono uppercase text-slate-600 dark:text-slate-400">
            {title}
          </h4>
        </div>
        {tooltip && (
          <div className="group relative">
            <button aria-label="Information tooltip" className="focus:outline-none">
              <Info className="w-3.5 h-3.5 text-slate-300 hover:text-blue-500 cursor-help transition-colors" />
            </button>
            <div className="absolute bottom-full right-0 mb-2 w-56 p-2 bg-slate-800 text-white text-[10px] rounded shadow-lg opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 pointer-events-none transition-opacity z-10 font-sans leading-normal">
              {tooltip}
            </div>
          </div>
        )}
      </div>
      {subtitle && <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono leading-relaxed">{subtitle}</p>}
    </div>
    {children}
  </section>
));

const InfoBox = memo(({ label, value }: { label: string; value?: string | number }) => (
  <div className="p-4 rounded-lg border transition-colors bg-slate-50/50 border-slate-200 dark:bg-slate-800/30 dark:border-slate-700">
    <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-1 font-semibold uppercase tracking-tighter">
      {label}
    </span>
    <span className="text-sm font-mono font-bold break-all text-slate-900 dark:text-slate-100">
      {value || 'N/A'}
    </span>
  </div>
));

const StatusCard = memo(({ label, value, danger }: { label: string; value: string | number; danger?: boolean }) => (
  <div className="p-3 rounded-lg border transition-colors border-slate-200 bg-slate-50/50 dark:border-slate-700 dark:bg-slate-800/40 shadow-sm">
    <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-1">{label}</span>
    <span className={`text-sm font-mono font-bold ${
      danger ? 'text-red-500 dark:text-red-400' : 'text-slate-900 dark:text-white'
    }`}>
      {value}
    </span>
  </div>
));

const IpAdvanceTab: React.FC<IpAdvanceTabProps> = ({ results, showToast }) => {
  // Memoized styles for the risk gauge
  const riskStyles = useMemo(() => {
    const score = results?.riskScore || 0;
    if (score >= 70) return {
      color: 'text-emerald-500',
      bg: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
    };
    if (score >= 50) return {
      color: 'text-amber-500',
      bg: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
    };
    return {
      color: 'text-red-500',
      bg: 'bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20'
    };
  }, [results?.riskScore]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(results.ip);
    showToast?.('IP address copied to clipboard', 'success');
  }, [results.ip, showToast]);

  const handleExport = useCallback(() => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(results, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `osint_report_${results.ip}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
    showToast?.('Report exported as JSON', 'info');
  }, [results, showToast]);

  if (!results) return (
    <div className="p-12 text-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-slate-500 dark:text-slate-400">
      No data available for this analysis.
    </div>
  );

  return (
    <div id="ipadvance_panel" className="space-y-6">
      {/* Action Bar */}
      <div className="flex justify-end gap-2 mb-2">
        <button
          onClick={handleExport}
          className="px-3 py-1.5 rounded-lg border text-[10px] font-bold transition-all flex items-center gap-1.5 border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 shadow-sm"
        >
          <Download className="w-3.5 h-3.5" aria-hidden="true" /> Export Report
        </button>
      </div>

      {/* Hero IP Card */}
      <header className="border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900 shadow-sm dark:shadow-none">
        <div className="space-y-1 min-w-0">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 block">
            {results.queryMode === 'self' ? 'Your Public IP Address' : 'Analyzed IP Address'}
          </span>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl sm:text-3xl font-black font-mono break-all text-slate-900 dark:text-white">
              {results.ip}
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold shrink-0 bg-blue-500/10 text-blue-600 border border-blue-500/20">
              {results.ipVersion}
            </span>
          </div>
          {results.queryMode === 'target' && results.targetInput && (
            <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">queried from: {results.targetInput}</span>
          )}
        </div>
        <button
          onClick={handleCopy}
          aria-label={`Copy IP address ${results.ip}`}
          className="shrink-0 px-3 py-2 rounded-lg border text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 shadow-sm"
        >
          <Copy className="w-3.5 h-3.5" aria-hidden="true" /> Copy IP
        </button>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk score gauge */}
        <div className="lg:col-span-1 rounded-2xl p-6 flex flex-col items-center justify-between min-h-[260px] border transition-colors border-blue-100 bg-white dark:border-slate-800 dark:bg-slate-900 shadow-sm dark:shadow-none">
          <div className="w-full text-left">
            <h3 className="text-sm font-bold tracking-wider uppercase font-mono text-slate-600 dark:text-slate-400">RISK PURITY</h3>
            <p className="text-xs mt-1 text-slate-500 dark:text-slate-400">Higher = purer / safer IP</p>
          </div>
          <div className="relative flex items-center justify-center my-6" aria-label={`Risk score: ${results.riskScore} out of 100`}>
            <svg className="w-44 h-44 transform -rotate-90">
              <title>Risk Score Gauge</title>
              <circle cx="88" cy="88" r="74" fill="none" className="stroke-slate-100 dark:stroke-slate-800" strokeWidth="12" />
              <circle
                cx="88" cy="88" r="74" fill="none" stroke="currentColor" strokeWidth="12" strokeLinecap="round"
                className={riskStyles.color}
                strokeDasharray={465} strokeDashoffset={465 - (465 * (results.riskScore || 0)) / 100}
              />
            </svg>
            <div className="absolute text-center">
              <div className="text-4xl font-black font-mono text-slate-900 dark:text-white">{results.riskScore || 0}</div>
              <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400">/ 100</div>
            </div>
          </div>
          <div className="text-center">
            <span className={`text-xs px-3 py-1 rounded-full font-mono font-bold border transition-colors ${riskStyles.bg}`}>
              {results.riskGrade || 'Unknown'}
            </span>
          </div>
        </div>

        {/* Identity & Network Details */}
        <div className="lg:col-span-2 space-y-4">
          <Section title="Network & Identity" icon={<Globe className="w-3.5 h-3.5" />}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <InfoBox label="ISP" value={results.isp} />
              <InfoBox label="Organization" value={results.org} />
              <InfoBox label="ASN" value={results.asn} />
              <InfoBox label="Location" value={`${results.city}, ${results.region}, ${results.country} (${results.countryCode})`} />
              <InfoBox label="Timezone" value={results.timezone} />
              <InfoBox label="IP Type" value={results.ipType} />
              {results.hostname && <InfoBox label="Hostname" value={results.hostname} />}
              {results.reverseDns && <InfoBox label="Reverse DNS (PTR)" value={results.reverseDns} />}
            </div>
          </Section>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatusCard label="Proxy Users" value={results.proxyUsersEstimate ?? '—'} danger={(results.proxyUsersEstimate ?? '') === '50+'} />
            <StatusCard label="Native IP" value={results.isNativeIp ? 'Yes' : 'No'} danger={!results.isNativeIp} />
            <StatusCard label="Anonymity" value={`${results.anonymityScore ?? 0}/100`} danger={(results.anonymityScore ?? 0) < 80} />
            <StatusCard label="WebRTC Leak" value={results.webrtcLeak ? 'Yes' : 'No'} danger={!!results.webrtcLeak} />
          </div>
        </div>
      </div>

      {/* Multi-source Risk Validation */}
      <Section
        title="Multi-Source Risk Validation"
        icon={<ShieldCheck className="w-3.5 h-3.5" />}
        subtitle="Cross-validation against 5 major threat intelligence providers."
        tooltip="Aggregates security verdicts from independent threat feeds to ensure high accuracy and reduce false positives."
      >
        <div className="overflow-x-auto rounded-lg border border-slate-100 dark:border-slate-800 shadow-inner">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead className="bg-slate-50 text-slate-500 dark:bg-slate-800 dark:text-slate-400">
              <tr>
                <th className="px-3 py-2 font-bold uppercase tracking-tighter">Data Source</th>
                <th className="px-3 py-2 font-bold uppercase tracking-tighter">Risk Value</th>
                <th className="px-3 py-2 font-bold uppercase tracking-tighter">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {results.sources?.map((s, idx) => (
                <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition-colors">
                  <td className="px-3 py-2 font-semibold text-slate-900 dark:text-slate-200">{s.name}</td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-400">{s.score}</td>
                  <td className="px-3 py-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${
                      s.verdict === 'clean'
                        ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
                        : s.verdict === 'Residential' || s.verdict === 'Mobile network'
                          ? 'bg-blue-500/10 text-blue-600 border-blue-500/20'
                          : 'bg-red-500/10 text-red-500 border-red-500/20'
                    }`}>
                      {s.verdict}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* BGP & Routing */}
      <Section
        title="BGP Routing Relationships"
        icon={<Server className="w-3.5 h-3.5" />}
        tooltip="Border Gateway Protocol (BGP) info showing how the IP is announced and the status of RPKI routing security validation."
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <InfoBox label="Announcement Prefix" value={results.bgp?.announcementPrefix} />
          <InfoBox label="RPKI Validation" value={results.bgp?.rpki} />
        </div>
        <div>
          <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-2 font-mono uppercase font-semibold">AS Holders</span>
          <div className="flex flex-wrap gap-2">
            {results.bgp?.holders?.length ? results.bgp.holders.map((h, idx) => (
              <span key={idx} className="text-[11px] px-2 py-1 rounded bg-blue-500/10 text-blue-500 dark:text-blue-400 border border-blue-500/20 font-mono shadow-sm">{h}</span>
            )) : <span className="text-xs text-slate-400 italic">No holders identified</span>}
          </div>
        </div>
        {results.bgp?.relations?.length > 0 && (
          <div>
            <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-2 font-mono uppercase font-semibold">Upstream / Downstream Peers</span>
            <div className="space-y-1.5">
              {results.bgp.relations.map((r, idx) => (
                <div key={idx} className="flex items-center justify-between p-2.5 rounded border transition-colors bg-slate-50/40 border-slate-200/60 dark:bg-slate-800/30 dark:border-slate-700/50">
                  <div className="flex items-center gap-2">
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                      r.role === 'upstream'
                        ? 'bg-violet-500/10 text-violet-500 border-violet-500/20'
                        : 'bg-slate-500/10 text-slate-500 border-slate-500/20'
                    }`}>{r.role}</span>
                    <span className="text-xs font-mono text-slate-900 dark:text-slate-300">{r.asn}</span>
                  </div>
                  <span className="text-[11px] text-slate-500 dark:text-slate-400 truncate ml-4">{r.holder}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Section>

      {/* Neighbor scan */}
      <Section
        title="/24 Neighbour Scan"
        icon={<Activity className="w-3.5 h-3.5" />}
        subtitle="Analyzes 256 neighbors in the same segment."
        tooltip="Scans the reputation of adjacent IPs. A high percentage of flagged neighbors often leads to 'guilt by association' in security filters."
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Clean', value: `${(results.neighbors?.total || 0) - (results.neighbors?.flagged || 0)} / ${results.neighbors?.total || 0}`, color: 'text-emerald-500' },
            { label: 'Flagged', value: results.neighbors?.flagged || 0, color: (results.neighbors?.flagged || 0) > 0 ? 'text-red-500' : 'text-emerald-500' },
            { label: 'VPN', value: results.neighbors?.vpn || 0, color: 'text-amber-500' },
            { label: 'Tor', value: results.neighbors?.tor || 0, color: 'text-red-500' },
          ].map((field, idx) => (
            <div key={idx} className="p-3 rounded-lg border text-center transition-colors border-slate-200 bg-slate-50/50 dark:border-slate-700 dark:bg-slate-800/40 shadow-sm">
              <div className={`text-2xl font-black font-mono ${field.color}`}>{field.value}</div>
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase block mt-0.5">{field.label}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* Browser fingerprint */}
      <Section
        title="Fingerprint Consistency"
        icon={<Cpu className="w-3.5 h-3.5" />}
        subtitle="Compares local browser profile against network metadata."
        tooltip="Checks for mismatches between your browser's reported OS/software and what network headers reveal, a common technique for proxy/bot detection."
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {results.fingerprint?.length ? results.fingerprint.map((f, idx) => (
            <div key={idx} className="flex items-center justify-between p-2.5 rounded border transition-colors bg-slate-50/40 border-slate-200/60 dark:bg-slate-800/30 dark:border-slate-700/50">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                  f.category === 'network' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20' :
                  f.category === 'software' ? 'bg-violet-500/10 text-violet-500 border-violet-500/20' :
                  'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'
                }`}>{f.category}</span>
                <span className="text-xs font-semibold truncate text-slate-900 dark:text-slate-300">{f.label}</span>
              </div>
              <span className={`text-[10px] font-mono font-bold shrink-0 ${f.status === 'normal' ? 'text-emerald-500' : 'text-red-500'}`}>
                {f.status === 'normal' ? '✓ Normal' : '⚠ Exposed'}
              </span>
            </div>
          )) : <div className="col-span-2 text-center text-xs text-slate-500 italic py-4">No fingerprint data detected in current context.</div>}
        </div>
      </Section>

      {/* Leaks and Availability */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Section
          title="Privacy Leak Detection"
          icon={<ShieldAlert className="w-3.5 h-3.5" />}
          tooltip="Detection of WebRTC and DNS leaks which could unmask your real IP address even when behind a VPN or proxy."
        >
          <div className="space-y-3">
            {[
              { label: 'WebRTC Leak', status: results.webrtcLeak, desc: 'WebRTC may expose local IP addresses behind NAT.' },
              { label: 'DNS Leak', status: results.dnsLeak, desc: 'Your DNS resolver reveals your ISP location, potentially leaking identity.' }
            ].map((leak, idx) => (
              <div key={idx} className="p-3 rounded-lg border transition-colors bg-slate-50/50 border-slate-200 dark:bg-slate-800/30 dark:border-slate-700 shadow-sm">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs font-bold text-slate-700 dark:text-slate-300">{leak.label}</span>
                  <span className={`text-[10px] font-black uppercase ${leak.status ? 'text-red-500' : 'text-emerald-500'}`}>
                    {leak.status ? 'Leak Detected' : 'Secure'}
                  </span>
                </div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400">{leak.desc}</p>
              </div>
            ))}
          </div>
        </Section>

        <Section
          title="Service Availability"
          icon={<Globe className="w-3.5 h-3.5" />}
          tooltip="Checking service accessibility based on the IP's geographic metadata and provider policies."
        >
          <div className="space-y-4">
             <div>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-tighter mb-2 block">AI Services</span>
                <div className="grid grid-cols-2 gap-2">
                  {results.aiServices?.map((s, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 px-3 rounded border bg-slate-50/40 border-slate-200/60 dark:bg-slate-800/30 dark:border-slate-700/50 shadow-sm">
                      <span className="text-[11px] font-medium text-slate-700 dark:text-slate-300">{s.name}</span>
                      <span className={s.supported ? 'text-emerald-500' : 'text-red-500'} title={s.supported ? 'Supported' : 'Blocked'}>
                        {s.supported ? '✓' : '✗'}
                      </span>
                    </div>
                  ))}
                </div>
             </div>
             <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-bold tracking-tighter mb-2 block">Streaming Zones</span>
                <div className="grid grid-cols-2 gap-2">
                  {results.streamingZones?.map((s, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 px-3 rounded border bg-slate-50/40 border-slate-200/60 dark:bg-slate-800/30 dark:border-slate-700/50 shadow-sm">
                      <span className="text-[11px] font-medium text-slate-700 dark:text-slate-300">{s.name}</span>
                      <span className={s.supported ? 'text-emerald-500' : 'text-red-500'} title={s.supported ? 'Supported' : 'Blocked'}>
                        {s.supported ? '✓' : '✗'}
                      </span>
                    </div>
                  ))}
                </div>
             </div>
          </div>
        </Section>
      </div>
    </div>
  );
};

export default memo(IpAdvanceTab);
