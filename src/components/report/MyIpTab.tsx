/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo } from 'react';
import { Copy, Globe, MapPin, Monitor, Clock, Shield, Network } from 'lucide-react';
import { MyIpResult } from '../../types';

interface MyIpTabProps {
  results: MyIpResult;
  scanTime: string;
  showToast?: (message: string, type: 'success' | 'error' | 'info') => void;
}

const InfoCard = memo(({ label, value, icon: Icon, mono = true }: { label: string; value?: string | number; icon?: any; mono?: boolean }) => (
  <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors shadow-sm">
    <div className="flex items-center gap-2 mb-1">
      {Icon && <Icon className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />}
      <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase tracking-tight">{label}</span>
    </div>
    <span className={`text-sm font-bold block break-all text-slate-900 dark:text-slate-100 ${mono ? 'font-mono' : ''}`}>
      {value || 'N/A'}
    </span>
  </div>
));

export const MyIpTab: React.FC<MyIpTabProps> = memo(({ results, scanTime, showToast }) => {
  const handleCopy = () => {
    navigator.clipboard.writeText(results.ip);
    if (showToast) showToast('IP address copied to clipboard', 'success');
  };

  return (
    <div id="myip_panel" className="space-y-6 animate-in fade-in duration-500">
      {/* Hero IP */}
      <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm transition-colors">
        <div className="space-y-1 min-w-0">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 block">Your Public IP Address</span>
          <div className="flex items-center gap-3">
            <h2 className="text-2xl sm:text-3xl font-black font-mono text-slate-900 dark:text-white break-all transition-colors">{results.ip}</h2>
            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold shrink-0 bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
              {results.ipVersion}
            </span>
          </div>
        </div>
        <button
          onClick={handleCopy}
          className="shrink-0 px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 text-xs font-bold transition-all flex items-center gap-2 cursor-pointer shadow-sm active:scale-95"
          aria-label="Copy public IP address"
        >
          <Copy className="w-4 h-4" /> COPY IP
        </button>
      </div>

      <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
        <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
          <Globe className="w-4 h-4" /> NETWORK & LOCATION
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <InfoCard label="ISP" value={results.isp} icon={Network} />
          <InfoCard label="Organization" value={results.org} />
          <InfoCard label="ASN" value={results.asn} />
          <InfoCard label="Country" value={results.country} />
          <InfoCard label="Region" value={results.region} />
          <InfoCard label="City" value={results.city} icon={MapPin} />
          <InfoCard label="Timezone" value={results.timezone} />
          {(results.latitude !== undefined && results.longitude !== undefined) && (
            <InfoCard label="Coordinates" value={`${results.latitude.toFixed(4)}, ${results.longitude.toFixed(4)}`} icon={MapPin} />
          )}
        </div>
      </div>

      <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
        <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
          <Monitor className="w-4 h-4" /> CONNECTION FINGERPRINT
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <InfoCard label="Platform" value={results.platform} icon={Monitor} />
          <InfoCard label="Language" value={results.language} />
        </div>
        <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors shadow-sm">
          <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-1 font-bold uppercase tracking-tight">User Agent</span>
          <span className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all leading-relaxed">{results.userAgent}</span>
        </div>
      </div>

      <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 text-[11px] text-slate-500 dark:text-slate-500 font-mono flex items-center justify-between transition-colors">
        <div className="flex items-center gap-2">
          <Clock className="w-3.5 h-3.5" />
          <span>Scan captured at {scanTime}</span>
        </div>
        <div className="flex items-center gap-1.5 opacity-60">
          <Shield className="w-3 h-3" />
          <span>Local Geolocation Analysis</span>
        </div>
      </div>
    </div>
  );
});

MyIpTab.displayName = 'MyIpTab';
InfoCard.displayName = 'InfoCard';

export default MyIpTab;
