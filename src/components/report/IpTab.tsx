/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo } from 'react';
import { Shield, Globe, MapPin, Building, Network, Activity, Terminal } from 'lucide-react';
import { IPResult } from '../../types';

interface IpTabProps {
  results: IPResult;
}

const InfoCard = memo(({ label, value, icon: Icon, mono = true }: { label: string; value?: string | number; icon?: any; mono?: boolean }) => (
  <div className="p-3 rounded-lg bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors">
    <div className="flex items-center gap-2 mb-1">
      {Icon && <Icon className="w-3 h-3 text-slate-400 dark:text-slate-500" />}
      <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase tracking-tight">{label}</span>
    </div>
    <span className={`text-sm font-bold block break-all text-slate-900 dark:text-slate-100 ${mono ? 'font-mono' : ''}`}>
      {value || 'N/A'}
    </span>
  </div>
));

const ThreatIndicator = memo(({ label, isDetected, warning = false }: { label: string; isDetected: boolean; warning?: boolean }) => (
  <div className="flex items-center justify-between p-2.5 rounded bg-slate-50/40 dark:bg-slate-800/20 border border-slate-200/60 dark:border-slate-800/60 transition-colors">
    <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{label}</span>
    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
      isDetected
        ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20'
        : warning
          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
          : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
    }`}>
      {isDetected ? 'DETECTED' : 'NOT DETECTED'}
    </span>
  </div>
));

export const IpTab: React.FC<IpTabProps> = memo(({ results }) => {
  return (
    <div id="ip_panel" className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-500">
      {/* IP Quick Details Card */}
      <div className="lg:col-span-1 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Globe className="w-3.5 h-3.5" /> NETWORK INTELLIGENCE
          </h4>
          <div className="space-y-3">
            <InfoCard label="IP Address" value={results.ip} icon={Network} />

            <div className="p-3 rounded-lg bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors">
              <div className="flex items-center gap-2 mb-1">
                <Terminal className="w-3 h-3 text-slate-400 dark:text-slate-500" />
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-bold uppercase tracking-tight">Hostname</span>
              </div>
              <span className="text-sm font-mono font-bold text-red-600 dark:text-red-400 break-all transition-colors">
                {results.hostname || 'N/A'}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <InfoCard label="Country Code" value={results.countryCode} />
              <InfoCard label="Country" value={results.country} />
            </div>

            <InfoCard label="Organization" value={results.org} icon={Building} />

            {results.region && <InfoCard label="Region" value={results.region} />}

            <InfoCard label="ASN" value={results.asn} />

            {results.city && <InfoCard label="City" value={results.city} icon={MapPin} />}

            {results.currency && <InfoCard label="Currency" value={results.currency} />}
          </div>
        </div>

        {/* Threat Indicators */}
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" /> THREAT INDICATORS
          </h4>
          <div className="space-y-2">
            <ThreatIndicator label="Tor Exit Node" isDetected={results.isTor} />
            <ThreatIndicator label="VPN / Proxy" isDetected={results.isVpn || results.isProxy} />
            <ThreatIndicator label="Hosting Provider" isDetected={results.isHosting} warning={results.isHosting} />
            <div className="flex items-center justify-between p-2.5 rounded bg-slate-50/40 dark:bg-slate-800/20 border border-slate-200/60 dark:border-slate-800/60 transition-colors">
              <span className="text-xs font-medium text-slate-700 dark:text-slate-300">Threat Level</span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                results.threatLevel === 'high' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' :
                results.threatLevel === 'medium' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20' :
                results.threatLevel === 'low' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20' :
                'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
              }`}>
                {results.threatLevel.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* IP Ports & Details */}
      <div className="lg:col-span-2 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Activity className="w-4 h-4" /> OPEN PORTS & SERVICES
          </h3>
          <div className="space-y-2">
            {results.ports.length > 0 ? results.ports.map((port, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 rounded-xl bg-slate-50/40 dark:bg-slate-800/30 border border-slate-200/60 dark:border-slate-800/60 hover:border-slate-300 dark:hover:border-slate-700 transition-all">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-bold text-red-600 dark:text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">:{port.port}</span>
                  <span className="text-xs font-medium text-slate-900 dark:text-slate-200">{port.service}</span>
                </div>
                <div className="flex items-center gap-3">
                  {port.version && <span className="text-[10px] text-slate-500 dark:text-slate-500 font-mono">{port.version}</span>}
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                    port.state === 'open' ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                  }`}>
                    {port.state.toUpperCase()}
                  </span>
                </div>
              </div>
            )) : (
              <div className="p-8 text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-xl text-slate-500 dark:text-slate-500">
                No open ports detected in initial scan.
              </div>
            )}
          </div>
        </div>

        {results.loc && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
            <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
              <MapPin className="w-4 h-4 text-red-500" /> GEOLOCATION COORDINATES
            </h3>
            <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 block mb-1 font-bold uppercase">Latitude, Longitude</span>
              <span className="text-sm font-mono font-bold text-slate-900 dark:text-slate-100">{results.loc}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
});

IpTab.displayName = 'IpTab';
InfoCard.displayName = 'InfoCard';
ThreatIndicator.displayName = 'ThreatIndicator';

export default IpTab;
