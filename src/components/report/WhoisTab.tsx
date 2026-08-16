/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo } from 'react';
import { Check, Copy, Search, Calendar, Shield, Terminal } from 'lucide-react';
import { WHOISResult } from '../../types';

interface WhoisTabProps {
  results: WHOISResult;
  handleCopy: (text: string, id: string) => void;
  copiedText: string | null;
}

const WhoisDetail = memo(({ label, value, colorClass = "text-slate-900 dark:text-slate-100" }: { label: string; value: string | number; colorClass?: string }) => (
  <div>
    <span className="text-[10px] text-slate-500 dark:text-slate-500 block font-mono font-bold uppercase tracking-tight">{label}</span>
    <span className={`text-sm font-semibold ${colorClass}`}>{value}</span>
  </div>
));

export const WhoisTab: React.FC<WhoisTabProps> = memo(({ results, handleCopy, copiedText }) => {
  return (
    <div id="whois_panel" className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-500">
      {/* WHOIS Quick Details Card */}
      <div className="lg:col-span-1 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Search className="w-3.5 h-3.5" /> REGISTRAR DETAILS
          </h4>

          <div className="space-y-4">
            <WhoisDetail label="REGISTRAR ORG" value={results.registrar || 'Redacted'} />

            <div className="grid grid-cols-2 gap-4">
              <WhoisDetail
                label="DOMAIN AGE"
                value={results.domainAgeDays ? `${results.domainAgeDays} Days` : 'N/A'}
                colorClass="text-red-600 dark:text-red-400 font-mono font-bold"
              />
              <div>
                <span className="text-[10px] text-slate-500 dark:text-slate-500 block font-mono font-bold uppercase tracking-tight">DAYS TO LEASE</span>
                <span className={`text-sm font-mono font-bold ${results.daysToExpiry && results.daysToExpiry <= 30 ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                  {results.daysToExpiry ? `${results.daysToExpiry} Days` : 'N/A'}
                </span>
              </div>
            </div>

            <div className="h-px bg-slate-100 dark:bg-slate-800 transition-colors" />

            <div className="space-y-2.5">
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Calendar className="w-3 h-3" />
                  <span className="font-mono">Creation Date</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono">{results.creationDate || 'N/A'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Calendar className="w-3 h-3" />
                  <span className="font-mono">Expiration Date</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono">{results.expiryDate || 'N/A'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Calendar className="w-3 h-3" />
                  <span className="font-mono">Update Date</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono">{results.updatedDate || 'N/A'}</span>
              </div>
            </div>

            {results.nameservers && results.nameservers.length > 0 && (
              <>
                <div className="h-px bg-slate-100 dark:bg-slate-800 transition-colors" />
                <div className="space-y-2">
                   <span className="text-[10px] text-slate-500 dark:text-slate-500 block font-mono font-bold uppercase tracking-tight">Nameservers</span>
                   <div className="flex flex-col gap-1.5">
                      {results.nameservers.map((ns, idx) => (
                        <code key={idx} className="text-[10px] p-1.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-100 dark:border-slate-800 text-slate-600 dark:text-slate-400 font-mono break-all">
                          {ns}
                        </code>
                      ))}
                   </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* WHOIS Raw Output Terminal */}
      <div className="lg:col-span-2 border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 rounded-2xl overflow-hidden flex flex-col h-[600px] shadow-sm transition-colors">
        <div className="bg-slate-100 dark:bg-slate-900 px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between transition-colors">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5 mr-2">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500/80 dark:bg-red-500/60" />
              <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80 dark:bg-amber-500/60" />
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 dark:bg-emerald-500/60" />
            </div>
            <Terminal className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
            <span className="text-xs text-slate-600 dark:text-slate-400 font-mono">whois_query_output.log</span>
          </div>
          <button
            onClick={() => handleCopy(results.raw || '', 'whois_raw')}
            className="px-3 py-1 text-[10px] font-bold rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-all flex items-center gap-1.5 active:scale-95"
            aria-label="Copy raw WHOIS output"
          >
            {copiedText === 'whois_raw' ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
            <span>{copiedText === 'whois_raw' ? 'COPIED' : 'COPY RAW'}</span>
          </button>
        </div>
        <div className="p-6 overflow-y-auto font-mono text-[11px] text-slate-700 dark:text-slate-300 leading-relaxed bg-white dark:bg-slate-950 flex-1 transition-colors">
          <pre className="whitespace-pre-wrap break-all select-text selection:bg-red-500/20">{results.raw || 'No raw data available.'}</pre>
        </div>
      </div>
    </div>
  );
});

WhoisTab.displayName = 'WhoisTab';
WhoisDetail.displayName = 'WhoisDetail';

export default WhoisTab;
