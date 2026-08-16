/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo, useMemo } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Terminal, Server, Info, AlertTriangle } from 'lucide-react';
import { HeaderResult } from '../../types';

interface HeadersTabProps {
  results: HeaderResult;
}

const SecurityHeaderBadge = memo(({ label, present }: { label: string; present: boolean }) => (
  <div className="p-3.5 rounded-xl bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 flex items-center justify-between transition-colors shadow-sm">
    <div className="flex items-center gap-2.5">
      {present ? (
        <ShieldCheck className="w-4 h-4 text-emerald-500" />
      ) : (
        <ShieldAlert className="w-4 h-4 text-red-500" />
      )}
      <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{label}</span>
    </div>
    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
      present
        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
        : 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20'
    }`}>
      {present ? 'ACTIVE' : 'MISSING'}
    </span>
  </div>
));

export const HeadersTab: React.FC<HeadersTabProps> = memo(({ results }) => {
  const hardeningFlags = useMemo(() => [
    { key: 'hsts', label: 'HSTS (Strict Transport)', present: results.securityHeaders.hsts.present },
    { key: 'csp', label: 'Content-Security-Policy', present: results.securityHeaders.csp.present },
    { key: 'xFrame', label: 'X-Frame-Options (Clickjack)', present: results.securityHeaders.xFrameOptions.present },
    { key: 'xContent', label: 'X-Content-Type (Mime Sniff)', present: results.securityHeaders.xContentTypeOptions.present },
    { key: 'referrer', label: 'Referrer-Policy', present: results.securityHeaders.referrerPolicy.present },
  ], [results.securityHeaders]);

  return (
    <div id="headers_panel" className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-500">
      {/* Security Headers Summary Badges */}
      <div className="lg:col-span-1 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" /> HARDENING FLAGS
          </h4>
          <div className="space-y-3">
            {hardeningFlags.map((h) => (
              <SecurityHeaderBadge key={h.key} label={h.label} present={h.present} />
            ))}
          </div>
        </div>

        {results.server && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
            <div className="flex items-center gap-2 mb-1">
              <Server className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
              <span className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase">SERVER EMBEDDED FLAG</span>
            </div>
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-800 transition-colors">
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">{results.server}</span>
                <span className="text-[9px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-mono border border-amber-500/20 font-bold">INFO REVEAL</span>
              </div>
              <p className="text-[10px] text-slate-500 dark:text-slate-500 italic leading-relaxed">
                <AlertTriangle className="w-3 h-3 inline mr-1 text-amber-500" />
                Revealing server versions facilitates targeted exploits by threat actors.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Complete Headers Table */}
      <div className="lg:col-span-2 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-6 shadow-sm transition-colors">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
              <Terminal className="w-4 h-4" /> COMPLETE HTTP RESPONSE HEADERS
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">Full header mappings captured on primary document handshake</p>
          </div>
          <div className="flex items-center gap-2 px-2 py-1 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-800">
            <Info className="w-3.5 h-3.5 text-blue-500" />
            <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 uppercase font-bold">{Object.keys(results.headers).length} HEADERS FOUND</span>
          </div>
        </div>

        <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden transition-colors">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-[10px] text-slate-500 dark:text-slate-500 font-mono uppercase tracking-wider">
                  <th className="p-4 font-bold">Header Key</th>
                  <th className="p-4 font-bold">Header Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-[11px] font-mono">
                {Object.entries(results.headers).map(([key, value]) => (
                  <tr key={key} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 group transition-colors">
                    <td className="p-4 text-red-600 dark:text-red-400 font-semibold break-all select-all align-top w-1/3 border-r border-slate-100 dark:border-slate-800">
                      {key}
                    </td>
                    <td className="p-4 text-slate-700 dark:text-slate-300 break-all select-all leading-relaxed">
                      {value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
});

HeadersTab.displayName = 'HeadersTab';
SecurityHeaderBadge.displayName = 'SecurityHeaderBadge';

export default HeadersTab;
