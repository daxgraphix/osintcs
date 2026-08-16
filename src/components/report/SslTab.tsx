/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo } from 'react';
import { Check, Copy, Shield, Lock, Calendar, Hash, FileText, Globe } from 'lucide-react';
import { SSLResult } from '../../types';

interface SslTabProps {
  results: SSLResult;
  handleCopy: (text: string, id: string) => void;
  copiedText: string | null;
}

const CertificateDetail = memo(({ label, value, colorClass = "text-slate-900 dark:text-slate-100" }: { label: string; value: string | number; colorClass?: string }) => (
  <div>
    <span className="text-[10px] text-slate-500 dark:text-slate-500 block font-mono font-bold uppercase tracking-tight">{label}</span>
    <span className={`text-sm font-semibold ${colorClass}`}>{value}</span>
  </div>
));

const SslStatusRow = memo(({ label, isEnabled, warning = false }: { label: string; isEnabled: boolean; warning?: boolean }) => (
  <div className="flex justify-between items-center text-xs">
    <span className="text-slate-500 dark:text-slate-400 font-mono">{label}</span>
    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
      isEnabled
        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
        : warning
          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
          : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-transparent'
    }`}>
      {isEnabled ? 'ENABLED' : 'DISABLED'}
    </span>
  </div>
));

export const SslTab: React.FC<SslTabProps> = memo(({ results, handleCopy, copiedText }) => {
  return (
    <div id="ssl_panel" className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-500">
      {/* SSL Quick Specs Card */}
      <div className="lg:col-span-1 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" /> CERTIFICATE HEALTH
          </h4>

          <div className="space-y-4">
            <CertificateDetail label="ISSUING AUTHORITY (CA)" value={results.issuer ?? '—'} />

            <div className="grid grid-cols-2 gap-4">
              <CertificateDetail
                label="PROTOCOL VERSION"
                value={results.protocol ?? '—'}
                colorClass="text-red-600 dark:text-red-400 font-mono"
              />
              <div>
                <span className="text-[10px] text-slate-500 dark:text-slate-500 block font-mono font-bold uppercase tracking-tight">CIPHER SUITE</span>
                <span className="text-[10px] text-slate-700 dark:text-slate-300 font-mono block break-all leading-tight mt-0.5">
                  {results.cipher ?? '—'}
                </span>
              </div>
            </div>

            <div className="h-px bg-slate-100 dark:bg-slate-800 transition-colors" />

            <div className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Calendar className="w-3 h-3" />
                  <span className="font-mono">Valid From</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono">{results.validFrom ?? '—'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Calendar className="w-3 h-3" />
                  <span className="font-mono">Valid To</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono">{results.validTo ?? '—'}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-500 dark:text-slate-400 font-mono">Remaining Days</span>
                <span className={`font-mono font-bold ${(results.daysRemaining ?? 0) < 30 ? 'text-red-500' : 'text-slate-700 dark:text-slate-300'}`}>
                  {results.daysRemaining ?? '—'} days
                </span>
              </div>
            </div>

            <div className="h-px bg-slate-100 dark:bg-slate-800 transition-colors" />

            <div className="space-y-3">
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <Lock className="w-3 h-3" />
                  <span className="font-mono">Key Exchange</span>
                </div>
                <span className="text-slate-700 dark:text-slate-300 font-mono font-bold">{results.keyExchange || 'N/A'}</span>
              </div>

              <SslStatusRow label="Forward Secrecy" isEnabled={!!results.hasPerfectForwardSecrecy} warning={!results.hasPerfectForwardSecrecy} />

              <SslStatusRow label="Certificate Transparency" isEnabled={!!results.certificateTransparency} />

              <div>
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 mb-1">
                  <Hash className="w-3 h-3" />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-tight">Serial Number</span>
                </div>
                <span className="text-[10px] text-slate-700 dark:text-slate-300 font-mono break-all block p-2 bg-slate-50 dark:bg-slate-950 rounded border border-slate-100 dark:border-slate-800 transition-colors">
                  {results.serialNumber || 'N/A'}
                </span>
              </div>

              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
                  <FileText className="w-3 h-3" />
                  <span className="font-mono">Signature Algorithm</span>
                </div>
                <span className="text-[10px] text-slate-700 dark:text-slate-300 font-mono">{results.signatureAlgorithm || 'N/A'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Subject Alternative Names list */}
      <div className="lg:col-span-2 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-6 shadow-sm transition-colors">
        <div>
          <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
            <Globe className="w-4 h-4" /> CERTIFICATE EXTENSIONS (SANs)
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">Authorized hostnames compiled in the SSL Subject Alternative Name block</p>
        </div>

        <div className="space-y-3">
          {results.sans && results.sans.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {results.sans.map((san, idx) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-50/40 dark:bg-slate-800/30 border border-slate-200/60 dark:border-slate-800/60 flex items-center justify-between hover:border-slate-300 dark:hover:border-slate-700 transition-all group">
                  <span className="text-xs font-mono text-red-500 dark:text-red-400 truncate mr-2">{san}</span>
                  <button
                    onClick={() => handleCopy(san, `san_${idx}`)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all shrink-0 active:scale-95"
                    aria-label={`Copy SAN ${san}`}
                  >
                    {copiedText === `san_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100" />}
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-slate-500 dark:text-slate-500 font-mono text-xs py-12 text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-xl">
              No Subject Alternative Names defined.
            </div>
          )}
        </div>
      </div>
    </div>
  );
});

SslTab.displayName = 'SslTab';
CertificateDetail.displayName = 'CertificateDetail';
SslStatusRow.displayName = 'SslStatusRow';

export default SslTab;
