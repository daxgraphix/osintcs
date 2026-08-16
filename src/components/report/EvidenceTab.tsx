/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo, useMemo } from 'react';
import {
  ListFilter,
  Copy,
  Check,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  ShieldCheck,
  Star,
  Flag
} from 'lucide-react';
import { Finding } from '../../types';

interface EvidenceTabProps {
  findings: Finding[];
  evidenceFilter: string;
  setEvidenceFilter: (filter: string) => void;
  flaggedFindings: Record<string, 'critical' | 'interesting' | null>;
  toggleFlagFinding: (findingId: string, flag: 'critical' | 'interesting') => void;
  handleCopy: (text: string, id: string) => void;
  copiedText: string | null;
  handleCopyFindingsMarkdown: () => void;
  copiedFindingsMarkdown: boolean;
}

const SeverityBadge = memo(({ severity }: { severity: string }) => {
  const config = useMemo(() => {
    switch (severity) {
      case 'critical': return { icon: ShieldAlert, bg: 'bg-red-600', text: 'text-white' };
      case 'high': return { icon: AlertTriangle, bg: 'bg-orange-500', text: 'text-white' };
      case 'medium': return { icon: AlertCircle, bg: 'bg-amber-500', text: 'text-slate-900' };
      case 'low': return { icon: Info, bg: 'bg-blue-500', text: 'text-white' };
      case 'pass': return { icon: ShieldCheck, bg: 'bg-emerald-500', text: 'text-white' };
      default: return { icon: Info, bg: 'bg-slate-500', text: 'text-white' };
    }
  }, [severity]);

  const Icon = config.icon;

  return (
    <div className={`p-2.5 rounded-xl ${config.bg} ${config.text} shadow-sm transition-transform group-hover:scale-110 duration-300`}>
      <Icon className="w-5 h-5" />
    </div>
  );
});

const FindingCard = memo(({
  finding,
  isFlagged,
  toggleFlagFinding,
  handleCopy,
  isCopied
}: {
  finding: Finding;
  isFlagged: 'critical' | 'interesting' | null;
  toggleFlagFinding: any;
  handleCopy: any;
  isCopied: boolean;
}) => {
  const severityStyles = useMemo(() => {
    switch (finding.severity) {
      case 'critical': return 'bg-red-50/30 dark:bg-red-950/10 border-red-200/50 dark:border-red-900/30 text-red-900 dark:text-red-200';
      case 'high': return 'bg-orange-50/30 dark:bg-orange-950/10 border-orange-200/50 dark:border-orange-900/30 text-orange-900 dark:text-orange-200';
      case 'medium': return 'bg-amber-50/30 dark:bg-amber-950/10 border-amber-200/50 dark:border-amber-900/30 text-amber-900 dark:text-amber-200';
      case 'low': return 'bg-blue-50/30 dark:bg-blue-950/10 border-blue-200/50 dark:border-blue-900/30 text-blue-900 dark:text-blue-200';
      case 'pass': return 'bg-emerald-50/30 dark:bg-emerald-950/10 border-emerald-200/50 dark:border-emerald-900/30 text-emerald-900 dark:text-emerald-200';
      default: return 'bg-slate-50/30 dark:bg-slate-950/10 border-slate-200/50 dark:border-slate-900/30 text-slate-900 dark:text-slate-200';
    }
  }, [finding.severity]);

  return (
    <div className={`group transition-all border rounded-2xl overflow-hidden ${severityStyles} shadow-sm hover:shadow-md dark:shadow-none`}>
      <div className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <SeverityBadge severity={finding.severity} />
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-mono font-black uppercase tracking-widest opacity-60 dark:opacity-40">
                  {finding.module} // {finding.category}
                </span>
                {isFlagged && (
                  <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase flex items-center gap-1 shadow-sm ${
                    isFlagged === 'critical' ? 'bg-red-600 text-white' : 'bg-amber-500 text-slate-900'
                  }`}>
                    {isFlagged === 'critical' ? <Flag className="w-2.5 h-2.5" /> : <Star className="w-2.5 h-2.5" />}
                    {isFlagged === 'critical' ? 'Critical Evidence' : 'Interesting'}
                  </span>
                )}
              </div>
              <h4 className="text-lg font-bold tracking-tight text-slate-900 dark:text-white transition-colors">
                {finding.title}
              </h4>
              <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300 max-w-4xl transition-colors">
                {finding.description}
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-2 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
            <button
              onClick={() => toggleFlagFinding(finding.id, 'critical')}
              className={`p-2 rounded-xl border transition-all cursor-pointer active:scale-90 ${
                isFlagged === 'critical' ? 'bg-red-600 border-red-700 text-white' : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-400 hover:text-red-500'
              }`}
              aria-label="Flag as critical evidence"
            >
              <Flag className="w-4 h-4" />
            </button>
            <button
              onClick={() => toggleFlagFinding(finding.id, 'interesting')}
              className={`p-2 rounded-xl border transition-all cursor-pointer active:scale-90 ${
                isFlagged === 'interesting' ? 'bg-amber-500 border-amber-600 text-slate-900' : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-400 hover:text-amber-500'
              }`}
              aria-label="Mark as interesting"
            >
              <Star className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="mt-6 pt-5 border-t border-slate-900/10 dark:border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors">
          <div className="flex flex-col">
            <span className="opacity-50 dark:opacity-40 font-bold uppercase text-[9px] mb-1 tracking-wider">Recommended Remediation</span>
            <span className="text-sm text-slate-800 dark:text-slate-200 font-medium italic transition-colors">"{finding.remediation}"</span>
          </div>
          <button
            onClick={() => handleCopy(finding.description, finding.id)}
            className="flex items-center gap-2 px-4 py-2 text-[10px] font-bold uppercase tracking-widest rounded-xl border border-slate-900/10 dark:border-white/10 bg-white/40 dark:bg-slate-800/40 hover:bg-white dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition-all cursor-pointer active:scale-95 shadow-sm"
          >
            {isCopied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy Raw Evidence
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
});

export const EvidenceTab: React.FC<EvidenceTabProps> = memo(({
  findings,
  evidenceFilter,
  setEvidenceFilter,
  flaggedFindings,
  toggleFlagFinding,
  handleCopy,
  copiedText,
  handleCopyFindingsMarkdown,
  copiedFindingsMarkdown,
}) => {
  const filteredFindings = useMemo(() =>
    findings.filter((f) => evidenceFilter === 'all' || f.severity === evidenceFilter)
  , [findings, evidenceFilter]);

  return (
    <div id="evidence_panel" className="space-y-6 animate-in fade-in duration-500">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 border-b border-slate-200 dark:border-slate-800 pb-6 transition-colors">
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-sm transition-colors">
            <ListFilter className="w-4 h-4 text-slate-500 dark:text-slate-400" />
            <select
              value={evidenceFilter}
              onChange={(e) => setEvidenceFilter(e.target.value)}
              className="text-sm font-bold bg-transparent border-none focus:ring-0 cursor-pointer text-slate-700 dark:text-slate-300 outline-none"
            >
              <option value="all">All Findings</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Severity</option>
              <option value="medium">Medium Risk</option>
              <option value="low">Low Risk</option>
              <option value="pass">Passed Checks</option>
            </select>
          </div>
          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500 font-black uppercase tracking-widest">
            {filteredFindings.length} OF {findings.length} RECORDS DISPLAYED
          </span>
        </div>
        <button
          onClick={handleCopyFindingsMarkdown}
          className="px-5 py-2.5 text-[10px] font-bold uppercase tracking-widest rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition-all flex items-center gap-2.5 cursor-pointer shadow-sm active:scale-95"
        >
          {copiedFindingsMarkdown ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
          Copy Findings Summary (MD)
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              isFlagged={flaggedFindings[finding.id]}
              toggleFlagFinding={toggleFlagFinding}
              handleCopy={handleCopy}
              isCopied={copiedText === finding.id}
            />
          ))
        ) : (
          <div className="py-24 text-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-3xl transition-colors">
            <div className="inline-flex p-4 rounded-full bg-slate-50 dark:bg-slate-900 mb-4 transition-colors">
              <ShieldCheck className="w-8 h-8 text-slate-300 dark:text-slate-700" />
            </div>
            <h3 className="text-slate-900 dark:text-white font-bold transition-colors">No matches found</h3>
            <p className="text-sm text-slate-500 dark:text-slate-500 mt-1 transition-colors">Adjust your filter to view other findings.</p>
          </div>
        )}
      </div>
    </div>
  );
});

EvidenceTab.displayName = 'EvidenceTab';
SeverityBadge.displayName = 'SeverityBadge';
FindingCard.displayName = 'FindingCard';
