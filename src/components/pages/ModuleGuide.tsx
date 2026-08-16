/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { CheckCircle2, Info } from 'lucide-react';
import { ModuleConfig } from './moduleConfig';

interface ModuleGuideProps {
  module: ModuleConfig;
  isLightMode: boolean;
}

export default function ModuleGuide({ module, isLightMode }: ModuleGuideProps) {
  if (!module.guide || module.guide.length === 0) return null;

  return (
    <div className={`soft-panel rounded-xl border p-5 sm:p-6 space-y-5 ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/40'}`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-500 shrink-0">
            <Info className="w-4 h-4" />
          </div>
          <div>
            <h4 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
              How to use {module.label}
            </h4>
            <p className="text-[11px] muted-copy font-mono">Quick-start workflow for clean results</p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-wider">
          <span className={`px-2 py-1 rounded-full border ${isLightMode ? 'border-slate-200 bg-slate-50 text-slate-600' : 'border-slate-700 bg-slate-900/50 text-slate-400'}`}>
            Quick start
          </span>
          <span className={`px-2 py-1 rounded-full border ${isLightMode ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'}`}>
            Live scan
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {module.guide.map((step, index) => (
          <div key={index} className="flex items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-900/20" style={{ borderColor: 'var(--border-default)', background: 'var(--bg-hover)' }}>
            <div className={`shrink-0 w-6 h-6 rounded-full border flex items-center justify-center text-[10px] font-black font-mono ${isLightMode ? 'border-slate-300 bg-slate-50 text-slate-600' : 'border-slate-700 bg-slate-900/50 text-slate-400'}`}>
              {index + 1}
            </div>
            <div className="flex-1 pt-0.5">
              <p className="text-xs leading-relaxed content-copy">
                {step}
              </p>
            </div>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5 opacity-0" aria-hidden="true" />
          </div>
        ))}
      </div>
    </div>
  );
}
