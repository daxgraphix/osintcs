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
    <div className={`rounded-xl border p-5 sm:p-6 space-y-4 ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/40'}`}>
      <div className="flex items-center gap-2">
        <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-500 shrink-0">
          <Info className="w-4 h-4" />
        </div>
        <div>
          <h4 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
            How to use {module.label}
          </h4>
          <p className="text-[11px] text-slate-400 font-mono">Step-by-step guide for beginners</p>
        </div>
      </div>

      <div className="space-y-3">
        {module.guide.map((step, index) => (
          <div key={index} className="flex items-start gap-3">
            <div className={`shrink-0 w-6 h-6 rounded-full border flex items-center justify-center text-[10px] font-black font-mono ${isLightMode ? 'border-slate-300 bg-slate-50 text-slate-600' : 'border-slate-700 bg-slate-900/50 text-slate-400'}`}>
              {index + 1}
            </div>
            <div className="flex-1 pt-0.5">
              <p className={`text-xs leading-relaxed ${isLightMode ? 'text-slate-700' : 'text-slate-300'}`}>
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
