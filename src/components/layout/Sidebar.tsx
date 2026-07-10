import React from 'react';
import {
  Globe,
  FileText,
  Layers,
  History,
  Settings,
  ChevronRight,
  ChevronLeft,
} from 'lucide-react';
import { TargetType } from '../../types';
import { QUICK_MODULES } from '../pages/moduleConfig';

export default function Sidebar({
  activeTab,
  sidebarOpen,
  setSidebarOpen,
  isLightMode,
  results,
  batchResults,
  viewingReport,
  setViewingReport,
  viewingBatch,
  setViewingBatch,
  onSelectModule,
}: {
  activeTab: TargetType | 'home' | 'risk' | 'settings' | 'history';
  sidebarOpen: boolean;
  setSidebarOpen: (v: boolean) => void;
  isLightMode: boolean;
  results: any;
  batchResults: any[];
  viewingReport: boolean;
  setViewingReport: (v: boolean) => void;
  viewingBatch: boolean;
  setViewingBatch: (v: boolean) => void;
  onSelectModule: (id: typeof activeTab) => void;
}) {
  return (
    <aside
      className={`hidden md:flex flex-col shrink-0 border-r transition-all duration-300 z-30 ${
        isLightMode ? 'bg-white border-slate-200' : 'bg-[#090d16] border-slate-850'
      } ${sidebarOpen ? 'w-64' : 'w-20'}`}
    >
      <div
        className={`h-16 flex items-center justify-between px-4 border-b ${
          isLightMode ? 'border-slate-100' : 'border-slate-850'
        }`}
      >
<div className="flex items-center gap-2.5 overflow-hidden">
           <div className="p-1.5 rounded bg-cyan-500/10 text-cyan-500 border border-cyan-500/20">
             <svg className="w-5 h-5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
               <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
             </svg>
           </div>
           {sidebarOpen && (
             <div className="flex flex-col leading-none">
               <span className={`text-base font-black font-display tracking-tight ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                 osint<span className="text-cyan-400">cs</span>
               </span>
               <span className="text-[8px] font-mono tracking-widest text-slate-500 mt-0.5">OSINT SUITE</span>
             </div>
           )}
         </div>

        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className={`p-1.5 rounded-md hover:bg-slate-800/35 text-slate-500 hover:text-slate-300 transition-colors cursor-pointer`}
        >
          {sidebarOpen ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6 scrollbar-thin">
        <div className="space-y-1">
          <button
            onClick={() => onSelectModule('home')}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-semibold transition-all cursor-pointer ${
              activeTab === 'home'
                ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
            }`}
          >
            <Globe className="w-4 h-4" />
            {sidebarOpen && <span>Lobby Home</span>}
          </button>
        </div>

        <div className="space-y-1">
          {sidebarOpen && (
            <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider block px-3 mb-2">
              OSINT TOOLS
            </span>
          )}
          <div className="space-y-0.5">
            {QUICK_MODULES.map((mod) => {
              const Icon = mod.icon;
              const isSelected = activeTab === mod.id;
              return (
                <button
                  key={mod.id}
                  onClick={() => onSelectModule(mod.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/20'
                  }`}
                  title={mod.label}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  {sidebarOpen && <span className="truncate">{mod.label}</span>}
                </button>
              );
            })}
          </div>
        </div>

        <div className="space-y-1 pt-2 border-t border-slate-850/65">
          {sidebarOpen && (
            <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider block px-3 mb-2">
              WORKSPACE
            </span>
          )}
          <div className="space-y-0.5">
            {results && (
              <button
                onClick={() => {
                  setViewingReport(true);
                  setViewingBatch(false);
                }}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-bold transition-all border cursor-pointer mb-1 ${
                  viewingReport
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    : isLightMode
                    ? 'text-slate-600 border-dashed border-cyan-500/35 hover:text-cyan-600 hover:bg-cyan-500/5'
                    : 'text-slate-400 border-dashed border-cyan-500/20 hover:text-cyan-400 hover:bg-cyan-500/5'
                }`}
                title={`View report for ${results.target.value}`}
              >
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                </span>
                <FileText className="w-4 h-4 shrink-0 text-cyan-500" />
                {sidebarOpen && <span className="truncate">Active Report</span>}
              </button>
            )}

            {batchResults && batchResults.length > 0 && (
              <button
                onClick={() => {
                  setViewingBatch(true);
                  setViewingReport(false);
                }}
                className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-bold transition-all border cursor-pointer mb-1 ${
                  viewingBatch && !viewingReport
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                    : isLightMode
                    ? 'text-slate-600 border-dashed border-emerald-500/35 hover:text-emerald-600 hover:bg-emerald-500/5'
                    : 'text-slate-400 border-dashed border-emerald-500/20 hover:text-emerald-400 hover:bg-emerald-500/5'
                }`}
                title={`View batch of ${batchResults.length} targets`}
              >
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <Layers className="w-4 h-4 shrink-0 text-emerald-500" />
                {sidebarOpen && <span className="truncate">Batch ({batchResults.length})</span>}
              </button>
            )}

            <button
              onClick={() => onSelectModule('history')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'history'
                  ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/20'
              }`}
            >
              <History className="w-4 h-4 shrink-0" />
              {sidebarOpen && <span>Scan History</span>}
            </button>
            <button
              onClick={() => onSelectModule('settings')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                activeTab === 'settings'
                  ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/20'
              }`}
            >
              <Settings className="w-4 h-4 shrink-0" />
              {sidebarOpen && <span>Settings & Sandbox</span>}
            </button>
          </div>
        </div>
      </div>

      <div className={`p-4 border-t ${isLightMode ? 'border-slate-100' : 'border-slate-850'}`}>
        <div className="flex items-center gap-2 px-1.5 py-1 rounded bg-emerald-500/5 border border-emerald-500/10">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shrink-0" />
          {sidebarOpen && (
            <span className="text-[9px] font-mono text-emerald-400 font-bold uppercase tracking-wider">
              LOCAL SECURE SANDBOX
            </span>
          )}
        </div>
      </div>
    </aside>
  );
}
