import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Globe, FileText, Layers, History, Settings,
  ChevronRight, ChevronLeft, Shield, Mail, User,
  Key, Database, Server, Eye, FileCode,
  Network,
} from 'lucide-react';
import { TargetType } from '../../types';
import { QUICK_MODULES } from '../pages/moduleConfig';

/* ── Module accent colours — all high-contrast for light mode ── */
const MODULE_ACCENTS: Record<string, { bg: string; border: string; text: string; icon: string }> = {
  risk:     { bg: 'rgba(220,38,38,0.10)',   border: 'rgba(220,38,38,0.30)',   text: '#b91c1c',  icon: '#dc2626' },
  image:    { bg: 'rgba(220,38,38,0.08)',   border: 'rgba(220,38,38,0.25)',   text: '#dc2626',  icon: '#ef4444' },
  domain:   { bg: 'rgba(71,85,105,0.08)',   border: 'rgba(71,85,105,0.22)',   text: '#334155',  icon: '#475569' },
  website:  { bg: 'rgba(71,85,105,0.07)',   border: 'rgba(71,85,105,0.20)',   text: '#475569',  icon: '#64748b' },
  ip:       { bg: 'rgba(220,38,38,0.08)',   border: 'rgba(220,38,38,0.22)',   text: '#dc2626',  icon: '#ef4444' },
  email:    { bg: 'rgba(194,65,12,0.08)',   border: 'rgba(194,65,12,0.22)',   text: '#c2410c',  icon: '#ea580c' },
  username: { bg: 'rgba(71,85,105,0.08)',  border: 'rgba(71,85,105,0.22)',  text: '#475569',  icon: '#64748b' },
  hash:     { bg: 'rgba(8,145,178,0.08)',   border: 'rgba(8,145,178,0.22)',  text: '#0e7490',  icon: '#0891b2' },
  metadata: { bg: 'rgba(22,163,74,0.08)',   border: 'rgba(22,163,74,0.22)',   text: '#15803d',  icon: '#16a34a' },
  myip:     { bg: 'rgba(37,99,235,0.08)',   border: 'rgba(37,99,235,0.22)',   text: '#1d4ed8',  icon: '#2563eb' },
  googlehacking: { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: '#0e7490',  icon: '#0891b2' },
  websitescanner: { bg: 'rgba(194,65,12,0.08)', border: 'rgba(194,65,12,0.22)', text: '#c2410c',  icon: '#ea580c' },
  networkscan:    { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: '#dc2626',  icon: '#ef4444' },
  subdomain:      { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: '#475569',  icon: '#64748b' },
  portscan:       { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: '#dc2626',  icon: '#ef4444' },
  urlfuzz:        { bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.22)', text: '#7e22ce',  icon: '#a855f7' },
  waf:            { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: '#dc2626',  icon: '#ef4444' },
  peoplehunter:   { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: '#0e7490',  icon: '#0891b2' },
  domainfinder:   { bg: 'rgba(22,163,74,0.08)',  border: 'rgba(22,163,74,0.22)',  text: '#15803d',  icon: '#16a34a' },
  vhosts:         { bg: 'rgba(71,85,105,0.08)',  border: 'rgba(71,85,105,0.22)', text: '#475569',  icon: '#64748b' },
  wifi:          { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: '#0e7490',  icon: '#0891b2' },
};

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
  const navBtn = (
    id: typeof activeTab,
    icon: React.ReactNode,
    label: string,
    accent?: { bg: string; border: string; text: string; icon: string }
  ) => {
    const isActive = activeTab === id;
    const iconColor = isActive ? (accent?.icon ?? '#dc2626') : '#64748b';
    return (
      <button
        key={String(id)}
        onClick={() => onSelectModule(id)}
        title={!sidebarOpen ? label : undefined}
        className={`
          w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-semibold
          transition-all duration-150 cursor-pointer relative group
        `}
        style={isActive ? {
          background: accent ? accent.bg : 'rgba(220,38,38,0.10)',
          border: `1px solid ${accent ? accent.border : 'rgba(220,38,38,0.28)'}`,
          color: accent ? accent.text : '#b91c1c',
          boxShadow: '0 1px 3px rgba(15,23,42,0.06)',
        } : {
          background: 'transparent',
          border: '1px solid transparent',
          color: '#475569',
        }}
        onMouseEnter={e => {
          if (!isActive) {
            (e.currentTarget as HTMLButtonElement).style.background = '#f1f5f9';
            (e.currentTarget as HTMLButtonElement).style.color = '#0f172a';
            (e.currentTarget as HTMLButtonElement).style.border = '1px solid #e2e8f0';
          }
        }}
        onMouseLeave={e => {
          if (!isActive) {
            (e.currentTarget as HTMLButtonElement).style.background = 'transparent';
            (e.currentTarget as HTMLButtonElement).style.color = '#475569';
            (e.currentTarget as HTMLButtonElement).style.border = '1px solid transparent';
          }
        }}
      >
        {/* Icon wrapper */}
        <span
          className="shrink-0 w-6 h-6 flex items-center justify-center rounded-lg transition-colors"
          style={{
            color: iconColor,
            background: isActive ? 'rgba(255,255,255,0.7)' : 'transparent',
          }}
        >
          {icon}
        </span>

        <AnimatePresence>
          {sidebarOpen && (
            <motion.span
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.15 }}
              className="truncate overflow-hidden whitespace-nowrap font-semibold"
            >
              {label}
            </motion.span>
          )}
        </AnimatePresence>

        {/* Active dot indicator when collapsed */}
        {isActive && !sidebarOpen && (
          <span
            className="absolute right-1.5 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full"
            style={{ background: accent?.icon ?? '#dc2626' }}
          />
        )}
      </button>
    );
  };

  return (
    <aside
      id="sidebar_root"
      className={`
        hidden md:flex flex-col shrink-0 border-r transition-all duration-300 z-30
        bg-white border-slate-200
        ${sidebarOpen ? 'w-64' : 'w-[68px]'}
      `}
      style={{ boxShadow: '1px 0 0 0 #e2e8f0, 2px 0 8px rgba(15,23,42,0.04)' }}
    >
       {/* ── Logo / Collapse Row ─────────────────────────── */}
       <div className="h-16 flex items-center justify-between px-3 border-b border-slate-200 bg-white">
         <button
           onClick={() => onSelectModule('home')}
           className="flex items-center gap-2.5 overflow-hidden min-w-0 cursor-pointer bg-transparent border-none p-0"
         >
           <div className="flex items-center gap-2.5 overflow-hidden min-w-0">
             {/* Shield logo mark */}
             <div
               className="w-9 h-9 shrink-0 flex items-center justify-center rounded-xl"
               style={{
                 background: 'rgba(220,38,38,0.10)',
                 border: '1.5px solid rgba(220,38,38,0.28)',
               }}
             >
               <Shield className="w-4.5 h-4.5" style={{ color: '#dc2626' }} />
             </div>

             <AnimatePresence>
               {sidebarOpen && (
                 <motion.div
                   initial={{ opacity: 0, x: -8 }}
                   animate={{ opacity: 1, x: 0 }}
                   exit={{ opacity: 0, x: -8 }}
                   transition={{ duration: 0.15 }}
                   className="flex flex-col leading-none overflow-hidden"
                 >
                   <span className="text-[16px] font-black font-display tracking-tight text-slate-900">
                     osint<span style={{ color: '#dc2626' }}>cs</span>
                   </span>
                   <span className="text-[9px] font-mono tracking-widest mt-0.5 font-bold" style={{ color: '#64748b' }}>
                     INTEL SUITE
                   </span>
                 </motion.div>
               )}
             </AnimatePresence>
           </div>
         </button>

         <button
           onClick={() => setSidebarOpen(!sidebarOpen)}
           className="p-1.5 rounded-lg transition-colors cursor-pointer shrink-0 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
           style={{ border: '1px solid #e2e8f0' }}
         >
           {sidebarOpen
             ? <ChevronLeft className="w-3.5 h-3.5" />
             : <ChevronRight className="w-3.5 h-3.5" />
           }
         </button>
       </div>

      {/* ── Scrollable Nav Body ─────────────────────────── */}
      <div className="flex-1 overflow-y-auto py-4 px-2.5 space-y-5 scrollbar-thin bg-white">

        {/* Home */}
        <div>
          {navBtn('home',
            <Globe className="w-4 h-4" />,
            'Lobby Home',
            { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: '#334155', icon: '#475569' }
          )}
        </div>

        {/* OSINT Tools */}
        <div className="space-y-1">
          {sidebarOpen && (
            <span
              className="text-[10px] font-mono font-bold tracking-widest px-3 block mb-2"
              style={{ color: '#64748b' }}
            >
              RECON MODULES
            </span>
          )}
          {!sidebarOpen && <div className="h-px mx-2 mb-2 bg-slate-200" />}

          {QUICK_MODULES.map((mod) => {
            const accent = MODULE_ACCENTS[mod.id] ?? MODULE_ACCENTS.hash;
            const Icon = mod.icon;
            return navBtn(mod.id, <Icon className="w-4 h-4" />, mod.label, accent);
          })}
        </div>

        {/* Workspace */}
        <div className="space-y-1 pt-1">
          <div className="h-px mx-1 mb-3 bg-slate-200" />
          {sidebarOpen && (
            <span
              className="text-[10px] font-mono font-bold tracking-widest px-3 block mb-2"
              style={{ color: '#64748b' }}
            >
              WORKSPACE
            </span>
          )}

          {/* Active report link */}
          {results && (
            <button
              onClick={() => { setViewingReport(true); setViewingBatch(false); }}
              className={`
                w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-semibold
                transition-all cursor-pointer mb-1
              `}
              style={viewingReport ? {
                background: 'rgba(220,38,38,0.10)',
                border: '1px solid rgba(220,38,38,0.28)',
                color: '#b91c1c',
              } : {
                background: 'rgba(220,38,38,0.04)',
                border: '1px dashed rgba(220,38,38,0.25)',
                color: '#dc2626',
              }}
              title={`View report: ${results?.target?.value}`}
            >
              <span className="relative flex h-2.5 w-2.5 shrink-0">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-60" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
              </span>
              <FileText className="w-4 h-4 shrink-0" />
              <AnimatePresence>
                {sidebarOpen && (
                  <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="truncate">
                    Active Report
                  </motion.span>
                )}
              </AnimatePresence>
            </button>
          )}

          {/* Batch report link */}
          {batchResults && batchResults.length > 0 && (
            <button
              onClick={() => { setViewingBatch(true); setViewingReport(false); }}
              className={`
                w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-semibold
                transition-all cursor-pointer mb-1
              `}
              style={viewingBatch && !viewingReport ? {
                background: '#f1f5f9',
                border: '1px solid #cbd5e1',
                color: '#334155',
              } : {
                background: 'transparent',
                border: '1px dashed #cbd5e1',
                color: '#64748b',
              }}
              title={`Batch: ${batchResults.length} targets`}
            >
              <span className="relative flex h-2.5 w-2.5 shrink-0">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-slate-500 opacity-60" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-slate-400" />
              </span>
              <Layers className="w-4 h-4 shrink-0" />
              <AnimatePresence>
                {sidebarOpen && (
                  <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="truncate">
                    Batch ({batchResults.length})
                  </motion.span>
                )}
              </AnimatePresence>
            </button>
          )}

          {navBtn('history', <History className="w-4 h-4" />, 'Scan History',
            { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: '#334155', icon: '#475569' }
          )}
          {navBtn('settings', <Settings className="w-4 h-4" />, 'Settings',
            { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: '#334155', icon: '#475569' }
          )}
        </div>
      </div>

      {/* ── Footer Status Badge ─────────────────────────── */}
      <div className="p-3 border-t border-slate-200 bg-white">
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-xl"
          style={{ background: 'rgba(220,38,38,0.06)', border: '1.5px solid rgba(220,38,38,0.20)' }}
        >
          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0" />
          <AnimatePresence>
            {sidebarOpen && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-[10px] font-mono font-bold tracking-widest"
                style={{ color: '#dc2626' }}
              >
                LOCAL SECURE SANDBOX · CYBERSWAHILI
              </motion.span>
            )}
          </AnimatePresence>
        </div>
      </div>
    </aside>
  );
}
