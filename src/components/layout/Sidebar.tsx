/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Globe, FileText, Layers, History, Settings,
  ChevronRight, ChevronLeft, Shield, Mail, User,
  Key, Database, Server, Eye, FileCode,
  Network,
} from 'lucide-react';
import { TargetType } from '../../types';
import { getAllModules } from '../pages/moduleRegistry';
import { useInvestigationStore } from '../../stores/investigationStore';
import ThemeToggle from '../ThemeToggle';

/* ── Module accent colours — theme-aware via CSS variables ── */
const MODULE_ACCENTS: Record<string, { bg: string; border: string; text: string; icon: string }> = {
  risk:     { bg: 'rgba(220,38,38,0.10)',   border: 'rgba(220,38,38,0.30)',   text: 'var(--text-primary)',  icon: 'var(--accent)' },
  image:    { bg: 'rgba(220,38,38,0.08)',   border: 'rgba(220,38,38,0.25)',   text: 'var(--text-primary)',  icon: 'var(--accent)' },
  domain:   { bg: 'rgba(71,85,105,0.08)',   border: 'rgba(71,85,105,0.22)',   text: 'var(--text-primary)',  icon: 'var(--text-secondary)' },
  website:  { bg: 'rgba(71,85,105,0.07)',   border: 'rgba(71,85,105,0.20)',   text: 'var(--text-primary)',  icon: 'var(--text-secondary)' },
  ip:       { bg: 'rgba(220,38,38,0.08)',   border: 'rgba(220,38,38,0.22)',   text: 'var(--text-primary)',  icon: 'var(--accent)' },
  email:    { bg: 'rgba(194,65,12,0.08)',   border: 'rgba(194,65,12,0.22)',   text: 'var(--text-primary)',  icon: 'var(--color-high)' },
  username: { bg: 'rgba(71,85,105,0.08)',  border: 'rgba(71,85,105,0.22)',  text: 'var(--text-primary)',  icon: 'var(--text-secondary)' },
  hash:     { bg: 'rgba(8,145,178,0.08)',   border: 'rgba(8,145,178,0.22)',   text: 'var(--text-primary)',  icon: 'var(--color-info)' },
  metadata: { bg: 'rgba(22,163,74,0.08)',   border: 'rgba(22,163,74,0.22)',   text: 'var(--text-primary)',  icon: 'var(--color-pass)' },
  myip:     { bg: 'rgba(37,99,235,0.08)',   border: 'rgba(37,99,235,0.22)',   text: 'var(--text-primary)',  icon: 'var(--color-low)' },
  ipadvance: { bg: 'rgba(37,99,235,0.10)',  border: 'rgba(37,99,235,0.25)',  text: 'var(--text-primary)',  icon: 'var(--color-low)' },
  googlehacking: { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: 'var(--text-primary)',  icon: 'var(--color-info)' },
  websitescanner: { bg: 'rgba(194,65,12,0.08)', border: 'rgba(194,65,12,0.22)', text: 'var(--text-primary)',  icon: 'var(--color-high)' },
  networkscan:    { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: 'var(--text-primary)',  icon: 'var(--accent)' },
  subdomain:      { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: 'var(--text-primary)',  icon: 'var(--text-secondary)' },
  portscan:       { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: 'var(--text-primary)',  icon: 'var(--accent)' },
  urlfuzz:        { bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.22)', text: 'var(--text-primary)',  icon: '#a855f7' },
  waf:            { bg: 'rgba(220,38,38,0.08)', border: 'rgba(220,38,38,0.22)', text: 'var(--text-primary)',  icon: 'var(--accent)' },
  peoplehunter:   { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: 'var(--text-primary)',  icon: 'var(--color-info)' },
  domainfinder:   { bg: 'rgba(22,163,74,0.08)',  border: 'rgba(22,163,74,0.22)',  text: 'var(--text-primary)',  icon: 'var(--color-pass)' },
  vhosts:         { bg: 'rgba(71,85,105,0.08)',  border: 'rgba(71,85,105,0.22)',  text: 'var(--text-primary)',  icon: 'var(--text-secondary)' },
  techlookup:     { bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.22)', text: 'var(--text-primary)', icon: '#a855f7' },
  geolookup:     { bg: 'rgba(8,145,178,0.08)',  border: 'rgba(8,145,178,0.22)',  text: 'var(--text-primary)',  icon: 'var(--color-info)' },
  speedtest:     { bg: 'rgba(22,163,74,0.08)',  border: 'rgba(22,163,74,0.22)',  text: 'var(--text-primary)',  icon: 'var(--color-pass)' },
  poplenscan:    { bg: 'rgba(139,92,246,0.08)', border: 'rgba(139,92,246,0.22)', text: 'var(--text-primary)',  icon: '#8b5cf6' },
};

export default function Sidebar() {
  const activeTab = useInvestigationStore(s => s.activeTab);
  const sidebarOpen = useInvestigationStore(s => s.sidebarOpen);
  const setSidebarOpen = useInvestigationStore(s => s.setSidebarOpen);
  const results = useInvestigationStore(s => s.results);
  const batchResults = useInvestigationStore(s => s.batchResults);
  const viewingReport = useInvestigationStore(s => s.viewingReport);
  const setViewingReport = useInvestigationStore(s => s.setViewingReport);
  const viewingBatch = useInvestigationStore(s => s.viewingBatch);
  const setViewingBatch = useInvestigationStore(s => s.setViewingBatch);
  const setActiveTab = useInvestigationStore(s => s.setActiveTab);
  const modules = useMemo(() => getAllModules(), []);

  const navBtn = (
    id: TargetType | 'home' | 'risk' | 'settings' | 'history',
    icon: React.ReactNode,
    label: string,
    accent?: { bg: string; border: string; text: string; icon: string }
  ) => {
    const isActive = activeTab === id;
    const iconColor = isActive ? (accent?.icon ?? 'var(--accent)') : 'var(--text-muted)';
    return (
      <button
        key={String(id)}
        onClick={() => {
          setActiveTab(id);
          setViewingReport(false);
          setViewingBatch(false);
        }}
        title={!sidebarOpen ? label : undefined}
        aria-current={isActive ? 'page' : undefined}
        aria-label={label}
        className={`
          w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-semibold
          transition-all duration-150 cursor-pointer relative group
        `}
        style={isActive ? {
          background: accent ? accent.bg : 'rgba(220,38,38,0.10)',
          border: `1px solid ${accent ? accent.border : 'rgba(220,38,38,0.28)'}`,
          color: accent ? accent.text : 'var(--accent-dim)',
          boxShadow: '0 1px 3px rgba(15,23,42,0.06)',
        } : {
          background: 'transparent',
          border: '1px solid transparent',
          color: 'var(--text-muted)',
        }}
        onMouseEnter={e => {
          if (!isActive) {
            const el = e.currentTarget as HTMLButtonElement;
            el.style.background = 'var(--bg-hover)';
            el.style.color = 'var(--text-primary)';
            el.style.border = '1px solid var(--border-default)';
          }
        }}
        onMouseLeave={e => {
          if (!isActive) {
            const el = e.currentTarget as HTMLButtonElement;
            el.style.background = 'transparent';
            el.style.color = 'var(--text-muted)';
            el.style.border = '1px solid transparent';
          }
        }}
      >
         {/* Icon wrapper */}
         <span
           className="shrink-0 w-6 h-6 flex items-center justify-center rounded-lg transition-colors"
           style={{
             color: iconColor,
             background: isActive ? 'rgba(255,255,255,0.12)' : 'transparent',
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
             style={{ background: 'var(--accent)' }}
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
      style={{ boxShadow: '1px 0 0 0 var(--border-default), 2px 0 8px rgba(15,23,42,0.04)', background: 'var(--bg-panel)', borderColor: 'var(--border-default)' }}
      role="navigation"
      aria-label="Main navigation"
    >
       {/* ── Logo / Collapse Row ─────────────────────────── */}
        <div className="h-16 flex items-center justify-between px-3 border-b border-slate-200 bg-white">
           <button
             onClick={() => setActiveTab('home')}
             className="flex items-center gap-2.5 overflow-hidden min-w-0 cursor-pointer bg-transparent border-none p-0"
           >
             <div className="flex items-center gap-2.5 overflow-hidden min-w-0">
               {/* Shield logo mark */}
               <div
                 className="w-9 h-9 shrink-0 flex items-center justify-center rounded-xl"
                 style={{
                   background: 'var(--accent-bg-strong)',
                   border: '1.5px solid var(--accent-border)',
                 }}
               >
                 <Shield className="w-4.5 h-4.5" style={{ color: 'var(--accent-dim)' }} />
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
                       osint<span style={{ color: 'var(--accent-dim)' }}>cs</span>
                     </span>
                     <span className="text-[9px] font-mono tracking-widest mt-0.5 font-bold" style={{ color: 'var(--text-muted)' }}>
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
             style={{ border: '1px solid var(--border-default)', color: 'var(--text-muted)' }}
           >
            {sidebarOpen
              ? <ChevronLeft className="w-3.5 h-3.5" />
              : <ChevronRight className="w-3.5 h-3.5" />
            }
          </button>
        </div>

      {/* ── Scrollable Nav Body ─────────────────────────── */}
      <div className="flex-1 overflow-y-auto py-4 px-2.5 space-y-5 scrollbar-thin" style={{ background: 'var(--bg-panel)' }}>

        {/* Home */}
         <div>
           {navBtn('home',
             <Globe className="w-4 h-4" />,
             'Lobby Home',
             { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: 'var(--text-primary)', icon: 'var(--text-secondary)' }
           )}
         </div>

        {/* OSINT Tools */}
        <div className="space-y-1">
          {sidebarOpen && (
              <span
                className="text-[10px] font-mono font-bold tracking-widest px-3 block mb-2"
                style={{ color: 'var(--text-muted)' }}
              >
                RECON MODULES
              </span>
          )}
           {!sidebarOpen && <div className="h-px mx-2 mb-2" style={{ background: 'var(--border-subtle)' }} />}

          {modules.map((mod) => {
            const accent = MODULE_ACCENTS[mod.id] ?? MODULE_ACCENTS.hash;
            const Icon = mod.icon;
            return navBtn(mod.id, <Icon className="w-4 h-4" />, mod.label, accent);
          })}
        </div>

        {/* Workspace */}
        <div className="space-y-1 pt-1">
           <div className="h-px mx-1 mb-3" style={{ background: 'var(--border-subtle)' }} />
           {sidebarOpen && (
             <span
               className="text-[10px] font-mono font-bold tracking-widest px-3 block mb-2"
               style={{ color: 'var(--text-muted)' }}
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
                 color: 'var(--accent-dim)',
               } : {
                 background: 'rgba(220,38,38,0.04)',
                 border: '1px dashed rgba(220,38,38,0.25)',
                 color: 'var(--accent)',
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
                 background: 'var(--bg-elevated)',
                 border: '1px solid var(--border-default)',
                 color: 'var(--text-secondary)',
               } : {
                 background: 'transparent',
                 border: '1px dashed var(--border-default)',
                 color: 'var(--text-muted)',
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
            { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: 'var(--text-primary)', icon: 'var(--text-secondary)' }
          )}
          {navBtn('settings', <Settings className="w-4 h-4" />, 'Settings',
            { bg: 'rgba(71,85,105,0.08)', border: 'rgba(71,85,105,0.22)', text: 'var(--text-primary)', icon: 'var(--text-secondary)' }
          )}
        </div>
      </div>

      {/* ── Footer Status Badge ─────────────────────────── */}
      <div className="p-3 border-t border-slate-200" style={{ borderColor: 'var(--border-default)', background: 'var(--bg-panel)' }}>
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-xl"
          style={{ background: 'var(--accent-bg)', border: '1.5px solid var(--accent-border)' }}
        >
          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0" />
          <AnimatePresence>
            {sidebarOpen && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-[10px] font-mono font-bold tracking-widest"
                style={{ color: 'var(--accent-dim)' }}
              >
                LOCAL SECURE SANDBOX · CYBERSWAHILI
              </motion.span>
            )}
          </AnimatePresence>
          <div className="ml-auto">
            <ThemeToggle />
          </div>
        </div>
      </div>
    </aside>
  );
}
