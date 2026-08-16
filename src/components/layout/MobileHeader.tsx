/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Menu, X, Globe, Settings, Shield, History } from 'lucide-react';
import { TargetType } from '../../types';
import { getAllModules } from '../pages/moduleRegistry';
import { useInvestigationStore } from '../../stores/investigationStore';
import ThemeToggle from '../ThemeToggle';

export default function MobileHeader() {
  const activeTab = useInvestigationStore(s => s.activeTab);
  const mobileMenuOpen = useInvestigationStore(s => s.mobileMenuOpen);
  const setMobileMenuOpen = useInvestigationStore(s => s.setMobileMenuOpen);
  const setActiveTab = useInvestigationStore(s => s.setActiveTab);
  const theme = useInvestigationStore(s => s.theme);
  const setTheme = useInvestigationStore(s => s.setTheme);

  const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  const navItem = (id: TargetType | 'home' | 'risk' | 'settings' | 'history', icon: React.ReactNode, label: string) => {
    const isActive = activeTab === id;
    return (
      <button
        key={String(id)}
        onClick={() => { setActiveTab(id); setMobileMenuOpen(false); }}
        aria-label={label}
        className={`
          w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold
          transition-all duration-150 cursor-pointer
        `}
        style={isActive ? {
          background: 'var(--accent-bg-strong)',
          color: 'var(--text-accent)',
          border: '1px solid var(--accent-border)',
        } : {
          background: 'transparent',
          color: 'var(--text-secondary)',
          border: '1px solid transparent',
        }}
      >
        <span
          className="shrink-0 w-7 h-7 flex items-center justify-center rounded-lg"
          style={isActive
            ? { background: 'var(--accent-bg)', color: 'var(--accent-dim)' }
            : { background: 'var(--bg-muted)', color: 'var(--text-muted)' }
          }
        >
          {icon}
        </span>
        <span style={{ color: 'var(--text-primary)' }}>{label}</span>
        {isActive && (
          <span className="ml-auto w-1.5 h-1.5 rounded-full" style={{ background: 'var(--accent)' }} />
        )}
      </button>
    );
  };

  return (
    <>
      {/* ── Top Mobile Bar ──────────────────────────────── */}
      <header
        className="md:hidden shrink-0 flex items-center justify-between h-14 px-4 border-b z-40 relative"
        style={{ boxShadow: '0 1px 4px rgba(15,23,42,0.08)', background: 'var(--bg-panel)', borderColor: 'var(--border-default)' }}
      >
        {/* Left: hamburger + logo */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-lg cursor-pointer border transition-colors"
            style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-default)', color: 'var(--text-muted)' }}
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          <span className="text-lg font-black font-display tracking-tight" style={{ color: 'var(--text-primary)' }}>
            osint<span style={{ color: 'var(--accent-dim)' }}>cs</span>
          </span>
        </div>

        {/* Right: quick actions */}
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <button
            onClick={() => setActiveTab('history')}
            className="p-2 rounded-lg cursor-pointer border transition-colors"
            title="Scan History"
            style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-default)', color: 'var(--text-muted)' }}
          >
            <History className="w-4 h-4" />
          </button>
          <button
            onClick={() => setActiveTab('settings')}
            className="p-2 rounded-lg cursor-pointer border transition-colors"
            title="Settings"
            style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-default)', color: 'var(--text-muted)' }}
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* ── Mobile Slide-down Menu ─────────────────────── */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="md:hidden fixed inset-0 bg-black/30 z-40"
              onClick={() => setMobileMenuOpen(false)}
            />
            <motion.aside
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 24, stiffness: 260 }}
              className="md:hidden fixed top-14 left-0 bottom-0 w-72 bg-white border-r border-slate-200 z-50 shadow-xl flex flex-col"
              style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-default)', boxShadow: 'var(--shadow-lg)' }}
            >
              <div className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
                <div>
                  {navItem('home', <Globe className="w-4 h-4" />, 'Lobby Home')}
                </div>

                 <div className="space-y-1">
                   <span className="text-[10px] font-mono font-bold tracking-widest px-3 block mb-2" style={{ color: 'var(--text-muted)' }}>
                     RECON MODULES
                   </span>
                   {getAllModules().map((mod) => {
                    const Icon = mod.icon;
                    return navItem(mod.id, <Icon className="w-4 h-4" />, mod.label);
                  })}
                </div>

                <div className="space-y-1 pt-1">
                   <div className="h-px mx-1 mb-3" style={{ background: 'var(--border-default)' }} />
                  {navItem('history', <History className="w-4 h-4" />, 'Scan History')}
                  {navItem('settings', <Settings className="w-4 h-4" />, 'Settings')}
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
