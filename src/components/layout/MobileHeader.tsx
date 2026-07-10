import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Menu, X, Globe, Sun, Moon, Settings } from 'lucide-react';
import { TargetType } from '../../types';
import { QUICK_MODULES } from '../pages/moduleConfig';

export default function MobileHeader({
  activeTab,
  mobileMenuOpen,
  setMobileMenuOpen,
  isLightMode,
  theme,
  setTheme,
  onSelectModule,
}: {
  activeTab: TargetType | 'home' | 'risk' | 'settings' | 'history';
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (v: boolean) => void;
  isLightMode: boolean;
  theme: 'dark' | 'light' | 'high-contrast';
  setTheme: (v: 'dark' | 'light' | 'high-contrast') => void;
  onSelectModule: (id: typeof activeTab) => void;
}) {
  return (
    <header
      className={`md:hidden flex items-center justify-between h-14 px-4 border-b z-40 relative ${
        isLightMode ? 'bg-white border-slate-200' : 'bg-[#090d16] border-slate-850'
      }`}
    >
<div className="flex items-center gap-2">
         <button
           onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
           className="p-1.5 rounded-lg border border-slate-800 text-slate-300 hover:bg-slate-800 cursor-pointer"
         >
           <Menu className="w-4 h-4" />
         </button>
         <span className={`text-sm font-black font-display tracking-tight ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
           osint<span className="text-cyan-400">cs</span>
         </span>
       </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => {
            const next = theme === 'dark' ? 'light' : theme === 'light' ? 'high-contrast' : 'dark';
            setTheme(next);
          }}
          className="p-1.5 rounded-lg border border-slate-800 text-slate-300 cursor-pointer flex items-center justify-center"
          title="Cycle theme (Dark / Light / High-Contrast)"
        >
          {theme === 'high-contrast' ? (
            <span className="text-[10px] font-mono font-black px-0.5 text-cyan-400">HC</span>
          ) : isLightMode ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-cyan-400" />
          )}
        </button>
      </div>

      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, x: -100 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -100 }}
            className={`fixed inset-y-0 left-0 w-64 border-r p-5 flex flex-col justify-between z-50 ${
              isLightMode ? 'bg-white border-slate-200 text-slate-800' : 'bg-[#090d16] border-slate-800 text-slate-200'
            }`}
          >
            <div className="space-y-6">
<div className="flex items-center justify-between border-b border-slate-850 pb-3">
                 <span className="text-base font-black font-display">osint<span className="text-cyan-400">cs</span></span>
                 <button onClick={() => setMobileMenuOpen(false)} className="p-1 text-slate-400">
                   <X className="w-4 h-4" />
                 </button>
               </div>

              <div className="space-y-1">
                <button
                  onClick={() => onSelectModule('home')}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-bold ${
                    activeTab === 'home' ? 'bg-cyan-500/10 text-cyan-400' : 'text-slate-400'
                  }`}
                >
                  <Globe className="w-4 h-4" />
                  <span>Lobby Home</span>
                </button>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] font-mono font-bold text-slate-500 tracking-wider block px-3">OSINT TOOLS</span>
                <div className="space-y-0.5 overflow-y-auto max-h-[250px] scrollbar-thin">
                  {QUICK_MODULES.map((mod) => {
                    const Icon = mod.icon;
                    return (
                      <button
                        key={mod.id}
                        onClick={() => onSelectModule(mod.id)}
                        className={`w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs font-bold ${
                          activeTab === mod.id ? 'bg-cyan-500/10 text-cyan-400' : 'text-slate-400'
                        }`}
                      >
                        <Icon className="w-4 h-4" />
                        <span>{mod.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="space-y-1 pt-2 border-t border-slate-800/60">
                <button
                  onClick={() => onSelectModule('history')}
                  className="w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs font-bold text-slate-400"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <polyline points="12 6 12 12 16 14" />
                  </svg>
                  <span>Scan History</span>
                </button>
                <button
                  onClick={() => onSelectModule('settings')}
                  className="w-full flex items-center gap-3 px-3 py-1.5 rounded-lg text-xs font-bold text-slate-400"
                >
                  <Settings className="w-4 h-4 shrink-0" />
                  <span>Settings</span>
                </button>
              </div>
            </div>

            <div className="p-3 rounded bg-emerald-500/5 border border-emerald-500/10 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-[9px] font-mono text-emerald-400">LOCAL SECURE SANDBOX</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
