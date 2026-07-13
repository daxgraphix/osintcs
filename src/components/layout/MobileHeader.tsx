import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Menu, X, Globe, Settings, Shield, History } from 'lucide-react';
import { TargetType } from '../../types';
import { QUICK_MODULES } from '../pages/moduleConfig';

export default function MobileHeader({
  activeTab,
  mobileMenuOpen,
  setMobileMenuOpen,
  onSelectModule,
}: {
  activeTab: TargetType | 'home' | 'risk' | 'settings' | 'history';
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (v: boolean) => void;
  isLightMode?: boolean;
  onSelectModule: (id: typeof activeTab) => void;
}) {
  const navItem = (id: typeof activeTab, icon: React.ReactNode, label: string) => {
    const isActive = activeTab === id;
    return (
      <button
        key={String(id)}
        onClick={() => onSelectModule(id)}
        className={`
          w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold
          transition-all duration-150 cursor-pointer
          ${isActive
            ? 'bg-red-50 text-red-700 border border-red-200'
            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
          }
        `}
      >
        <span
          className="shrink-0 w-7 h-7 flex items-center justify-center rounded-lg"
          style={isActive
            ? { background: 'rgba(220,38,38,0.12)', color: '#dc2626' }
            : { background: '#f1f5f9', color: '#64748b' }
          }
        >
          {icon}
        </span>
        <span>{label}</span>
        {isActive && (
          <span className="ml-auto w-1.5 h-1.5 rounded-full bg-red-500" />
        )}
      </button>
    );
  };

  return (
    <>
      {/* ── Top Mobile Bar ──────────────────────────────── */}
      <header
        className="md:hidden flex items-center justify-between h-14 px-4 border-b z-40 relative bg-white border-slate-200"
        style={{ boxShadow: '0 1px 4px rgba(15,23,42,0.08)' }}
      >
        {/* Left: hamburger + logo */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-xl border transition-all cursor-pointer border-slate-200 text-slate-600 hover:bg-slate-50 hover:border-slate-300"
            aria-label="Toggle navigation"
          >
            <AnimatePresence mode="wait">
              {mobileMenuOpen
                ? <motion.span key="close" initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={{ duration: 0.15 }}><X className="w-4.5 h-4.5" /></motion.span>
                : <motion.span key="open" initial={{ rotate: 90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: -90, opacity: 0 }} transition={{ duration: 0.15 }}><Menu className="w-4.5 h-4.5" /></motion.span>
              }
            </AnimatePresence>
          </button>

           <button
             onClick={() => onSelectModule('home')}
             className="flex items-center gap-2 bg-transparent border-none p-0 cursor-pointer"
           >
             <div className="flex items-center gap-2">
               <div
                 className="w-7 h-7 flex items-center justify-center rounded-lg"
                 style={{ background: 'rgba(220,38,38,0.10)', border: '1.5px solid rgba(220,38,38,0.28)' }}
               >
                 <Shield className="w-4 h-4" style={{ color: '#dc2626' }} />
               </div>
               <span className="text-[16px] font-black font-display tracking-tight text-slate-900">
                 osint<span style={{ color: '#dc2626' }}>cs</span>
               </span>
             </div>
           </button>
        </div>

        {/* Right: status badge */}
        <div
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-full"
          style={{ background: 'rgba(220,38,38,0.08)', border: '1.5px solid rgba(220,38,38,0.22)' }}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
          <span className="text-[10px] font-mono font-black tracking-widest uppercase" style={{ color: '#dc2626' }}>LIVE</span>
        </div>
      </header>

      {/* ── Slide-in Drawer ─────────────────────────────── */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              key="drawer-backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              onClick={() => setMobileMenuOpen(false)}
              className="md:hidden fixed inset-0 z-40"
              style={{ background: 'rgba(15,23,42,0.35)', backdropFilter: 'blur(4px)' }}
            />

            {/* Drawer panel */}
            <motion.nav
              key="drawer-panel"
              initial={{ x: '-100%', opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: '-100%', opacity: 0 }}
              transition={{ type: 'spring', stiffness: 320, damping: 32 }}
              className="md:hidden fixed inset-y-0 left-0 w-76 z-50 flex flex-col bg-white border-r border-slate-200"
              style={{ boxShadow: '8px 0 40px rgba(15,23,42,0.12)', width: '288px' }}
            >
              {/* Drawer header */}
              <div
                className="h-16 flex items-center justify-between px-5 border-b border-slate-200"
                style={{ background: '#fafafa' }}
              >
              <button
                onClick={() => onSelectModule('home')}
                className="flex items-center gap-3 bg-transparent border-none p-0 cursor-pointer"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-9 h-9 flex items-center justify-center rounded-xl"
                    style={{ background: 'rgba(220,38,38,0.10)', border: '1.5px solid rgba(220,38,38,0.28)' }}
                  >
                    <Shield className="w-4.5 h-4.5" style={{ color: '#dc2626' }} />
                  </div>
                  <div>
                    <span className="text-[16px] font-black font-display tracking-tight text-slate-900">
                      osint<span style={{ color: '#dc2626' }}>cs</span>
                    </span>
                    <p className="text-[9px] font-mono tracking-widest mt-0.5 font-bold" style={{ color: '#64748b' }}>INTELLIGENCE SUITE</p>
                  </div>
                </div>
              </button>
                <button
                  onClick={() => setMobileMenuOpen(false)}
                  className="p-2 rounded-xl transition-colors cursor-pointer text-slate-400 hover:text-slate-700 hover:bg-slate-100 border border-slate-200"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Nav content */}
              <div className="flex-1 overflow-y-auto p-4 space-y-5 scrollbar-thin">
                {/* Home */}
                {navItem('home', <Globe className="w-4 h-4" />, 'Lobby Home')}

                {/* Tools section */}
                <div className="space-y-1">
                  <p
                    className="text-[10px] font-mono font-bold tracking-widest px-4 mb-2 mt-1 block uppercase"
                    style={{ color: '#64748b' }}
                  >
                    RECON MODULES
                  </p>
                  <div className="space-y-0.5 overflow-y-auto max-h-[300px] scrollbar-thin">
                    {QUICK_MODULES.map((mod) => {
                      const Icon = mod.icon;
                      return navItem(mod.id, <Icon className="w-4 h-4" />, mod.label);
                    })}
                  </div>
                </div>

                {/* Workspace */}
                <div className="space-y-0.5 pt-2 border-t border-slate-200">
                  <p
                    className="text-[10px] font-mono font-bold tracking-widest px-4 mb-2 mt-3 block uppercase"
                    style={{ color: '#64748b' }}
                  >
                    WORKSPACE
                  </p>
                  {navItem('history', <History className="w-4 h-4" />, 'Scan History')}
                  {navItem('settings', <Settings className="w-4 h-4" />, 'Settings')}
                </div>
              </div>

              {/* Drawer footer */}
              <div className="p-4 border-t border-slate-200" style={{ background: '#fafafa' }}>
                <div
                  className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl"
                  style={{ background: 'rgba(220,38,38,0.06)', border: '1.5px solid rgba(220,38,38,0.20)' }}
                >
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  <span className="text-[10px] font-mono font-bold tracking-widest" style={{ color: '#dc2626' }}>
                    LOCAL SECURE SANDBOX
                  </span>
                </div>
              </div>
            </motion.nav>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
