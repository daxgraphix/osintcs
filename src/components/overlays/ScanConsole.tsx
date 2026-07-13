import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Activity, Cpu, Zap } from 'lucide-react';

/* Colour-code log lines by prefix */
function classifyLog(line: string): { color: string; prefix: string } {
  const l = line.toLowerCase();
  if (l.startsWith('[✓]') || l.includes('success') || l.includes('found') || l.includes('pass') || l.startsWith('[ok]')) {
    return { color: '#4ade80', prefix: '' }; // green – success
  }
  if (l.startsWith('[!]') || l.includes('warn') || l.includes('missing') || l.includes('not found')) {
    return { color: '#fbbf24', prefix: '' }; // amber – warning
  }
  if (l.startsWith('[✗]') || l.includes('fail') || l.includes('error') || l.includes('critical') || l.includes('vuln')) {
    return { color: '#f87171', prefix: '' }; // red – error
  }
  if (l.startsWith('---') || l.startsWith('===') || l.startsWith('>>')) {
    return { color: '#a3a3a3', prefix: '' }; // muted – section header
  }
  return { color: '#d4d4d4', prefix: '' }; // white-ish – info
}

export default function ScanConsole({
  isScanning,
  scanLogs,
}: {
  isScanning: boolean;
  scanLogs: string[];
}) {
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs]);

  return (
    <AnimatePresence>
      {isScanning && (
        <motion.div
          key="scan_console_overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed inset-0 z-50 flex items-center justify-center px-4"
          style={{ background: 'rgba(0,0,0,0.88)', backdropFilter: 'blur(8px)' }}
        >
          {/* Outer glow ring */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background: 'radial-gradient(ellipse at center, rgba(239,68,68,0.04) 0%, transparent 70%)',
            }}
          />

          {/* Console window */}
          <motion.div
            initial={{ scale: 0.96, y: 20 }}
            animate={{ scale: 1, y: 0 }}
            exit={{ scale: 0.96, y: 20 }}
            transition={{ type: 'spring', stiffness: 280, damping: 28 }}
            className="relative w-full max-w-xl overflow-hidden rounded-2xl flex flex-col"
            style={{
              height: 460,
              background: '#050505',
              border: '1px solid rgba(239,68,68,0.2)',
              boxShadow: '0 0 60px rgba(239,68,68,0.08), 0 32px 80px rgba(0,0,0,0.8)',
            }}
          >
            {/* Window chrome / title bar */}
            <div
              className="flex items-center justify-between px-5 py-3 border-b shrink-0"
              style={{ background: '#0a0a0a', borderColor: 'rgba(239,68,68,0.15)' }}
            >
              {/* Traffic lights */}
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#3f3f3f' }} />
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#3f3f3f' }} />
                <div
                  className="w-2.5 h-2.5 rounded-full animate-pulse"
                  style={{ background: '#ef4444' }}
                />
              </div>

              {/* Title */}
              <div className="flex items-center gap-2 absolute left-1/2 -translate-x-1/2">
                <Terminal className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
                <span className="text-[11px] font-mono font-bold tracking-widest" style={{ color: '#a3a3a3' }}>
                  OSINTCS  RECON  CONSOLE
                </span>
              </div>

              {/* Live badge */}
              <div className="flex items-center gap-1.5">
                <Activity className="w-3 h-3 animate-pulse" style={{ color: '#ef4444' }} />
                <span className="text-[9px] font-mono font-black tracking-widest" style={{ color: '#ef4444' }}>
                  LIVE
                </span>
              </div>
            </div>

            {/* Scanning progress bar */}
            <div className="h-px w-full" style={{ background: '#111' }}>
              <motion.div
                className="h-full"
                style={{ background: 'linear-gradient(90deg, #dc2626, #f87171, #dc2626)', backgroundSize: '200% 100%' }}
                initial={{ width: '0%' }}
                animate={{ width: '100%' }}
                transition={{ duration: 18, ease: 'linear' }}
              />
            </div>

            {/* Status pills row */}
            <div
              className="flex items-center gap-3 px-5 py-2.5 border-b shrink-0"
              style={{ background: '#070707', borderColor: '#111' }}
            >
              <div className="flex items-center gap-1.5">
                <Cpu className="w-3 h-3" style={{ color: '#ef4444' }} />
                <span className="text-[9px] font-mono" style={{ color: '#525252' }}>ENGINES ACTIVE</span>
              </div>
              <div className="h-3 w-px" style={{ background: '#1a1a1a' }} />
              <div className="flex items-center gap-1.5">
                <Zap className="w-3 h-3" style={{ color: '#525252' }} />
                <span className="text-[9px] font-mono" style={{ color: '#525252' }}>
                  {scanLogs.length} CHECKS COMPLETED
                </span>
              </div>
              <div className="ml-auto flex gap-0.5">
                {[0,1,2,3,4].map((i) => (
                  <motion.div
                    key={i}
                    className="w-1 rounded-full"
                    style={{ background: '#ef4444' }}
                    animate={{ height: ['6px','14px','6px'] }}
                    transition={{
                      duration: 0.6,
                      repeat: Infinity,
                      delay: i * 0.1,
                      ease: 'easeInOut',
                    }}
                  />
                ))}
              </div>
            </div>

            {/* Log output area */}
            <div
              className="flex-1 overflow-y-auto p-5 space-y-1 scrollbar-thin font-mono text-[11px] leading-relaxed"
              style={{ background: '#030303' }}
            >
              <AnimatePresence initial={false}>
                {scanLogs.map((log, idx) => {
                  const { color } = classifyLog(log);
                  return (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.12 }}
                      className="flex items-start gap-2"
                    >
                      {/* Line number */}
                      <span className="shrink-0 w-6 text-right select-none" style={{ color: '#2a2a2a' }}>
                        {String(idx + 1).padStart(2, '0')}
                      </span>
                      <span style={{ color }} className="whitespace-pre-wrap break-all">
                        {log}
                      </span>
                    </motion.div>
                  );
                })}
              </AnimatePresence>

              {/* Blinking cursor at end */}
              <div className="flex items-center gap-2">
                <span className="w-6 shrink-0" />
                <motion.span
                  animate={{ opacity: [1, 0] }}
                  transition={{ duration: 0.8, repeat: Infinity, ease: 'steps(1)' }}
                  className="w-2 h-[13px] rounded-sm inline-block"
                  style={{ background: '#ef4444' }}
                />
              </div>

              <div ref={logEndRef} />
            </div>

            {/* Bottom status bar */}
            <div
              className="px-5 py-2 border-t flex items-center justify-between shrink-0"
              style={{ background: '#070707', borderColor: '#111' }}
            >
              <span className="text-[9px] font-mono" style={{ color: '#2a2a2a' }}>
                OSINTCS  v2.0  ·  LOCAL  EXECUTION  ·  ZERO  TELEMETRY
              </span>
              <span className="text-[9px] font-mono" style={{ color: '#ef4444' }}>
                ● SCANNING
              </span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
