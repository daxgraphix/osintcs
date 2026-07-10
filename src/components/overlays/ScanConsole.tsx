import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Cpu, Activity } from 'lucide-react';

export default function ScanConsole({
  isScanning,
  scanLogs,
}: {
  isScanning: boolean;
  scanLogs: string[];
}) {
  return (
    <AnimatePresence>
      {isScanning && (
        <motion.div
          key="console_logs"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/90 backdrop-blur-sm"
        >
          <div className="max-w-xl w-full border border-slate-850 bg-[#070a13] rounded-xl overflow-hidden shadow-2xl flex flex-col h-[420px]">
            <div className="bg-[#0b0e1a] px-4 py-3 border-b border-slate-850 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-mono font-bold text-slate-300">osintcs Real-Time HUD Console</span>
              </div>
              <div className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase">Live</span>
              </div>
            </div>
            <div className="p-4 overflow-y-auto font-mono text-[11px] text-emerald-400 bg-[#04060d] flex-1 space-y-1 scrollbar-thin">
              {scanLogs.map((log, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.15 }}
                  className="leading-relaxed whitespace-pre-wrap"
                >
                  {log}
                </motion.div>
              ))}
              <div className="w-1.5 h-3.5 bg-emerald-400 animate-pulse inline-block" />
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
