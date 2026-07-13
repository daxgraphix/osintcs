import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

type ToastType = 'success' | 'info' | 'error';

const VARIANTS: Record<ToastType, {
  icon: React.ReactNode;
  bar: string;
  border: string;
  iconColor: string;
  bg: string;
}> = {
  success: {
    icon: <CheckCircle2 className="w-4 h-4" />,
    bar: '#4ade80',
    border: 'rgba(74,222,128,0.25)',
    iconColor: '#4ade80',
    bg: 'rgba(74,222,128,0.06)',
  },
  error: {
    icon: <AlertCircle className="w-4 h-4" />,
    bar: '#ef4444',
    border: 'rgba(239,68,68,0.3)',
    iconColor: '#f87171',
    bg: 'rgba(239,68,68,0.06)',
  },
  info: {
    icon: <Info className="w-4 h-4" />,
    bar: '#a3a3a3',
    border: 'rgba(163,163,163,0.2)',
    iconColor: '#d4d4d4',
    bg: 'rgba(163,163,163,0.05)',
  },
};

export default function Toast({
  toast,
  onDismiss,
}: {
  toast: { message: string; type: ToastType } | null;
  onDismiss: () => void;
}) {
  const variant = toast ? VARIANTS[toast.type] : null;

  return (
    <AnimatePresence>
      {toast && variant && (
        <motion.div
          key={toast.message + toast.type}
          initial={{ opacity: 0, y: 32, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 16, scale: 0.96 }}
          transition={{ type: 'spring', stiffness: 320, damping: 28 }}
          className="fixed bottom-6 right-6 z-[60] w-80 overflow-hidden rounded-2xl"
          style={{
            background: '#0a0a0a',
            border: `1px solid ${variant.border}`,
            boxShadow: `0 0 30px rgba(0,0,0,0.6), 0 0 12px ${variant.border}`,
          }}
          role="alert"
          aria-live="polite"
        >
          {/* Accent bar top */}
          <div className="h-0.5 w-full" style={{ background: variant.bar }} />

          {/* Content row */}
          <div className="flex items-start gap-3 p-4">
            {/* Icon */}
            <span
              className="shrink-0 mt-0.5 flex items-center justify-center w-7 h-7 rounded-lg"
              style={{ background: variant.bg, color: variant.iconColor }}
            >
              {variant.icon}
            </span>

            {/* Message */}
            <p className="flex-1 text-xs font-semibold leading-relaxed text-slate-200 font-mono pt-0.5">
              {toast.message}
            </p>

            {/* Dismiss */}
            <button
              type="button"
              onClick={onDismiss}
              className="shrink-0 p-1 rounded-lg transition-colors cursor-pointer text-slate-500 hover:text-slate-200 hover:bg-white/[0.05]"
              aria-label="Dismiss notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Auto-dismiss progress bar */}
          <motion.div
            className="h-0.5 w-full"
            style={{ background: `linear-gradient(90deg, ${variant.bar}, transparent)`, transformOrigin: 'left' }}
            initial={{ scaleX: 1 }}
            animate={{ scaleX: 0 }}
            transition={{ duration: 4, ease: 'linear' }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
