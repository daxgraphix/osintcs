/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

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
  text: string;
}> = {
  success: {
    icon: <CheckCircle2 className="w-4 h-4" />,
    bar: '#22c55e',
    border: 'rgba(34,197,94,0.35)',
    iconColor: '#22c55e',
    bg: 'rgba(34,197,94,0.12)',
    text: 'var(--text-primary)',
  },
  error: {
    icon: <AlertCircle className="w-4 h-4" />,
    bar: '#ef4444',
    border: 'rgba(239,68,68,0.35)',
    iconColor: '#f87171',
    bg: 'rgba(239,68,68,0.12)',
    text: 'var(--text-primary)',
  },
  info: {
    icon: <Info className="w-4 h-4" />,
    bar: '#3b82f6',
    border: 'rgba(59,130,246,0.35)',
    iconColor: '#60a5fa',
    bg: 'rgba(59,130,246,0.12)',
    text: 'var(--text-primary)',
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
            background: 'var(--bg-panel)',
            border: `1px solid ${variant.border}`,
            boxShadow: `0 0 30px rgba(0,0,0,0.25), 0 0 12px ${variant.border}`,
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
            <p className="flex-1 text-xs font-semibold leading-relaxed font-mono pt-0.5" style={{ color: variant.text }}>
              {toast.message}
            </p>

            {/* Dismiss */}
            <button
              type="button"
              onClick={onDismiss}
              className="shrink-0 p-1 rounded-lg transition-colors cursor-pointer hover:bg-white/[0.06]"
              style={{ color: 'var(--text-muted)' }}
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
