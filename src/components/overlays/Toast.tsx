import { motion, AnimatePresence } from 'motion/react';

export default function Toast({
  toast,
  onDismiss,
}: {
  toast: { message: string; type: 'success' | 'info' | 'error' } | null;
  onDismiss: () => void;
}) {
  return (
    <AnimatePresence>
      {toast && (
        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.95 }}
          className="fixed bottom-6 right-6 z-50 max-w-sm p-4 border-2 border-red-600 bg-black text-white rounded shadow-2xl flex items-center gap-3 font-mono text-xs uppercase"
        >
          <span className="w-2 h-2 rounded-full bg-red-600 animate-ping shrink-0" />
          <p className="flex-1 font-bold">{toast.message}</p>
          <button
            type="button"
            onClick={onDismiss}
            className="text-red-500 hover:text-white font-black text-sm pl-2 cursor-pointer"
          >
            ×
          </button>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
