/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { create } from 'zustand';
import { InvestigationTarget, TargetType, ScanResults } from '../types';
import { idbGet, idbSet, idbRemove, idbClear } from '../utils/idb';

interface InvestigationStore {
  // Navigation
  activeTab: 'home' | TargetType | 'risk' | 'settings' | 'history';
  setActiveTab: (tab: 'home' | TargetType | 'risk' | 'settings' | 'history') => void;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (open: boolean) => void;

  // Search
  query: string;
  setQuery: (query: string) => void;
  detectedType: TargetType;
  setDetectedType: (type: TargetType) => void;
  scanMode: 'single' | 'batch';
  setScanMode: (mode: 'single' | 'batch') => void;
  batchQuery: string;
  setBatchQuery: (query: string) => void;

  // Results
  results: ScanResults | null;
  setResults: (results: ScanResults | null) => void;
  batchResults: ScanResults[] | null;
  setBatchResults: (results: ScanResults[] | null) => void;
  viewingReport: boolean;
  setViewingReport: (viewing: boolean) => void;
  viewingBatch: boolean;
  setViewingBatch: (viewing: boolean) => void;

  // History
  recentScans: ScanResults[];
  setRecentScans: (scans: ScanResults[]) => void;
  addRecentScan: (scan: ScanResults) => void;
  removeRecentScan: (value: string, type: string) => void;
  clearRecentScans: () => void;

  // UI
  showQrScanner: boolean;
  setShowQrScanner: (show: boolean) => void;
  isDragging: boolean;
  setIsDragging: (dragging: boolean) => void;
  toast: { message: string; type: 'success' | 'info' | 'error' } | null;
  setToast: (toast: { message: string; type: 'success' | 'info' | 'error' } | null) => void;
  showToast: (message: string, type?: 'success' | 'info' | 'error') => void;

  // Settings
  simulateDelay: boolean;
  setSimulateDelay: (delay: boolean) => void;
  strictScans: boolean;
  setStrictScans: (strict: boolean) => void;
  theme: 'light' | 'dark' | 'system';
  setTheme: (theme: 'light' | 'dark' | 'system') => void;

  // Actions
  resetForNewScan: () => void;
  hydrate: () => Promise<void>;
}

const MAX_RECENT_SCANS = 20;

function sanitizeScanForStorage(scan: ScanResults): ScanResults {
  if (scan.image && scan.image.previewUrl && scan.image.previewUrl.length > 200000) {
    return { ...scan, image: { ...scan.image, previewUrl: undefined } };
  }
  return scan;
}

export const useInvestigationStore = create<InvestigationStore>((set, get) => ({
  // Navigation
  activeTab: (() => {
    try {
      const stored = sessionStorage.getItem('osintcs_active_tab');
      return (stored as TargetType | 'home' | 'risk' | 'settings' | 'history') || 'home';
    } catch {
      return 'home';
    }
  })(),
  setActiveTab: (tab) => {
    try { sessionStorage.setItem('osintcs_active_tab', tab); } catch {}
    set({ activeTab: tab });
  },
  sidebarOpen: true,
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  mobileMenuOpen: false,
  setMobileMenuOpen: (open) => set({ mobileMenuOpen: open }),

  // Search
  query: '',
  setQuery: (query) => set({ query }),
  detectedType: 'domain',
  setDetectedType: (type) => set({ detectedType: type }),
  scanMode: 'single',
  setScanMode: (mode) => set({ scanMode: mode }),
  batchQuery: '',
  setBatchQuery: (query) => set({ batchQuery: query }),

  // Results
  results: (() => {
    try {
      const stored = sessionStorage.getItem('osintcs_current_results');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  })(),
  setResults: (results) => {
    try {
      if (results) {
        const sanitized = sanitizeScanForStorage(results);
        sessionStorage.setItem('osintcs_current_results', JSON.stringify(sanitized));
      } else {
        sessionStorage.removeItem('osintcs_current_results');
      }
    } catch {}
    set({ results });
  },
  batchResults: (() => {
    try {
      const stored = sessionStorage.getItem('osintcs_current_batch_results');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  })(),
  setBatchResults: (batchResults) => {
    try {
      if (batchResults) {
        const sanitized = batchResults.map(sanitizeScanForStorage);
        sessionStorage.setItem('osintcs_current_batch_results', JSON.stringify(sanitized));
      } else {
        sessionStorage.removeItem('osintcs_current_batch_results');
      }
    } catch {}
    set({ batchResults });
  },
  viewingReport: (() => {
    try {
      return sessionStorage.getItem('osintcs_viewing_report') === 'true';
    } catch {
      return false;
    }
  })(),
  setViewingReport: (viewingReport) => {
    try { sessionStorage.setItem('osintcs_viewing_report', String(viewingReport)); } catch {}
    set({ viewingReport });
  },
  viewingBatch: (() => {
    try {
      return sessionStorage.getItem('osintcs_viewing_batch') === 'true';
    } catch {
      return false;
    }
  })(),
  setViewingBatch: (viewingBatch) => {
    try { sessionStorage.setItem('osintcs_viewing_batch', String(viewingBatch)); } catch {}
    set({ viewingBatch });
  },

  // History
  recentScans: [],
  setRecentScans: async (recentScans) => {
    try {
      await idbSet('recentScans', recentScans);
    } catch (e) {
      console.error('Failed to save recent scans to IndexedDB:', e);
    }
    set({ recentScans });
  },
  addRecentScan: async (scan) => {
    const { recentScans, setRecentScans } = get();
    const filtered = recentScans.filter(
      (s) => !(s.target.value === scan.target.value && s.target.type === scan.target.type)
    );
    const updated = [sanitizeScanForStorage(scan), ...filtered].slice(0, MAX_RECENT_SCANS);
    try {
      await idbSet('recentScans', updated);
    } catch (e) {
      console.error('Failed to save recent scan to IndexedDB:', e);
    }
    set({ recentScans: updated });
  },
  removeRecentScan: async (value, type) => {
    const { recentScans, setRecentScans } = get();
    const updated = recentScans.filter((s) => !(s.target.value === value && s.target.type === type));
    try {
      if (updated.length === 0) {
        await idbRemove('recentScans');
      } else {
        await idbSet('recentScans', updated);
      }
    } catch (e) {
      console.error('Failed to remove recent scan from IndexedDB:', e);
    }
    set({ recentScans: updated });
  },
  clearRecentScans: async () => {
    try {
      await idbRemove('recentScans');
    } catch (e) {
      console.error('Failed to clear recent scans from IndexedDB:', e);
    }
    set({ recentScans: [] });
  },

  // UI
  showQrScanner: false,
  setShowQrScanner: (show) => set({ showQrScanner: show }),
  isDragging: false,
  setIsDragging: (dragging) => set({ isDragging: dragging }),
  toast: null,
  setToast: (toast) => set({ toast }),
  showToast: (message, type = 'success') => {
    set({ toast: { message, type } });
    setTimeout(() => set({ toast: null }), 4000);
  },

  // Settings
  simulateDelay: true,
  setSimulateDelay: (simulateDelay) => set({ simulateDelay }),
  strictScans: false,
  setStrictScans: (strictScans) => set({ strictScans }),
  theme: (() => {
    try {
      const stored = localStorage.getItem('osintcs_theme');
      if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
    } catch {}
    return 'light';
  })(),
  setTheme: (theme) => {
    try { localStorage.setItem('osintcs_theme', theme); } catch {}
    set({ theme });
  },

  // Actions
  resetForNewScan: () => set({
    query: '',
    detectedType: 'domain',
    batchQuery: '',
    results: null,
    batchResults: null,
    viewingReport: false,
    viewingBatch: false,
  }),

  hydrate: async () => {
    try {
      const stored = await idbGet<ScanResults[]>('recentScans');
      if (stored && Array.isArray(stored)) {
        set({ recentScans: stored });
      }
    } catch (e) {
      console.error('Failed to hydrate recent scans from IndexedDB:', e);
    }
  },
}));
