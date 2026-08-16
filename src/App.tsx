/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import jsQR from 'jsqr';
import {
  Shield,
  Search,
  Globe,
  Server,
  User,
  Key,
  Mail,
  Hash,
  FileCode,
  Terminal,
  Upload,
  AlertCircle,
  Eye,
  FileUp,
  Cpu,
  Lock,
  Database,
  QrCode,
  Trash2,
  History,
  Layers,
  ChevronRight,
  ChevronLeft,
  Play,
  Check,
  Copy,
  CameraOff,
  CheckCircle2,
  X,
  FileText,
  RefreshCw,
  AlertTriangle,
  Menu,
  Sliders,
  Settings,
  ArrowRight,
  Info,
  FileSpreadsheet,
  Network,
  Radar,
  MapPin,
  Boxes,
} from 'lucide-react';

import { InvestigationTarget, TargetType, ScanResults, MyIpResult, IpAdvanceResult, TechLookupResult, GeoLookupResult, SpeedTestResult, Finding, PopoScanResult, ReconResult } from './types';
import { detectTargetType, parseInvestigationTarget, scanMyIp, scanIpAdvance, scanTechnology, scanGeoLookup, scanPopoScan, findSubdomains } from './services/osintServices';
import { calculateRiskScore } from './engines/osintEngines';
import { getAllModules, getModule } from './components/pages/moduleRegistry';
import { useScanWorkflow } from './hooks/useScanWorkflow';
import Toast from './components/overlays/Toast';
import ScanConsole from './components/overlays/ScanConsole';
import QrScannerModal from './components/overlays/QrScannerModal';
import Sidebar from './components/layout/Sidebar';
import MobileHeader from './components/layout/MobileHeader';
import { sanitizeText, sanitizeFilename, escapeHtml } from './utils/security';
import { processBatchFile } from './utils/batchFileParser';
import { ErrorBoundary } from './components/ErrorBoundary';
import { VirtualizedList } from './components/VirtualizedList';
import ThemeToggle from './components/ThemeToggle';
import { useInvestigationStore } from './stores/investigationStore';
import {
  makeMyIpResults,
  makeIpAdvanceResults,
  makeTechLookupResults,
  makeGeoLookupResults,
  makeSpeedTestResults,
  makePopoScanResults,
  makeSubdomainResults,
} from './utils/resultBuilders';

const SpeedTestWorkspace = lazy(() => import('./features/speedtest/SpeedTestWorkspace').then(m => ({ default: m.default })));
const ReportDashboard = lazy(() => import('./components/ReportDashboard').then(m => ({ default: m.default })));

export default function App() {
  const store = useInvestigationStore();
  const activeTab = store.activeTab;
  const setActiveTab = store.setActiveTab;
  const sidebarOpen = store.sidebarOpen;
  const setSidebarOpen = store.setSidebarOpen;
  const mobileMenuOpen = store.mobileMenuOpen;
  const setMobileMenuOpen = store.setMobileMenuOpen;
  const query = store.query;
  const setQuery = store.setQuery;
  const detectedType = store.detectedType;
  const setDetectedType = store.setDetectedType;
  const scanMode = store.scanMode;
  const setScanMode = store.setScanMode;
  const theme = store.theme;
  const setTheme = store.setTheme;
  const batchQuery = store.batchQuery;
  const setBatchQuery = store.setBatchQuery;
  const results = store.results;
  const setResults = store.setResults;
  const batchResults = store.batchResults;
  const setBatchResults = store.setBatchResults;
  const viewingReport = store.viewingReport;
  const setViewingReport = store.setViewingReport;
  const viewingBatch = store.viewingBatch;
  const setViewingBatch = store.setViewingBatch;
  const isDragging = store.isDragging;
  const setIsDragging = store.setIsDragging;
  const showQrScanner = store.showQrScanner;
  const setShowQrScanner = store.setShowQrScanner;
  const toast = store.toast;
  const setToast = store.setToast;
  const showToast = store.showToast;
  const simulateDelay = store.simulateDelay;
  const setSimulateDelay = store.setSimulateDelay;
  const strictScans = store.strictScans;
  const setStrictScans = store.setStrictScans;
  const recentScans = store.recentScans;
  const setRecentScans = store.setRecentScans;
  const addRecentScan = store.addRecentScan;
  const removeHistoryItem = store.removeRecentScan;
  const clearHistory = store.clearRecentScans;
  const hydrateStore = store.hydrate;

  const fileInputRef = useRef<HTMLInputElement>(null);
  const batchFileInputRef = useRef<HTMLInputElement>(null);

  const [rateLimitCountdown, setRateLimitCountdown] = useState<{ ms: number; type: 'single' | 'batch' } | null>(null);

  const handleQueryChange = (value: string) => {
    setQuery(sanitizeText(value, 500));
  };

  const isValidUrl = (value: string): boolean => {
    try {
      const u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  };

  useEffect(() => {
    const root = document.documentElement;
    const applyTheme = (t: string) => {
      if (t === 'system') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
      } else {
        root.setAttribute('data-theme', t);
      }
    };
    applyTheme(theme);
    if (theme === 'system') {
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      const handler = (e: MediaQueryListEvent) => {
        root.setAttribute('data-theme', e.matches ? 'dark' : 'light');
      };
      mq.addEventListener('change', handler);
      return () => mq.removeEventListener('change', handler);
    }
  }, [theme]);

  useEffect(() => {
    hydrateStore();
  }, [hydrateStore]);

  useEffect(() => {
    if ('serviceWorker' in navigator && window.location.hostname !== 'localhost') {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    }
  }, []);

  useEffect(() => {
    if (!rateLimitCountdown) return;
    const interval = setInterval(() => {
      setRateLimitCountdown((prev) => {
        if (!prev || prev.ms <= 1000) {
          setRateLimitCountdown(null);
          return null;
        }
        return { ...prev, ms: prev.ms - 1000 };
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [rateLimitCountdown]);

  const handleBatchQueryChange = (value: string) => {
    setBatchQuery(sanitizeText(value, 5000));
  };

  const handleBatchFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    await processBatchFile(file, {
      onSuccess: (targets) => triggerBatchInvestigation(targets),
      onError: (message) => showToast(message, 'error'),
    });
    if (e.target) e.target.value = '';
  };

  const handleExportBatchCSV = () => {
    if (!batchResults || batchResults.length === 0) return;
    
    const headers = ["Target", "Type", "Risk Score", "Security Grade", "Total Findings", "Critical/High Findings", "Key Findings"];
    
    const rows = batchResults.map(r => {
      const sDetails = calculateRiskScore(r.findings);
      const criticalHighCount = r.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
      
      const keyFindingsList = r.findings
        .filter(f => f.severity !== 'pass')
        .slice(0, 3)
        .map(f => `[${f.severity.toUpperCase()}] ${f.title}`);
      const keyFindingsStr = keyFindingsList.length > 0 ? keyFindingsList.join('; ') : "No significant vulnerabilities detected";
      
      return [
        r.target.value,
        r.target.type,
        r.riskScore,
        sDetails.grade,
        r.findings.length,
        criticalHighCount,
        keyFindingsStr
      ];
    });
    
    const csvContent = [
      headers.join(','),
      ...rows.map(row => 
        row.map(val => {
          const str = String(val);
          if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
          }
          return str;
        }).join(',')
      )
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `osintcs_batch_export_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast("Consolidated Batch CSV exported successfully", "success");
  };

  // Theme-driven mode — supports light / dark / system
  const isLightMode = theme === 'light' || (theme === 'system' && !window.matchMedia('(prefers-color-scheme: dark)').matches);
  const isDarkMode = !isLightMode;

  // PopoScan expandable sections state
  const [popoScanExpanded, setPopoScanExpanded] = useState<Record<string, boolean>>({
    redirects: false,
    thirdParty: false,
    firstParty: false,
    resources: false,
    cookies: false,
  });

  const [popoScanExpandedDomains, setPopoScanExpandedDomains] = useState<Set<string>>(new Set());

  const [subdomainResult, setSubdomainResult] = useState<ReconResult | null>(null);
  const [expandedSubdomain, setExpandedSubdomain] = useState<string | null>(null);

  const togglePopoScanSection = (section: string) => {
    setPopoScanExpanded(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const togglePopoScanDomain = (domain: string) => {
    setPopoScanExpandedDomains(prev => {
      const next = new Set(prev);
      if (next.has(domain)) {
        next.delete(domain);
      } else {
        next.add(domain);
      }
      return next;
    });
  };

  // Handle live type auto-detection
  useEffect(() => {
    if (query) {
      const type = detectTargetType(query);
      setDetectedType(type);
    }
  }, [query, setDetectedType]);

  // Prevent copying of sensitive UI sections
  useEffect(() => {
    const preventCopy = (e: ClipboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target) return;
      const className = target.className;
      if (typeof className === 'string' && className.includes('no-copy')) {
        e.preventDefault();
      }
    };
    document.addEventListener('copy', preventCopy);
    return () => document.removeEventListener('copy', preventCopy);
  }, []);

  // Investigation workflow is delegated to the shared useScanWorkflow hook.
  const {
    isScanning,
    setIsScanning,
    scanLogs,
    triggerInvestigation: runInvestigation,
    triggerBatchInvestigation: runBatchInvestigation,
  } = useScanWorkflow({
    simulateDelay,
    activeTab,
    onInvestigationComplete: (result) => {
      setResults(result);
      addRecentScan(result);
      setViewingReport(true);
      setViewingBatch(false);
    },
    onBatchComplete: (results) => {
      results.forEach((r) => addRecentScan(r));
      setBatchResults(results);
      setViewingBatch(true);
      setViewingReport(false);
    },
    onRateLimited: (resetMs, type) => {
      setRateLimitCountdown({ ms: resetMs, type });
      showToast(`Rate limit reached. Please wait ${Math.ceil(resetMs / 1000)}s before retrying.`, 'error');
    },
  });

  /* Auto-detect public IP when the "What is My IP" module is opened */
  useEffect(() => {
    if (activeTab === 'myip' && !results?.myip && !isScanning) {
      (async () => {
        setIsScanning(true);
        try {
          const result = await scanMyIp();
          setResults(makeMyIpResults(result));
        } catch (e) {
          showToast('Failed to detect IP. Please try again.', 'error');
        } finally {
          setIsScanning(false);
        }
      })();
    }
  }, [activeTab, results, isScanning, showToast]);

  /* Auto-run IP Advance when the module is opened (uses your public IP by default) */
  useEffect(() => {
    if (activeTab === 'ipadvance' && !results?.ipadvance && !isScanning) {
      (async () => {
        setIsScanning(true);
        try {
          const result = await scanIpAdvance();
          setResults(makeIpAdvanceResults(result));
          addRecentScan(makeIpAdvanceResults(result));
          setViewingReport(true);
          setViewingBatch(false);
        } catch (e) {
          showToast('IP Advance scan failed. Please try again.', 'error');
        } finally {
          setIsScanning(false);
        }
      })();
    }
  }, [activeTab, results, isScanning, showToast]);

  /* Auto-run Technology Lookup when opened with a target pre-filled (e.g. from URL) */
  useEffect(() => {
    if (activeTab === 'techlookup' && query.trim() && !results?.techlookup && !isScanning) {
      (async () => {
        setIsScanning(true);
        setQuery('Fingerprinting website stack...');
        try {
          const result = await scanTechnology(query.trim());
          setResults(makeTechLookupResults(result));
          addRecentScan(makeTechLookupResults(result));
          setViewingReport(true);
          setViewingBatch(false);
        } catch (e) {
          showToast('Technology lookup failed. Please try again.', 'error');
        } finally {
          setIsScanning(false);
        }
      })();
    }
  }, [activeTab, results, isScanning, query, showToast]);

  /* Auto-run Geo Lookup when opened with a target pre-filled */
  useEffect(() => {
    if (activeTab === 'geolookup' && query.trim() && !results?.geolookup && !isScanning) {
      (async () => {
        setIsScanning(true);
        setQuery('Resolving geolocation...');
        try {
          const result = await scanGeoLookup(query.trim());
          setResults(makeGeoLookupResults(result));
          addRecentScan(makeGeoLookupResults(result));
          setViewingReport(true);
          setViewingBatch(false);
        } catch (e) {
          showToast('Geo lookup failed. Please try again.', 'error');
        } finally {
          setIsScanning(false);
        }
      })();
    }
  }, [activeTab, results, isScanning, query, showToast]);

  // Thin wrappers preserving the original public call signatures.
  const triggerInvestigation = useCallback((overrideTarget?: InvestigationTarget, localFile?: File) => {
    const run = (target: InvestigationTarget, file?: File) => {
      runInvestigation(target, file);
    };
    if (!overrideTarget) {
      if (!query.trim()) return;
      const sanitizedQuery = sanitizeText(query, 500);
      const parsed = parseInvestigationTarget(sanitizedQuery);
      const isModuleTab =
        activeTab !== 'home' &&
        activeTab !== 'risk' &&
        activeTab !== 'settings' &&
        activeTab !== 'history' &&
        activeTab !== 'image' &&
        activeTab !== 'metadata';
      const finalTarget: InvestigationTarget = isModuleTab
        ? { value: parsed.value, type: activeTab as TargetType }
        : parsed;
      run(finalTarget, localFile);
    } else {
      const sanitizedOverride = {
        ...overrideTarget,
        value: sanitizeText(overrideTarget.value, 500),
      };
      run(sanitizedOverride, localFile);
    }
  }, [query, activeTab, runInvestigation]);

  const triggerBatchInvestigation = useCallback((targetValues: string[]) => {
    const sanitizedTargets = targetValues
      .map((val) => sanitizeText(val, 500))
      .filter((val) => val.length > 0);
    if (sanitizedTargets.length === 0) return;
    runBatchInvestigation(sanitizedTargets);
  }, [runBatchInvestigation]);

  // Drag & drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const maxSize = 25 * 1024 * 1024;
    if (file.size > maxSize) {
      showToast('File too large. Maximum size is 25MB.', 'error');
      return;
    }

    const isTextOrCsv = file.name.endsWith('.txt') || file.name.endsWith('.csv') || file.type === 'text/plain' || file.type === 'text/csv';
    if (isTextOrCsv) {
      await processBatchFile(file, {
        onSuccess: (targets) => triggerBatchInvestigation(targets),
        onError: (message) => showToast(message, 'error'),
      });
      return;
    }

    const isImg = file.type.startsWith('image/');
    const targetObj: InvestigationTarget = {
      value: sanitizeFilename(file.name),
      type: isImg ? 'image' : 'metadata',
    };
    await triggerInvestigation(targetObj, file);
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const maxSize = 25 * 1024 * 1024;
    if (file.size > maxSize) {
      showToast('File too large. Maximum size is 25MB.', 'error');
      if (e.target) e.target.value = '';
      return;
    }

    const isTextOrCsv = file.name.endsWith('.txt') || file.name.endsWith('.csv') || file.type === 'text/plain' || file.type === 'text/csv';
    if (isTextOrCsv) {
      if (file.size > 5 * 1024 * 1024) {
        showToast('Text/CSV file too large. Maximum size is 5MB.', 'error');
        if (e.target) e.target.value = '';
        return;
      }
      await processBatchFile(file, {
        onSuccess: (targets) => triggerBatchInvestigation(targets),
        onError: (message) => showToast(message, 'error'),
      });
      if (e.target) e.target.value = '';
      return;
    }

    const isImg = file.type.startsWith('image/');
    const targetObj: InvestigationTarget = {
      value: sanitizeFilename(file.name),
      type: isImg ? 'image' : 'metadata',
    };
    await triggerInvestigation(targetObj, file);
    if (e.target) e.target.value = '';
  };

  // Try chip trigger helper
  const handleTryChip = (val: string) => {
    setQuery(val);
    const parsed = parseInvestigationTarget(val);
    triggerInvestigation(parsed);
  };

  // Sidebar module selector helper
  const handleSelectModule = (modId: typeof activeTab) => {
    setActiveTab(modId);
    setQuery('');
    setMobileMenuOpen(false);
    setViewingReport(false);
    setViewingBatch(false);
  };

  return (
    <div className={`h-screen overflow-hidden font-sans flex flex-col md:flex-row transition-colors duration-200`} style={{
      background: 'var(--bg-base)',
      color: 'var(--text-primary)'
    }}>
      <style>{`
        .no-copy {
          -webkit-user-select: none;
          user-select: none;
        }
        .no-copy * {
          -webkit-user-select: none;
          user-select: none;
        }
      `}</style>
      {/* Global Toast Notification Overlay */}
      <Toast toast={toast} onDismiss={() => setToast(null)} />

      {/* Background radial overlays */}
      {!isLightMode && (
        <div className="fixed inset-0 pointer-events-none z-0">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(220,38,38,0.03),transparent)]" />
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_left,rgba(220,38,38,0.03),transparent)]" />
        </div>
      )}

      {/* --- DESKTOP SIDEBAR --- */}
      <Sidebar />

      {/* --- MOBILE NAVIGATION DRAWER & TOP HEADER --- */}
      <MobileHeader />

      {/* --- MAIN CONTENT CANVAS WORKSPACE --- */}
      <ErrorBoundary>
        <main className="flex-1 min-h-0 flex flex-col min-w-0 z-10 relative overflow-y-auto" role="main" aria-label="OSINT.CS main content">
          <a href="#main_content" className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-red-600 focus:text-white focus:rounded-lg focus:text-sm focus:font-bold">Skip to main content</a>
          
          {/* Dynamic page/module views container */}
          <div id="main_content" className="flex-1 p-4 sm:p-6 lg:p-8">
            <AnimatePresence mode="wait">
              
              {/* --- ACTIVE REPORT OVERLAY --- */}
            {results && viewingReport && (
              <motion.div
                key="active_report_panel"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                 className="space-y-8"
               >
                 <Suspense fallback={<div className="flex items-center justify-center h-64"><div className="text-sm font-mono" style={{ color: 'var(--text-muted)' }}>Loading report dashboard...</div></div>}>
                  <ReportDashboard
                    results={results}
                    onBack={() => setViewingReport(false)}
                    isLightMode={isLightMode}
                    showToast={showToast}
                  />
                </Suspense>
              </motion.div>
            )}

            {/* --- BATCH SCAN OVERVIEW PANEL --- */}
            {batchResults && viewingBatch && !viewingReport && (
              <motion.div
                key="batch_overview_panel"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.2 }}
                className="space-y-8"
              >
                <div className="max-w-4xl mx-auto space-y-6">
                  <div className="flex items-center justify-between border-b pb-4 border-slate-800">
                    <div className="flex items-center gap-3">
                      <Layers className="w-8 h-8 text-red-500" />
                      <div>
                        <h1 className="text-2xl font-black font-display">Batch Scan Overview</h1>
                        <p className="text-xs text-slate-400 font-mono">Completed reconnaissance across {batchResults.length} targets</p>
                      </div>
                    </div>
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
                      <button
                        onClick={handleExportBatchCSV}
                        className={`px-4 py-2 rounded-lg border text-xs font-bold transition-all cursor-pointer flex items-center justify-center gap-2 ${
                          isLightMode
                            ? 'border-red-200 bg-red-50 text-red-700 hover:bg-red-100 shadow-sm'
                            : 'border-red-950 bg-red-500/10 text-red-400 hover:bg-red-500/20'
                        }`}
                        title="Export consolidated CSV summary of the risk scores and key findings for all scanned targets"
                      >
                        <FileSpreadsheet className="w-4 h-4" />
                        <span>Batch Export (CSV)</span>
                      </button>
                      <button
                        onClick={() => setViewingBatch(false)}
                        className={`px-4 py-2 rounded-lg border text-xs font-bold transition-all cursor-pointer flex items-center justify-center ${
                          isLightMode 
                            ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-100 shadow-sm'
                            : 'border-slate-800 bg-[#0e1424]/80 text-slate-300 hover:bg-slate-850'
                        }`}
                      >
                        Back to Lobby
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className={`border p-4 rounded-xl ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                      <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">Average Risk Level</div>
                      <div className="text-3xl font-black text-red-500 mt-1">
                        {batchResults.length > 0 ? Math.round(batchResults.reduce((acc, r) => acc + r.riskScore, 0) / batchResults.length) : 0} <span className="text-xs font-normal text-slate-500">/ 100</span>
                      </div>
                    </div>
                    <div className={`border p-4 rounded-xl ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                      <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">Successful Audits</div>
                      <div className="text-3xl font-black text-emerald-500 mt-1">{batchResults.length} <span className="text-xs font-normal text-slate-500">nodes</span></div>
                    </div>
                    <div className={`border p-4 rounded-xl ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                      <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">Security Standing</div>
                      <div className={`text-2xl font-black mt-1 ${
                        (batchResults.length > 0 ? Math.round(batchResults.reduce((acc, r) => acc + r.riskScore, 0) / batchResults.length) : 0) > 60 
                          ? 'text-red-500' 
                          : (batchResults.length > 0 ? Math.round(batchResults.reduce((acc, r) => acc + r.riskScore, 0) / batchResults.length) : 0) > 30 
                          ? 'text-amber-500' 
                          : 'text-emerald-500'
                      }`}>
                        {(batchResults.length > 0 ? Math.round(batchResults.reduce((acc, r) => acc + r.riskScore, 0) / batchResults.length) : 0) > 60 ? 'CRITICAL' : (batchResults.length > 0 ? Math.round(batchResults.reduce((acc, r) => acc + r.riskScore, 0) / batchResults.length) : 0) > 30 ? 'WARNING' : 'SECURE'}
                      </div>
                    </div>
                  </div>

                  <div className={`border rounded-xl overflow-hidden ${isLightMode ? 'border-slate-200 bg-white shadow-sm' : 'border-slate-800 bg-[#0e1424]/20'}`}>
                    <div className={`px-4 py-3 border-b flex items-center justify-between font-mono text-[10px] font-bold ${
                      isLightMode ? 'border-slate-200 bg-slate-50 text-slate-500' : 'border-slate-800 bg-[#0c1221] text-slate-400'
                    }`}>
                      <span>TARGET NODE INFORMATION</span>
                      <span>SECURITY SCORES</span>
                    </div>

                     <div className={`divide-y ${isLightMode ? 'divide-slate-200' : 'divide-slate-800/40'}`}>
                       <VirtualizedList
                         items={batchResults}
                         itemHeight={72}
                         height={Math.min(400, batchResults.length * 72)}
                         renderItem={(r, idx) => {
                           const sDetails = calculateRiskScore(r.findings);
                           return (
                             <div key={idx} className={`p-4 flex items-center justify-between transition-colors hover:bg-red-500/5 ${isLightMode ? 'border-b border-slate-200' : 'border-b border-slate-800/40'}`}>
                               <div className="flex items-center gap-3 truncate max-w-[70%]">
                                 <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-500 font-mono border border-red-500/25 uppercase shrink-0">
                                   {r.target.type}
                                 </span>
                                  <span className={`text-sm font-bold truncate ${isLightMode ? 'text-slate-800' : 'text-white'}`}>{sanitizeText(r.target.value, 80)}</span>
                               </div>

                               <div className="flex items-center gap-4">
                                 <div className="text-right">
                                   <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                                     r.riskScore > 60 ? 'bg-red-500/10 text-red-400 border border-red-500/20' : r.riskScore > 30 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                   }`}>
                                     {sDetails.grade} ({r.riskScore})
                                   </span>
                                 </div>
                                 <button
                                   onClick={() => {
                                     setResults(r);
                                     setViewingReport(true);
                                   }}
                                   className={`px-3 py-1.5 rounded text-xs font-bold transition-all cursor-pointer flex items-center gap-1 ${
                                     isLightMode 
                                       ? 'bg-slate-100 hover:bg-red-500 hover:text-white text-slate-700 border border-slate-200' 
                                       : 'bg-slate-900 border border-slate-800 hover:border-red-500 text-slate-300'
                                   }`}
                                 >
                                   <Eye className="w-3.5 h-3.5" /> Inspect
                                 </button>
                               </div>
                             </div>
                           );
                         }}
                       />
                     </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* --- 1. LOBBY / LANDING PAGE VIEW --- */}
            {activeTab === 'home' && !viewingReport && !viewingBatch && (
              <motion.div
                key="lobby_landing"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.25 }}
                className="space-y-16"
              >
                {/* HERO AREA (Split Columns) */}
                <section className="grid grid-cols-1 md:gap-12 lg:gap-16 lg:grid-cols-12 gap-8 items-center">
                   
                    {/* Left Column (Brand info & quick search bar) */}
                    <div className="lg:col-span-7 space-y-5 sm:space-y-6 text-left">
                      <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/5 border border-red-500/10">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" />
                        <span className="text-[10px] font-mono tracking-widest text-red-400 font-bold uppercase">
                          AI-POWERED OPEN-SOURCE INTELLIGENCE
                        </span>
                      </div>

                      <div className="space-y-1">
                        <h1 className="text-4xl sm:text-5xl md:text-6xl font-black font-display tracking-tight leading-tighter">
                          osint<span className="text-red-400">cs</span>
                        </h1>
                        <h2 className="text-2xl sm:text-3xl md:text-4xl font-black tracking-tight leading-tight" style={{ color: 'var(--text-primary)' }}>
                          Digital Verification &amp; Intelligence Platform
                        </h2>
                        <p className="text-slate-400 leading-relaxed text-sm sm:text-base">
                          OSINTCS helps investigators, journalists, cybersecurity professionals, and researchers discover, analyze, and verify fragmented digital information.
                        </p>
                      </div>

                     {/* Integrated Quick Search Bar with Dual Mode */}
                     <div className="space-y-3 sm:space-y-4">
                       {/* Search Mode Tab Toggle */}
                       <div className="flex gap-2 sm:gap-2.5 pb-1">
 <button
            type="button"
            onClick={() => setScanMode('single')}
            className="text-xs font-mono font-bold px-3 py-1.5 rounded-lg border transition-all cursor-pointer"
            style={scanMode === 'single'
              ? { background: 'var(--accent-bg)', color: 'var(--text-accent)', borderColor: 'var(--accent-border)' }
              : { background: 'var(--bg-panel)', color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }
            }
          >
            SINGLE TARGET ANALYSIS
          </button>
          <button
            type="button"
            onClick={() => setScanMode('batch')}
            className="text-xs font-mono font-bold px-3 py-1.5 rounded-lg border transition-all cursor-pointer"
            style={scanMode === 'batch'
              ? { background: 'var(--accent-bg)', color: 'var(--text-accent)', borderColor: 'var(--accent-border)' }
              : { background: 'var(--bg-panel)', color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }
            }
          >
            BATCH INVESTIGATION
          </button>
                       </div>

                      {scanMode === 'single' ? (
                         <form
                           onSubmit={(e) => {
                             e.preventDefault();
                             if (!query.trim()) return;
                             const sanitizedQuery = sanitizeText(query, 500);
                             const targets = sanitizedQuery.split(',').map((t) => t.trim()).filter(Boolean);
                             if (targets.length > 1) {
                               triggerBatchInvestigation(targets);
                             } else {
                               triggerInvestigation();
                             }
                           }}
                           className="relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 focus-within:border-red-500"
                           style={{
                             borderColor: 'var(--border-default)',
                             background: 'var(--bg-panel)',
                             boxShadow: isDarkMode ? 'var(--shadow-md)' : 'var(--shadow-sm)',
                           }}
                         >
                           <div className="pl-3.5" style={{ color: 'var(--text-muted)' }}>
                             <Search className="w-5 h-5" />
                           </div>
                           <input
                             type="text"
                             value={query}
                             onChange={(e) => handleQueryChange(e.target.value)}
                             placeholder="Enter a domain, URL, email, username or hash..."
                             className="w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm placeholder-slate-500 focus:ring-0"
                             style={{ color: 'var(--text-primary)' }}
                             disabled={isScanning}
                           />
                           <div className="flex items-center gap-1.5 shrink-0 pr-1">
                              <button
                                type="button"
                                onClick={() => setShowQrScanner(true)}
                                className="p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-center"
                                style={{
                                  borderColor: 'var(--border-default)',
                                  background: 'var(--bg-hover)',
                                  color: 'var(--text-muted)',
                                }}
                                title="Scan Target QR Code"
                              >
                                <QrCode className="w-4 h-4" />
                              </button>
                              <button
                                type="submit"
                                disabled={!query.trim() || isScanning}
                                className="px-5 py-3 rounded-lg hover:bg-red-500 text-white font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer font-sans flex items-center justify-center gap-1.5"
                                style={{
                                  background: 'var(--accent)',
                                  opacity: (!query.trim() || isScanning) ? 0.5 : 1,
                                  cursor: (!query.trim() || isScanning) ? 'not-allowed' : 'pointer',
                                }}
                              >
                                Analyze
                              </button>
                              {rateLimitCountdown && (
                                <div className="text-[10px] font-mono text-red-400 font-bold uppercase tracking-wider animate-pulse">
                                  Retry in {Math.ceil(rateLimitCountdown.ms / 1000)}s
                                </div>
                              )}
                           </div>
                        </form>
                      ) : (
                        <div className="space-y-3.5">
                        <div className="border rounded-xl p-4 space-y-3.5" style={{
                          borderColor: 'var(--border-default)',
                          background: 'var(--bg-panel)',
                          boxShadow: isDarkMode ? 'var(--shadow-md)' : 'var(--shadow-sm)',
                        }}>
                             <div>
                               <span className="text-[10px] font-mono tracking-wider text-slate-500 uppercase font-bold block mb-1">Enter Comma or Newline Separated Targets</span>
                               <textarea
                                 value={batchQuery}
                                 onChange={(e) => handleBatchQueryChange(e.target.value)}
                                 placeholder="Enter multiple targets (one per line, or comma-separated)&#10;e.g.&#10;google.com&#10;cloudflare.com&#10;user@gmail.com"
                                 rows={4}
                                 className="w-full bg-transparent border rounded-lg p-3 text-xs font-mono outline-none transition-all resize-none"
                                 style={{
                                   color: 'var(--text-primary)',
                                   borderColor: 'var(--border-default)',
                                 }}
                                 disabled={isScanning}
                               />
                             </div>
                             
                             <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 sm:gap-4 pt-1">
                               {/* File Upload Selector */}
                               <div className="flex items-center gap-2">
                                 <input
                                   type="file"
                                   ref={batchFileInputRef}
                                   accept=".txt,.csv"
                                   onChange={handleBatchFileSelect}
                                   className="hidden"
                                 />
                                 <button
                                   type="button"
                                   onClick={() => batchFileInputRef.current?.click()}
                                   className="px-3.5 py-2 rounded-lg border text-xs font-mono font-black transition-all cursor-pointer flex items-center gap-1.5"
                                   style={{
                                     borderColor: 'var(--border-default)',
                                     background: 'var(--bg-hover)',
                                     color: 'var(--text-secondary)',
                                   }}
                                 >
                                   <Upload className="w-3.5 h-3.5" style={{ color: 'var(--accent)' }} />
                                  <span>Upload List (.txt / .csv)</span>
                                </button>
                              </div>

                                <button
                                  type="button"
                                  onClick={() => {
                                    if (!batchQuery.trim()) return;
                                    const sanitizedBatch = sanitizeText(batchQuery, 5000);
                                    const targets = sanitizedBatch
                                      .split(/[\n,;]+/)
                                      .map((t) => t.trim())
                                      .filter(Boolean);
                                    if (targets.length > 0) {
                                      triggerBatchInvestigation(targets);
                                    }
                                  }}
                                  disabled={!batchQuery.trim() || isScanning}
                                  className="px-5 py-2.5 rounded-lg hover:bg-red-500 text-white font-bold text-xs transition-all uppercase tracking-wider cursor-pointer flex items-center justify-center gap-1.5 font-sans"
                                  style={{
                                    background: 'var(--accent)',
                                    opacity: (!batchQuery.trim() || isScanning) ? 0.5 : 1,
                                    cursor: (!batchQuery.trim() || isScanning) ? 'not-allowed' : 'pointer',
                                  }}
                                 >
                                   <Play className="w-3.5 h-3.5" />
                                   <span>Run Batch Scan</span>
                                 </button>
                                 {rateLimitCountdown && rateLimitCountdown.type === 'batch' && (
                                   <div className="text-[10px] font-mono text-red-400 font-bold uppercase tracking-wider animate-pulse">
                                     Retry in {Math.ceil(rateLimitCountdown.ms / 1000)}s
                                   </div>
                                 )}
                            </div>
                          </div>
                        </div>
                      )}

                    {/* Try Chips */}
                    <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                      <span className="text-slate-500 uppercase font-semibold">QUICK ACCESS:</span>
                      {['cloudflare.com', 'github.com', 'natro.com', 'turhost.com', 'example.com'].map((chip) => (
                        <button
                          key={chip}
                          onClick={() => handleTryChip(chip)}
                          className="px-2.5 py-1 rounded-md border text-[11px] font-medium transition-all cursor-pointer"
                          style={{
                            borderColor: 'var(--border-default)',
                            background: 'var(--bg-panel)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {chip}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right Column (The interactive "Smart Target Router" card!) */}
                  <div className="lg:col-span-5">
                    <div className="border rounded-2xl p-4 sm:p-6 relative flex flex-col justify-between min-h-[360px] sm:min-h-[380px] shadow-xl overflow-hidden"
                      style={{
                        borderColor: 'var(--border-default)',
                        background: 'var(--bg-panel)',
                        boxShadow: isDarkMode ? 'var(--shadow-xl)' : 'var(--shadow-md)',
                      }}>
                      {/* Interactive background effect */}
                      <div className="absolute top-0 right-0 w-20 h-20 sm:w-24 sm:h-24 bg-red-500/5 rounded-full blur-xl pointer-events-none" />

                      <div className="space-y-5 sm:space-y-6">
                        {/* Title Row */}
                         <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: 'var(--border-subtle)' }}>
                          <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-widest flex items-center gap-1.5">
                            <Sliders className="w-3.5 h-3.5" /> SMART TARGET ROUTER
                          </span>
                          <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold uppercase tracking-wider border"
                            style={query.trim()
                              ? { background: 'var(--color-pass-bg)', borderColor: 'var(--color-pass-border)', color: 'var(--color-pass)' }
                              : { background: 'var(--bg-muted)', borderColor: 'var(--border-default)', color: 'var(--text-muted)' }
                            }>
                            {query.trim() ? `${detectedType.toUpperCase()} DETECTED` : 'WAITING TARGET'}
                          </span>
                        </div>

                        {/* Dial Indicator */}
                        <div className="flex items-center gap-3 sm:gap-4">
                          <div className="relative shrink-0 flex items-center justify-center w-14 h-14 sm:w-16 sm:h-16">
                            <svg className="w-full h-full transform -rotate-90">
                              <circle cx="32" cy="32" r="28" className="stroke-slate-850 fill-none" strokeWidth="4" />
                              <circle
                                cx="32"
                                cy="32"
                                r="28"
                                className="fill-none stroke-red-400 transition-all duration-500"
                                strokeWidth="4"
                                strokeDasharray={176}
                                strokeDashoffset={query.trim() ? 20 : 140}
                                strokeLinecap="round"
                              />
                            </svg>
                            <span className="absolute text-[10px] font-mono font-black" style={{ color: 'var(--text-primary)' }}>
                              {query.trim() ? '98%' : '0%'}
                            </span>
                          </div>

                          <div className="space-y-1">
                            <h4 className="text-sm font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                              {query.trim() ? `Recommended module: ${detectedType.toUpperCase()}` : 'Awaiting target analysis...'}
                            </h4>
                            <p className="text-[11px] text-slate-400 leading-normal">
                              {query.trim()
                                ? `Target "${sanitizeText(query.slice(0, 20), 20)}..." analyzed. Optimal module: ${detectedType.toUpperCase()}.`
                                : 'Enter any target (domain, IP, email, username, hash, image) for intelligent routing.'}
                            </p>
                          </div>
                        </div>

                         {/* List of Module pathways */}
                         <div className="grid grid-cols-2 gap-2 pt-2">
  {[
                               { step: '01', name: 'Domain Intelligence', active: query.trim() && (detectedType === 'domain' || detectedType === 'website') },
                               { step: '02', name: 'SSL/TLS Analysis', active: query.trim() && detectedType === 'website' },
                               { step: '03', name: 'Digital Footprinting', active: query.trim() && (detectedType === 'email' || detectedType === 'username') },
                               { step: '04', name: 'Image Forensics', active: query.trim() && (detectedType === 'image' || detectedType === 'metadata') },
                               { step: '05', name: 'Tech & Geo Intelligence', active: query.trim() && (detectedType === 'ip' || detectedType === 'domain') },
                               { step: '06', name: 'IP Risk Purity', active: query.trim() && detectedType === 'ip' },
                               { step: '07', name: 'Web Forensics', active: query.trim() && (detectedType === 'website' || detectedType === 'domain') },
                             ].map((m, idx) => (
                             <div
                               key={idx}
                               className={`p-2.5 rounded-lg border text-xs flex flex-col gap-0.5 transition-all ${
                                 m.active
                                   ? 'border-red-500/50 bg-red-500/10 text-red-300'
                                   : 'border-slate-800/40 bg-slate-950/20 text-slate-500'
                               }`}
                             >
                               <span className="text-[9px] font-mono font-bold block">{m.step}</span>
                               <span className="font-semibold truncate">{m.name}</span>
                             </div>
                           ))}
                        </div>
                      </div>

                      {/* Action Button */}
                      <div className="pt-4 mt-4 border-t flex items-center justify-between text-xs font-mono" style={{ borderColor: 'var(--border-default)' }}>
                        <span className="text-slate-500 text-[10px]">◎ Open selected pathway directly</span>
                        <button
                          onClick={() => {
                            if (query.trim()) {
                              handleSelectModule(detectedType);
                              triggerInvestigation();
                            } else {
                              handleSelectModule('risk');
                            }
                          }}
                          className="text-red-400 hover:text-red-300 font-bold uppercase tracking-wider flex items-center gap-1.5 cursor-pointer"
                        >
                          {query.trim() ? 'Open Scan' : 'Browse Tools'} <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                </section>

                {/* STATISTICS TICKER */}
                <section className="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6 border-y py-6 sm:py-8 text-center font-mono" style={{ borderColor: 'var(--border-default)' }}>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase tracking-wider">Modules</span>
                    <span className="text-2xl sm:text-3xl font-black mt-1 block" style={{ color: 'var(--text-primary)' }}>{getAllModules().length}+</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase tracking-wider">Checks Per Scan</span>
                    <span className="text-2xl sm:text-3xl font-black mt-1 block" style={{ color: 'var(--text-primary)' }}>100+</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase tracking-wider">Report Formats</span>
                    <span className="text-2xl sm:text-3xl font-black mt-1 block" style={{ color: 'var(--text-primary)' }}>5 Formats</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 block uppercase tracking-wider">Access Mode</span>
                    <span className="text-2xl sm:text-3xl font-black mt-1 block" style={{ color: 'var(--text-primary)' }}>100% Local</span>
                  </div>
                </section>

                {/* PLATFORM MODULES SECTION */}
                <section id="module_grid" className="space-y-8 sm:space-y-10">
                  <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 sm:gap-4 border-b pb-3 sm:pb-4" style={{ borderColor: 'var(--border-default)' }}>
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-widest block">
                        OSINTCS MODULES
                      </span>
                      <h3 className="text-xl sm:text-2xl font-black tracking-tight font-display">
                        Full-spectrum reconnaissance arsenal
                      </h3>
                    </div>
                    <p className="text-xs text-slate-400 max-w-md">
                        {getAllModules().length}+ integrated modules covering DNS, SSL, email, identity, forensics, network mapping, geolocation, technology fingerprinting, and attack-surface discovery.
                    </p>
                  </div>

                  {[
                     { category: 'INFRASTRUCTURE & NETWORK RECON', color: 'text-red-400', modules: ['domain','website','websitescanner','networkscan','subdomain','portscan','urlfuzz','waf','domainfinder','vhosts','googlehacking','ip','ipadvance'] },
                    { category: 'TECHNOLOGY & GEO INTELLIGENCE', color: 'text-violet-400', modules: ['techlookup','geolookup','speedtest'] },
                    { category: 'IDENTITY & PEOPLE', color: 'text-amber-400', modules: ['email','username','peoplehunter'] },
                    { category: 'FORENSICS & FILES', color: 'text-emerald-400', modules: ['image','metadata','hash','myip','poplenscan'] },
                  ].map((cat) => (
                    <div key={cat.category} className="space-y-4">
                      <h4 className={`text-[10px] font-mono font-bold uppercase tracking-widest ${cat.color}`}>{cat.category}</h4>
                       <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 sm:gap-4">
                          {cat.modules.map((modId) => {
                             const mod = getModule(modId as TargetType | 'risk');
                             if (!mod) return null;
                           const Icon = mod.icon;
                           return (
                             <div key={modId} onClick={() => handleSelectModule(modId as TargetType | 'risk' | 'settings' | 'history')}
                               className="border rounded-xl p-3.5 sm:p-4 space-y-3 group transition-all cursor-pointer hover:-translate-y-0.5"
                               style={{
                                 borderColor: 'var(--border-default)',
                                 background: 'var(--bg-panel)',
                                 boxShadow: isDarkMode ? 'var(--shadow-sm)' : 'var(--shadow-xs)',
                               }}>
                               <div className="flex justify-between items-start">
                                 <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/20" style={{ color: 'var(--text-accent)' }}>
                                   <Icon className="w-4 h-4" />
                                 </div>
                               </div>
                               <div className="space-y-1">
                                 <h5 className="font-bold text-sm" style={{ color: 'var(--text-primary)' }}>{mod.label}</h5>
                                 <p className="text-[11px] text-slate-400 leading-normal line-clamp-2">{mod.description}</p>
                               </div>
                               <div className="text-[11px] font-semibold text-red-400 font-mono group-hover:underline flex items-center gap-1">
                                 Open module <ArrowRight className="w-3 h-3" />
                               </div>
                             </div>
                           );
                         })}
                       </div>
                    </div>
                  ))}
                </section>

                 {/* ANALYSIS ENGINE STAGES (Details list) */}
                 <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 sm:gap-8 items-start border-t pt-8 sm:pt-12" style={{ borderColor: 'var(--border-default)' }}>
                   <div className="lg:col-span-5 space-y-3 sm:space-y-4">
                     <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-widest block">
                       ANALYSIS PIPELINE
                     </span>
                     <h3 className="text-2xl font-black font-display tracking-tight">
                       Intelligent Investigation Flow
                     </h3>
                     <p className="text-xs text-slate-400 leading-relaxed">
                       Multi-module intelligence processing with correlated results, real-time validation, and structured evidence output.
                     </p>
                   </div>

                   {/* Numbered Steps list matching the screenshot details */}
                   <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                        {[
                          { num: '01', title: 'DNS Intelligence Mapping', desc: 'Resolve MX, NS, SPF, DMARC, and TXT records for attack surface analysis.' },
                          { num: '02', title: 'Website Security Scan', desc: 'Live headers, TLS, cookies, CORS, CMS, security header fingerprinting.' },
                          { num: '03', title: 'Mail Server Audit', desc: 'Audit SMTP, open relays, spoofing vectors, and mailflow posture.' },
                          { num: '04', title: 'WHOIS / RDAP Records', desc: 'Evaluate registration age, registrars, and ownership intelligence.' },
                          { num: '05', title: 'SSL/TLS Audit', desc: 'Certificates, cipher suites, protocol versions, and chain trust.' },
                          { num: '06', title: 'BGP / ASN Mapping', desc: 'Trace autonomous networks and physical hosting infrastructure.' },
                          { num: '07', title: 'Reverse IP / Hostmap', desc: 'Co-hosted servers, shared hosting neighbors, and origin exposure.' },
                          { num: '08', title: 'Security Headers Review', desc: 'CSP, HSTS, X-Frame, COOP/COEP, and secure transport options.' },
                          { num: '09', title: 'Subdomain Enumeration', desc: 'Certificate transparency logs and passive recon coverage.' },
                          { num: '10', title: 'Port & Service Profiling', desc: 'Top and deep port sweeps, service fingerprinting, and exposure triage.' },
                          { num: '11', title: 'WAF Detection', desc: 'Identify CDN/WAF vendors, challenge pages, and header-based protections.' },
                          { num: '12', title: 'Identity & People OSINT', desc: 'Email breach exposure, username footprinting, and entity correlation.' },
                          { num: '13', title: 'Image & Metadata Forensics', desc: 'EXIF, GPS, AI-generation indicators, and ELA compression analysis.' },
                          { num: '14', title: 'URL & Path Discovery', desc: 'Endpoint fuzzing, common admin paths, and parameter exposure.' },
                          { num: '15', title: 'Webpage Resource Mapping', desc: 'Capture page load graph: domains, resources, redirects, cookies, third-party exposure, and risk scoring.' },
                          { num: '16', title: 'Local Execution Mode', desc: 'Zero backend dependency. All scanning runs in-browser with fallback simulation.' },
                        ].map((step, idx) => (
                       <div key={idx} className="border p-3 rounded-lg flex items-start gap-3 transition-all"
                         style={{
                           borderColor: 'var(--border-default)',
                           background: 'var(--bg-panel)',
                         }}>
                         <span className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded shrink-0">
                           {step.num}
                         </span>
                         <div className="space-y-0.5 min-w-0">
                           <strong className="block font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{step.title}</strong>
                           <p className="text-[10px] text-slate-500 leading-normal line-clamp-2">{step.desc}</p>
                         </div>
                       </div>
                     ))}
                   </div>
                 </section>

                 {/* BOTTOM CALL-TO-ACTION BANNER */}
                 <section className="border rounded-2xl p-6 sm:p-8 text-center relative overflow-hidden"
                   style={{
                     borderColor: 'var(--border-default)',
                     background: 'var(--bg-panel)',
                   }}>
                   <div className="absolute top-0 right-0 w-40 h-40 bg-red-500/5 rounded-full blur-2xl pointer-events-none" />
                   <div className="max-w-xl mx-auto space-y-4">
                     <span className="text-[10px] font-mono font-bold text-red-400 uppercase tracking-widest block">START WITH ONE TARGET</span>
                     <h3 className="text-xl sm:text-2xl font-black tracking-tight font-display">Run a domain through the full reconnaissance suite.</h3>
                     <p className="text-xs text-slate-400">
                       Audit DNS, SSL, headers, subdomains, WAF, open ports, virtual hosts, and known paths in a single synchronous workflow.
                     </p>
                     <button
                       onClick={() => {
                         setQuery('cloudflare.com');
                         handleSelectModule('domain');
                         triggerInvestigation({ value: 'cloudflare.com', type: 'domain' });
                       }}
                       className="px-6 py-2.5 rounded-lg hover:bg-red-500 text-white font-bold text-xs uppercase tracking-wider transition-all cursor-pointer inline-flex items-center gap-1.5 shadow-lg"
                       style={{ background: 'var(--accent)' }}
                     >
                       Launch Intelligence Scan
                     </button>
                   </div>
                 </section>

                {/* FOOTER (home page) */}
                <footer className="pt-10 sm:pt-12 border-t text-xs" style={{ borderColor: 'var(--border-default)', color: 'var(--text-secondary)' }}>
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-6 sm:gap-8 pb-6 sm:pb-8">
                    <div className="md:col-span-5 space-y-3">
                      <span className="text-base font-black font-display">osint<span className="text-red-400">cs</span></span>
                      <p className="text-[11px] text-slate-500 leading-relaxed max-w-sm">
                        Created by <span className="text-red-400 font-bold">Cyberswahili</span>. Professional-grade OSINT platform for infrastructure intelligence, digital forensics, and security assessments. All analysis runs locally in your browser.
                      </p>
                    </div>

                    <div className="md:col-span-7 grid grid-cols-2 sm:grid-cols-3 gap-4 sm:gap-6 font-mono text-[10px] text-left">
                      <div className="space-y-2">
                        <strong className="text-slate-500 uppercase tracking-wider font-black block">INFRASTRUCTURE</strong>
                        <ul className="space-y-1.5">
                          <li><button onClick={() => handleSelectModule('domain')} className="hover:text-red-400 cursor-pointer">Domain DNS</button></li>
                          <li><button onClick={() => handleSelectModule('website')} className="hover:text-red-400 cursor-pointer">Website SSL</button></li>
                          <li><button onClick={() => handleSelectModule('websitescanner')} className="hover:text-red-400 cursor-pointer">Web Security</button></li>
                          <li><button onClick={() => handleSelectModule('subdomain')} className="hover:text-red-400 cursor-pointer">Subdomains</button></li>
                          <li><button onClick={() => handleSelectModule('portscan')} className="hover:text-red-400 cursor-pointer">Port Scanner</button></li>
                          <li><button onClick={() => handleSelectModule('networkscan')} className="hover:text-red-400 cursor-pointer">Network Scan</button></li>
                        </ul>
                      </div>
                      <div className="space-y-2">
                        <strong className="text-slate-500 uppercase tracking-wider font-black block">ATTACK SURFACE</strong>
                        <ul className="space-y-1.5">
                          <li><button onClick={() => handleSelectModule('urlfuzz')} className="hover:text-red-400 cursor-pointer">URL Fuzzer</button></li>
                          <li><button onClick={() => handleSelectModule('waf')} className="hover:text-red-400 cursor-pointer">WAF Detector</button></li>
                          <li><button onClick={() => handleSelectModule('domainfinder')} className="hover:text-red-400 cursor-pointer">Domain Finder</button></li>
                          <li><button onClick={() => handleSelectModule('vhosts')} className="hover:text-red-400 cursor-pointer">VHosts</button></li>
                          <li><button onClick={() => handleSelectModule('googlehacking')} className="hover:text-red-400 cursor-pointer">Google Dorking</button></li>
                          <li><button onClick={() => handleSelectModule('ip')} className="hover:text-red-400 cursor-pointer">IP Address</button></li>
                          <li><button onClick={() => handleSelectModule('ipadvance')} className="hover:text-red-400 cursor-pointer">IP Advance</button></li>
                        </ul>
                      </div>
                      <div className="space-y-2">
                        <strong className="text-slate-500 uppercase tracking-wider font-black block">IDENTITY & FORENSICS</strong>
                        <ul className="space-y-1.5">
                          <li><button onClick={() => handleSelectModule('email')} className="hover:text-red-400 cursor-pointer">Email Audit</button></li>
                          <li><button onClick={() => handleSelectModule('username')} className="hover:text-red-400 cursor-pointer">Username Footprint</button></li>
                          <li><button onClick={() => handleSelectModule('peoplehunter')} className="hover:text-red-400 cursor-pointer">People Hunter</button></li>
                          <li><button onClick={() => handleSelectModule('image')} className="hover:text-red-400 cursor-pointer">Image Forensics</button></li>
                          <li><button onClick={() => handleSelectModule('metadata')} className="hover:text-red-400 cursor-pointer">Metadata</button></li>
                          <li><button onClick={() => handleSelectModule('hash')} className="hover:text-red-400 cursor-pointer">Hash Intel</button></li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </footer>

              </motion.div>
            )}

            {/* --- 2. STAND-ALONE TOOL WORKSPACE VIEW --- */}
            {activeTab !== 'home' && activeTab !== 'settings' && activeTab !== 'history' && !viewingReport && !viewingBatch && (
              <motion.div
                key={`tool_${activeTab}`}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.15 }}
                className="space-y-8"
              >
                {/* Tool Title Block */}
                 <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 sm:gap-4 border-b pb-4 sm:pb-5" style={{ borderColor: 'var(--border-default)' }}>
                   <div className="flex items-start gap-3">
                     <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 shrink-0" style={{ color: 'var(--text-accent)' }}>
                        {React.createElement(getModule(activeTab)?.icon || Shield, { className: "w-6 h-6" })}
                     </div>
                     <div>
                       <h2 className="text-xl font-black font-display flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                          {getModule(activeTab)?.label}
                       </h2>
                       <p className="text-xs text-slate-400 font-medium">
                          {getModule(activeTab)?.description}
                       </p>
                     </div>
                   </div>

                   {/* Return Home Button */}
                   <button
                     onClick={() => handleSelectModule('home')}
                     className="px-3.5 py-1.5 rounded-lg border text-xs font-bold transition-all cursor-pointer"
                     style={{
                       borderColor: 'var(--border-default)',
                       background: 'var(--bg-panel)',
                       color: 'var(--text-secondary)',
                     }}
                   >
                     Back to Lobby
                   </button>
                 </div>

                {/* Interactive Work Area */}
                <div className="max-w-3xl mx-auto space-y-6">
                  {activeTab === 'image' ? (
                    /* Interactive Image Upload */
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8 items-stretch">
                      <div className="flex flex-col justify-between border rounded-xl p-5 sm:p-6 relative"
                        style={{
                          borderColor: 'var(--border-default)',
                          background: 'var(--bg-panel)',
                          boxShadow: isDarkMode ? 'var(--shadow-md)' : 'var(--shadow-sm)',
                        }}>
                        <div>
                          <h3 className="text-xs font-bold font-mono uppercase tracking-wider mb-3 sm:mb-4 flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping" /> Target Image
                          </h3>
                          <div
                            onDragOver={handleDragOver}
                            onDragLeave={handleDragLeave}
                            onDrop={handleDrop}
                            onClick={() => fileInputRef.current?.click()}
                            className="border-2 border-dashed rounded-lg p-6 sm:p-8 text-center transition-all cursor-pointer flex flex-col items-center justify-center gap-2.5"
                            style={{
                              borderColor: isDragging ? 'var(--accent)' : 'var(--border-default)',
                              background: isDragging ? 'var(--accent-bg)' : 'var(--bg-hover)',
                              transform: isDragging ? 'scale(1.01)' : 'none',
                            }}
                          >
                            <input
                              type="file"
                              ref={fileInputRef}
                              accept="image/jpeg,image/png,image/webp,image/gif,image/avif"
                              onChange={handleFileSelect}
                              className="hidden"
                              id="image_file_picker"
                            />
                            <Upload className="w-8 h-8" style={{ color: isDragging ? 'var(--accent)' : 'var(--text-muted)' }} />
                            <div className="space-y-1">
                              <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>Drop or choose an image</p>
                              <p className="text-xs text-slate-500 font-mono">JPEG, PNG, WebP, GIF, AVIF · max 20 MB</p>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-3 sm:space-y-4 pt-5 sm:pt-6 mt-4 sm:mt-6 border-t" style={{ borderColor: 'var(--border-default)' }}>
                          <button
                            onClick={() => fileInputRef.current?.click()}
                            className="w-full py-3 rounded-lg hover:bg-red-500 text-white font-bold text-xs tracking-wider uppercase transition-all flex items-center justify-center gap-2 cursor-pointer shadow-lg"
                            style={{ background: 'var(--accent)' }}
                          >
                            <Eye className="w-4 h-4" /> Scan authenticity
                          </button>
                          <div className="text-[10px] text-slate-500 leading-normal flex items-start gap-1.5 font-mono">
                            <AlertCircle className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
                            <div>
                              Scans authenticity traces. Cloud AI detection is used as the primary score when configured.
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="border rounded-xl p-5 sm:p-6 flex flex-col justify-between"
                        style={{
                          borderColor: 'var(--border-default)',
                          background: 'var(--bg-panel)',
                          boxShadow: isDarkMode ? 'var(--shadow-md)' : 'var(--shadow-sm)',
                        }}>
<div className="space-y-4">
                       <h4 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                         From IOC to Actionable Intelligence
                       </h4>
                       <p className="text-slate-400">
                         Begin with any indicator of compromise (domain, IP, email, username, hash, image) and transform disparate data points into correlated, source-verified intelligence packages.
                       </p>

                          <div className="grid grid-cols-1 gap-3 pt-2">
                            {[
                              { title: 'AI-generation indicators', desc: 'Anomalous edge pixels, synthetic upscaler frequencies, and neural renders.' },
                              { title: 'EXIF and GPS clues', desc: 'Hidden camera tags, timestamp logs, and georeference coordinates.' },
                              { title: 'SHA-256 fingerprint', desc: 'Secure local hashing models validating binary structure integrity.' },
                              { title: 'Visual forensic metric', desc: 'Discrete Fourier spectral patterns and ELA compression noise grids.' }
                            ].map((item, index) => (
                              <div key={index} className="p-3 rounded-lg border border-slate-850 bg-slate-900/10 flex items-start gap-2.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-500 mt-1.5" />
                                <div className="space-y-0.5">
                                  <strong className="text-xs font-semibold block text-slate-300">{item.title}</strong>
                                  <p className="text-[10px] text-slate-500 leading-normal">{item.desc}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : activeTab === 'ipadvance' ? (
                    /* IP Advance — multi-source intelligence */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-500 shrink-0">
                              <Radar className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>IP Advance</h3>
                              <p className="text-[11px] font-mono text-slate-400">Multi-source intelligence · risk purity · BGP · neighbour scan</p>
                            </div>
                          </div>
                          {results?.ipadvance && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Scanned
                            </span>
                          )}
                        </div>

                        {isScanning ? (
                          <div className="flex items-center justify-center gap-3 py-10">
                            <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Running multi-source IP intelligence...</span>
                          </div>
                        ) : results?.ipadvance ? (
                          <div className="space-y-6">
                            {/* Hero IP */}
                            <div className={`p-5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${isLightMode ? 'border-blue-200 bg-blue-50' : 'border-blue-500/30 bg-blue-500/10'}`}>
                              <div className="space-y-1 min-w-0">
                                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">Analysed IP Address</span>
                                <div className="flex items-center gap-3">
                                  <span className={`text-2xl sm:text-3xl font-black font-mono break-all ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{results.ipadvance.ip}</span>
                                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold shrink-0 ${results.ipadvance.ipVersion === 'IPv6' ? 'bg-violet-500/10 text-violet-600 border border-violet-500/20' : 'bg-blue-500/10 text-blue-600 border border-blue-500/20'}`}>{results.ipadvance.ipVersion}</span>
                                </div>
                              </div>
                              <button
                                type="button"
                                onClick={() => { navigator.clipboard.writeText(results.ipadvance!.ip); showToast('IP address copied to clipboard', 'success'); }}
                                className={`shrink-0 px-3 py-2 rounded-lg border text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5 ${isLightMode ? 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <Copy className="w-3.5 h-3.5" /> Copy
                              </button>
                            </div>

                            {/* Risk + identity summary */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                { label: 'Risk Purity', value: `${results.ipadvance.riskScore}/100`, danger: results.ipadvance.riskScore < 50 },
                                { label: 'Grade', value: results.ipadvance.riskGrade },
                                { label: 'IP Type', value: results.ipadvance.ipType },
                                { label: 'Native IP', value: results.ipadvance.isNativeIp ? 'Yes' : 'No', danger: !results.ipadvance.isNativeIp },
                              ].map((field, idx) => (
                                <div key={idx} className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                  <span className="text-[10px] text-slate-500 block mb-1">{field.label}</span>
                                  <span className={`text-sm font-mono font-bold break-all ${field.danger ? 'text-red-400' : isLightMode ? 'text-slate-900' : 'text-white'}`}>{field.value}</span>
                                </div>
                              ))}
                            </div>

                            {/* Quick actions */}
                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={async () => {
                                  if (isScanning) return;
                                  setIsScanning(true);
                                  setQuery('Running multi-source IP intelligence...');
                                  try {
                                    const result = await scanIpAdvance();
                                    setResults(makeIpAdvanceResults(result));
                                    addRecentScan(makeIpAdvanceResults(result));
                                  } catch (e) {
                                    showToast('IP Advance scan failed. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Scan Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={async () => {
                              if (isScanning) return;
                              setIsScanning(true);
                              setQuery('Running multi-source IP intelligence...');
                              try {
                                const result = await scanIpAdvance();
                                setResults(makeIpAdvanceResults(result));
                                addRecentScan(makeIpAdvanceResults(result));
                                setViewingReport(true);
                              } catch (e) {
                                showToast('IP Advance scan failed. Please try again.', 'error');
                              } finally {
                                setIsScanning(false);
                              }
                            }}
                            className="w-full py-3.5 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
                          >
                            <span className="flex items-center gap-2">
                              <Radar className="w-4 h-4" /> Run IP Advance Scan
                            </span>
                          </button>
                        )}
                      </div>
                    </div>
                  ) : activeTab === 'techlookup' ? (
                    /* Technology Lookup */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-500 shrink-0">
                              <Cpu className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Technology Lookup</h3>
                              <p className="text-[11px] font-mono text-slate-400">Web stack · CMS · framework · CDN/WAF</p>
                            </div>
                          </div>
                          {results?.techlookup && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Scanned
                            </span>
                          )}
                        </div>

                        {isScanning ? (
                          <div className="flex items-center justify-center gap-3 py-10">
                            <RefreshCw className="w-6 h-6 animate-spin text-violet-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Fingerprinting website stack...</span>
                          </div>
                        ) : results?.techlookup ? (
                          <div className="space-y-6">
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: 'Web Server', value: results.techlookup.server },
                                { label: 'CMS / Platform', value: results.techlookup.cms, danger: results.techlookup.cms === 'WordPress' },
                                { label: 'JS Framework', value: results.techlookup.jsFramework },
                                { label: 'CDN / Edge', value: results.techlookup.cdn },
                                { label: 'WAF', value: results.techlookup.waf },
                                { label: 'Hosting', value: results.techlookup.hosting },
                              ].map((field, idx) => (
                                <div key={idx} className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                  <span className="text-[10px] text-slate-500 block mb-1">{field.label}</span>
                                  <span className={`text-xs font-mono font-bold break-all ${field.danger ? 'text-red-400' : isLightMode ? 'text-slate-900' : 'text-white'}`}>{field.value || 'N/A'}</span>
                                </div>
                              ))}
                            </div>

                            <div className="overflow-x-auto border rounded-lg ${isLightMode ? 'border-slate-200' : 'border-slate-850'}">
                              <table className="w-full text-left border-collapse font-mono text-[11px]">
                                <thead className={`${isLightMode ? 'bg-slate-50 text-slate-500' : 'bg-slate-900/40 text-slate-400'}`}>
                                  <tr>
                                    <th className="px-3 py-2 font-bold">Technology</th>
                                    <th className="px-3 py-2 font-bold">Value</th>
                                    <th className="px-3 py-2 font-bold">Category</th>
                                  </tr>
                                </thead>
                                <tbody className={`divide-y ${isLightMode ? 'divide-slate-100' : 'divide-slate-850'}`}>
                                  {results.techlookup.tech.map((t, idx) => (
                                    <tr key={idx}>
                                      <td className={`px-3 py-2 font-semibold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{t.label}</td>
                                      <td className={`px-3 py-2 ${isLightMode ? 'text-slate-600' : 'text-slate-400'}`}>{t.value}</td>
                                      <td className={`px-3 py-2 ${isLightMode ? 'text-slate-500' : 'text-slate-500'}`}>{t.category}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>

                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={async () => {
                                  if (isScanning) return;
                                  setIsScanning(true);
                                  setQuery('Fingerprinting website stack...');
                                  try {
                                    const result = await scanTechnology(results.techlookup!.domain);
                                    setResults(makeTechLookupResults(result));
                                    addRecentScan(makeTechLookupResults(result));
                                  } catch (e) {
                                    showToast('Technology lookup failed. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-violet-600 hover:bg-violet-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Scan Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        ) : !query.trim() ? (
                          <div className="space-y-4">
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                if (!query.trim()) return;
                                (async () => {
                                  setIsScanning(true);
                                  setQuery('Fingerprinting website stack...');
                                  try {
                                    const result = await scanTechnology(query.trim());
                                    setResults(makeTechLookupResults(result));
                                    addRecentScan(makeTechLookupResults(result));
                                    setViewingReport(true);
                                  } catch (err) {
                                    showToast('Technology lookup failed. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                })();
                              }}
                              className={`relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 ${
                                isLightMode
                                  ? 'border-slate-200 bg-white shadow-sm focus-within:border-violet-500'
                                  : 'border-slate-850 bg-[#0e1424]/40 shadow-lg focus-within:border-violet-500/80'
                              }`}
                            >
                              <div className="pl-3.5 text-slate-500">
                                <Search className="w-5 h-5" />
                              </div>
                              <input
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                placeholder="Enter a website URL or hostname (e.g., example.com)..."
                                className={`w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm focus:ring-0 ${
                                  isLightMode ? 'text-slate-900' : 'text-white'
                                }`}
                                disabled={isScanning}
                              />
                              <button
                                type="submit"
                                disabled={!query.trim() || isScanning}
                                className="px-5 py-3 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:bg-slate-900/50 text-white disabled:text-slate-500 font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer"
                              >
                                Scan
                              </button>
                            </form>
                            <p className="text-[11px] text-slate-500 font-mono">
                              Enter a domain or URL to fingerprint its web server, CMS, framework, CDN and WAF.
                            </p>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={async () => {
                              if (isScanning || !query.trim()) return;
                              setIsScanning(true);
                              setQuery('Fingerprinting website stack...');
                              try {
                                const result = await scanTechnology(query.trim());
                                setResults(makeTechLookupResults(result));
                                addRecentScan(makeTechLookupResults(result));
                                setViewingReport(true);
                              } catch (e) {
                                showToast('Technology lookup failed. Please try again.', 'error');
                              } finally {
                                setIsScanning(false);
                              }
                            }}
                            className="w-full py-3.5 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-violet-600 hover:bg-violet-500 text-white"
                          >
                            <span className="flex items-center gap-2">
                              <Cpu className="w-4 h-4" /> Scan Website Stack
                            </span>
                          </button>
                        )}
                      </div>
                    </div>
                  ) : activeTab === 'geolookup' ? (
                    /* IP Geo Lookup */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-500 shrink-0">
                              <MapPin className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>IP Geo Lookup</h3>
                              <p className="text-[11px] font-mono text-slate-400">City · region · country · ASN</p>
                            </div>
                          </div>
                          {results?.geolookup && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Resolved
                            </span>
                          )}
                        </div>

                        {isScanning ? (
                          <div className="flex items-center justify-center gap-3 py-10">
                            <RefreshCw className="w-6 h-6 animate-spin text-cyan-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Resolving geolocation...</span>
                          </div>
                        ) : results?.geolookup ? (
                          <div className="space-y-6">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                { label: 'IP', value: results.geolookup.ip },
                                { label: 'Country', value: results.geolookup.country ? `${results.geolookup.country} (${results.geolookup.countryCode})` : 'N/A' },
                                { label: 'Region', value: results.geolookup.region },
                                { label: 'City', value: results.geolookup.city },
                                { label: 'ASN', value: results.geolookup.asn },
                                { label: 'ISP', value: results.geolookup.isp },
                                { label: 'Timezone', value: results.geolookup.timezone },
                                { label: 'Threat', value: results.geolookup.threatLevel },
                              ].map((field, idx) => (
                                <div key={idx} className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                  <span className="text-[10px] text-slate-500 block mb-1">{field.label}</span>
                                  <span className={`text-xs font-mono font-bold break-all ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{field.value || 'N/A'}</span>
                                </div>
                              ))}
                            </div>

                            {(results.geolookup.latitude !== undefined && results.geolookup.longitude !== undefined) && (
                              <div className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                <span className="text-[10px] text-slate-500 block mb-1">Coordinates</span>
                                <span className={`text-xs font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{results.geolookup.latitude!.toFixed(4)}, {results.geolookup.longitude!.toFixed(4)}</span>
                              </div>
                            )}

                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={async () => {
                                  if (isScanning) return;
                                  setIsScanning(true);
                                  setQuery('Resolving geolocation...');
                                  try {
                                    const result = await scanGeoLookup(results.geolookup!.target);
                                    setResults(makeGeoLookupResults(result));
                                    addRecentScan(makeGeoLookupResults(result));
                                  } catch (e) {
                                    showToast('Geo lookup failed. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Lookup Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        ) : !query.trim() ? (
                          <div className="space-y-4">
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                if (!query.trim()) return;
                                (async () => {
                                  setIsScanning(true);
                                  setQuery('Resolving geolocation...');
                                  try {
                                    const result = await scanGeoLookup(query.trim());
                                    setResults(makeGeoLookupResults(result));
                                    addRecentScan(makeGeoLookupResults(result));
                                    setViewingReport(true);
                                  } catch (err) {
                                    showToast('Geo lookup failed. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                })();
                              }}
                              className={`relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 ${
                                isLightMode
                                  ? 'border-slate-200 bg-white shadow-sm focus-within:border-cyan-500'
                                  : 'border-slate-850 bg-[#0e1424]/40 shadow-lg focus-within:border-cyan-500/80'
                              }`}
                            >
                              <div className="pl-3.5 text-slate-500">
                                <Search className="w-5 h-5" />
                              </div>
                              <input
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                placeholder="Enter an IP address or domain..."
                                className={`w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm focus:ring-0 ${
                                  isLightMode ? 'text-slate-900' : 'text-white'
                                }`}
                                disabled={isScanning}
                              />
                              <button
                                type="submit"
                                disabled={!query.trim() || isScanning}
                                className="px-5 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-900/50 text-white disabled:text-slate-500 font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer"
                              >
                                Lookup
                              </button>
                            </form>
                            <p className="text-[11px] text-slate-500 font-mono">
                              Enter an IP address or a domain (resolved to its A record) to map city, region, ASN and threat flags.
                            </p>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={async () => {
                              if (isScanning || !query.trim()) return;
                              setIsScanning(true);
                              setQuery('Resolving geolocation...');
                              try {
                                const result = await scanGeoLookup(query.trim());
                                setResults(makeGeoLookupResults(result));
                                addRecentScan(makeGeoLookupResults(result));
                                setViewingReport(true);
                              } catch (e) {
                                showToast('Geo lookup failed. Please try again.', 'error');
                              } finally {
                                setIsScanning(false);
                              }
                            }}
                            className="w-full py-3.5 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white"
                          >
                            <span className="flex items-center gap-2">
                              <MapPin className="w-4 h-4" /> Lookup Geolocation
                            </span>
                          </button>
                        )}
                      </div>
                    </div>
                  ) : activeTab === 'poplenscan' ? (
                    /* PopoScan — Webpage Resource Mapping */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-500 shrink-0">
                              <Layers className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>PopoScan</h3>
                              <p className="text-[11px] font-mono text-slate-400">Capture webpage · map resources · trace redirects · identify third parties</p>
                            </div>
                          </div>
                          {results?.poplenscan && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Mapped
                            </span>
                          )}
                        </div>

                        {isScanning ? (
                          <div className="flex items-center justify-center gap-3 py-10">
                            <RefreshCw className="w-6 h-6 animate-spin text-violet-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Capturing webpage and mapping connections...</span>
                          </div>
                        ) : results?.poplenscan ? (
                          <div className="space-y-6">
                            {/* Summary Stats - Clickable Cards */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                { label: 'Total Requests', value: results.poplenscan.statistics.requests.total, color: 'text-slate-900', section: null },
                                { label: 'Total Domains', value: results.poplenscan.statistics.domains.total, color: 'text-slate-900', section: null },
                                { label: 'Third-Party', value: results.poplenscan.statistics.domains.thirdParty, color: 'text-red-400', section: 'thirdParty' },
                                { label: 'Redirects', value: results.poplenscan.statistics.redirects.total, color: 'text-amber-400', section: 'redirects' },
                              ].map((field, idx) => (
                                <button
                                  key={idx}
                                  type="button"
                                  onClick={() => field.section && togglePopoScanSection(field.section)}
                                  className={`p-3.5 rounded-lg border text-left transition-all cursor-pointer ${field.section ? 'hover:shadow-md hover:scale-[1.02] active:scale-[0.98]' : 'cursor-default'} ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}
                                >
                                  <span className="text-[10px] text-slate-500 block mb-1">{field.label}</span>
                                  <div className="flex items-center justify-between gap-2">
                                    <span className={`text-xl font-black font-mono ${field.color}`}>{field.value}</span>
                                    {field.section && (
                                      <span className={`text-slate-400 transition-transform duration-200 ${popoScanExpanded[field.section] ? 'rotate-180' : ''}`}>
                                        <ChevronRight className="w-4 h-4 rotate-90" />
                                      </span>
                                    )}
                                  </div>
                                </button>
                              ))}
                            </div>

                            {/* Redirect Chain - Collapsible */}
                            {results.poplenscan.redirectChain.length > 0 && (
                              <div className={`border rounded-lg overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-slate-900/30'}`}>
                                <button
                                  type="button"
                                  onClick={() => togglePopoScanSection('redirects')}
                                  className={`w-full p-3 flex items-center justify-between cursor-pointer transition-colors ${isLightMode ? 'hover:bg-slate-50' : 'hover:bg-slate-900/20'}`}
                                >
                                  <span className={`text-xs font-bold font-mono uppercase tracking-wider ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                                    Redirect Chain ({results.poplenscan.redirectChain.length})
                                  </span>
                                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${popoScanExpanded['redirects'] ? 'rotate-90' : ''}`} />
                                </button>
                                <AnimatePresence>
                                  {popoScanExpanded['redirects'] && (
                                    <motion.div
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                      transition={{ duration: 0.2 }}
                                      className="overflow-hidden"
                                    >
                                      <div className="overflow-x-auto">
                                        <table className="w-full text-left border-collapse font-mono text-[11px]">
                                          <thead className={`${isLightMode ? 'bg-slate-50 text-slate-500' : 'bg-slate-900/40 text-slate-400'}`}>
                                            <tr>
                                              <th className="px-3 py-2 font-bold">Step</th>
                                              <th className="px-3 py-2 font-bold">From</th>
                                              <th className="px-3 py-2 font-bold">To</th>
                                              <th className="px-3 py-2 font-bold">Status</th>
                                              <th className="px-3 py-2 font-bold">Type</th>
                                            </tr>
                                          </thead>
                                          <tbody className={`divide-y ${isLightMode ? 'divide-slate-100' : 'divide-slate-850'}`}>
                                            {results.poplenscan.redirectChain.map((r, idx) => (
                                              <tr key={idx}>
                                                <td className={`px-3 py-2 ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{idx + 1}</td>
                                                <td className={`px-3 py-2 ${isLightMode ? 'text-slate-600' : 'text-slate-400'}`}><code className="break-all">{r.from}</code></td>
                                                <td className={`px-3 py-2 ${isLightMode ? 'text-slate-600' : 'text-slate-400'}`}><code className="break-all">{r.to}</code></td>
                                                <td className="px-3 py-2">
                                                  <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold ${r.statusCode >= 300 && r.statusCode < 400 ? 'bg-amber-500/10 text-amber-600 border border-amber-500/20' : 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20'}`}>{r.statusCode}</span>
                                                </td>
                                                <td className="px-3 py-2">
                                                  {r.isThirdParty && (
                                                    <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-red-500/10 text-red-600 border border-red-500/20">Third-Party</span>
                                                  )}
                                                </td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </div>
                            )}

                            {/* Third-Party Domains - Collapsible */}
                            {results.poplenscan.statistics.domains.thirdParty > 0 && (
                              <div className={`border rounded-lg overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-slate-900/30'}`}>
                                <button
                                  type="button"
                                  onClick={() => togglePopoScanSection('thirdParty')}
                                  className={`w-full p-3 flex items-center justify-between cursor-pointer transition-colors ${isLightMode ? 'hover:bg-slate-50' : 'hover:bg-slate-900/20'}`}
                                >
                                  <span className={`text-xs font-bold font-mono uppercase tracking-wider ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                                    Third-Party Domains ({results.poplenscan.statistics.domains.thirdParty})
                                  </span>
                                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${popoScanExpanded['thirdParty'] ? 'rotate-90' : ''}`} />
                                </button>
                                <AnimatePresence>
                                  {popoScanExpanded['thirdParty'] && (
                                    <motion.div
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                      transition={{ duration: 0.2 }}
                                      className="overflow-hidden"
                                    >
                                       <div className="divide-y divide-slate-850">
                                         {results.poplenscan.domains.filter(d => d.isThirdParty).map((domain, idx) => {
                                           const isDomainExpanded = popoScanExpandedDomains.has(domain.domain);
                                           const visibleResources = isDomainExpanded ? domain.resources : domain.resources.slice(0, 8);
                                           return (
                                           <div key={idx} className={`p-3 ${isLightMode ? 'bg-white' : 'bg-slate-900/30'}`}>
                                             <div className="flex items-center justify-between mb-1">
                                               <span className="text-xs font-bold font-mono truncate pr-2 text-violet-400">{domain.domain}</span>
                                               <div className="flex items-center gap-2">
                                                 <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold bg-red-500/10 text-red-600 border border-red-500/20">{domain.requestCount} req</span>
                                                 <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold bg-slate-500/10 text-slate-600 border border-slate-500/20">{domain.totalSize > 0 ? `${(domain.totalSize / 1024).toFixed(1)} KB` : '—'}</span>
                                               </div>
                                             </div>
                                             <div className="flex flex-wrap gap-1.5">
                                               {visibleResources.map((r, ri) => (
                                                 <span key={ri} className="text-[9px] px-1.5 py-0.5 rounded bg-slate-200/60 text-slate-700 font-mono break-all">
                                                   {r.type}: {r.url}
                                                 </span>
                                               ))}
                                               {domain.resources.length > 8 && !isDomainExpanded && (
                                                 <button
                                                   type="button"
                                                   onClick={() => togglePopoScanDomain(domain.domain)}
                                                   className="text-[9px] text-violet-400 hover:text-violet-300 font-mono font-bold cursor-pointer"
                                                 >
                                                   +{domain.resources.length - 8} more
                                                 </button>
                                               )}
                                               {isDomainExpanded && domain.resources.length > 8 && (
                                                 <button
                                                   type="button"
                                                   onClick={() => togglePopoScanDomain(domain.domain)}
                                                   className="text-[9px] text-violet-400 hover:text-violet-300 font-mono font-bold cursor-pointer"
                                                 >
                                                   Show less
                                                 </button>
                                               )}
                                             </div>
                                             {domain.cookies.length > 0 && (
                                               <div className="text-[9px] text-slate-500 font-mono mt-1">Cookies: {domain.cookies.join(', ')}</div>
                                             )}
                                           </div>
                                           );
                                         })}
                                       </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </div>
                            )}

                            {/* First-Party Domains - Collapsible */}
                            <div className={`border rounded-lg overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-slate-900/30'}`}>
                              <button
                                type="button"
                                onClick={() => togglePopoScanSection('firstParty')}
                                className={`w-full p-3 flex items-center justify-between cursor-pointer transition-colors ${isLightMode ? 'hover:bg-slate-50' : 'hover:bg-slate-900/20'}`}
                              >
                                <span className={`text-xs font-bold font-mono uppercase tracking-wider ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                                  First-Party Domains ({results.poplenscan.domains.filter(d => !d.isThirdParty).length})
                                </span>
                                <div className="flex items-center gap-2">
                                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${isLightMode ? 'bg-slate-100 text-slate-600' : 'bg-slate-800 text-slate-400'}`}>
                                    {results.poplenscan.domains.filter(d => !d.isThirdParty).length}
                                  </span>
                                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${popoScanExpanded['firstParty'] ? 'rotate-90' : ''}`} />
                                </div>
                              </button>
                              <AnimatePresence>
                                {popoScanExpanded['firstParty'] && (
                                  <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    transition={{ duration: 0.2 }}
                                    className="overflow-hidden"
                                  >
                                     <div className="divide-y divide-slate-850">
                                       {results.poplenscan.domains.filter(d => !d.isThirdParty).map((domain, idx) => {
                                         const isDomainExpanded = popoScanExpandedDomains.has(domain.domain);
                                         const visibleResources = isDomainExpanded ? domain.resources : domain.resources.slice(0, 8);
                                         return (
                                         <div key={idx} className={`p-3 ${isLightMode ? 'bg-white' : 'bg-slate-900/30'}`}>
                                           <div className="flex items-center justify-between mb-1">
                                             <span className="text-xs font-bold font-mono truncate pr-2 text-emerald-400">{domain.domain}</span>
                                             <div className="flex items-center gap-2">
                                               <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/20">{domain.requestCount} req</span>
                                               <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold bg-slate-500/10 text-slate-600 border border-slate-500/20">{domain.totalSize > 0 ? `${(domain.totalSize / 1024).toFixed(1)} KB` : '—'}</span>
                                             </div>
                                           </div>
                                           <div className="flex flex-wrap gap-1.5">
                                             {visibleResources.map((r, ri) => (
                                               <span key={ri} className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-700 font-mono break-all">
                                                 {r.type}: {r.url}
                                               </span>
                                             ))}
                                             {domain.resources.length > 8 && !isDomainExpanded && (
                                               <button
                                                 type="button"
                                                 onClick={() => togglePopoScanDomain(domain.domain)}
                                                 className="text-[9px] text-violet-400 hover:text-violet-300 font-mono font-bold cursor-pointer"
                                               >
                                                 +{domain.resources.length - 8} more
                                               </button>
                                             )}
                                             {isDomainExpanded && domain.resources.length > 8 && (
                                               <button
                                                 type="button"
                                                 onClick={() => togglePopoScanDomain(domain.domain)}
                                                 className="text-[9px] text-violet-400 hover:text-violet-300 font-mono font-bold cursor-pointer"
                                               >
                                                 Show less
                                               </button>
                                             )}
                                           </div>
                                           {domain.cookies.length > 0 && (
                                             <div className="text-[9px] text-slate-500 font-mono mt-1">Cookies: {domain.cookies.join(', ')}</div>
                                           )}
                                         </div>
                                         );
                                       })}
                                     </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>
                            </div>

                            {/* Resource Type Breakdown - Collapsible */}
                            <div className={`border rounded-lg overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-slate-900/30'}`}>
                              <button
                                type="button"
                                onClick={() => togglePopoScanSection('resources')}
                                className={`w-full p-3 flex items-center justify-between cursor-pointer transition-colors ${isLightMode ? 'hover:bg-slate-50' : 'hover:bg-slate-900/20'}`}
                              >
                                <span className={`text-xs font-bold font-mono uppercase tracking-wider ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                                  Resource Type Breakdown
                                </span>
                                <div className="flex items-center gap-2">
                                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${isLightMode ? 'bg-slate-100 text-slate-600' : 'bg-slate-800 text-slate-400'}`}>
                                    {Object.keys(results.poplenscan.statistics.resources.byType).length} types
                                  </span>
                                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${popoScanExpanded['resources'] ? 'rotate-90' : ''}`} />
                                </div>
                              </button>
                              <AnimatePresence>
                                {popoScanExpanded['resources'] && (
                                  <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    transition={{ duration: 0.2 }}
                                    className="overflow-hidden"
                                  >
                                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 p-3">
                                      {Object.entries(results.poplenscan.statistics.resources.byType).map(([type, count]) => (
                                        <div key={type} className="p-3 rounded-lg bg-slate-50/50 border border-slate-200 text-center">
                                          <div className={`text-xl font-black font-mono ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{count}</div>
                                          <div className="text-[10px] font-mono uppercase text-slate-500 capitalize">{type}</div>
                                        </div>
                                      ))}
                                    </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>
                            </div>

                            {/* Cookies - Collapsible */}
                            {results.poplenscan.statistics.cookies.total > 0 && (
                              <div className={`border rounded-lg overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-slate-900/30'}`}>
                                <button
                                  type="button"
                                  onClick={() => togglePopoScanSection('cookies')}
                                  className={`w-full p-3 flex items-center justify-between cursor-pointer transition-colors ${isLightMode ? 'hover:bg-slate-50' : 'hover:bg-slate-900/20'}`}
                                >
                                  <span className={`text-xs font-bold font-mono uppercase tracking-wider ${isLightMode ? 'text-slate-900' : 'text-white'}`}>
                                    Cookies ({results.poplenscan.statistics.cookies.total})
                                  </span>
                                  <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${popoScanExpanded['cookies'] ? 'rotate-90' : ''}`} />
                                </button>
                                <AnimatePresence>
                                  {popoScanExpanded['cookies'] && (
                                    <motion.div
                                      initial={{ height: 0, opacity: 0 }}
                                      animate={{ height: 'auto', opacity: 1 }}
                                      exit={{ height: 0, opacity: 0 }}
                                      transition={{ duration: 0.2 }}
                                      className="overflow-hidden"
                                    >
                                      <div className="overflow-x-auto">
                                        <table className="w-full text-left border-collapse font-mono text-xs">
                                          <thead className={`${isLightMode ? 'bg-slate-50 text-slate-500' : 'bg-slate-900/40 text-slate-400'}`}>
                                            <tr>
                                              <th className="px-3 py-2 font-bold">Name</th>
                                              <th className="px-3 py-2 font-bold">Domain</th>
                                              <th className="px-3 py-2 font-bold">Secure</th>
                                              <th className="px-3 py-2 font-bold">HttpOnly</th>
                                              <th className="px-3 py-2 font-bold">SameSite</th>
                                            </tr>
                                          </thead>
                                          <tbody className={`divide-y ${isLightMode ? 'divide-slate-100' : 'divide-slate-850'}`}>
                                            {results.poplenscan.cookies.map((cookie, idx) => (
                                              <tr key={idx}>
                                                <td className="px-3 py-2 font-semibold text-slate-900">{cookie.name}</td>
                                                <td className="px-3 py-2 text-slate-700">{cookie.domain}</td>
                                                <td className="px-3 py-2 text-center">{cookie.secure ? '✓' : '✗'}</td>
                                                <td className="px-3 py-2 text-center">{cookie.httpOnly ? '✓' : '✗'}</td>
                                                <td className="px-3 py-2 text-center">{cookie.sameSite || '—'}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </div>
                            )}

                            <div className={`p-3 rounded-lg border text-[11px] text-slate-500 font-mono ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                              Scan captured at {results.poplenscan.scanTime} · Webpage fetched via CORS proxy; resource extraction via DOM parsing; redirects tracked; third-party classification by domain comparison.
                            </div>

                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={() => {
                                  setResults(null);
                                  setQuery('');
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-violet-600 hover:bg-violet-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Scan Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        ) : !query.trim() || (query.trim() && !isValidUrl(query.trim())) ? (
                          <div className="space-y-4">
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                const trimmed = query.trim();
                                if (!trimmed || !isValidUrl(trimmed)) return;
                                (async () => {
                                  setIsScanning(true);
                                  setQuery('Capturing webpage resources and mapping connections...');
                                  try {
                                    const result = await scanPopoScan(trimmed);
                                    setResults(makePopoScanResults(result));
                                    addRecentScan(makePopoScanResults(result));
                                    setViewingReport(true);
                                  } catch (err) {
                                    showToast('PopoScan failed. Please check the URL and try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                })();
                              }}
                              className={`relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 ${
                                isLightMode
                                  ? 'border-slate-200 bg-white shadow-sm focus-within:border-violet-500'
                                  : 'border-slate-850 bg-[#0e1424]/40 shadow-lg focus-within:border-violet-500/80'
                              }`}
                            >
                              <div className="pl-3.5 text-slate-500">
                                <Search className="w-5 h-5" />
                              </div>
                              <input
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                placeholder="Enter a website URL (e.g., https://example.com)..."
                                className={`w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm focus:ring-0 ${isLightMode ? 'text-slate-900' : 'text-white'}`}
                                disabled={isScanning}
                              />
                              <button
                                type="submit"
                                disabled={!query.trim() || isScanning || !isValidUrl(query.trim())}
                                className="px-5 py-3 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:bg-slate-900/50 text-white disabled:text-slate-500 font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer"
                              >
                                Scan
                              </button>
                            </form>
                            <p className="text-[11px] text-slate-500 font-mono">
                              Enter a website URL to capture its resources, redirects, third-party connections, and cookies.
                            </p>
                            {query.trim() && !isValidUrl(query.trim()) && (
                              <p className="text-[11px] text-red-400 font-mono">
                                Please enter a valid URL starting with http:// or https://
                              </p>
                            )}
                          </div>
                        ) : (
                          <div className="space-y-4">
                            <div className={`border rounded-xl p-4 space-y-3 ${
                              isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'
                            }`}>
                              <div className="flex items-center gap-2 text-xs font-mono">
                                <Globe className="w-4 h-4 text-violet-400 shrink-0" />
                                <span className="text-slate-400">Target:</span>
                                <span className="text-slate-200 font-semibold truncate">{query.trim()}</span>
                              </div>
                            </div>
                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={async () => {
                                  if (isScanning || !query.trim()) return;
                                  setIsScanning(true);
                                  setQuery('Capturing webpage resources and mapping connections...');
                                  try {
                                    const result = await scanPopoScan(query.trim());
                                    setResults(makePopoScanResults(result));
                                    addRecentScan(makePopoScanResults(result));
                                    setViewingReport(true);
                                  } catch (e) {
                                    showToast('PopoScan failed. Please check the URL and try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-violet-600 hover:bg-violet-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Start PopoScan
                              </button>
                              <button
                                type="button"
                                onClick={() => setQuery('')}
                                className="px-4 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border border-slate-700 bg-slate-900/40 text-slate-400 hover:text-white"
                              >
                                Change URL
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : activeTab === 'speedtest' ? (
                    <Suspense fallback={
                      <div className="flex items-center justify-center gap-3 py-10">
                        <RefreshCw className="w-6 h-6 animate-spin text-emerald-500" />
                        <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Loading speed test module...</span>
                      </div>
                    }>
                      <SpeedTestWorkspace
                        isLightMode={isLightMode}
                        isScanning={isScanning}
                        results={results}
                        onScanComplete={(r) => {
                          setResults(r);
                          addRecentScan(r);
                        }}
                        showToast={showToast}
                      />
                    </Suspense>
                  ) : activeTab === 'myip' ? (
                    /* What is My IP — auto-detected, no manual search */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-500 shrink-0">
                              <Network className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>What is My IP</h3>
                              <p className="text-[11px] font-mono text-slate-400">Your public IP is detected automatically</p>
                            </div>
                          </div>
                          {results?.myip && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Detected
                            </span>
                          )}
                        </div>

                        {isScanning ? (
                          <div className="flex items-center justify-center gap-3 py-10">
                            <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Detecting your public IP...</span>
                          </div>
                        ) : results?.myip ? (
                          <div className="space-y-6">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                { label: 'IP', value: results.myip.ip },
                                { label: 'Version', value: results.myip.ipVersion },
                                { label: 'Country', value: results.myip.country },
                                { label: 'ISP', value: results.myip.isp },
                              ].map((field, idx) => (
                                <div key={idx} className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                  <span className="text-[10px] text-slate-500 block mb-1">{field.label}</span>
                                  <span className={`text-sm font-mono font-bold break-all ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{field.value || 'N/A'}</span>
                                </div>
                              ))}
                            </div>

                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={async () => {
                                  if (isScanning) return;
                                  setIsScanning(true);
                                  try {
                                    const result = await scanMyIp();
                                    setResults(makeMyIpResults(result));
                                    addRecentScan(makeMyIpResults(result));
                                  } catch (e) {
                                    showToast('Failed to detect IP. Please try again.', 'error');
                                  } finally {
                                    setIsScanning(false);
                                  }
                                }}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Scan Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        ) : (
                          <div className="text-center text-xs text-slate-500 font-mono py-6">
                            Unable to detect your public IP. Check your connection and try again.
                          </div>
                        )}
                      </div>
                    </div>
                   ) : activeTab === 'subdomain' ? (
                    /* Subdomain Finder — inline results */
                    <div className="space-y-6">
                      <div className={`border rounded-xl p-6 space-y-6 ${isLightMode ? 'border-slate-200 bg-white shadow-sm text-slate-800' : 'border-slate-800 bg-[#0e1424]/40'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-500 shrink-0">
                              <Boxes className="w-5 h-5" />
                            </div>
                            <div>
                              <h3 className={`text-sm font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Subdomain Finder</h3>
                              <p className="text-[11px] font-mono text-slate-400">Certificate transparency + active DNS validation</p>
                            </div>
                          </div>
                          {subdomainResult && (
                            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 text-[10px] font-mono font-bold uppercase">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Complete
                            </span>
                          )}
                        </div>

                        <form
                          onSubmit={(e) => {
                            e.preventDefault();
                            if (!query.trim() || isScanning) return;
                            (async () => {
                              setIsScanning(true);
                              setQuery('Enumerating subdomains...');
                              try {
                                const result = await findSubdomains(query.trim());
                                setSubdomainResult(result);
                                const scanResults = makeSubdomainResults(result);
                                setResults(scanResults);
                                addRecentScan(scanResults);
                              } catch (err) {
                                showToast('Subdomain scan failed. Please try again.', 'error');
                              } finally {
                                setIsScanning(false);
                              }
                            })();
                          }}
                          className={`relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 ${
                            isLightMode ? 'border-slate-200 bg-white shadow-sm focus-within:border-red-500' : 'border-slate-800 bg-[#0e1424]/40 shadow-lg focus-within:border-red-500/85'
                          }`}
                        >
                          <div className="pl-3.5 text-slate-500">
                            <Search className="w-5 h-5" />
                          </div>
                          <input
                            type="text"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            placeholder="Enter a domain (e.g., example.com)..."
                            className={`w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm focus:ring-0 ${isLightMode ? 'text-slate-900' : 'text-white'}`}
                            disabled={isScanning}
                          />
                          <button
                            type="submit"
                            disabled={!query.trim() || isScanning}
                            className="px-5 py-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-900/50 text-white disabled:text-slate-500 font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer"
                          >
                            {isScanning ? 'Scanning...' : 'Discover'}
                          </button>
                        </form>

                        {isScanning && (
                          <div className="flex items-center justify-center gap-3 py-8">
                            <RefreshCw className="w-5 h-5 animate-spin text-indigo-500" />
                            <span className={`text-sm font-mono font-bold ${isLightMode ? 'text-slate-900' : 'text-white'}`}>Enumerating subdomains via CT logs and DNS validation...</span>
                          </div>
                        )}

                        {subdomainResult && !isScanning && (
                          <div className="space-y-6">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                { label: 'Discovered', value: subdomainResult.items.length, color: 'text-blue-500' },
                                { label: 'Verified', value: subdomainResult.items.filter(i => i.status !== 'wildcard').length, color: 'text-emerald-500' },
                                { label: 'Sensitive', value: subdomainResult.items.filter(i => i.severity === 'medium').length, color: 'text-amber-500' },
                                { label: 'CT + Wordlist', value: `${subdomainResult.extra?.CT || 0} + ${subdomainResult.extra?.Wordlist || 0}`, color: 'text-purple-500' },
                              ].map((stat) => (
                                <div key={stat.label} className={`p-3.5 rounded-lg border ${isLightMode ? 'border-slate-200 bg-slate-50' : 'border-slate-850 bg-slate-900/30'}`}>
                                  <span className="text-[10px] text-slate-500 block mb-1">{stat.label}</span>
                                  <span className={`text-lg font-black font-mono ${isLightMode ? 'text-slate-900' : 'text-white'}`}>{stat.value}</span>
                                </div>
                              ))}
                            </div>

                            <div className={`border rounded-xl overflow-hidden ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-800 bg-[#0e1424]/20'}`}>
                              <div className={`px-4 py-3 border-b flex items-center justify-between font-mono text-[10px] font-bold ${isLightMode ? 'border-slate-200 bg-slate-50 text-slate-500' : 'border-slate-800 bg-[#0c1221] text-slate-400'}`}>
                                <span>DISCOVERED SUBDOMAINS</span>
                                <button
                                  onClick={() => {
                                    const text = subdomainResult.items.map(i => i.label).join('\n');
                                    navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard'));
                                  }}
                                  className="px-2 py-1 rounded text-[10px] font-bold uppercase border cursor-pointer hover:bg-slate-100 transition-all flex items-center gap-1"
                                >
                                  <Copy className="w-3 h-3" /> Copy All
                                </button>
                              </div>
                              <div className="divide-y divide-slate-200/50 max-h-[400px] overflow-y-auto">
                                {subdomainResult.items.map((item, idx) => (
                                  <div key={idx} className="hover:bg-slate-50/50 transition-colors">
                                    <div
                                      className="px-4 py-3 flex items-center justify-between gap-4 cursor-pointer"
                                      onClick={() => setExpandedSubdomain(expandedSubdomain === item.label ? null : item.label)}
                                    >
                                      <div className="flex items-center gap-3 flex-1 min-w-0">
                                        <Boxes className={`w-4 h-4 shrink-0 ${item.status === 'wildcard' ? 'text-red-400' : 'text-indigo-400'}`} />
                                        <div className="flex-1 min-w-0">
                                          <span className="text-sm font-mono text-slate-700 truncate block">{item.label}</span>
                                          {item.value && (
                                            <span className="text-[10px] text-slate-500 font-mono">{item.value}</span>
                                          )}
                                        </div>
                                      </div>
                                      <div className="flex items-center gap-2 shrink-0">
                                        {item.severity === 'medium' && (
                                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono font-bold uppercase">Sensitive</span>
                                        )}
                                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase ${
                                          item.status === 'wildcard' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                          'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                        }`}>
                                          {item.status}
                                        </span>
                                        <ChevronRight className={`w-3.5 h-3.5 text-slate-400 transition-transform ${expandedSubdomain === item.label ? 'rotate-90' : ''}`} />
                                      </div>
                                    </div>
                                    {expandedSubdomain === item.label && (
                                      <div className={`px-4 py-3 border-t ${isLightMode ? 'border-slate-100 bg-slate-50/80' : 'border-slate-800 bg-slate-900/20'}`}>
                                        <div className="text-[10px] font-mono text-slate-500 leading-relaxed space-y-1">
                                          <div className="flex items-start gap-1.5">
                                            <Info className="w-3 h-3 mt-0.5 shrink-0 text-indigo-400" />
                                            <span>{item.detail}</span>
                                          </div>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                ))}
                                {subdomainResult.items.length === 0 && (
                                  <div className="px-4 py-8 text-center text-slate-500 font-mono text-sm">
                                    No subdomains discovered. Try a different domain.
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="flex flex-col sm:flex-row gap-3">
                              <button
                                type="button"
                                onClick={() => setSubdomainResult(null)}
                                className="flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white"
                              >
                                <RefreshCw className="w-4 h-4" /> Scan Again
                              </button>
                              <button
                                type="button"
                                onClick={() => setViewingReport(true)}
                                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 border ${isLightMode ? 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50' : 'border-slate-700 bg-slate-900/40 text-slate-300'}`}
                              >
                                <FileText className="w-4 h-4" /> View Full Report
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          if (!query.trim()) return;
                          const sanitizedQuery = sanitizeText(query, 500);
                          const targets = sanitizedQuery.split(',').map((t) => t.trim()).filter(Boolean);
                          if (targets.length > 1) {
                            triggerBatchInvestigation(targets);
                          } else {
                            triggerInvestigation();
                          }
                        }}
                        className={`relative flex items-center border rounded-xl overflow-hidden transition-all p-1.5 ${
                          isLightMode
                            ? 'border-slate-200 bg-white shadow-sm focus-within:border-red-500'
                            : 'border-slate-850 bg-[#0e1424]/40 shadow-lg focus-within:border-red-500/85'
                        }`}
                      >
                        <div className="pl-3.5 text-slate-500">
                          <Search className="w-5 h-5" />
                        </div>
                        <input
                          type="text"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                           placeholder={getModule(activeTab)?.placeholder}
                          className={`w-full bg-transparent border-none outline-none py-3.5 px-3 text-sm focus:ring-0 ${
                            isLightMode ? 'text-slate-900' : 'text-white'
                          }`}
                          disabled={isScanning}
                        />
                        <div className="flex items-center gap-1.5 shrink-0 pr-1">
                          <button
                            type="button"
                            onClick={() => setShowQrScanner(true)}
                            className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center justify-center ${
                              isLightMode
                                ? 'border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                                : 'border-slate-800 bg-slate-900/50 text-slate-400 hover:border-slate-700'
                            }`}
                            title="Scan Target QR Code"
                          >
                            <QrCode className="w-4 h-4" />
                          </button>
                          <button
                            type="submit"
                            disabled={!query.trim() || isScanning}
                            className="px-5 py-3 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-slate-900/50 text-white disabled:text-slate-500 font-semibold text-xs transition-all uppercase tracking-wider cursor-pointer"
                          >
                            Analyze
                          </button>
                        </div>
                      </form>

                      {/* Helper Hint line */}
                      <div className="flex items-center justify-between text-xs font-mono text-slate-500">
                         <span>* {getModule(activeTab)?.helpHint}</span>
                        {query.trim() && (
                          <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold uppercase">
                            MATCH: {detectedType}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Focused Module recent activity */}
                  <div className="space-y-3 pt-6 border-t border-dashed border-slate-850">
                    <h4 className="text-xs font-bold font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <History className="w-4 h-4 text-slate-500" /> Recent {getModule(activeTab)?.label} scans
                    </h4>
                    
                    {recentScans.filter(s => s.target.type === activeTab || (activeTab === 'risk' && s.target.type !== 'image' && s.target.type !== 'metadata')).length === 0 ? (
                      <div className="border border-dashed border-slate-850 rounded-xl p-6 text-center text-xs text-slate-500 font-mono italic">
                        No recent scans for this tool. Run a query above to log results locally.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {recentScans
                          .filter(s => s.target.type === activeTab || (activeTab === 'risk' && s.target.type !== 'image' && s.target.type !== 'metadata'))
                          .map((scan, idx) => {
                            const scGrade = calculateRiskScore(scan.findings).grade;
                            return (
                              <div
                                key={idx}
                                className={`border rounded-xl p-3.5 transition-all relative group flex flex-col justify-between ${
                                  isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-[#0e1424]/20 hover:border-slate-700'
                                }`}
                              >
                          <div onClick={() => { setResults(scan); setViewingReport(true); }} className="cursor-pointer space-y-2 pr-6 no-copy">
                            <div className="flex justify-between items-center text-[10px] font-mono">
                              <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/25 uppercase font-bold">
                                {scan.target.type}
                              </span>
                              <span className="text-slate-500 font-bold">{scGrade} GRADE ({scan.riskScore})</span>
                            </div>
                            <h5 className="font-bold font-mono text-xs truncate text-slate-200">{sanitizeText(scan.target.value, 80)}</h5>
                            <span className="text-[9px] text-slate-500 font-mono block">{scan.scanTime}</span>
                          </div>
                                <button
                                  onClick={() => removeHistoryItem(scan.target.value, scan.target.type)}
                                  className="absolute top-3 right-3 p-1 rounded hover:bg-red-500/10 text-slate-500 hover:text-red-500 cursor-pointer"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            );
                          })}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            {/* --- 3. WORKSPACE SETTINGS VIEW --- */}
            {activeTab === 'settings' && !viewingReport && !viewingBatch && (
              <motion.div
                key="settings_view"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.15 }}
                className="space-y-8"
              >
                <div className="border-b border-slate-850 pb-4">
                  <h2 className="text-xl font-black font-display flex items-center gap-2">
                    <Sliders className="w-5 h-5 text-red-500" /> Workspace Settings
                  </h2>
                  <p className="text-xs text-slate-400 font-medium">Configure simulated telemetry delays and inspect browser DOM cache stores.</p>
                </div>

                <div className="max-w-2xl mx-auto space-y-6">
                  {/* Settings Control Block */}
                  <div className={`border rounded-xl p-5 space-y-5 ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-[#0e1424]/40'}`}>
                    <h3 className="text-xs font-bold font-mono uppercase text-slate-400 tracking-wider">Recon Controls</h3>
                    
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5 pr-4">
                        <strong className="text-sm font-semibold block">Realistic Console Delays</strong>
                        <p className="text-xs text-slate-500 leading-normal">Simulates network query delays in the HUD console logs.</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={simulateDelay}
                          onChange={(e) => setSimulateDelay(e.target.checked)}
                          className="sr-only peer"
                        />
                        <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-red-500"></div>
                      </label>
                    </div>

                    <div className="flex items-center justify-between pt-4 border-t border-slate-800/40">
                      <div className="space-y-0.5 pr-4">
                        <strong className="text-sm font-semibold block">Thorough Network Auditing</strong>
                        <p className="text-xs text-slate-500 leading-normal">Performs deep parallel certificate validations on subdomain mappings.</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={strictScans}
                          onChange={(e) => setStrictScans(e.target.checked)}
                          className="sr-only peer"
                        />
                        <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-red-500"></div>
                      </label>
                    </div>
                   </div>

                   {/* Appearance */}
                   <div className={`border rounded-xl p-5 space-y-5 ${isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-[#0e1424]/40'}`}>
                     <h3 className="text-xs font-bold font-mono uppercase text-slate-400 tracking-wider">Appearance</h3>
                     <div className="flex items-center justify-between">
                       <div className="space-y-0.5 pr-4">
                         <strong className="text-sm font-semibold block">Theme</strong>
                         <p className="text-xs text-slate-500 leading-normal">Choose between light, dark, or system preference.</p>
                       </div>
                       <ThemeToggle />
                     </div>
                   </div>

                   {/* Sandbox Cache Clear */}
                  <div className={`border rounded-xl p-5 space-y-4 border-red-500/20 bg-red-500/5`}>
                    <h3 className="text-xs font-bold font-mono uppercase text-red-400 tracking-wider">Data Management</h3>
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5 pr-4">
                        <strong className="text-sm font-semibold block text-red-300">Wipe Investigation History</strong>
                        <p className="text-xs text-red-500/70 leading-normal">Irreversibly cleans all stored targets, files, and findings from local storage.</p>
                      </div>
                      <button
                        onClick={clearHistory}
                        disabled={recentScans.length === 0}
                        className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-slate-900 disabled:text-slate-500 font-bold text-xs uppercase tracking-wider text-white rounded-lg transition-all cursor-pointer"
                      >
                        Clear All
                      </button>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}

            {/* --- 4. ALL WORKSPACE HISTORY VIEW --- */}
            {activeTab === 'history' && !viewingReport && !viewingBatch && (
              <motion.div
                key="history_view"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.15 }}
                className="space-y-8"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-850 pb-4">
                  <div>
                    <h2 className="text-xl font-black font-display flex items-center gap-2">
                      <History className="w-5 h-5 text-red-400" /> Stored Local Investigations
                    </h2>
                    <p className="text-xs text-slate-400 font-medium">Browse, review, and export findings from all sandbox runs.</p>
                  </div>

                  {recentScans.length > 0 && (
                    <button
                      onClick={clearHistory}
                      className="px-3.5 py-1.5 rounded-lg border border-red-500/20 bg-red-500/5 hover:bg-red-500/10 text-red-400 text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5"
                    >
                      <Trash2 className="w-4 h-4" /> Clear All Scan Logs
                    </button>
                  )}
                </div>

                <div className="max-w-6xl mx-auto">
                  {recentScans.length === 0 ? (
                    <div className="border border-dashed border-slate-850 rounded-xl p-12 text-center text-xs text-slate-500 font-mono italic space-y-2">
                      <History className="w-8 h-8 text-slate-600 mx-auto stroke-[1.2]" />
                      <p>No investigations logged yet.</p>
                      <p className="text-[10px] text-slate-600">Start from the Lobby Home to build your local findings cache.</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                      {recentScans.map((scan, idx) => {
                        const scoreDetails = calculateRiskScore(scan.findings);
                        return (
                          <div
                            key={idx}
                            className={`border rounded-xl p-4 transition-all relative group flex flex-col justify-between hover:-translate-y-0.5 ${
                              isLightMode ? 'border-slate-200 bg-white' : 'border-slate-850 bg-[#0e1424]/40 hover:border-slate-700'
                            }`}
                          >
                            <div onClick={() => { setResults(scan); setViewingReport(true); }} className="cursor-pointer space-y-3 pr-6 no-copy">
                              <div className="flex justify-between items-center text-[10px] font-mono">
                                <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold uppercase">
                                  {scan.target.type}
                                </span>
                                <div className="flex items-center gap-1.5">
                                  <div className={`w-1.5 h-1.5 rounded-full ${scan.riskScore > 60 ? 'bg-red-500' : scan.riskScore > 30 ? 'bg-amber-500' : 'bg-emerald-500'}`} />
                                  <span className="font-bold text-slate-400 uppercase">{scoreDetails.grade} ({scan.riskScore})</span>
                                </div>
                              </div>

                              <div className="space-y-1">
                                <h4 className="font-bold font-mono text-sm truncate text-slate-200">{sanitizeText(scan.target.value, 80)}</h4>
                                <span className="text-[10px] text-slate-500 font-mono block">{scan.scanTime}</span>
                              </div>

                              <div className="pt-2 border-t border-slate-850 flex items-center gap-4 text-[10px] font-mono text-slate-400">
                                <span>Findings: {scan.findings.length}</span>
                                <span>Timeline: {scan.timeline.length}</span>
                              </div>
                            </div>

                            <button
                              onClick={() => removeHistoryItem(scan.target.value, scan.target.type)}
                              className="absolute top-4 right-4 p-1 rounded hover:bg-red-500/10 text-slate-500 hover:text-red-500 cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity"
                              title="Delete from cache"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

          </AnimatePresence>
        </div>

        {/* --- GLOBAL PERSISTENT FOOTER (shown on every screen) --- */}
        <footer
          className="mt-auto shrink-0 border-t px-4 sm:px-6 lg:px-8 py-4"
          style={{
            borderColor: 'var(--border-default)',
            backgroundColor: 'var(--bg-panel)',
          }}
        >
          <p className="text-center text-[11px] sm:text-xs font-medium leading-relaxed" style={{ color: 'var(--text-primary)' }}>
            Created by <span className="font-bold" style={{ color: 'var(--text-accent)' }}>Cyberswahili</span>
            <span style={{ color: 'var(--text-secondary)' }}> : </span>
            <span className="font-bold" style={{ color: 'var(--text-primary)' }}>OSINTCS v2.0</span>
            <span style={{ color: 'var(--text-secondary)' }}> · </span>
            Browser-Based Security Sandbox Intelligence
            <span style={{ color: 'var(--text-secondary)' }}> · </span>
            <span className="font-bold" style={{ color: 'var(--text-accent)' }}>Zero Telemetry</span>
          </p>
        </footer>
      </main>
      </ErrorBoundary>

      {/* --- HUD CONSOLE OVERLAY --- */}
      <ScanConsole isScanning={isScanning} scanLogs={scanLogs} />

      {/* --- QR SCANNER COMPONENT MODAL --- */}
      {showQrScanner && (
        <QrScannerModal
          onClose={() => setShowQrScanner(false)}
          onScanSuccess={(text) => {
            setQuery(text);
            setShowQrScanner(false);
            setTimeout(() => {
              const parsed = parseInvestigationTarget(text);
              triggerInvestigation(parsed);
            }, 300);
          }}
        />
      )}
    </div>
  );
}


